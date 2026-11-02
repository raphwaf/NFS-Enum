# nfs_enum.py

An NFS enumeration tool for pentesters. It walks a target through six phases from a quick port check all the way to mounting shares and flagging dangerous export options and writes a structured report at the end.

## Features

- **Phase 1 – Ports:** TCP check for portmapper (111), NFS (2049), mountd, and lockd. Reminds you that these services often answer over UDP too, so `rpcinfo` is treated as the source of truth.
- **Phase 2 – RPC:** `rpcinfo -p` with an `nmap --script rpcinfo` fallback; NFS-related services are highlighted.
- **Phase 3 – Shares:** `showmount -e/-a` to list exports and active mounts, with an `nmap nfs-showmount` fallback. Wildcard (`*` / everyone) exports are called out.
- **Phase 4 – Security analysis:** flags remotely-visible issues (wildcard exports), runs `nfs-ls` / `nfs-statfs` recon, and prints an attack cheat-sheet (`no_root_squash` privesc, UID spoofing, NFSv3 sniffing). Notes that squash options live in `/etc/exports` and can't be read remotely — only confirmed by a write-test.
- **Phase 5 – Mount & explore (`--mount`):** read-only mounts each export (tries v3 → v4 → v2), then walks the tree for interesting files (SSH keys, `shadow`, configs, backups, `*secret*`, etc.), SUID/SGID binaries, and world-writable dirs. As root, also runs a deliberate rw write-test to confirm `no_root_squash`. Falls back to the NFSv4 pseudo-root (`host:/`) when `showmount` returns nothing. Without root, it prints the equivalent mount commands instead.
- **Phase 6 – Nmap NSE:** `nfs-ls`, `nfs-showmount`, `nfs-statfs` as a final supplement.
- **Reporting:** writes both a JSON and a plain-text summary per run.

## Requirements

- Python 3 (standard library only)
- External tools used when present: `rpcinfo`, `showmount` (package `nfs-common`), `mount`, `nmap`. The script degrades gracefully when any are missing.
- `--mount` needs **root** for the actual mounts and the root-squash write-test.

## Usage

```bash
python3 nfs_enum.py <target>                              # recon only
python3 nfs_enum.py <target> --mount                      # print mount commands (non-root)
sudo python3 nfs_enum.py <target> --mount --output ./loot # full mount + explore
python3 nfs_enum.py <target> --skip-nmap --timeout 3
```

### Flags

| Flag | Description |
|------|-------------|
| `target` | Target IP or hostname (required) |
| `--mount` | Mount shares read-only and enumerate files; as root also runs the root-squash write-test |
| `--skip-nmap` | Skip the nmap NSE phase |
| `--output DIR` | Directory for reports (default: `./nfs_results`) |
| `--timeout SEC` | TCP port-check timeout (default: 2) |

## Output

Each run drops two files in the output directory:

- `nfs_<host>_<timestamp>.json` — full structured results
- `nfs_<host>_<timestamp>.txt` — human-readable summary (ports, exports, findings, mounted-share loot)

## Safety notes

- Recon mounts are always read-only; the rw write-test uses a `soft` mount, writes a single probe file, reads back its owner UID, then removes it and unmounts.
- Cleanup only deletes mountpoints confirmed unmounted (via `/proc/mounts`), so it never unlinks files on a live remote share. Anything it can't unmount is left in place with a warning.
- Set `NO_COLOR=1` to disable ANSI colors.

## Disclaimer

For authorized security testing and lab use only. Only run this against systems you own or have explicit written permission to test.
