# AGENTS.md

## Cursor Cloud specific instructions

This repo is a collection of standalone Python scripts (educational offensive-security lab)
plus some PHP webshell files. There is no build system, no test suite, and no long-running
service — the "applications" are CLI scripts run directly with `python3`.

### Python dependencies
`scapy`, `matplotlib`, `pandas`, `termcolor` (see `requirements.txt`). The startup update
script installs them to the system Python via `pip --break-system-packages` (Ubuntu 24.04 is
PEP 668 "externally managed"). They are installed for BOTH the `ubuntu` user and `root` so
scripts run with or without `sudo`.

### Running the sniffers (core functionality)
- `full.py` / `Part03.py` / `part 01.py` / `part 02.py` / `wifi_&_mobile/Sniffer.py` use
  `scapy.sniff`, which needs raw-socket privileges — run them with `sudo`.
- The scripts hardcode a network interface (`eth0`, `wlan0`, or `Wi-Fi`). On this VM the real
  interface is `eth0`; `full.py` already picks `eth0` on Linux, but the other scripts default to
  `Wi-Fi`/`wlan0` and will error unless the `iface=` value is adjusted. Do not commit such
  edits unless asked.
- These sniffers run indefinitely and/or open interactive matplotlib windows. In a headless
  VM set `MPLBACKEND=Agg` to avoid GUI errors, and bound captures with scapy's
  `timeout=`/`count=` when testing.
- `full.py` appends captured packet summaries to `packets_log.txt` (a tracked file) — revert
  it after test runs to keep the working tree clean.

### Stéganographie tool
`Stéganographies /webinaire_2025.py` (note the trailing space in the dir name) is a thin
`argparse` wrapper around external CLI tools (`exiftool`, `steghide`, `binwalk`) invoked via
`os.system`. `--help` works out of the box; the actual modes require those system binaries,
which are not part of the Python setup.

### Lint / test / build
There is no configured linter, test runner, or build step. Use `python3 -m py_compile <file>`
to syntax-check scripts.
