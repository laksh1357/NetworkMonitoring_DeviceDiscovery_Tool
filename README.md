# LAN Watchtower

A desktop network monitoring and device discovery tool built with Python and CustomTkinter. It detects the local IPv4 subnet, scans the LAN in a background thread, displays active devices, preserves disconnected devices as `Offline`, reports join/leave changes, and exports the current device table to CSV.

## Web Console

The related Atlas web console is available in the [AI_PROJECT repository](https://github.com/laksh1357/AI_PROJECT). When running locally, open [http://127.0.0.1:8000](http://127.0.0.1:8000) and its [API documentation](http://127.0.0.1:8000/docs).

The web console is a separate FastAPI application and is not the CustomTkinter desktop interface in this repository.

## Project structure

```text
.
├── main.py
├── vendor_lookup.py
├── oui_vendors.json
├── database_manager.py
├── port_scanner.py
├── notifications.py
├── requirements.txt
├── README.md
├── .github/copilot-instructions.md
└── tests/test_main.py
```

## Setup

Python 3.10 or newer is recommended. CustomTkinter provides the modern dark/light interface, while the device table uses a themed `ttk.Treeview`. Tkinter is included with the official macOS Python installer; Linux users may need their distribution's `python3-tk` package.

On macOS with Homebrew Python, install the matching Tk runtime before creating the environment:

```bash
brew install python-tk@3.14
```

Use a regular macOS Terminal or VS Code external terminal to launch the GUI. Sandboxed command runners may import Tkinter but cannot connect to the macOS window server.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests
python main.py
```

Scapy is optional. When it is installed, the app uses an ARP broadcast scan and can display MAC addresses. Without Scapy, it uses a multithreaded operating-system ICMP ping sweep; MAC addresses may remain `Unknown`. CustomTkinter is required to launch the GUI.

## Permissions

On macOS and Linux, Scapy ARP scans generally require administrator/root privileges because they create raw Ethernet packets. Start the app with `sudo` only when ARP discovery is needed:

```bash
sudo .venv/bin/python main.py
```

The fallback ICMP scan normally does not require root, though local firewall rules can prevent ping responses. Windows may require an elevated terminal for some Scapy capture operations.

At startup the app checks the current privilege level. Without administrator/root access it shows a warning and continues in unprivileged mode. Each host is evaluated in layers: available ARP data, ICMP ping, and finally short TCP connection checks to ports 80 and 445. A positive result from any layer marks the host online, reducing false offline results when ICMP is blocked.

## How it works

1. A UDP route lookup identifies the active local interface, then the app uses its `/24` network as the scan range.
2. The scan runs off the Tkinter main thread. Progress and results are delivered through a thread-safe queue.
3. Scapy ARP discovery is attempted only when privileges are available. Hosts then use bounded ICMP and TCP fallback checks with strict timeouts.
4. Reverse DNS resolves hostnames when possible. Devices missing from a later scan remain in the table as `Offline`, allowing connection changes to be seen.
5. The vendor resolver loads `oui_vendors.json` offline and returns `Unknown` safely for unrecognized prefixes. Set `MAC_VENDOR_API=1` to allow an optional API lookup after the local database misses; API errors and offline use fall back to `Unknown`.
6. `Export Log` writes IP, MAC, vendor, hostname, status, latency, and last-seen data to CSV.

## New-device alerts

`notifications.py` uses Plyer for native desktop notifications and falls back to macOS `osascript` when Plyer cannot load its optional Objective-C bridge. The first completed scan establishes the baseline and does not alert. Later scans compare known, non-`Unknown` MAC addresses with the previous scan; each new MAC triggers `New Device Detected: [hostname]`, falling back to the IP address when hostname resolution is unavailable. If notification support is unavailable, scanning continues normally without crashing.

## Device port checks

Select an online device in the device table to check common TCP ports in the background. The scanner currently checks ports such as FTP (21), SSH (22), HTTP (80), HTTPS (443), SMB (445), and alternate HTTP (8080), returning only ports that accept a TCP connection. Results appear in the `PORTS` panel without freezing the interface. This is a limited diagnostic check, not a full port scan; only scan devices and networks you are authorized to assess.

## SQLite history

The application automatically creates `network_logs.db` in the project directory. `database_manager.py` exposes `NetworkDatabase` with `upsert_device`, `insert_scan_record`, `record_scan`, `fetch_devices`, and `fetch_scan_logs`. Each completed scan updates device `last_seen` values and inserts a timestamped online-device total. The database uses parameterized SQL, WAL mode, and a re-entrant lock for safe access from worker/UI threads.

Only scan networks you own or are authorized to monitor.
