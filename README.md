# LAN Watchtower

A desktop network monitoring and device discovery tool built with Python and CustomTkinter. It detects the local IPv4 subnet, scans the LAN in a background thread, displays active devices in a modern dashboard, preserves disconnected devices as `Offline`, reports join/leave changes, and exports the current device table to CSV.

## Project Website

Visit the [LAN Watchtower project website](https://laksh1357.github.io/NetworkMonitoring_DeviceDiscovery_Tool/) for an overview of the network detection workflow and capabilities.

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

The application also exposes a backend package boundary for incremental
evolution toward a web dashboard:

```text
backend/
├── api/             # Future HTTP API boundary
├── core/            # Shared settings and transport-neutral events
├── database/        # Persistence service boundary
├── discovery/       # Network discovery primitives
├── models/          # UI- and transport-independent domain models
├── monitoring/      # Monitoring state helpers
├── notifications/  # Notification channel boundary
├── scanning/        # Host and service scanning boundary
├── services/        # Application orchestration services
├── utils/           # Shared utilities
└── websocket/       # Future live-update boundary
```

The original top-level modules remain supported as compatibility entry points.
No continuous monitoring, HTTP server, or WebSocket server is enabled by this
architecture step.

## Deployment

LAN Watchtower remains a desktop-first monitoring application. The deployment
profile adds a small single-process backend for liveness/readiness checks and
serves the existing static project site as the frontend. SQLite is persisted
in a named Docker volume; a separate database container is not appropriate
for the current SQLite storage engine.

### Local development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m unittest discover -s tests -v
python main.py
```

The desktop application writes `network_logs.db` in the project directory by
default. It requires a graphical session and should run on the host when LAN
discovery needs the host network interface.

### Docker development

Copy the example environment file and start the deployment profile:

```bash
cp .env.example .env
docker compose up --build
```

The static frontend is available at `http://localhost:8080`. The backend
health API is available at `http://localhost:8000/health` and
`http://localhost:8000/ready`.

### Production deployment

Use a private registry or a pinned image build, provide secrets through the
deployment platform rather than committing `.env`, and put TLS/authentication
in an ingress or reverse proxy. The compose backend uses one Python process
(`WEB_CONCURRENCY=1`) and does not start monitoring schedulers, preventing
duplicate discovery/health/port workers when the API is scaled. Run the
desktop monitoring process as one explicitly managed instance on the
authorized host network, or add a deliberate leader-election/scheduler
service before scaling monitoring horizontally.

The backend process handles `SIGTERM`/`SIGINT`, stops accepting requests, and
closes its HTTP server cleanly. Docker's `restart: unless-stopped` policy can
restart a failed process without creating a second process in the same
container.

### Environment variables

See [.env.example](./.env.example). Supported deployment variables include:

- `API_HOST`, `API_PORT`
- `FRONTEND_PORT`
- `DATABASE_PATH`
- `WEB_CONCURRENCY` (keep at `1` for this deployment)
- `WEBSOCKET_ENABLED`
- `NOTIFICATION_EMAIL_ENABLED`
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`
- `SMTP_FROM`, `NOTIFICATION_EMAIL_TO`
- `WEBHOOK_URL`

Never commit SMTP passwords, webhook URLs containing credentials, or other
secrets. The Settings page does not render these values.

### Database setup

The Docker backend stores SQLite at `/data/network_logs.db`, backed by the
`network-data` named volume. Back up the volume before upgrades and do not
mount the same SQLite file into multiple writer containers. For host
development, use a separate path such as `network_logs.db` and stop the
desktop process before copying it.

### Network permissions

The health API and static frontend do not perform LAN discovery. The desktop
monitor needs access to the host interface; ARP discovery may require
administrator/root privileges and Scapy raw-packet permissions. In Docker on
Linux, a deliberately configured monitoring container may require host
networking and `NET_RAW`/`NET_ADMIN` capabilities. Do not grant those
capabilities to the health/frontend containers by default, and only monitor
networks you own or are authorized to inspect.

### Troubleshooting

- `GET /health` is a process liveness check and does not verify the database.
- `GET /ready` returns `503` when the SQLite database cannot be opened.
- If the frontend cannot load, check `docker compose ps` and the backend
  healthcheck before changing ports.
- If discovery finds no devices, run the desktop process outside Docker first,
  confirm the interface and permissions, and review the unprivileged fallback.
- If a database volume is locked, stop duplicate writers and restore from a
  consistent backup; do not delete the database to hide the error.

## Dashboard

The desktop dashboard provides a dark network-operations layout with sidebar
navigation, device summary cards, searchable/filterable/sortable device
inventory, explicit loading and empty states, and a device details panel.
Summary values and port counts are derived only from discovered devices and
completed checks; an empty inventory is shown as `No devices discovered yet.`
The navigation items establish the future dashboard surface, while the current
scanner and port-check workflows remain the active functionality.

Dashboard statistics are read from the SQLite backend through
`backend.services.dashboard_service`. Device status is updated during completed
scan transactions, port observations are persisted after a completed port
check, and saved device data is loaded when the dashboard starts. Empty data is
shown explicitly rather than replaced with sample values.

## Continuous discovery

Use `Start monitoring` in the dashboard to run the existing layered discovery
mechanism periodically. The interval field accepts a positive number of
seconds; monitoring prevents overlapping cycles and stops the scanner during
application shutdown. Each completed cycle updates the in-memory registry and
SQLite device status, identifying new, existing, disappeared, and returning
devices without creating duplicate records. Discovery remains bounded by the
existing worker and host-timeout settings and continues safely when a network,
permission, timeout, or individual-host failure occurs.

## Device health monitoring

Continuous monitoring also runs bounded health checks for registered devices.
`HealthSettings` configures `health_check_interval`, probe `timeout`,
`failure_threshold`, and `warning_latency_threshold`. A successful check is
`ONLINE`; latency above the warning threshold is `WARNING`; repeated failures
become `OFFLINE` only after the configured threshold; and incomplete results
remain `UNKNOWN`. Health observations, latency, reachability, and consecutive
failure counts are stored in the SQLite `health_history` table. A single
temporary timeout never immediately marks a device offline.

## Continuous port monitoring

Port monitoring reuses the bounded TCP scanner and supports configurable
per-device and scheduled scans. Current open ports are stored with protocol,
service, first-seen, last-seen, last-scan, and status fields. Changes generate
`NEW_OPEN_PORT` and `PORT_CLOSED` events in SQLite. Scheduled scans skip
offline devices, use configurable timeouts and worker limits, and avoid
overlapping runs.

## Intelligent alerting

The alert service supports `NEW_DEVICE`, `DEVICE_OFFLINE`, `DEVICE_ONLINE`,
`HIGH_LATENCY`, `NEW_OPEN_PORT`, `PORT_CLOSED`, `UNKNOWN_DEVICE`, and
`SCAN_FAILURE` alert types with `INFO`, `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`
severity levels. Active alerts are deduplicated by type and device, can be
acknowledged or resolved, and remain available in alert history. Discovery,
health, port, and scan-failure events feed the same persisted lifecycle, so
repeated monitoring cycles do not create duplicate active incidents.

## Notification channels

Alert delivery is provider-based. The dashboard channel is always available
and is persisted in `notification_deliveries`; optional email and webhook
providers use environment variables only:

```text
NOTIFICATION_EMAIL_ENABLED=true
SMTP_HOST=smtp.example.test
SMTP_PORT=587
SMTP_USERNAME=...
SMTP_PASSWORD=...
SMTP_FROM=...
NOTIFICATION_EMAIL_TO=...
WEBHOOK_URL=https://example.test/hooks/network
```

Severity routing defaults to `CRITICAL` (dashboard, email, webhook), `HIGH`
(dashboard, email), `MEDIUM` (dashboard), and `LOW`/`INFO` (dashboard).
Missing configuration and provider failures are isolated and never stop the
monitoring engine. Credentials are not stored in source code or the database.

## Live dashboard updates

The application publishes monitoring events through a thread-safe event hub
and exposes them at `ws://127.0.0.1:8765` for a future web dashboard. The
host and port can be changed with `WEBSOCKET_HOST` and `WEBSOCKET_PORT`, or
disabled with `WEBSOCKET_ENABLED=false`.

Messages use this stable envelope:

```json
{"event":"DEVICE_UPDATED","timestamp":"2026-10-07T17:17:37+00:00","data":{}}
```

Supported events include device discovery and state changes, port changes,
alert creation/resolution, and scan start/completion. The endpoint uses
WebSocket ping/pong timeouts and bounded per-client queues so stale or slow
connections are removed without affecting monitoring. REST/database loading
remains the source for initial dashboard state; clients should reconnect and
reload that state after a server restart or connection loss.

## Network map

The **Network Map** page visualizes the devices actually discovered by the
scanner, including hostname, IP address, MAC address, vendor, status, and
latency when available. Because the scanner cannot reliably determine Layer-2
or physical topology, the page is explicitly labeled **“Discovered network
topology / inferred relationships”**. Dashed links to the discovered LAN
context are informational and must not be interpreted as physically verified
connections.

The map supports node selection, device details, zoom, and pan. Monitoring
updates redraw node status without inventing devices or relationships.

## Historical analytics

The **History** page uses bounded SQLite aggregation for device availability,
latency, discovery/disappearance events, port changes, alerts, and uptime.
Available ranges are the last 1 hour, 6 hours, 24 hours, 7 days, and 30 days.
Queries group observations into range-appropriate time buckets and enforce a
maximum result size, so raw history is not loaded without a limit.

## Potentially suspicious activity

The device details panel includes a rule-based risk assessment using bounded
recent observations. It considers unknown vendors, newly discovered devices,
unexpected ports, multiple port changes, unusual latency, repeated
appearance/disappearance, and selected port combinations. Scores are mapped
to `LOW` (0-30), `MEDIUM` (31-60), `HIGH` (61-80), or `CRITICAL` (81-100),
with the contributing reasons shown next to the score.

These signals are indicators for investigation only. The application calls
the result **Potentially suspicious activity** and does not claim that a
device is malicious based on these observations alone.

## Settings

The Settings page validates and applies discovery, health, port monitoring,
timeout, concurrency, port-list, offline-threshold, latency-threshold, and
interface values at runtime. Save updates running service configuration
without restarting the application; Reset restores the form defaults, and
Test Configuration validates inputs and checks local subnet detection.
Notification credentials and passwords are never rendered in the UI and
remain environment-variable based. Database location is displayed read-only
to avoid unsafe live migrations or connection replacement.

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
