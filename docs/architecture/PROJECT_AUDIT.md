# Project Audit: LAN Watchtower

## Current Architecture
The project is a dual-interface network monitoring and device discovery tool. It provides a desktop GUI application built with CustomTkinter and a Web API server built on Python's built-in `http.server`. The core engine uses a multi-threaded active scanner that probes local subnets. Discovery is layered: it attempts ARP broadcasting (via Scapy, if privileged), falls back to OS-level ICMP pings, and finally attempts TCP connection probes. State and history are persisted locally in a thread-safe SQLite database.

## Data Flow
1. **Initiation**: A scan is triggered manually via the GUI or a REST POST request.
2. **Discovery**: A background `NetworkScanner` thread uses a bounded `ThreadPoolExecutor` to probe IP addresses. 
3. **Enrichment**: For each responding IP, the scanner looks up the MAC address (via OS ARP cache or Scapy), resolves the vendor via a local JSON cache, and heuristically infers the device type.
4. **State Update & Events**: Discovered devices are emitted as events. In the GUI, the main thread polls a queue to update the view. In the web server, an in-memory dictionary is updated.
5. **Persistence**: Devices and scan metrics are written to the SQLite database.
6. **Alerts**: New MAC addresses trigger desktop notifications natively (Plyer/osascript) and insert alerts into the database.

## Module Responsibilities
* `main.py`: Contains the `NetworkScanner` engine, network utility functions (ping, ARP extraction), `Device` dataclass, and the CustomTkinter GUI dashboard.
* `web_server.py`: A lightweight HTTP server exposing REST API endpoints for a web-based NOC dashboard. Manages its own in-memory state of online devices.
* `database_manager.py`: Manages the SQLite database, schema migrations, and exposes thread-safe CRUD operations using WAL mode.
* `port_scanner.py`: Provides a background multi-threaded TCP connect scanner targeting a hardcoded list of common ports.
* `vendor_lookup.py`: Handles MAC OUI matching primarily using a local `oui_vendors.json` file, with an optional remote API fallback.
* `notifications.py`: Wrapper for native desktop notifications using Plyer or macOS `osascript`.

## Dependency Map
* **Core Logic (`main.py`)** -> `database_manager.py`, `vendor_lookup.py`, `port_scanner.py`, `notifications.py`
  * *External:* `scapy` (optional), `customtkinter` (optional)
* **Web API (`web_server.py`)** -> `main.py` (for core logic), `database_manager.py`, `port_scanner.py`
* **Persistence (`database_manager.py`)** -> SQLite3 (Standard Library)
* **Notifications (`notifications.py`)** -> `plyer` (optional)

## Database Schema
* `devices`: ip (PK), mac, hostname, vendor, device_type, custom_name, notes, location, first_seen, last_seen
* `scan_logs`: id (PK), timestamp, total_devices_online
* `alerts`: id (PK), timestamp, severity, title, message, ip
* `activity_logs`: id (PK), timestamp, user_name, action_type, description, ip
* `user_profile`: id (PK=1), display_name, role_title, email, avatar_initials

## Current Limitations
* Active scanning only; no continuous background monitoring loops or passive traffic analysis.
* OS-dependent: Subprocess calls to `ping`, `arp`, and `osascript` can be brittle across different OS versions and environments.
* IPv4 only; no support for IPv6 network discovery.
* Port scanning is restricted to a statically defined dictionary of ~24 common ports.
* API clients must poll for scan progress instead of using WebSockets or Server-Sent Events (SSE).

## Security Issues
* **No Authentication:** The REST API binds to `0.0.0.0` with no authentication, allowing any network user to view topology and control scans.
* **SSRF Vulnerability:** The `/api/ports/scan` endpoint accepts arbitrary IPs, allowing attackers to proxy port scans against internal or external infrastructure.
* **Permissive CORS:** The API hardcodes `Access-Control-Allow-Origin: *`, exposing data to malicious web pages.
* **Single-threaded DoS:** `web_server.py` uses a standard `HTTPServer` which handles one request at a time. It is highly susceptible to denial of service via slow connections.

## Performance Issues
* **Subprocess Overhead:** Spawning hundreds of `ping` subprocesses during an ICMP sweep is CPU and memory intensive compared to native raw sockets or async I/O.
* **Blocking Web Server:** Concurrent API requests will block each other, causing the NOC dashboard to feel sluggish for multiple users.
* **Synchronous Threading:** Thread pools are used heavily for I/O bound tasks (port scanning, discovery). While functional, `asyncio` would scale much better for concurrent network connections.

## Testing Gaps
* **Web API:** Complete absence of tests for `web_server.py`. Endpoints, JSON payloads, and state consistency are untested.
* **GUI / E2E:** No UI testing or end-to-end integration tests for the scanning lifecycle.
* **Error Handling:** Minimal testing around subprocess timeouts, failed network interfaces, or missing permissions.

## Maintainability Issues
* **Coupling:** `main.py` mixes CLI initialization, core network logic (`NetworkScanner`, `Device`), and GUI presentation.
* **State Duplication:** `web_server.py` maintains an `in_memory_devices` dictionary, creating duplicate state management logic alongside the GUI and the database.
* **Legacy HTTP Server:** Using `http.server` requires manual routing and JSON serialization, increasing boilerplate and reducing maintainability compared to modern frameworks.

## Potential Research/Innovation Areas
* **Passive Network Sniffing:** Implementing continuous passive monitoring of ARP, DHCP, and mDNS broadcasts to discover devices without generating active scan traffic.
* **Advanced Fingerprinting:** Using TCP/IP stack fingerprinting (e.g., analyzing TTL, window size, TCP options) or ML models to classify devices beyond simple MAC OUI lookups.
* **Distributed Probing:** Architecting a multi-node system where lightweight agents scan segmented VLANs and report back to a central aggregator.
* **Real-time Topology Mapping:** Analyzing network paths and switch CAM tables to infer physical topology relationships automatically.

---

### Action Plan Summary

#### A. Keep unchanged
* **Database Manager:** The SQLite WAL implementation is thread-safe and robust.
* **Vendor Lookup:** Offline JSON OUI resolution is fast and privacy-preserving.
* **Layered Discovery Concept:** The fallback strategy (ARP -> ICMP -> TCP) is highly effective for bypassing local firewalls.

#### B. Improve
* **Decouple Architecture:** Extract `NetworkScanner`, `Device`, and network utilities from `main.py` into a dedicated `scanner/` core package.
* **Subprocess Usage:** Refactor `ping_host` to use native socket ICMP (when privileged) or asynchronous approaches to reduce OS process overhead.
* **Security:** Implement API authentication, validate IP inputs to prevent SSRF, and restrict CORS headers.

#### C. Replace
* **Web Server:** Replace the built-in `http.server` with a production-ready asynchronous framework (e.g., FastAPI or Flask).
* **Network Concurrency:** Replace `ThreadPoolExecutor` in the port scanner and network prober with `asyncio` for vastly superior connection scaling.

#### D. New modules required
* **API Routing:** A dedicated module for REST routes, request validation, and WebSocket event streaming.
* **Configuration Manager:** A module to parse settings from `.env` or `config.yaml` (scan intervals, target ports, API keys) rather than hardcoding them.
* **Authentication/Security Middleware:** To protect endpoints and handle user sessions securely.
