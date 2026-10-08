# Security Architecture & Threat Model

This document outlines the security assumptions, threat model, and boundaries of the LAN Watchtower system. 

## 1. Threat Model

### Attacker Assumptions
- **External Attacker:** The system assumes it may be exposed to broader network routing without reverse proxy protection (though a reverse proxy is highly recommended in production). The attacker has no prior credentials.
- **Internal/Local Attacker:** The attacker has access to the local network where the tool is running and can send ARP, DHCP, and TCP/UDP traffic to attempt network-layer spoofing or resource exhaustion.

### Attack Surface
- **Web API (`0.0.0.0:8000`):** Ingestion of HTTP REST requests.
- **Network Discovery Layer:** Handling of incoming ICMP, ARP, and TCP probes.
- **Subprocess Invocations:** Underlying OS-level utilities (e.g., `ping`, `osascript`).
- **Database (`network_logs.db`):** Local persistence.

### Trust Boundaries
1. **Network Interface -> Discovery Engine:** Traffic received is implicitly untrusted. Packet parsing strictly avoids executing arbitrary payload bytes.
2. **API Client -> Web Server:** All incoming JSON payloads, HTTP headers, and query parameters are untrusted and must be validated against expected schemas.
3. **Database -> UI:** The local database is a trusted boundary, but all inputs ingested from the API into the DB are parameterized.

## 2. Security Mitigation Strategies

### Command Execution & Subprocess Safety
No commands use shell interpolation (`shell=True` in Python). Network tools are executed securely via list arguments. 
*(Note: A legacy AppleScript interpolation vulnerability in `notifications.py` was identified and patched to use discrete argument passing).*

### Database Security
All queries rely on parameterization (`?` syntax in `sqlite3`) to mathematically prevent SQL Injection (SQLi). 

### Server-Side Request Forgery (SSRF) Protection
To prevent the API from being used as a blind proxy for attacking external infrastructure, port scanning and discovery endpoints mathematically validate target IPs against RFC 1918 private network spaces. Non-private IP scans are rejected.

### Privilege Management
By default, the Web Server runs under a standard non-privileged user account. The background Discovery Daemon may require elevated privileges (`CAP_NET_RAW` on Linux) to craft raw ICMP/ARP packets. These two components are isolated to enforce the Principle of Least Privilege.

### Sensitive Data Handling
- **No Hardcoded Credentials:** The system relies entirely on environment variables (`.env`) for configuration.
- **Log Sanitation:** Sensitive data (e.g., specific HTTP payloads if captured during port identification) are strictly excluded from the application logs to prevent accidental exposure of PII or proprietary network traffic.

## 3. Vulnerability Reporting
Please do not open a public issue for a security vulnerability. If you discover a flaw in the system, refer to the project's security contact documented in the repository root.
