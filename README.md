# LAN Watchtower: Network Monitoring & Discovery Engine

## 1. Project Overview
LAN Watchtower is a research-grade open-source network monitoring and device discovery system. It passively and actively scans local networks, building persistent device identities and tracking behavioral baselines over time to deterministically identify network anomalies.

## 2. Technical Problem
Modern local networks are dynamic environments characterized by frequent DHCP churn, mobile devices dropping online/offline, and varying presence patterns. Traditional ping sweepers and monitoring tools fail to maintain a coherent behavioral history when a device changes its IP address or moves between network segments, leading to fractured data and high false-positive alert rates.

## 3. Architecture
The system is built on a decoupled, modular architecture featuring a Python backend and a Web-based Single Page Application (SPA). The backend is composed of distinct analytical engines communicating asynchronously. For a full architectural breakdown, refer to [ARCHITECTURE.md](docs/TECHNICAL_ARCHITECTURE.md).

## 4. Core Mechanisms
- **Adaptive Discovery:** Dynamically selects between ICMP, ARP, and TCP probing based on historical responsiveness.
- **Cross-Scan Identity Fusion:** Correlates MAC, Hostname, and Port heuristics to track devices persistently across DHCP lease expirations.
- **O(1) Incremental Baselining:** Utilizes Welford's online algorithm to mathematically bound response latencies and presence frequencies without requiring unbounded time-series storage.
- **Rule-Based Anomaly Detection:** Deterministically evaluates deviations against statistical baselines (avoiding black-box AI heuristics).

## 5. Installation
```bash
# Clone the repository
git clone https://github.com/laksh1357/NetworkMonitoring_DeviceDiscovery_Tool.git
cd NetworkMonitoring_DeviceDiscovery_Tool

# Install dependencies
pip install -r requirements.txt
```

## 6. Configuration
The system can be configured via environment variables or a local `.env` file to control concurrency limits, subnet targets, and baseline strictness thresholds. See `docs/CONFIGURATION.md` (Pending) for details.

## 7. Usage
```bash
# Run the core background scanner
python -m src.main

# Run the API server
python -m src.api.server
```

## 8. Screenshots
![Dashboard Placeholder](docs/images/dashboard_placeholder.png)
*Figure 1: The Network Topology and Evidence Timeline Dashboard.*

## 9. API
The decoupled REST API is documented via OpenAPI 3.0 specification. It provides pagination, filtering, and structured JSON responses for Device Identities and Timeline Events. See [API.md](docs/API.md).

## 10. Database
LAN Watchtower uses SQLite configured in WAL (Write-Ahead Logging) mode. Device identities are stored relationally, and the `evidence_timeline` table acts as an append-only ledger referencing heavy JSON anomaly payloads by UUID to prevent data duplication.

## 11. Experiments
A strict experimental framework has been defined to validate the deterministic accuracy of the core engines against standard scenarios (DHCP churn, latency spikes, noisy devices). See [EXPERIMENTAL_EVALUATION.md](docs/EXPERIMENTAL_EVALUATION.md).

## 12. Performance Results
Initial benchmarks of the legacy sequential threading model showed a `/24` scan duration of ~6.17 seconds. The planned `asyncio` refactoring targets sub-second scan completions with database batch writes executing in `< 1.0 ms` for 256 records. See [PERFORMANCE.md](docs/PERFORMANCE.md).

## 13. Security Considerations
- **No Raw Payloads Exposed:** The UI API drops raw packet context.
- **SSRF Protections:** Port scanning endpoints are restricted to private network ranges.
- **Subprocess Safety:** Network tools are executed via safe argument arrays (bypassing the shell). 
See [SECURITY.md](docs/SECURITY.md) for the complete threat model.

## 14. Limitations
- Identity fusion currently relies on Layer-2 (ARP) visibility. Devices strictly behind NAT or routers without static MAC/Hostname associations may be duplicated.
- Does not inspect application-layer payloads (e.g., Deep Packet Inspection).

## 15. Testing
The test suite utilizes a `MockNetworkSimulator` to execute offline integration tests representing complex multi-stage anomalies and DHCP churn events without sending unauthorized packets onto a live network. See [TESTING.md](docs/TESTING.md).

## 16. Future Research
- Evaluation of Count-Min Sketches for tracking port-service distributions in highly dynamic server environments.
- Integration with external Threat Intelligence feeds for cross-referencing deterministic anomalies.

## 17. License
Distributed under the MIT License. See `LICENSE` for more information.
