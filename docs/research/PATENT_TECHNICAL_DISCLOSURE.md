# Technical Disclosure Document

*Note: This document provides a technical analysis of the implemented mechanisms for discussion with a qualified patent professional. It does not make legal claims regarding the patentability or novelty of the described systems.*

---

## Part I: System Categorization

### A. Generic/Common Software Features
- **RESTful API & Web SPA:** Standard decoupling of backend endpoints from frontend rendering (React/Vue).
- **SQLite Data Persistence:** Standard usage of a relational database for state storage.
- **Port Scanning:** Standard TCP connection attempts to determine open services.
- **Vendor OUI Lookup:** Standard mapping of MAC addresses to vendor strings via public JSON datasets.

### B. Engineering Improvements
- **Asynchronous Adaptive Discovery:** Replacing blocked thread pools with native non-blocking `asyncio` sockets to drastically reduce scan latency.
- **Evidence-Referenced Chronological Timeline:** An append-only ledger that logs state transitions (e.g., `ONLINE_TRANSITION`) but uses a `reference_id` UUID to link to complex anomaly payloads, maintaining database efficiency and preventing redundant data storage.

### C. Potentially Differentiated Technical Mechanisms
1. Deterministic Cross-Scan Device Fingerprinting & Identity Fusion.
2. Incremental Constant-Space Behavioral Baselining for Network Topologies.

### D. Features Requiring Prior-Art Investigation
- Time-bound sliding-window event deduplication algorithms applied specifically to localized anomaly rollups (Event Correlation Engine).

---

## Part II: Specific Technical Mechanisms

### Mechanism 1: Deterministic Cross-Scan Device Identity Fusion

1. **Technical Problem:** Devices frequently change their IP addresses (via DHCP churn) or drop offline between scans, making it difficult to construct a continuous behavioral history for a single physical device in a dynamic network.
2. **Existing Conventional Approach:** Network scanners treat each IP address as a distinct entity or rely exclusively on MAC addresses (which are unavailable across Layer-3 boundaries).
3. **Limitation of Conventional Approach:** Leads to fractured historical logs. A single device moving between subnets or losing its MAC layer visibility is recorded as multiple distinct entities, rendering behavioral baselining inaccurate.
4. **Our Implemented Mechanism:** A persistent `DeviceIdentityEngine` that executes a deterministic matching cascade using weighted physical (MAC) and logical (IP/Hostname/Ports) signals.
5. **Technical Operation:** The engine resolves transient observations into a unified persistent UUID, freezing conflicting states to handle IP reassignment.
6. **Inputs:** `Observation` (IP, MAC, hostname, open_ports, timestamp).
7. **Processing Steps:**
   - Attempt exact MAC match. If successful but IP differs, append old IP to `ip_history`, update `primary_ip`, and emit `IP_CHANGE`.
   - If MAC is missing, execute heuristic match against IP + Hostname + Open Ports.
   - If IP matches but MAC/Hostname completely conflict, freeze the old `DeviceIdentity` and initialize a new UUID for the reassigned IP.
8. **Outputs:** A single persistent `DeviceIdentity` UUID and an array of `IdentityChangeEvent` state transitions.
9. **Technical Effect:** Prevents data fragmentation. Allows long-term behavioral models (like presence frequency) to persist accurately even as a device traverses network segments.
10. **Experimental Evidence:** *Pending Implementation (Reference Experiment 4: IP Address Change)*.
11. **Possible Alternative Implementations:** Utilizing unsupervised Machine Learning clustering (e.g., K-Means on device metrics) to probabilistically link identities rather than strict deterministic rules.
12. **Potential Prior-Art Search Terms:** "Cross-scan device identity fusion", "MAC-less network fingerprinting", "DHCP churn identity resolution", "deterministic endpoint matching cascade".

---

### Mechanism 2: Incremental Constant-Space Behavioral Baselining

1. **Technical Problem:** Modeling normal network behavior requires analyzing thousands of historical data points (latency, presence) per device. Storing raw time-series data for every ping response causes unbounded database growth and severe IO bottlenecks on edge hardware.
2. **Existing Conventional Approach:** Storing a rolling window (e.g., last 10,000 pings) in a time-series database and running batch aggregations nightly.
3. **Limitation of Conventional Approach:** Requires massive storage overhead, expensive CPU cycles for batch recalculation, and forces reliance on external heavy databases (like InfluxDB).
4. **Our Implemented Mechanism:** An online `BaselineEngine` utilizing Welford's algorithm and Exponential Moving Averages (EMA).
5. **Technical Operation:** The system updates a device's statistical boundaries mathematically in real-time without ever storing the underlying raw observation arrays.
6. **Inputs:** Current baseline state (`latency_ema`, `latency_variance`, `observation_count`) and a new data point (`current_latency`).
7. **Processing Steps:**
   - Reject outlier data dynamically if `current_latency > (latency_ema + 3*StdDev)`.
   - Update the moving average using standard EMA formulas.
   - Incrementally update the variance using Welford's online algorithm (O(1) time and space complexity).
   - Increment the `observation_count`.
8. **Outputs:** An updated, robust statistical envelope (e.g., `Expected Latency: 10ms ± 2ms`) requiring only 3 float values stored in SQLite.
9. **Technical Effect:** Reduces database storage requirements from O(N) to O(1) per device. Enables real-time, low-latency anomaly detection directly on edge hardware with minimal CPU utilization.
10. **Experimental Evidence:** *Pending Implementation (Reference Experiment 7: Latency Deviation)*.
11. **Possible Alternative Implementations:** Using sketch data structures (like Count-Min Sketch for categorical data) or fixed-size circular arrays (Ring Buffers).
12. **Potential Prior-Art Search Terms:** "O(1) network baselining", "Welford's algorithm network anomaly detection", "incremental variance moving average latency tracking", "constant space behavioral modeling".
