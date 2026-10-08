# Experimental Evaluation Framework

This document defines the controlled experimental framework for evaluating the technical performance and deterministic accuracy of the LAN Watchtower system's core engines. 

*Note: All results sections are currently marked as "Pending Implementation" as no experimental data has been fabricated prior to executing the modular refactoring.*

---

## Experiment 1: Normal LAN Discovery
**Hypothesis:** The Adaptive Discovery Engine will correctly identify all active hosts on a local `/24` subnet without triggering false positives for dead IPs.
**Setup:** A controlled local subnet with exactly 5 known active devices (various OS types).
**Inputs:** Subnet mask `192.168.1.0/24`.
**Procedure:** Trigger a standard discovery scan. 
**Expected Result:** Exactly 5 nodes identified with confidence > 0.8.
**Metrics:** Detection latency, Discovery accuracy, False positive rate, Resource consumption.
**Acceptance Criteria:** 100% true positive rate, 0% false positive rate, scan duration < 2 seconds.
**Results:** *Pending Implementation*

---

## Experiment 2: New Device Appearance
**Hypothesis:** A previously unseen device joining the network will trigger a `FIRST_SEEN` event and an `INFORMATIONAL` anomaly within one scan cycle.
**Setup:** Baseline established with 5 devices. Connect a 6th device (e.g., a smartphone) to the network.
**Inputs:** Execution of the periodic background scan.
**Procedure:** Wait for the scan cycle to complete after the device connects.
**Expected Result:** A new `DeviceIdentity` is created. An `INFORMATIONAL` anomaly is logged.
**Metrics:** Detection latency (time from connection to alert).
**Acceptance Criteria:** Detection within 1 standard scan cycle interval.
**Results:** *Pending Implementation*

---

## Experiment 3: Device Disappearance
**Hypothesis:** A device disconnecting gracefully (or abruptly) will be marked as offline, but its persistent `DeviceIdentity` and baseline history will be retained.
**Setup:** Baseline established with 5 online devices. Disconnect device #3.
**Inputs:** Execution of the periodic background scan.
**Procedure:** Run scan, observe device status.
**Expected Result:** Device #3 status changes to `Offline`. No anomalies are incorrectly generated for simple offline transitions.
**Metrics:** False positive rate (for malicious anomalies).
**Acceptance Criteria:** Device accurately flagged as offline without identity corruption.
**Results:** *Pending Implementation*

---

## Experiment 4: IP Address Change
**Hypothesis:** A device receiving a new IP via DHCP will maintain its persistent `DeviceIdentity` based on its MAC address.
**Setup:** Device A at `192.168.1.100` (known MAC). Force DHCP release/renew so Device A gets `192.168.1.105`.
**Inputs:** Execution of discovery scan.
**Procedure:** Observe identity mapping post-scan.
**Expected Result:** Device A's `primary_ip` updates to `.105`. An `IP_CHANGE` event is logged in the timeline. The same `DeviceIdentity` UUID is retained.
**Metrics:** Discovery accuracy, False negative rate (avoiding creation of a duplicate device).
**Acceptance Criteria:** 1 UUID remains; `ip_history` array length equals 2.
**Results:** *Pending Implementation*

---

## Experiment 5: Hostname Change
**Hypothesis:** A device changing its hostname while maintaining its IP and MAC will append the old hostname to history and update its primary hostname.
**Setup:** Device A known as `host-A`. Change device configuration to `host-B`.
**Inputs:** Discovery scan resolving MDNS/NetBIOS.
**Procedure:** Run scan.
**Expected Result:** `primary_hostname` updates to `host-B`. `HOSTNAME_CHANGE` event logged.
**Metrics:** Discovery accuracy.
**Acceptance Criteria:** The old hostname is preserved in `hostname_history` for querying.
**Results:** *Pending Implementation*

---

## Experiment 6: New Service/Port Observation
**Hypothesis:** The Anomaly Detection Engine will correctly flag unexpected new open ports on a baselined device as a `MEDIUM` severity anomaly.
**Setup:** Device A establishes a baseline with only port 80 open. Start an SSH server on port 22 on Device A.
**Inputs:** Execution of Port Scanner submodule.
**Procedure:** Run scan against Device A.
**Expected Result:** `MEDIUM` anomaly generated explaining "Port 22 was not observed during previous N observations but is now reachable."
**Metrics:** Event correlation accuracy.
**Acceptance Criteria:** Exact formatted explanation string generated; severity correctly assigned.
**Results:** *Pending Implementation*

---

## Experiment 7: Latency Deviation
**Hypothesis:** The Baseline Engine's Welford variance calculation will accurately flag severe network latency spikes without triggering on minor jitter.
**Setup:** Device A baselined with 10ms avg latency. Use `tc qdisc` to artificially inject 500ms delay.
**Inputs:** ICMP discovery probe.
**Procedure:** Ping Device A.
**Expected Result:** The latency exceeds the `EMA + 3*StdDev` threshold. A `LOW` severity anomaly is generated.
**Metrics:** False positive rate (ensure small jitter doesn't trigger it).
**Acceptance Criteria:** The statistical bounds correctly distinguish the 500ms delay from the variance.
**Results:** *Pending Implementation*

---

## Experiment 8: Multiple Simultaneous Changes
**Hypothesis:** The Event Correlation Engine will accurately roll up multiple simultaneous anomalies on a single device into a high-severity Correlated Event.
**Setup:** Device A simultaneously changes its IP, opens a new port, and spikes in latency.
**Inputs:** Discovery and port scan.
**Procedure:** Ingest the three distinct anomalies.
**Expected Result:** A single `CorrelatedEvent` is generated, linking the 3 anomalies, and its severity is elevated to `HIGH`.
**Metrics:** Event correlation accuracy, Detection latency.
**Acceptance Criteria:** Exactly 1 CorrelatedEvent is produced within the sliding window, not 3 separate alerts.
**Results:** *Pending Implementation*

---

## Experiment 9: Noisy/Intermittent Device
**Hypothesis:** A device that rapidly flaps between online/offline states will not flood the database or the Anomaly engine.
**Setup:** Device A toggles network interface every 2 seconds.
**Inputs:** Rapid periodic scanning (e.g., 5 second intervals).
**Procedure:** Run scanner for 2 minutes.
**Expected Result:** The Event Correlation Engine's duplicate suppression will group the flapping into a limited number of events (or a single summary event).
**Metrics:** Database query performance (write volume), Network overhead.
**Acceptance Criteria:** Database size growth is bounded; UI alert ticker is not flooded.
**Results:** *Pending Implementation*

---

## Experiment 10: Large Number of Devices
**Hypothesis:** The system will gracefully scale to handle a large subnet without triggering memory exhaustion or unbound threading limits.
**Setup:** A simulated `/16` subnet containing 2,000 mock active devices.
**Inputs:** Full discovery scan.
**Procedure:** Initiate scan using the asynchronous Adaptive Discovery Engine.
**Expected Result:** Scan completes successfully using bounded concurrency limits (e.g., 500 max async workers).
**Metrics:** CPU usage, Memory usage, Network overhead, Scan duration.
**Acceptance Criteria:** Memory footprint remains under 250MB; scan completes in < 30 seconds; no socket exhaustion errors.
**Results:** *Pending Implementation*
