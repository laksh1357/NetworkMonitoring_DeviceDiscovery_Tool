# Prior Art Matrix: LAN Watchtower Architecture

This document identifies and categorizes existing patents, technical publications, and background technologies relevant to the LAN Watchtower architecture. It aims to isolate potentially distinguishing mechanisms (e.g., cross-scan identity fusion and constant-space behavioral baselining) from conventional industry practices.

---

## 1. Device Fingerprinting & Identity Tracking

**Reference 1:** *Systems and methods for tracking network devices using DHCP lease information*
- **Publication Identifier:** US-9XXXXXX-B2 (Generic representation of Cisco/Fortinet IPDT patents)
- **Relevant Mechanism:** Device fingerprinting via DHCP snooping and MAC-to-IP binding tables.
- **Overlap:** **Partial Overlap**. Both systems track devices as IP addresses change to maintain network access control policies.
- **Differences:** Conventional patents rely heavily on active DHCP Snooping (requiring access to the network switch or router). Our system utilizes a passive/active *Cross-Scan Deterministic Matching Cascade* that works purely from an edge node without privileged switch access, combining ARP and Layer-3 heuristics to fuse identities.
- **Potentially Distinguishing Aspects:** The specific deterministic fallback cascade (MAC -> IP/Hostname/Ports) used to resolve DHCP churn locally without network infrastructural support.

**Reference 2:** *Passive Device Fingerprinting across IP changes*
- **Publication Identifier:** Academic Paper (e.g., Morgan State University research on DHCP fingerprinting, 2020)
- **Relevant Mechanism:** Option 55 parameter lists used to identify operating systems.
- **Overlap:** **Background Technology**.
- **Differences:** Academic approaches primarily use fingerprinting for OS identification. Our system uses port-scanning and response latency as logical constraints to resolve identity continuity (not just OS typing).

---

## 2. Behavioral Baselining & Anomaly Detection

**Reference 3:** *Smart intrusion detection using wireless signals and AI*
- **Publication Identifier:** WO2017210770A1
- **Relevant Mechanism:** Utilizing moving variance for statistical anomaly detection in signal strength (RSSI) data streams.
- **Overlap:** **Partial Overlap**. Both systems use moving variance (such as Welford's algorithm) to establish a baseline and detect outliers.
- **Differences:** The referenced patent applies moving variance to physical layer wireless signals (RSSI) for device-free localization and intrusion detection. Our system applies Welford's algorithm specifically to network protocol response latencies (ICMP/TCP) and presence frequency maps, enabling O(1) database storage for behavioral baselining on constrained edge hardware.
- **Potentially Distinguishing Aspects:** The application of incremental variance math to compress network behavioral envelopes, specifically to prevent unbounded database growth in continuous network monitoring.

---

## 3. Network Event Correlation & Explainability

**Reference 4:** *System and Method for Network Event Correlation*
- **Publication Identifier:** US-8XXXXXX-B2 (Standard SIEM patent)
- **Relevant Mechanism:** Grouping multiple network alerts into a single correlated incident based on temporal windows and IP addresses.
- **Overlap:** **Exact/Near Overlap**. The concept of sliding window correlation to suppress duplicate alerts is a fundamental pillar of all modern SIEMs (Security Information and Event Management systems).
- **Differences:** Standard SIEMs often output probabilistic AI scores (e.g., "95% malicious"). Our system utilizes a strict *Explainability Formatter* that bans vague AI conclusions, enforcing rigid string templates (e.g., "Port 445 was not observed but is now reachable").
- **Potentially Distinguishing Aspects:** While event correlation itself is background technology, the strict deterministic formatting of the "Correlation Reason" to ensure purely evidentiary, non-assumptive explanations may present a narrow implementation difference (though likely not broadly patentable on its own).

---

## Summary of Distinctions

1. **Exact/Near Overlap:** Event correlation, sliding windows, and basic port-scanning are highly commoditized and heavily patented. No novelty is claimed here.
2. **Background Technology:** Active ICMP/ARP discovery and OUI vendor lookups are ubiquitous engineering foundations.
3. **Potentially Distinguishing Mechanisms:** 
   - The **Edge-Based Deterministic Identity Cascade**: Tracking devices across DHCP boundaries without switch-level DHCP snooping by correlating MAC, Hostname, and Port heuristics.
   - The **O(1) Incremental Behavioral Baseline**: Adapting Welford's algorithm to compress long-term ICMP/TCP latency histories into a 3-float SQLite footprint, preventing database exhaustion on edge monitoring nodes.
