# Technical Architecture

This document outlines the proposed architecture for a sophisticated network observation and behavioral analysis system. The architecture transitions the tool from a point-in-time discovery script into an intelligent, continuous monitoring platform.

## 1. Adaptive Discovery Engine
* **Input:** Subnet configurations, schedule triggers, and selective probe requests from the Observation Engine.
* **Processing:** Utilizes a hybrid discovery approach. It prioritizes *passive listening* (e.g., observing ARP, DHCP, mDNS broadcasts) to discover hosts silently. It dynamically schedules *active probing* (ICMP, TCP SYN, UDP) only when passive data is stale or missing, modulating the probe frequency based on network load and device type.
* **Output:** Raw network endpoints (IP, MAC, responsive ports) and protocol metadata.
* **Data structures:** Priority queues for dynamic scan scheduling; State machines for discovery phases (Passive -> Light Active -> Deep Probe).
* **Algorithms:** Exponential backoff for probing offline hosts; randomized jittering for polling intervals to prevent network storms.
* **Interaction:** Emits raw endpoints to the Device Identity Engine; receives cues from the Observation Engine.
* **Failure cases:** Dropped packets leading to false offline states; local host firewalls blocking active probes; switch port isolation (Private VLANs) defeating passive sniffing.
* **Security implications:** Active scanning can trigger external IDS/IPS. Spoofed ARP responses can poison the discovery pool.

## 2. Device Identity/Fingerprinting Engine
* **Input:** Raw network endpoints and metadata from the Discovery Engine.
* **Processing:** Fuses multiple network attributes (MAC OUI, TCP/IP stack signatures like TTL/Window Size/Options, DHCP parameter request lists, and open port combinations) into a deterministic signature. It correlates changing IPs and randomized MACs to a single logical entity.
* **Output:** Persistent Device Entity characterized by a unique UUID.
* **Data structures:** Fingerprint vector matrices; Entity resolution graphs mapping transient identifiers (IP/MAC) to persistent UUIDs.
* **Algorithms:** Locality-Sensitive Hashing (LSH) or Weighted Jaccard Similarity for fuzzy matching partial fingerprints; Naive Bayes classification for device type inference.
* **Interaction:** Provides stable UUIDs to the Baseline and Evidence Engines.
* **Failure cases:** Widespread MAC randomization combined with strict NAT environments breaking identity tracking; OS updates drastically changing the fingerprint.
* **Security implications:** Fingerprint data reveals specific, potentially vulnerable OS versions. Attackers could spoof DHCP/TCP signatures to disguise a malicious host as a trusted printer.

## 3. Observation Engine
* **Input:** Raw packet captures (pcap/BPF), NetFlow/sFlow exports, or high-frequency port state polling.
* **Processing:** Continuously monitors traffic volume, port state transitions, and connection patterns (who talks to whom) without performing deep payload inspection. 
* **Output:** Time-series metrics (e.g., bytes/sec, packet rates) and connection matrices.
* **Data structures:** Ring buffers for high-throughput metrics; Adjacency lists for connection graphs.
* **Algorithms:** Sliding window aggregations; Count-Min Sketch for tracking frequent talkers in high-volume traffic.
* **Interaction:** Feeds normalized time-series data to the Behavioral Baseline Engine.
* **Failure cases:** High packet volume causing buffer overflows and dropped observations.
* **Security implications:** Accessing raw traffic requires elevated privileges (root/CAP_NET_RAW). strict sanitization is needed to avoid logging payload PII.

## 4. Behavioral Baseline Engine
* **Input:** Time-series metrics and connection graphs tied to Device UUIDs.
* **Processing:** Learns the "normal" operational envelope over a training period. It profiles diurnal traffic cycles, standard peer communication sets, and typical open ports for each unique device.
* **Output:** Statistical baselines, allowed communication graphs, and expected temporal profiles.
* **Data structures:** Probabilistic data structures (e.g., Bloom filters for known peers); Temporal histograms.
* **Algorithms:** Exponential Moving Averages (EMA) for volume metrics; Unsupervised clustering (e.g., DBSCAN) to define normal state vectors.
* **Interaction:** Provides dynamic thresholds and normal models to the Anomaly Detection Engine.
* **Failure cases:** "Concept drift" where legitimate infrastructure changes cause massive false positives; "Poisoned baselines" if the training period unwittingly includes malicious activity.
* **Security implications:** If an attacker can slowly alter their behavior, they can poison the baseline to mask future malicious actions.

## 5. Anomaly Detection Engine
* **Input:** Real-time observations and established baselines.
* **Processing:** Compares current device behavior against its established envelope. Detects traffic spikes, new open ports, or communications with unknown internal/external peers.
* **Output:** Anomaly events (e.g., "Unexpected Port Open", "Lateral Movement Suspected") annotated with severity scores.
* **Data structures:** Anomaly score matrices; Event tuples.
* **Algorithms:** Z-score thresholding for volume anomalies; Isolation Forests for complex multivariate outlier detection.
* **Interaction:** Emits anomaly events to the Event Correlation Engine.
* **Failure cases:** High rate of false positives in highly dynamic environments (e.g., developer workstations or CI/CD servers).
* **Security implications:** The core defense component. If overwhelmed or bypassed through "low-and-slow" evasion, attacks will go unnoticed.

## 6. Event Correlation Engine
* **Input:** Anomaly events and infrastructure state changes.
* **Processing:** Groups related anomalies occurring in a tight time window or topologically related segment to reduce alert fatigue. Identifies causal chains (e.g., Device A scanned Device B, followed by Device B initiating a large external transfer).
* **Output:** Correlated Incidents (grouped events with root-cause hints).
* **Data structures:** Directed Acyclic Graphs (DAGs) representing event causality; Time-indexed priority queues.
* **Algorithms:** Complex Event Processing (CEP) state machines; Apriori algorithm for frequent pattern mining.
* **Interaction:** Triggers the Alerting Engine and requests context from the Evidence Engine.
* **Failure cases:** Combinatorial explosion of events during a widespread network failure (e.g., switch reboot) causing the engine to hang.
* **Security implications:** Attackers may attempt to flood the network with benign anomalies to overwhelm the correlation logic and hide their true attack.

## 7. Evidence/Timeline Engine
* **Input:** Discovered events, anomaly scores, and raw metrics leading up to an incident.
* **Processing:** Constructs an immutable, chronologically ordered narrative for a given Device UUID. Attaches contextual snapshots of the network state at the time of the anomaly.
* **Output:** Explainable Incident Reports and structured Timeline JSONs.
* **Data structures:** Append-only event logs; Merkle trees (optional, for immutability validation); Document stores.
* **Algorithms:** Time-series interpolation; causal graph traversal to translate raw DAGs into human-readable narratives.
* **Interaction:** Queried by the API/UI Layer for incident review and investigation.
* **Failure cases:** Storage exhaustion due to persisting high-granularity evidence for long periods.
* **Security implications:** Evidence tampering is a primary post-breach attacker goal. Logs must enforce strict append-only semantics.

## 8. Network Topology Engine
* **Input:** Discovery data, packet TTLs, trace routes, and ARP/MAC cache data (if integrated with SNMP).
* **Processing:** Maps the physical and logical layout of the network. Infers switch and router boundaries by observing broadcast domains, subnets, and hop counts.
* **Output:** Network Graph (Nodes = Devices/Switches, Edges = Links).
* **Data structures:** Adjacency matrices; Graph objects.
* **Algorithms:** Spanning tree discovery; Shortest path (Dijkstra); Force-directed graph layout for UI visualization.
* **Interaction:** Provides spatial context to the Correlation Engine.
* **Failure cases:** Incomplete graphs due to unmanaged "dumb" switches or strict VLAN isolation preventing mapping traffic.
* **Security implications:** The topology map provides a blueprint of the network, making it a prime target for attackers seeking lateral movement paths. Requires strict RBAC.

## 9. Alerting Engine
* **Input:** Correlated Incidents.
* **Processing:** Routes incidents based on severity and destination (Email, Slack, Webhooks). Manages alert state (New, Acknowledged, Resolved) and handles deduplication.
* **Output:** Formatted outbound messages and API calls.
* **Data structures:** Routing rule tables; State machines for incident lifecycles.
* **Algorithms:** Deduplication hashing; Exponential backoff and retry logic for external APIs.
* **Interaction:** Pushes notifications externally; updates the Persistence Layer.
* **Failure cases:** Alert storms leading to rate-limiting by external providers (e.g., Slack API blocks).
* **Security implications:** Webhook injection vulnerabilities; exposure of sensitive network metadata if alerts are sent via unencrypted channels.

## 10. Persistence Layer
* **Input:** Normalized data from all internal engines.
* **Processing:** Handles fast, high-volume writes for time-series data while maintaining relational integrity for device metadata and configurations.
* **Output:** Query results for the UI and background engines.
* **Data structures:** B-Trees; Time-Series optimized tables (e.g., TimescaleDB or optimized SQLite WAL); JSON binary blobs for unstructured evidence.
* **Algorithms:** Write-Ahead Logging (WAL); Background compaction and indexing.
* **Interaction:** Acts as the central state store bridging the background engines and the API/UI.
* **Failure cases:** Disk full errors; DB corruption; lock contention during extreme write spikes.
* **Security implications:** Data at rest must be strictly permissioned (or encrypted) to prevent local extraction of the network topology and device vulnerabilities.

## 11. API/UI Layer
* **Input:** User requests via HTTP REST or WebSockets.
* **Processing:** Authenticates users, validates inputs, queries the Persistence and Evidence engines, and streams live updates to the frontend.
* **Output:** JSON responses and WebSocket event frames.
* **Data structures:** REST API schemas (OpenAPI); GraphQL nodes.
* **Algorithms:** JWT validation; Token Bucket for rate limiting; Cursor-based pagination.
* **Interaction:** Acts as the secure gateway between the internal architecture and human operators.
* **Failure cases:** Connection exhaustion; memory leaks on dangling WebSockets.
* **Security implications:** The primary external attack surface. Susceptible to XSS, SSRF, CSRF, and Injection if inputs are not strictly sanitized. Requires robust OAuth/JWT authentication.
