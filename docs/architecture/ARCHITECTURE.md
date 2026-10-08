# Architecture Overview

This document describes the high-level architecture of LAN Watchtower, designed as a highly modular, decoupled system prioritizing deterministic behavior and constant-space resource utilization.

## 1. Engine Modules (`src/`)
The backend is composed of discrete analytical engines that pass immutable state transition events forward.

- **`src/discovery`**: Replaces traditional sequential pinging with an `asyncio` based non-blocking scanner that dynamically shifts between ICMP, ARP, and TCP protocols based on target responsiveness.
- **`src/fingerprinting`**: Receives raw transient observations and fuses them into a persistent `DeviceIdentity` using a deterministic matching cascade (handling DHCP churn and MAC changes).
- **`src/baseline`**: Uses Welford's online variance algorithm to compute Exponential Moving Averages (EMA) of latency and presence. This ensures database storage remains O(1) per device rather than growing infinitely over time.
- **`src/anomaly`**: A strict, rule-based inference engine. It bans black-box heuristics in favor of explicitly calculated mathematical deviations (e.g., latency exceeding `EMA + 3*StdDev`).
- **`src/correlation`**: Synthesizes multiple overlapping anomalies into single coherent `CorrelatedEvent`s using a time-bounded sliding window to prevent alert fatigue.
- **`src/topology`**: Translates observations into a graph structure (Nodes/Edges), explicitly segregating concrete Layer-2 evidence (e.g., ARP) from heuristically inferred Layer-3 routing relationships.
- **`src/evidence`**: Maintains an append-only ledger of state transitions referencing UUIDs rather than duplicating data.

## 2. Presentation Layer (`web/`)
The architecture deprecates tightly-coupled GUI loops (like Tkinter) in favor of a decoupled Web Single Page Application (SPA).
- **Separation of Concerns:** The backend only emits JSON via the `src/api/server.py` REST interface. The SPA handles all canvas-based chart rendering, topology mappings, and state management.

## 3. Storage (`network_logs.db`)
- Powered by SQLite in WAL (Write-Ahead Logging) mode to permit concurrent read operations.
- Enforces relational constraints and compound indexes on the Evidence Timeline to ensure query performance scales linearly even with tens of thousands of historical network transitions.
