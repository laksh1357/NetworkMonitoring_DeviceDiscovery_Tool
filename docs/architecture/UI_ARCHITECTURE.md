# UI Architecture: Network Monitoring Dashboard

This document outlines the architecture for the redesigned user interface, migrating the primary presentation layer to a decoupled Web-based Single Page Application (SPA). This ensures a strict separation of concerns, high performance for complex visualizations (topology graphs, historical charts), and a professional aesthetic without sacrificing responsiveness.

## 1. Architectural Separation
The UI is strictly decoupled from the core network engines and database. 
- **Backend API (`src/api/server.py`)**: Exposes RESTful endpoints and WebSockets for real-time telemetry.
- **Frontend SPA (`web/`)**: Handles all rendering, state management, and user interactions.

## 2. Core Dashboard Layout
The professional dashboard is divided into three primary regions:

### Global Status Header (Top)
Displays high-level network health at a glance:
- **Metrics Ribbons:** Total Devices, Online Devices, Offline Devices.
- **Scan Status Indicator:** Shows current adaptive discovery engine state (e.g., "Passive Listening", "Active Probe in Progress").
- **Alert Ticker:** Scrolling or prioritized view of unacknowledged Correlated Events and recent Anomalies.

### Main Navigation & Views (Center)
Provides tabbed or routed views for deep dives:
- **Overview:** Combined widget view (mini-charts, recent events).
- **Device Inventory:** A paginated, searchable, and filterable data table of all persistent Device Identities.
- **Network Topology:** An interactive force-directed graph (e.g., using D3.js or Cytoscape.js) visualizing nodes (devices/subnets) and relationship edges.
- **Event Center:** Unified feed of Correlated Events and Anomalies.

### Device Detail Panel (Slide-out or Dedicated Page)
When a device is selected from the Inventory or Topology map, it displays:
- **Identity Card:** Current IP, MAC, Hostname, Vendor, First/Last Seen.
- **Behavioral Baseline Summary:** Historical charts showing typical activity windows and latency envelopes.
- **Observed Services:** List of known open ports and protocols.
- **Evidence Timeline:** A chronological, scrollable feed of the device's lifecycle (IP changes, anomalies, correlated events).

## 3. Visualizations & Frameworks
To achieve a professional aesthetic without sacrificing performance:
- **Data Tables:** Virtualized scrolling to handle thousands of devices seamlessly.
- **Historical Charts:** Canvas-based rendering (e.g., Chart.js or Apache ECharts) for plotting presence frequencies and response latencies without DOM bloat.
- **Topology Map:** WebGL or optimized Canvas rendering to ensure the force-directed graph remains smooth during layout calculations. Animations are kept minimal (subtle transitions on state changes) rather than constant visual noise.

## 4. Security & Data Exposure
- **No Sensitive Payloads:** The UI will not expose raw packet data or PII.
- **Role-Based Views (Future):** The API enforces what data is sent to the UI, ensuring the frontend only renders what is explicitly authorized.

## 5. UI Testing Strategy
- **Unit Tests:** Component-level testing for formatters (e.g., MAC address formatting, timestamp localization).
- **Integration Tests:** Mocking the backend REST API to verify the UI correctly parses and renders the Device Identity models, Evidence Timelines, and Anomaly thresholds without relying on a live network scan.
