# Production-Quality Testing Strategy

This document outlines the testing strategy for the LAN Watchtower system. Because this is a network monitoring tool handling dynamic hardware and protocols, testing must balance deterministic isolation (mocking) with robust integration.

## 1. Testing Pyramid

### Unit Testing (`tests/unit/`)
- **Focus:** Fast, deterministic testing of isolated algorithms (e.g., Anomaly Detection rules, Identity Fingerprinting matching, Welford's baseline statistics).
- **Environment:** Entirely offline. No sockets opened.
- **Fixtures:** Hardcoded JSON fixtures representing synthetic `Observation` and `DeviceIdentity` states.

### Integration Testing (`tests/integration/`)
- **Focus:** Verifying the hand-off between engines (e.g., Discovery Engine feeding into the Fingerprinting Engine) and Database persistence.
- **Environment:** Uses a temporary in-memory SQLite database (`:memory:` or temporary disk file) for every test run to prevent state pollution.
- **Mocking:** Network operations (e.g., `asyncio.open_connection`, `scapy` packet emissions) are intercepted and mocked to return predefined deterministic bytes. No unauthorized network scanning occurs during testing.

### API & UI Testing (`tests/api/`, `tests/ui/`)
- **Focus:** Verifying that the REST API correctly serves data and handles invalid inputs (e.g., SSRF attempts), and ensuring UI components correctly render network topologies.
- **Framework:** `pytest` paired with `httpx` for the backend API, and a lightweight headless browser tester or component tests (e.g., Jest/Vitest) for the Web SPA.

## 2. Realistic Mock Network Environments
To avoid fragile, environment-dependent tests (flaky tests), we rely on a `MockNetworkSimulator` class inside our test suite. 
- It simulates an entire subnet lifecycle: DHCP leases expiring, MAC addresses changing, and services going offline.
- Instead of executing real `ping` commands, the Discovery Engine is configured in a "Test Mode" that queries the `MockNetworkSimulator` for state, ensuring instantaneous and reproducible test runs.

## 3. Failure Recovery & Configuration
- **Failure Recovery:** Tests explicitly inject database locked errors (`sqlite3.OperationalError`) and simulated network timeouts (`asyncio.TimeoutError`) to ensure the engines degrade gracefully and retry without crashing.
- **Configuration:** The test suite runs against multiple synthetic `config.yaml` states (e.g., aggressive rate-limiting vs. permissive rate-limiting) to ensure the application honors settings securely.

## 4. Coverage Metrics
- **Tooling:** `pytest-cov` is used to measure Python coverage.
- **Philosophy:** We target high *meaningful* coverage (e.g., >95% on the Anomaly Engine rules and Identity matching logic) rather than chasing arbitrary 100% metrics on boilerplate configuration classes.

## 5. Security-Sensitive Code
- All input validation boundaries (especially the API endpoints handling IP addresses) have dedicated negative test cases asserting that malicious inputs are safely rejected.
