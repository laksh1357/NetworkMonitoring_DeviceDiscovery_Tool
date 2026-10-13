# ECIV Integration Audit

Date: 2026-10-13

## Current execution path

The canonical runtime is `src.api.server`. `POST /api/scan/start` invokes
`src.discovery.scanner.NetworkScanner` in a worker thread. The scanner performs
ARP discovery when Scapy/raw sockets are available, then ICMP and TCP fallback
probes. Each live result is reported through `on_device_found`, persisted to
the legacy `devices` table, and now normalized into a
`src.identity.models.NetworkObservation`.

The observation is processed by `IdentityVerificationService`, which invokes
`EvidenceCorrelatedIdentityEngine`, persists the identity assessment,
immutable observation, and conflicts, and is idempotent for an observation ID.
The existing identity API reads those durable records.

## Baseline findings

| Area | Status | Evidence |
| --- | --- | --- |
| Typed ECIV observations | Implemented and verified | `src/identity/models.py`, ECIV tests |
| Identity state transitions | Implemented and verified | `src/identity/state.py` |
| Heuristic multi-signal scoring | Implemented; not statistically calibrated | `src/identity/scoring.py` |
| SQLite identity lineage records | Implemented and verified | `src/core/database/manager.py` |
| Scanner-to-ECIV integration | Implemented in canonical API path | `src/api/server.py` callback |
| Provenance source | Implemented for ARP/ICMP/TCP collection path | `src/discovery/scanner.py` |
| Adaptive strategy selection | Implemented as strategy selection | `src/identity/engine.py` |
| Actual adaptive verification execution | Partial | no safe executor/reassessment loop yet |
| Behavioral isolation and promotion | Partial | unresolved observations are retained, but no versioned baseline service exists |
| REST identity reads | Implemented and verified | `/api/identities` routes |
| WebSocket ECIV events | Partial | engine callback exists; durable outbox is not implemented |
| Merge/split operations | Missing | no transactional command/API exists |

## Duplicate or competing implementations

`backend/identity` and `backend/database` are compatibility-era copies. The
canonical production path is under `src/`; compatibility modules remain to
preserve existing imports and tests. `desktop/app.py` contains a separate
desktop scanner for Tkinter use and is not the HTTP API scanner path.

## Security and correctness issues

- The API still has no authentication or authorization layer and should not be
  exposed publicly without an ingress policy.
- Identity confidence is a heuristic score, not a calibrated probability.
- A failed or unavailable probe is not proof of identity mismatch.
- Topology edges remain empty unless relationship evidence is collected.
- Verification strategy labels are not yet backed by bounded, read-only
  execution adapters.

## Test plan

The focused tests cover observation normalization, conflict/state behavior,
SQLite persistence, duplicate observation handling, and scanner provenance.
Integration tests should next exercise a controlled scanner callback through
the API service and add verification executor, baseline promotion, and
transaction-recovery scenarios using localhost fixtures only.
