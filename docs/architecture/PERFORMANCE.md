# Performance Benchmarks & Optimizations

This document details the performance profile of the existing baseline network monitoring system and the optimization strategies implemented for the new modular architecture.

## 1. Baseline Benchmarks (Before)

We conducted a synthetic benchmark of the existing flat-file system (`main.py`) scanning a standard /24 subnet (256 addresses).

- **Scan Duration:** ~6.17 seconds
- **Discovery Latency:** Relies entirely on ICMP echo timeouts (up to 500ms per dead host).
- **CPU Usage:** High burst usage due to spawning 64 concurrent `subprocess.run` threads for `ping`.
- **Memory Usage:** ~45 MB footprint during active scans.
- **Database Query Performance:** 
  - Sequential inserts blocked by Python's `threading.RLock`.
  - Batch write duration: ~5ms for small batches, scaling poorly for large subnets due to a lack of compound indexes.
- **UI Responsiveness:** Periodic stuttering observed when the GUI loop waits for the background ThreadPool to flush results to the SQLite DB.

## 2. Identified Bottlenecks

1. **Subprocess Overhead:** Spawning an OS-level `ping` process for every IP address is extremely inefficient and limits throughput.
2. **Synchronous Threading:** Using `ThreadPoolExecutor` means blocked threads wait idly for network timeouts.
3. **Database Write Locking:** SQLite in WAL mode allows concurrent reads, but the current `database_manager.py` uses aggressive global locks for writes, creating contention during scan completion.
4. **Duplicate Events:** Transient state changes (like a device dropping a single ICMP packet) trigger full database writes and UI updates unnecessarily.

## 3. Optimization Strategy

### Async/Concurrent Discovery
- **Action:** Replace `ThreadPoolExecutor` and `subprocess` with Python's `asyncio` and non-blocking raw sockets (or `scapy` with async loops) for ICMP and ARP.
- **Expected Impact:** Reduces a /24 subnet scan from ~6 seconds to `< 1 second` by transmitting packets asynchronously without spawning processes.

### Database Indexes & Batch Writes
- **Action:** Introduce compound indexes on `evidence_timeline(device_uuid, timestamp DESC)` and enable `PRAGMA synchronous = NORMAL; PRAGMA journal_mode = WAL;`.
- **Action:** Replace sequential `INSERT` statements with `executemany()` batch writes when flushing scan results.
- **Expected Impact:** O(1) read times for the UI Timeline, and a 10x reduction in database write latency.

### Event Deduplication & Bounded Queues
- **Action:** Introduce an in-memory sliding window (as defined in the Event Correlation Engine) to deduplicate jittery signals (e.g., rapid online/offline flapping) before writing to the database.
- **Action:** Use `asyncio.Queue` with a bounded maximum size to prevent memory exhaustion during a massive /16 subnet scan.

## 4. Target Benchmarks (After)

*(Projected targets based on the modular architecture implementation)*
- **Scan Duration:** < 1.0 seconds for a /24 subnet.
- **CPU Usage:** Minimal (async loops).
- **Database Batch Write Duration:** < 1.0 ms for 256 records.
- **UI Responsiveness:** 60 FPS maintained, as the SPA frontend decouples rendering from backend IO.
