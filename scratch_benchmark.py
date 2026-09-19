import time
import ipaddress
import sys
import threading
import statistics

# Import the existing scanner
try:
    from main import NetworkScanner, detect_local_subnet
except ImportError:
    print("Failed to import main.py")
    sys.exit(1)

def run_benchmark():
    print("--- Performance Benchmark ---")
    try:
        subnet = detect_local_subnet()
        print(f"Detected subnet: {subnet}")
    except Exception as e:
        print(f"Error detecting subnet: {e}")
        subnet = ipaddress.ip_network("127.0.0.0/24")
        print(f"Using loopback subnet for testing: {subnet}")
    
    # We don't want to actually scan the whole network if it's large, but let's do a /24
    if subnet.num_addresses > 256:
        subnet = ipaddress.ip_network(f"{str(subnet.network_address)}/24", strict=False)
    
    scanner = NetworkScanner(max_workers=64, host_timeout=0.5)
    
    start_time = time.perf_counter()
    
    event = threading.Event()
    results = []
    latencies = []
    
    def on_progress(done, total):
        pass
        
    def on_device_found(device):
        if device.latency_ms:
            latencies.append(device.latency_ms)
            
    def on_complete(devices):
        results.extend(devices)
        event.set()
        
    def on_error(err):
        print(f"Scan error: {err}")
        event.set()
        
    scanner.scan(subnet, on_progress, on_complete, on_error, on_device_found=on_device_found)
    
    event.wait(timeout=60)
    
    end_time = time.perf_counter()
    duration = end_time - start_time
    
    print(f"Scan duration: {duration:.2f} seconds")
    print(f"Devices found: {len(results)}")
    
    if latencies:
        print(f"Avg Discovery Latency: {statistics.mean(latencies):.2f} ms")
        print(f"Max Discovery Latency: {max(latencies):.2f} ms")
    else:
        print("No latency data available (possibly offline or no ping responses).")
        
    # Test DB insertion performance
    from database_manager import NetworkDatabase
    import tempfile
    from pathlib import Path
    
    with tempfile.TemporaryDirectory() as tmpdirname:
        db_path = Path(tmpdirname) / "bench.db"
        db = NetworkDatabase(db_path)
        
        db_start = time.perf_counter()
        db.record_scan(results, len(results))
        db_end = time.perf_counter()
        
        print(f"Database batch write duration ({len(results)} devices): {(db_end - db_start) * 1000:.2f} ms")
        db.close()
        
if __name__ == "__main__":
    run_benchmark()
