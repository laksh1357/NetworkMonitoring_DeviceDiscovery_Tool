import sys
import threading
from src.discovery.scanner import NetworkScanner, detect_local_subnet
from src.core.database import NetworkDatabase
from src.api.server import NOCRequestHandler, scan_state, auto_scan_active, auto_scan_interval, scanner, database, init_demo_seed_if_empty, _BASE_DIR
from http.server import HTTPServer

def run_server():
    init_demo_seed_if_empty()
    print("NOC Engine Server starting on port 8000")
    httpd = HTTPServer(("0.0.0.0", 8000), NOCRequestHandler)
    httpd.serve_forever()

if __name__ == "__main__":
    run_server()
