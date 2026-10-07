"""Network Monitoring and Device Discovery Tool.

Run with: python main.py
"""

from __future__ import annotations

import csv
import ipaddress
import os
import platform
import queue
import re
import socket
import sqlite3
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

from backend.models import Device
from backend.core import RuntimeSettings
from backend.monitoring import (
    ContinuousDiscoveryService,
    DeviceRegistry,
    HealthMonitoringService,
    HealthSettings,
)
from backend.scanning import ContinuousPortMonitoringService, PortMonitoringSettings
from backend.notifications import EmailProvider, InAppProvider, NotificationDispatcher, WebhookProvider
from backend.services import AlertService, AnalyticsService, AnomalyDetectionService, DashboardService
from backend.websocket import EventHub, WebSocketServer
from vendor_lookup import load_oui_database, lookup_vendor
from database_manager import NetworkDatabase
from notifications import notify_new_device
from port_scanner import scan_ports

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except ImportError:  # Allows backend tests on headless Python installations.
    tk = None
    filedialog = messagebox = ttk = None

try:
    import customtkinter as ctk
except ImportError:  # Allows backend tests without the optional GUI dependency.
    ctk = None

try:
    from scapy.all import ARP, Ether, srp  # type: ignore
except ImportError:
    ARP = Ether = srp = None


def detect_local_subnet(interface: str = "auto") -> ipaddress.IPv4Network:
    """Detect the active IPv4 interface by opening a UDP socket route lookup."""
    if interface and interface != "auto" and hasattr(socket, "if_nametoindex"):
        try:
            socket.if_nametoindex(interface)
        except OSError as exc:
            raise OSError(f"network interface not found: {interface}") from exc
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
    except OSError:
        local_ip = socket.gethostbyname(socket.gethostname())
    finally:
        sock.close()
    return ipaddress.ip_network(f"{local_ip}/24", strict=False)


def ping_host(ip: str, timeout: float = 1.0) -> tuple[bool, float | None]:
    """Ping one address using the host OS and return success plus elapsed ms."""
    command = ["ping", "-n", "-c", "1", "-W", str(max(1, int(timeout * 1000))), ip]
    if platform.system().lower() == "windows":
        command = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout + 1.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False, None
    elapsed = (time.perf_counter() - started) * 1000
    return completed.returncode == 0, elapsed if completed.returncode == 0 else None


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return "Unknown"


def normalize_mac(value: str) -> str:
    return value.upper() if value else "Unknown"


def has_admin_privileges() -> bool:
    """Return whether raw-packet discovery can normally be attempted."""
    if os.name == "nt":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def resolve_mac_from_arp(ip: str) -> str:
    """Read a MAC from the OS ARP cache after an ICMP response."""
    try:
        result = subprocess.run(
            ["arp", "-n", ip] if platform.system().lower() != "windows" else ["arp", "-a", ip],
            capture_output=True,
            text=True,
            timeout=1.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "Unknown"
    match = re.search(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", result.stdout)
    return normalize_mac(match.group(0)) if match else "Unknown"


class NetworkScanner:
    """Background scanner that reports progress through callbacks."""

    def __init__(self, max_workers: int = 64, host_timeout: float = 1.0) -> None:
        self.max_workers = max(1, max_workers)
        self.host_timeout = host_timeout
        self.oui_database = load_oui_database()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._executor: ThreadPoolExecutor | None = None
        self.privileged = has_admin_privileges()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def stop(self) -> None:
        self._stop_event.set()
        if self._executor is not None:
            self._executor.shutdown(wait=False, cancel_futures=True)

    def scan(
        self,
        subnet: ipaddress.IPv4Network,
        on_progress: Callable[[int, int], None],
        on_complete: Callable[[list[Device]], None],
        on_error: Callable[[str], None],
        on_stopped: Callable[[], None] | None = None,
    ) -> None:
        if self.running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_scan,
            args=(subnet, on_progress, on_complete, on_error, on_stopped),
            daemon=True,
            name="network-scan",
        )
        self._thread.start()

    def _run_scan(
        self,
        subnet: ipaddress.IPv4Network,
        on_progress: Callable[[int, int], None],
        on_complete: Callable[[list[Device]], None],
        on_error: Callable[[str], None],
        on_stopped: Callable[[], None] | None,
    ) -> None:
        try:
            arp_devices: dict[str, str] = {}
            if self.privileged and srp is not None:
                try:
                    arp_devices = self._arp_scan(subnet)
                except Exception:
                    # Scapy raises platform-specific exceptions for missing raw-socket access.
                    self.privileged = False
            devices = self._layered_scan(subnet, arp_devices, on_progress)
            if self._stop_event.is_set():
                if on_stopped is not None:
                    on_stopped()
                return
            on_complete(devices)
        except Exception as exc:  # Keep worker failures out of the Tk main loop.
            on_error(str(exc))

    def _arp_scan(self, subnet: ipaddress.IPv4Network) -> dict[str, str]:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(subnet))
        answered, _ = srp(packet, timeout=2, verbose=False)
        return {received.psrc: normalize_mac(received.hwsrc) for _, received in answered}

    def _tcp_probe(self, ip: str) -> bool:
        for port in (80, 445):
            if self._stop_event.is_set():
                return False
            try:
                with socket.create_connection((ip, port), timeout=self.host_timeout):
                    return True
            except (ConnectionRefusedError, TimeoutError, socket.timeout, OSError):
                continue
        return False

    def _layered_scan(
        self,
        subnet: ipaddress.IPv4Network,
        arp_devices: dict[str, str],
        on_progress: Callable[[int, int], None],
    ) -> list[Device]:
        addresses = list(subnet.hosts())
        total = len(addresses)
        results: list[Device] = []
        completed = 0
        lock = threading.Lock()
        worker_semaphore = threading.BoundedSemaphore(self.max_workers)

        def check(address: ipaddress.IPv4Address) -> Device | None:
            nonlocal completed
            if self._stop_event.is_set():
                return None
            ip = str(address)
            mac = arp_devices.get(ip, "Unknown")
            online = bool(mac != "Unknown")
            latency: float | None = None
            if not online:
                online, latency = ping_host(ip, self.host_timeout)
            if not online:
                online = self._tcp_probe(ip)
            if online and mac == "Unknown":
                mac = resolve_mac_from_arp(ip)
            with lock:
                completed += 1
                on_progress(completed, total)
            if not online:
                return None
            return Device(
                ip=ip,
                mac=mac,
                vendor=lookup_vendor(mac, self.oui_database, allow_api=True),
                hostname=resolve_hostname(ip),
                status="Online",
                latency_ms=latency,
                last_seen=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )

        def guarded_check(address: ipaddress.IPv4Address) -> Device | None:
            while not self._stop_event.is_set():
                if worker_semaphore.acquire(timeout=0.1):
                    break
            else:
                return None
            try:
                return check(address)
            finally:
                worker_semaphore.release()

        from concurrent.futures import ThreadPoolExecutor, as_completed

        self._executor = ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="discovery")
        futures = [self._executor.submit(guarded_check, address) for address in addresses]
        try:
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    break
                device = future.result()
                if device is not None:
                    results.append(device)
        finally:
            self._executor.shutdown(wait=True, cancel_futures=True)
            self._executor = None
        return sorted(results, key=lambda item: ipaddress.ip_address(item.ip))


TkBase = ctk.CTk if ctk is not None else object


class NetworkMonitorApp(TkBase):
    """CustomTkinter dashboard that keeps all UI updates on the main thread."""

    columns = ("ip", "mac", "vendor", "hostname", "status", "latency", "last_seen")
    headings = ("IP Address", "MAC Address", "Vendor", "Hostname", "Status", "Latency", "Last Seen")

    def __init__(self) -> None:
        if ctk is None or tk is None:
            raise RuntimeError("CustomTkinter is not available. Install dependencies and use Python with Tk support.")
        super().__init__()
        self.title("LAN Watchtower")
        self.geometry("1220x720")
        self.minsize(980, 580)
        self.scanner = NetworkScanner()
        self.database = NetworkDatabase()
        self.dashboard_service = DashboardService(self.database)
        self.analytics_service = AnalyticsService(self.database)
        self.anomaly_service = AnomalyDetectionService()
        self.runtime_settings = RuntimeSettings()
        self.notification_dispatcher = NotificationDispatcher(
            [
                InAppProvider(self.database),
                EmailProvider(),
                WebhookProvider(),
            ]
        )
        self.event_hub = EventHub()
        self.alert_service = AlertService(
            self.database,
            self.notification_dispatcher,
            on_event=lambda name, data: self.event_hub.publish(name, data),
        )
        self.websocket_server: WebSocketServer | None = None
        if os.environ.get("WEBSOCKET_ENABLED", "true").lower() in {"1", "true", "yes"}:
            self.websocket_server = WebSocketServer(
                self.event_hub,
                host=os.environ.get("WEBSOCKET_HOST", "127.0.0.1"),
                port=int(os.environ.get("WEBSOCKET_PORT", "8765")),
            )
            try:
                self.websocket_server.start()
            except RuntimeError:
                self.websocket_server = None
        self.alerts: list[dict[str, object]] = []
        self.monitor_interval_var = tk.StringVar(value="60")
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.devices: dict[str, Device] = {}
        self.previous_online: set[str] = set()
        self.previous_macs: set[str] = set()
        self.has_completed_scan = False
        self.open_ports: dict[str, list[object]] = {}
        self.open_port_counts: dict[str, int] = {}
        self.port_events: list[dict[str, object]] = []
        self.subnet_var = tk.StringVar(value="Detecting local subnet...")
        self.status_var = tk.StringVar(value="Ready")
        self.count_var = tk.StringVar(value="0 active devices")
        self.port_status_var = tk.StringVar(value="Select an online device to inspect its common TCP ports")
        self.search_var = tk.StringVar()
        self.status_filter_var = tk.StringVar(value="All statuses")
        self.sort_var = tk.StringVar(value="IP address")
        self.nav_buttons: dict[str, ctk.CTkButton] = {}
        self.port_scan_thread: threading.Thread | None = None
        registry = DeviceRegistry()
        self.registry = registry
        health_service = HealthMonitoringService(
            registry,
            self.database,
            ping_host,
            settings=HealthSettings(),
            on_update=lambda device: self.events.put(("health_update", device)),
            on_error=lambda error: self.events.put(("health_error", error)),
            on_alert=lambda alert_type, severity, message, ip: self.events.put(
                ("alert_create", (alert_type, severity, message, ip))
            ),
        )
        self.port_monitor = ContinuousPortMonitoringService(
            registry,
            self.database,
            scan_ports,
            settings=PortMonitoringSettings(),
            on_events=lambda events: self.events.put(("port_events", events)),
            on_error=lambda error: self.events.put(("ports_error", ("scheduled", error))),
            on_alert=lambda event: self.events.put(("port_alert", event)),
        )
        self.monitor = ContinuousDiscoveryService(
            self.scanner,
            self.database,
            detect_local_subnet,
            interval_seconds=60.0,
            on_cycle=lambda devices, _transitions: self.events.put(("complete", devices)),
            on_error=lambda error: self.events.put(("error", error)),
            on_progress=lambda done, total: self.events.put(("progress", (done, total))),
            health_service=health_service,
            registry=registry,
            on_transitions=lambda transitions: self.events.put(("discovery_transitions", transitions)),
        )
        self._build_modern_ui()
        self._load_persisted_dashboard_state()
        self.after(250, self._show_privilege_warning)
        self.after(100, self._process_events)
        self.protocol("WM_DELETE_WINDOW", self._close)

    def _show_privilege_warning(self) -> None:
        if self.scanner.privileged:
            return
        self.status_var.set("Unprivileged mode: using ARP cache, ICMP, and TCP fallback")
        messagebox.showwarning(
            "Limited discovery mode",
            "Administrator/root privileges are not available.\n\n"
            "The app will continue using ARP-cache lookup, ICMP ping, and TCP checks. "
            "Some devices and MAC addresses may not be detected.",
        )

    def _build_ui(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=230, corner_radius=0, fg_color=("#e9eef3", "#121a23"))
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        ctk.CTkLabel(self.sidebar, text="LAN\nWATCHTOWER", justify="left", font=ctk.CTkFont(size=24, weight="bold"), text_color=("#17212b", "#f5f7fa")).pack(anchor="w", padx=24, pady=(34, 8))
        ctk.CTkLabel(self.sidebar, text="NETWORK OPERATIONS", font=ctk.CTkFont(size=10, weight="bold"), text_color=("#607384", "#9eafbd")).pack(anchor="w", padx=24, pady=(28, 8))
        self._nav_button("◈  Overview", True).pack(fill="x", padx=14, pady=3)
        self._nav_button("▦  Devices", False).pack(fill="x", padx=14, pady=3)
        self._nav_button("◷  Scan history", False).pack(fill="x", padx=14, pady=3)
        ctk.CTkLabel(self.sidebar, text="APPEARANCE", font=ctk.CTkFont(size=10, weight="bold"), text_color=("#607384", "#9eafbd")).pack(anchor="w", padx=24, pady=(34, 8))
        self.mode_switch = ctk.CTkSwitch(self.sidebar, text="Dark mode", command=self.toggle_appearance, onvalue="dark", offvalue="light")
        self.mode_switch.select()
        self.mode_switch.pack(anchor="w", padx=24)
        ctk.CTkLabel(self.sidebar, text="Discovery runs in the background.\nOnly scan networks you own.", justify="left", font=ctk.CTkFont(size=11), text_color=("#607384", "#8093a3")).pack(side="bottom", anchor="w", padx=24, pady=24)

        content = ctk.CTkFrame(self, corner_radius=0, fg_color=("#f5f7fa", "#18232e"))
        content.grid(row=0, column=1, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(3, weight=1)
        ctk.CTkLabel(content, text="Network overview", font=ctk.CTkFont(size=27, weight="bold"), anchor="w").grid(row=0, column=0, sticky="ew", padx=30, pady=(30, 2))
        ctk.CTkLabel(content, text="Discover and monitor devices connected to your local network", font=ctk.CTkFont(size=13), text_color=("#607384", "#9eafbd"), anchor="w").grid(row=1, column=0, sticky="ew", padx=30, pady=(0, 22))

        toolbar = ctk.CTkFrame(content, fg_color="transparent")
        toolbar.grid(row=2, column=0, sticky="new", padx=30)
        self.start_button = ctk.CTkButton(toolbar, text="Start scan", width=120, corner_radius=9, command=self.start_scan)
        self.start_button.pack(side="left")
        self.stop_button = ctk.CTkButton(toolbar, text="Stop", width=90, corner_radius=9, fg_color=("#dce3e9", "#2a3946"), text_color=("#334554", "#dbe5ec"), hover_color=("#cbd6df", "#354958"), command=self.stop_scan, state="disabled")
        self.stop_button.pack(side="left", padx=(8, 0))
        ctk.CTkButton(toolbar, text="Refresh", width=95, corner_radius=9, fg_color="transparent", border_width=1, border_color=("#b7c4ce", "#526776"), text_color=("#334554", "#dbe5ec"), command=self.start_scan).pack(side="left", padx=(8, 0))
        ctk.CTkButton(toolbar, text="Export CSV", width=105, corner_radius=9, fg_color="transparent", border_width=1, border_color=("#b7c4ce", "#526776"), text_color=("#334554", "#dbe5ec"), command=self.export_log).pack(side="left", padx=(8, 0))
        ctk.CTkLabel(toolbar, textvariable=self.subnet_var, text_color=("#607384", "#9eafbd")).pack(side="right", padx=4)

        table_frame = ctk.CTkFrame(content, corner_radius=12, fg_color=("#ffffff", "#202e3a"))
        table_frame.grid(row=3, column=0, sticky="nsew", padx=30, pady=(18, 24))
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(table_frame, columns=self.columns, show="headings", selectmode="browse")
        self.tree.bind("<<TreeviewSelect>>", self._on_device_selected)
        widths = (140, 165, 190, 210, 105, 100, 175)
        for column, heading, width in zip(self.columns, self.headings, widths):
            self.tree.heading(column, text=heading)
            self.tree.column(column, width=width, anchor="w")
        self.tree.tag_configure("online", foreground="#20b486")
        self.tree.tag_configure("offline", foreground="#87929b")
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.grid(row=0, column=0, sticky="nsew", padx=(12, 0), pady=12)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self._apply_table_theme()
        port_panel = ctk.CTkFrame(content, corner_radius=10, fg_color=("#e8f0f4", "#203541"))
        port_panel.grid(row=4, column=0, sticky="ew", padx=30, pady=(0, 12))
        ctk.CTkLabel(port_panel, text="PORTS", font=ctk.CTkFont(size=10, weight="bold"), text_color=("#607384", "#9eafbd")).pack(anchor="w", padx=16, pady=(10, 0))
        ctk.CTkLabel(port_panel, textvariable=self.port_status_var, anchor="w", justify="left", wraplength=850).pack(fill="x", padx=16, pady=(3, 10))
        footer = ctk.CTkFrame(content, height=36, corner_radius=0, fg_color="transparent")
        footer.grid(row=5, column=0, sticky="ew", padx=30, pady=(0, 14))
        ctk.CTkLabel(footer, textvariable=self.status_var, text_color=("#607384", "#9eafbd")).pack(side="left")
        ctk.CTkLabel(footer, textvariable=self.count_var, font=ctk.CTkFont(weight="bold"), text_color=("#334554", "#dbe5ec")).pack(side="right")

    def _nav_button(self, text: str, active: bool) -> ctk.CTkButton:
        return ctk.CTkButton(self.sidebar, text=text, anchor="w", height=38, corner_radius=8, fg_color=("#d7e5ef", "#263746") if active else "transparent", text_color=("#17212b", "#f5f7fa"), hover_color=("#d7e5ef", "#263746"), command=lambda: None)

    def _build_modern_ui(self) -> None:
        """Build the dashboard presentation without changing scan behavior."""
        ctk.set_appearance_mode("dark")
        self.configure(fg_color="#0b1220")
        self.grid_columnconfigure(0, weight=0, minsize=238)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=238, corner_radius=0, fg_color="#111a2b")
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        ctk.CTkLabel(
            self.sidebar,
            text="LAN\nWATCHTOWER",
            justify="left",
            font=ctk.CTkFont(size=23, weight="bold"),
            text_color="#f4f7fb",
        ).pack(anchor="w", padx=24, pady=(30, 4))
        ctk.CTkLabel(
            self.sidebar,
            text="NETWORK OPERATIONS",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color="#71819a",
        ).pack(anchor="w", padx=24, pady=(24, 10))
        for label, active in (
            ("▦  Dashboard", True),
            ("◉  Devices", False),
            ("⌁  Network Scanner", False),
            ("◌  Port Scanner", False),
            ("!  Alerts", False),
            ("⌖  Network Map", False),
            ("◷  History", False),
            ("⚙  Settings", False),
        ):
            button = self._dashboard_nav_button(label, active)
            button.pack(fill="x", padx=14, pady=2)
            self.nav_buttons[label] = button
        ctk.CTkLabel(
            self.sidebar,
            text="MONITORING STATUS",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color="#71819a",
        ).pack(anchor="w", padx=24, pady=(30, 8))
        ctk.CTkLabel(
            self.sidebar,
            textvariable=self.status_var,
            justify="left",
            wraplength=185,
            font=ctk.CTkFont(size=11),
            text_color="#9eabc0",
        ).pack(anchor="w", padx=24)
        ctk.CTkLabel(
            self.sidebar,
            text="Only scan networks you own or are authorized to monitor.",
            justify="left",
            wraplength=185,
            font=ctk.CTkFont(size=10),
            text_color="#596a83",
        ).pack(side="bottom", anchor="w", padx=24, pady=24)

        content = ctk.CTkFrame(self, corner_radius=0, fg_color="#0b1220")
        self.dashboard_content = content
        content.grid(row=0, column=1, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(3, weight=1)

        header = ctk.CTkFrame(content, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=30, pady=(26, 0))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            header,
            text="Network dashboard",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color="#f4f7fb",
            anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            header,
            textvariable=self.subnet_var,
            font=ctk.CTkFont(size=11),
            text_color="#8190a8",
            anchor="e",
        ).grid(row=0, column=1, sticky="e")
        ctk.CTkLabel(
            header,
            text="Live overview of discovered devices and network health",
            font=ctk.CTkFont(size=12),
            text_color="#8190a8",
            anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(3, 0))

        cards = ctk.CTkFrame(content, fg_color="transparent")
        cards.grid(row=1, column=0, sticky="ew", padx=30, pady=(22, 16))
        for index in range(6):
            cards.grid_columnconfigure(index, weight=1, uniform="summary")
        self.summary_vars: dict[str, tk.StringVar] = {}
        for index, (key, title, color) in enumerate(
            (
                ("total", "TOTAL DEVICES", "#5c9ded"),
                ("online", "ONLINE DEVICES", "#31c48d"),
                ("offline", "OFFLINE DEVICES", "#ef6262"),
                ("unknown", "UNKNOWN DEVICES", "#8b98aa"),
                ("alerts", "ACTIVE ALERTS", "#f0bd4f"),
                ("ports", "OPEN PORTS", "#b084f5"),
            )
        ):
            card = ctk.CTkFrame(cards, corner_radius=10, fg_color="#151f32", border_width=1, border_color="#202d44")
            card.grid(row=0, column=index, sticky="ew", padx=(0 if index == 0 else 5, 5 if index < 5 else 0))
            ctk.CTkLabel(card, text="●", text_color=color, font=ctk.CTkFont(size=14)).pack(anchor="w", padx=14, pady=(12, 0))
            variable = tk.StringVar(value="0")
            self.summary_vars[key] = variable
            ctk.CTkLabel(card, textvariable=variable, font=ctk.CTkFont(size=24, weight="bold"), text_color="#f4f7fb").pack(anchor="w", padx=14, pady=(1, 0))
            ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=9, weight="bold"), text_color="#8190a8").pack(anchor="w", padx=14, pady=(0, 12))

        toolbar = ctk.CTkFrame(content, fg_color="transparent")
        toolbar.grid(row=2, column=0, sticky="ew", padx=30, pady=(0, 12))
        toolbar.grid_columnconfigure(0, weight=1)
        self.search = ctk.CTkEntry(toolbar, textvariable=self.search_var, placeholder_text="Search hostname, IP, MAC, or vendor...  (Ctrl+F)", height=36, fg_color="#151f32", border_color="#2b3a55")
        self.search.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.search_var.trace_add("write", lambda *_args: self._refresh_table())
        self.status_filter = ctk.CTkComboBox(toolbar, values=["All statuses", "Online", "Offline", "Unknown"], variable=self.status_filter_var, width=125, height=36, command=lambda _value: self._refresh_table())
        self.status_filter.grid(row=0, column=1, padx=4)
        self.sort_control = ctk.CTkComboBox(toolbar, values=["IP address", "Hostname", "Status", "Latency"], variable=self.sort_var, width=125, height=36, command=lambda _value: self._refresh_table())
        self.sort_control.grid(row=0, column=2, padx=4)
        self.start_button = ctk.CTkButton(toolbar, text="Start monitoring", width=125, height=36, command=self.start_scan)
        self.start_button.grid(row=0, column=3, padx=(8, 4))
        self.stop_button = ctk.CTkButton(toolbar, text="Stop", width=80, height=36, fg_color="#263249", hover_color="#33425f", command=self.stop_scan, state="disabled")
        self.stop_button.grid(row=0, column=4, padx=4)
        ctk.CTkEntry(toolbar, textvariable=self.monitor_interval_var, width=58, height=36, placeholder_text="60").grid(row=0, column=5, padx=4)
        ctk.CTkLabel(toolbar, text="sec", text_color="#8190a8").grid(row=0, column=6, padx=(0, 4))
        ctk.CTkButton(toolbar, text="Export", width=80, height=36, fg_color="transparent", border_width=1, border_color="#33425f", command=self.export_log).grid(row=0, column=7, padx=(4, 0))

        workspace = ctk.CTkFrame(content, fg_color="transparent")
        workspace.grid(row=3, column=0, sticky="nsew", padx=30, pady=(0, 24))
        workspace.grid_columnconfigure(0, weight=1)
        workspace.grid_columnconfigure(1, weight=0, minsize=285)
        workspace.grid_rowconfigure(0, weight=1)
        table_frame = ctk.CTkFrame(workspace, corner_radius=10, fg_color="#151f32", border_width=1, border_color="#202d44")
        table_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)
        self.columns = ("hostname", "ip", "mac", "vendor", "status", "latency", "open_ports", "last_seen", "actions")
        self.headings = ("Hostname", "IP Address", "MAC Address", "Vendor", "Status", "Latency", "Open Ports", "Last Seen", "Actions")
        self.tree = ttk.Treeview(table_frame, columns=self.columns, show="headings", selectmode="browse", takefocus=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_device_selected)
        self.tree.bind("<Double-1>", self._on_device_selected)
        widths = (135, 115, 145, 145, 85, 80, 80, 145, 70)
        for column, heading, width in zip(self.columns, self.headings, widths):
            self.tree.heading(column, text=heading, command=lambda key=column: self._sort_by_column(key))
            self.tree.column(column, width=width, anchor="w", stretch=column in {"hostname", "vendor"})
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.grid(row=0, column=0, sticky="nsew", padx=(10, 0), pady=10)
        scrollbar.grid(row=0, column=1, sticky="ns", pady=10)
        self.empty_state = ctk.CTkLabel(table_frame, text="No devices discovered yet.", font=ctk.CTkFont(size=14, weight="bold"), text_color="#8190a8")
        self.empty_state.place(relx=0.5, rely=0.48, anchor="center")
        self._apply_table_theme()
        self.bind("<Control-f>", lambda _event: self._focus_search())
        self.bind("<Escape>", lambda _event: self._clear_search())

        self.detail_panel = ctk.CTkFrame(workspace, corner_radius=10, fg_color="#151f32", border_width=1, border_color="#202d44")
        self.detail_panel.grid(row=0, column=1, sticky="nsew")
        ctk.CTkLabel(self.detail_panel, text="DEVICE DETAILS", font=ctk.CTkFont(size=10, weight="bold"), text_color="#8190a8").pack(anchor="w", padx=18, pady=(18, 12))
        self.detail_title_var = tk.StringVar(value="Select a device")
        self.detail_status_var = tk.StringVar(value="No device selected")
        self.detail_info_var = tk.StringVar(value="Choose a row to inspect device details and run port checks.")
        self.activity_var = tk.StringVar(value="No recent activity.")
        self.alert_summary_var = tk.StringVar(value="No active alerts.")
        ctk.CTkLabel(self.detail_panel, textvariable=self.detail_title_var, font=ctk.CTkFont(size=19, weight="bold"), text_color="#f4f7fb", wraplength=245, justify="left").pack(anchor="w", padx=18)
        self.detail_status_label = ctk.CTkLabel(self.detail_panel, textvariable=self.detail_status_var, font=ctk.CTkFont(size=11, weight="bold"), text_color="#31c48d")
        self.detail_status_label.pack(anchor="w", padx=18, pady=(5, 16))
        ctk.CTkLabel(self.detail_panel, textvariable=self.detail_info_var, font=ctk.CTkFont(size=11), text_color="#a6b3c7", justify="left", wraplength=245).pack(anchor="w", padx=18)
        ctk.CTkButton(self.detail_panel, text="Check common ports", height=34, command=self._on_device_selected).pack(fill="x", padx=18, pady=(20, 8))
        ctk.CTkLabel(self.detail_panel, textvariable=self.port_status_var, font=ctk.CTkFont(size=10), text_color="#8190a8", justify="left", wraplength=245).pack(anchor="w", padx=18)
        ctk.CTkLabel(self.detail_panel, text="RECENT ACTIVITY", font=ctk.CTkFont(size=10, weight="bold"), text_color="#8190a8").pack(anchor="w", padx=18, pady=(24, 8))
        ctk.CTkLabel(self.detail_panel, textvariable=self.activity_var, font=ctk.CTkFont(size=10), text_color="#a6b3c7", justify="left", wraplength=245).pack(anchor="w", padx=18)
        ctk.CTkLabel(self.detail_panel, text="ALERTS", font=ctk.CTkFont(size=10, weight="bold"), text_color="#8190a8").pack(anchor="w", padx=18, pady=(24, 8))
        ctk.CTkLabel(self.detail_panel, textvariable=self.alert_summary_var, font=ctk.CTkFont(size=10), text_color="#f0bd4f", justify="left", wraplength=245).pack(anchor="w", padx=18)
        ctk.CTkButton(self.detail_panel, text="Acknowledge latest alert", height=30, command=self._acknowledge_latest_alert).pack(fill="x", padx=18, pady=(10, 0))

        self._update_summary_cards()
        self._build_topology_view()

    def _dashboard_nav_button(self, text: str, active: bool) -> ctk.CTkButton:
        target = self._navigation_target(text)
        return ctk.CTkButton(
            self.sidebar,
            text=text,
            anchor="w",
            height=38,
            corner_radius=7,
            fg_color="#243652" if active else "transparent",
            text_color="#f4f7fb" if active else "#9eabc0",
            hover_color="#1c2b43",
            command=lambda: self._navigate(target, text),
        )

    @staticmethod
    def _navigation_target(text: str) -> str:
        if "Network Map" in text:
            return "topology"
        if "History" in text:
            return "history"
        if "Settings" in text:
            return "settings"
        if "Devices" in text:
            return "devices"
        if "Network Scanner" in text:
            return "scanner"
        if "Port Scanner" in text:
            return "ports"
        if "Alerts" in text:
            return "alerts"
        return "dashboard"

    def _navigate(self, page: str, label: str) -> None:
        self._show_page(page)
        for name, button in self.nav_buttons.items():
            active = name == label
            button.configure(
                fg_color="#243652" if active else "transparent",
                text_color="#f4f7fb" if active else "#9eabc0",
            )
        if page == "devices":
            self.search_var.set("")
            self.status_filter_var.set("All statuses")
            self.status_var.set("Device inventory")
            self.tree.focus_set()
        elif page == "scanner":
            self.status_var.set("Network scanner ready")
            self.start_scan()
        elif page == "ports":
            self.status_var.set("Port scanner ready; select an online device to scan")
            self.tree.focus_set()
        elif page == "alerts":
            self.status_var.set(f"{len(self.alerts)} active alert{'s' if len(self.alerts) != 1 else ''}")
            self._update_summary_cards()

    def _focus_search(self) -> None:
        if hasattr(self, "search"):
            self.search.focus_set()

    def _clear_search(self) -> None:
        self.search_var.set("")

    def _sort_by_column(self, column: str) -> None:
        mapping = {"hostname": "Hostname", "ip": "IP address", "status": "Status", "latency": "Latency"}
        if column in mapping:
            self.sort_var.set(mapping[column])
            self._refresh_table()

    def _show_page(self, page: str) -> None:
        if page == "topology":
            self.dashboard_content.grid_remove()
            self.history_view.grid_remove()
            self.settings_view.grid_remove()
            self.topology_view.grid(row=0, column=1, sticky="nsew")
            self._render_topology()
        elif page == "history":
            self.dashboard_content.grid_remove()
            self.topology_view.grid_remove()
            self.settings_view.grid_remove()
            self.history_view.grid(row=0, column=1, sticky="nsew")
            self._render_history()
        elif page == "settings":
            self.dashboard_content.grid_remove()
            self.topology_view.grid_remove()
            self.history_view.grid_remove()
            self.settings_view.grid(row=0, column=1, sticky="nsew")
        else:
            self.topology_view.grid_remove()
            self.history_view.grid_remove()
            self.settings_view.grid_remove()
            self.dashboard_content.grid(row=0, column=1, sticky="nsew")

    def _build_topology_view(self) -> None:
        self.topology_view = ctk.CTkFrame(self, corner_radius=0, fg_color="#0b1220")
        self.topology_view.grid_columnconfigure(0, weight=1)
        self.topology_view.grid_rowconfigure(1, weight=1)
        header = ctk.CTkFrame(self.topology_view, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=30, pady=(26, 14))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            header, text="Network map", font=ctk.CTkFont(size=28, weight="bold"),
            text_color="#f4f7fb", anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            header,
            text="Discovered network topology / inferred relationships",
            font=ctk.CTkFont(size=12), text_color="#f0bd4f", anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))
        ctk.CTkLabel(
            header,
            text="Connections shown here are not physically verified.",
            font=ctk.CTkFont(size=11), text_color="#8190a8", anchor="w",
        ).grid(row=2, column=0, sticky="w", pady=(2, 0))
        controls = ctk.CTkFrame(header, fg_color="transparent")
        controls.grid(row=0, column=1, rowspan=3, sticky="e")
        ctk.CTkButton(controls, text="Zoom +", width=75, command=lambda: self._zoom_topology(1.2)).pack(side="left", padx=3)
        ctk.CTkButton(controls, text="Zoom -", width=75, command=lambda: self._zoom_topology(0.8)).pack(side="left", padx=3)
        ctk.CTkButton(controls, text="Reset", width=75, command=self._render_topology).pack(side="left", padx=3)
        body = ctk.CTkFrame(self.topology_view, fg_color="#151f32", corner_radius=10, border_width=1, border_color="#202d44")
        body.grid(row=1, column=0, sticky="nsew", padx=30, pady=(0, 24))
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(0, weight=1)
        self.topology_canvas = tk.Canvas(body, background="#151f32", highlightthickness=0)
        self.topology_canvas.grid(row=0, column=0, sticky="nsew")
        self.topology_canvas.bind("<ButtonPress-1>", self._topology_pan_start)
        self.topology_canvas.bind("<B1-Motion>", self._topology_pan_move)
        self.topology_canvas.bind("<MouseWheel>", lambda event: self._zoom_topology(1.1 if event.delta > 0 else 0.9))
        self.topology_canvas.bind("<Button-4>", lambda _event: self._zoom_topology(1.1))
        self.topology_canvas.bind("<Button-5>", lambda _event: self._zoom_topology(0.9))
        self.topology_scale = 1.0
        self.topology_offset = [0, 0]
        self.topology_nodes: dict[str, tuple[float, float]] = {}
        self._build_history_view()
        self._build_settings_view()

    def _build_settings_view(self) -> None:
        self.settings_view = ctk.CTkFrame(self, corner_radius=0, fg_color="#0b1220")
        self.settings_view.grid_columnconfigure(0, weight=1)
        self.settings_view.grid_rowconfigure(1, weight=1)
        header = ctk.CTkFrame(self.settings_view, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=30, pady=(26, 14))
        ctk.CTkLabel(header, text="Settings", font=ctk.CTkFont(size=28, weight="bold"), text_color="#f4f7fb").pack(anchor="w")
        ctk.CTkLabel(header, text="Runtime configuration applies without restarting the application", text_color="#8190a8").pack(anchor="w", pady=(4, 0))
        body = ctk.CTkScrollableFrame(self.settings_view, fg_color="#151f32")
        body.grid(row=1, column=0, sticky="nsew", padx=30, pady=(0, 24))
        self.settings_vars: dict[str, tk.StringVar] = {
            "network_interface": tk.StringVar(value=self.runtime_settings.network_interface),
            "discovery_interval": tk.StringVar(value=str(self.runtime_settings.discovery_interval)),
            "health_check_interval": tk.StringVar(value=str(self.runtime_settings.health_check_interval)),
            "port_scan_interval": tk.StringVar(value=str(self.runtime_settings.port_scan_interval)),
            "port_list": tk.StringVar(value=""),
            "timeout": tk.StringVar(value=str(self.runtime_settings.timeout)),
            "concurrency": tk.StringVar(value=str(self.runtime_settings.concurrency)),
            "offline_threshold": tk.StringVar(value=str(self.runtime_settings.offline_threshold)),
            "latency_threshold": tk.StringVar(value=str(self.runtime_settings.latency_threshold)),
        }
        fields = (
            ("network_interface", "Network interface", "auto"),
            ("discovery_interval", "Discovery interval (seconds)", "60"),
            ("health_check_interval", "Health check interval (seconds)", "30"),
            ("port_scan_interval", "Port scan interval (seconds)", "120"),
            ("port_list", "Port list (comma-separated, blank = scanner defaults)", "22,80,443"),
            ("timeout", "Probe timeout (seconds)", "1"),
            ("concurrency", "Scan concurrency", "16"),
            ("offline_threshold", "Consecutive failures before offline", "3"),
            ("latency_threshold", "Warning latency threshold (ms)", "250"),
        )
        for row, (key, label, placeholder) in enumerate(fields):
            ctk.CTkLabel(body, text=label, text_color="#dbe5ec", anchor="w").grid(row=row, column=0, sticky="w", padx=18, pady=(12, 3))
            ctk.CTkEntry(body, textvariable=self.settings_vars[key], placeholder_text=placeholder, width=320).grid(row=row, column=1, sticky="w", padx=18, pady=(12, 3))
        row = len(fields)
        ctk.CTkLabel(body, text="Notifications use environment variables; secrets are not shown here.", text_color="#f0bd4f", wraplength=500, justify="left").grid(row=row, column=0, columnspan=2, sticky="w", padx=18, pady=(18, 4))
        ctk.CTkLabel(body, text="Email/webhook enabled state and alert routing are read from environment configuration.", text_color="#8190a8", wraplength=500, justify="left").grid(row=row + 1, column=0, columnspan=2, sticky="w", padx=18, pady=4)
        ctk.CTkLabel(body, text=f"Database: {self.database.database_path} (managed locally; path is not changed here)", text_color="#8190a8", wraplength=500, justify="left").grid(row=row + 2, column=0, columnspan=2, sticky="w", padx=18, pady=4)
        ctk.CTkLabel(body, text="Alert settings: supported severities INFO, LOW, MEDIUM, HIGH, CRITICAL; acknowledgement and deduplication remain enabled.", text_color="#8190a8", wraplength=500, justify="left").grid(row=row + 3, column=0, columnspan=2, sticky="w", padx=18, pady=4)
        buttons = ctk.CTkFrame(body, fg_color="transparent")
        buttons.grid(row=row + 4, column=0, columnspan=2, sticky="w", padx=18, pady=20)
        ctk.CTkButton(buttons, text="Save", width=100, command=self._save_settings).pack(side="left", padx=(0, 8))
        ctk.CTkButton(buttons, text="Reset", width=100, fg_color="#263249", command=self._reset_settings).pack(side="left", padx=8)
        ctk.CTkButton(buttons, text="Test Configuration", width=145, fg_color="transparent", border_width=1, border_color="#33425f", command=self._test_settings).pack(side="left", padx=8)

    def _read_settings(self) -> RuntimeSettings:
        values = self.settings_vars
        ports = tuple(sorted({int(item.strip()) for item in values["port_list"].get().split(",") if item.strip()}))
        return RuntimeSettings(
            network_interface=values["network_interface"].get().strip() or "auto",
            discovery_interval=float(values["discovery_interval"].get()),
            health_check_interval=float(values["health_check_interval"].get()),
            port_scan_interval=float(values["port_scan_interval"].get()),
            port_list=ports,
            timeout=float(values["timeout"].get()),
            concurrency=int(values["concurrency"].get()),
            offline_threshold=int(values["offline_threshold"].get()),
            latency_threshold=float(values["latency_threshold"].get()),
        )

    def _save_settings(self) -> None:
        try:
            settings = self._read_settings()
            self.runtime_settings = settings
            self.monitor.interval_seconds = settings.discovery_interval
            self.monitor.subnet_detector = lambda: detect_local_subnet(settings.network_interface)
            self.monitor.health_service.monitor.settings = HealthSettings(
                health_check_interval=settings.health_check_interval,
                timeout=settings.timeout,
                failure_threshold=settings.offline_threshold,
                warning_latency_threshold=settings.latency_threshold,
            )
            self.port_monitor.settings = PortMonitoringSettings(
                interval_seconds=settings.port_scan_interval,
                timeout=settings.timeout,
                max_workers=settings.concurrency,
                ports=settings.port_list,
            )
            self.scanner.host_timeout = settings.timeout
            self.scanner.max_workers = settings.concurrency
            self.status_var.set("Settings saved and applied")
        except (TypeError, ValueError) as exc:
            messagebox.showerror("Invalid settings", str(exc))

    def _reset_settings(self) -> None:
        defaults = RuntimeSettings()
        for key, value in (
            ("network_interface", defaults.network_interface),
            ("discovery_interval", defaults.discovery_interval),
            ("health_check_interval", defaults.health_check_interval),
            ("port_scan_interval", defaults.port_scan_interval),
            ("port_list", ""),
            ("timeout", defaults.timeout),
            ("concurrency", defaults.concurrency),
            ("offline_threshold", defaults.offline_threshold),
            ("latency_threshold", defaults.latency_threshold),
        ):
            self.settings_vars[key].set(str(value))
        self.status_var.set("Settings reset to defaults; press Save to apply")

    def _test_settings(self) -> None:
        try:
            settings = self._read_settings()
            subnet = detect_local_subnet()
            messagebox.showinfo("Configuration valid", f"Settings are valid.\nDetected subnet: {subnet}\nInterface: {settings.network_interface}")
        except (OSError, TypeError, ValueError) as exc:
            messagebox.showerror("Configuration test failed", str(exc))

    def _build_history_view(self) -> None:
        self.history_view = ctk.CTkFrame(self, corner_radius=0, fg_color="#0b1220")
        self.history_view.grid_columnconfigure(0, weight=1)
        self.history_view.grid_rowconfigure(1, weight=1)
        header = ctk.CTkFrame(self.history_view, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=30, pady=(26, 14))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text="History & analytics", font=ctk.CTkFont(size=28, weight="bold"), text_color="#f4f7fb", anchor="w").grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(header, text="Aggregated historical network health and activity", font=ctk.CTkFont(size=12), text_color="#8190a8", anchor="w").grid(row=1, column=0, sticky="w", pady=(4, 0))
        self.history_range_var = tk.StringVar(value="Last 24 hours")
        self.history_ranges = {
            "Last 1 hour": "1h", "Last 6 hours": "6h", "Last 24 hours": "24h",
            "Last 7 days": "7d", "Last 30 days": "30d",
        }
        ctk.CTkComboBox(header, values=list(self.history_ranges), variable=self.history_range_var, width=150, command=lambda _value: self._render_history()).grid(row=0, column=1, rowspan=2, sticky="e")
        self.history_body = ctk.CTkFrame(self.history_view, fg_color="transparent")
        self.history_body.grid(row=1, column=0, sticky="nsew", padx=30, pady=(0, 24))
        self.history_body.grid_columnconfigure(0, weight=1, uniform="charts")
        self.history_body.grid_columnconfigure(1, weight=1, uniform="charts")
        for row in range(3):
            self.history_body.grid_rowconfigure(row, weight=1)

    def _render_history(self) -> None:
        if not hasattr(self, "history_body"):
            return
        for child in self.history_body.winfo_children():
            child.destroy()
        try:
            analytics = self.analytics_service.get_history(self.history_ranges[self.history_range_var.get()])
        except (OSError, sqlite3.Error, ValueError) as exc:
            ctk.CTkLabel(self.history_body, text=f"History unavailable: {exc}", text_color="#ef6262").grid(row=0, column=0, padx=20, pady=20)
            return
        charts = (
            ("Devices over time", analytics["devices"], "devices"),
            ("Online vs offline", analytics["availability"], "availability"),
            ("Average latency (ms)", analytics["availability"], "average_latency"),
            ("Alerts over time", analytics["alerts"], "count"),
            ("Port changes", analytics["ports"], "count"),
            ("Device uptime", analytics["uptime"], "uptime_ratio"),
        )
        for index, (title, rows, field) in enumerate(charts):
            panel = ctk.CTkFrame(self.history_body, fg_color="#151f32", corner_radius=10, border_width=1, border_color="#202d44")
            panel.grid(row=index // 2, column=index % 2, sticky="nsew", padx=(0 if index % 2 == 0 else 8, 8 if index % 2 == 0 else 0), pady=(0 if index < 2 else 8, 8))
            ctk.CTkLabel(panel, text=title.upper(), font=ctk.CTkFont(size=10, weight="bold"), text_color="#8190a8").pack(anchor="w", padx=14, pady=(12, 2))
            canvas = tk.Canvas(panel, height=125, background="#151f32", highlightthickness=0)
            canvas.pack(fill="both", expand=True, padx=10, pady=(0, 10))
            self._draw_history_chart(canvas, rows, field)

    def _draw_history_chart(self, canvas: tk.Canvas, rows: list[dict[str, object]], field: str) -> None:
        if not rows:
            canvas.create_text(180, 55, text="No data in selected range", fill="#8190a8")
            return
        if field == "availability":
            values = [
                float(row.get("online") or 0) + float(row.get("offline") or 0)
                for row in rows
            ]
        else:
            values = [float(row.get(field) or 0) for row in rows]
        maximum = max(values) or 1.0
        width = max(canvas.winfo_width(), 360)
        bar_width = max(3.0, (width - 20) / len(values) - 2)
        for index, value in enumerate(values):
            x1 = 10 + index * (bar_width + 2)
            x2 = x1 + bar_width
            y2 = 110
            y1 = y2 - (value / maximum) * 85
            canvas.create_rectangle(x1, y1, x2, y2, fill="#5c9ded", outline="")
            if field == "availability":
                offline = float(rows[index].get("offline") or 0)
                online_height = (float(rows[index].get("online") or 0) / maximum) * 85
                offline_height = (offline / maximum) * 85
                canvas.create_rectangle(x1, y2 - offline_height, x2, y2, fill="#ef6262", outline="")
                canvas.create_rectangle(x1, y2 - offline_height - online_height, x2, y2 - offline_height, fill="#31c48d", outline="")

    def _render_topology(self) -> None:
        if not hasattr(self, "topology_canvas"):
            return
        canvas = self.topology_canvas
        canvas.delete("all")
        width = max(canvas.winfo_width(), 700)
        height = max(canvas.winfo_height(), 450)
        cx, cy = width / 2 + self.topology_offset[0], height / 2 + self.topology_offset[1]
        devices = sorted(self.devices.values(), key=lambda device: ipaddress.ip_address(device.ip))
        if not devices:
            canvas.create_text(cx, cy, text="No devices discovered yet.", fill="#8190a8", font=("Helvetica", 15))
            return
        hub_x, hub_y = cx, cy - 120 * self.topology_scale
        radius = 42 * self.topology_scale
        canvas.create_oval(hub_x - radius, hub_y - radius, hub_x + radius, hub_y + radius, fill="#243652", outline="#f0bd4f", width=2)
        canvas.create_text(hub_x, hub_y - 8 * self.topology_scale, text="Discovered", fill="#f4f7fb", font=("Helvetica", 10, "bold"))
        canvas.create_text(hub_x, hub_y + 9 * self.topology_scale, text="LAN (inferred)", fill="#f0bd4f", font=("Helvetica", 9))
        self.topology_nodes.clear()
        columns = max(1, min(4, len(devices)))
        spacing = min(210 * self.topology_scale, max(130, width / columns))
        start_x = cx - spacing * (columns - 1) / 2
        for index, device in enumerate(devices):
            row, column = divmod(index, columns)
            x = start_x + column * spacing
            y = cy + row * 150 * self.topology_scale
            canvas.create_line(hub_x, hub_y + radius, x, y - 42 * self.topology_scale, fill="#52647f", dash=(5, 4))
            color = {"Online": "#31c48d", "Offline": "#ef6262", "Warning": "#f0bd4f"}.get(self._device_status(device), "#8b98aa")
            node_tag = "node:" + device.ip
            canvas.create_oval(x - 42 * self.topology_scale, y - 42 * self.topology_scale, x + 42 * self.topology_scale, y + 42 * self.topology_scale, fill="#202e3a", outline=color, width=3, tags=(node_tag,))
            label = device.hostname if device.hostname != "Unknown" else device.ip
            canvas.create_text(x, y - 10 * self.topology_scale, text=label[:22], fill="#f4f7fb", font=("Helvetica", 9, "bold"), tags=(node_tag,))
            canvas.create_text(x, y + 8 * self.topology_scale, text=f"{device.ip}\n{self._device_status(device)}", fill=color, font=("Helvetica", 8), tags=(node_tag,))
            self.topology_nodes[device.ip] = (x, y)
            canvas.tag_bind("node:" + device.ip, "<Button-1>", lambda _event, ip=device.ip: self._select_topology_device(ip))
        canvas.create_text(15, 15, anchor="nw", text=f"{len(devices)} discovered device(s)", fill="#8190a8", font=("Helvetica", 10))

    def _zoom_topology(self, factor: float) -> None:
        self.topology_scale = max(0.5, min(2.5, self.topology_scale * factor))
        self._render_topology()

    def _topology_pan_start(self, event: object) -> None:
        self._topology_pan_origin = (event.x, event.y)  # type: ignore[attr-defined]

    def _topology_pan_move(self, event: object) -> None:
        origin = getattr(self, "_topology_pan_origin", (event.x, event.y))
        self.topology_offset[0] += event.x - origin[0]  # type: ignore[attr-defined]
        self.topology_offset[1] += event.y - origin[1]  # type: ignore[attr-defined]
        self._topology_pan_origin = (event.x, event.y)  # type: ignore[attr-defined]
        self._render_topology()

    def _select_topology_device(self, ip: str) -> None:
        device = self.devices.get(ip)
        self._show_device_details(device)
        self.status_var.set(f"Selected topology node: {ip}")

    def _device_status(self, device: Device) -> str:
        status = device.status.upper()
        if status == "ONLINE":
            return "Online"
        if status == "OFFLINE":
            return "Offline"
        if status == "WARNING":
            return "Warning"
        return "Unknown"

    def _update_summary_cards(self) -> None:
        devices = list(self.devices.values())
        try:
            stats = self.dashboard_service.get_stats()
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.status_var.set(f"Dashboard data unavailable: {exc}")
            online = sum(self._device_status(device) == "Online" for device in devices)
            offline = sum(self._device_status(device) == "Offline" for device in devices)
            unknown = sum(self._device_status(device) == "Unknown" for device in devices)
            open_ports = sum(self.open_port_counts.values())
            active_alerts = 0
        else:
            online = stats.online_devices
            offline = stats.offline_devices
            unknown = stats.unknown_devices
            open_ports = stats.open_ports
            active_alerts = stats.active_alerts
            self.alerts = stats.active_alerts_list
            if self.alerts:
                self.alert_summary_var.set(
                    "\n".join(
                        f"{alert['severity']}: {alert['message']}" for alert in self.alerts[:3]
                    )
                )
            else:
                self.alert_summary_var.set("No active alerts.")
            activity_lines = []
            if stats.recently_discovered:
                activity_lines.append(f"Discovered: {stats.recently_discovered[0].get('hostname') or stats.recently_discovered[0]['ip']}")
            if stats.recently_offline:
                activity_lines.append(f"Offline: {stats.recently_offline[0].get('hostname') or stats.recently_offline[0]['ip']}")
            if stats.recent_scans:
                activity_lines.append(f"Last scan: {stats.recent_scans[0]['timestamp']}")
            self.activity_var.set("\n".join(activity_lines) if activity_lines else "No recent activity.")
        if hasattr(self, "summary_vars"):
            self.summary_vars["total"].set(str(len(devices)))
            self.summary_vars["online"].set(str(online))
            self.summary_vars["offline"].set(str(offline))
            self.summary_vars["unknown"].set(str(unknown))
            self.summary_vars["alerts"].set(str(active_alerts))
            self.summary_vars["ports"].set(str(open_ports))
        self.count_var.set(f"{online} online device{'s' if online != 1 else ''}")

    def _load_persisted_dashboard_state(self) -> None:
        """Load the last durable snapshot so the dashboard is useful on launch."""
        try:
            for row in self.dashboard_service.database.fetch_devices():
                self.devices[row["ip"]] = Device(
                    ip=row["ip"],
                    mac=row.get("mac", "Unknown"),
                    hostname=row.get("hostname", "Unknown"),
                    vendor=row.get("vendor", "Unknown"),
                    status=row.get("status", "Unknown"),
                    last_seen=row.get("last_seen", "Never"),
                )
            self.open_port_counts = self.dashboard_service.database.fetch_open_port_counts()
            self.port_events = self.dashboard_service.database.fetch_port_events(20)
            self.alerts = self.alert_service.active(20)
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.status_var.set(f"Could not load saved dashboard data: {exc}")
        self._refresh_table()

    def _filtered_devices(self) -> list[Device]:
        query = self.search_var.get().strip().lower()
        status = self.status_filter_var.get()
        devices = [
            device
            for device in self.devices.values()
            if (status == "All statuses" or self._device_status(device) == status)
            and (
                not query
                or query in device.ip.lower()
                or query in device.mac.lower()
                or query in device.vendor.lower()
                or query in device.hostname.lower()
            )
        ]
        sort_key = self.sort_var.get()
        if sort_key == "Hostname":
            return sorted(devices, key=lambda device: device.hostname.lower())
        if sort_key == "Status":
            return sorted(devices, key=lambda device: self._device_status(device))
        if sort_key == "Latency":
            return sorted(devices, key=lambda device: device.latency_ms if device.latency_ms is not None else float("inf"))
        return sorted(devices, key=lambda device: ipaddress.ip_address(device.ip))

    def _refresh_table(self) -> None:
        if not hasattr(self, "tree"):
            return
        for item in self.tree.get_children():
            self.tree.delete(item)
        devices = self._filtered_devices()
        for device in devices:
            open_port_count = len(self.open_ports.get(device.ip, []))
            if device.ip not in self.open_ports:
                open_port_count = self.open_port_counts.get(device.ip, 0)
            values = (
                device.hostname,
                device.ip,
                device.mac,
                device.vendor,
                self._device_status(device),
                f"{device.latency_ms:.1f} ms" if device.latency_ms is not None else "-",
                str(open_port_count) if open_port_count else "-",
                device.last_seen,
                "Inspect",
            )
            self.tree.insert("", "end", iid=device.ip, values=values, tags=(self._device_status(device).lower(),))
        if devices:
            self.empty_state.place_forget()
        else:
            message = "No devices discovered yet." if not self.devices else "No devices match the current filters."
            self.empty_state.configure(text=message)
            self.empty_state.place(relx=0.5, rely=0.48, anchor="center")
        self._update_summary_cards()

    def _show_device_details(self, device: Device | None) -> None:
        if device is None:
            self.detail_title_var.set("Select a device")
            self.detail_status_var.set("No device selected")
            self.detail_info_var.set("Choose a row to inspect device details and run port checks.")
            return
        self.detail_title_var.set(device.hostname if device.hostname != "Unknown" else device.ip)
        status = self._device_status(device)
        self.detail_status_var.set(status)
        self.detail_status_label.configure(
            text_color={"Online": "#31c48d", "Offline": "#ef6262", "Warning": "#f0bd4f"}.get(status, "#8b98aa")
        )
        latency = f"{device.latency_ms:.1f} ms" if device.latency_ms is not None else "unavailable"
        try:
            port_rows = self.database.fetch_port_summary(device.ip)
            port_events = [
                event for event in self.database.fetch_port_events(20)
                if event["ip"] == device.ip
            ][:3]
            device_events = self.database.fetch_device_events(device.ip, 20)
            health_samples = self.database.fetch_health_history(device.ip, 20)
        except (OSError, sqlite3.Error, ValueError):
            port_rows = []
            port_events = []
            device_events = []
            health_samples = []
        ports = ", ".join(f"{row['port']} ({row['service']})" for row in port_rows) or "None discovered"
        changes = ", ".join(str(event["event_type"]) for event in port_events) or "None"
        risk = self.anomaly_service.assess(
            device,
            open_ports=port_rows,
            port_events=port_events,
            device_events=device_events,
            health_samples=health_samples,
        )
        reasons = "\n".join(f"- {reason}" for reason in risk.reasons) or "- No rule-based risk signals"
        self.detail_info_var.set(
            f"IP address: {device.ip}\n"
            f"MAC address: {device.mac}\n"
            f"Vendor: {device.vendor}\n"
            f"Latency: {latency}\n"
            f"Last seen: {device.last_seen}\n"
            f"Open ports: {ports}\n"
            f"Port changes: {changes}\n"
            f"\nPotentially suspicious activity: {risk.score} {risk.level}\n"
            f"Reasons:\n{reasons}\n"
            "This is rule-based activity scoring, not a claim that the device is malicious."
        )

    def toggle_appearance(self) -> None:
        mode = "dark" if self.mode_switch.get() == "dark" else "light"
        ctk.set_appearance_mode(mode)
        self._apply_table_theme()

    def _apply_table_theme(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        dark = ctk.get_appearance_mode().lower() == "dark"
        background = "#202e3a" if dark else "#ffffff"
        alternate = "#263746" if dark else "#f1f5f8"
        foreground = "#e7eef3" if dark else "#253746"
        heading = "#2d404f" if dark else "#e1e9ef"
        style.configure("Treeview", rowheight=34, font=("Helvetica", 10), background=background, fieldbackground=background, foreground=foreground, borderwidth=0)
        style.map("Treeview", background=[("selected", "#286b84")], foreground=[("selected", "#ffffff")])
        style.configure("Treeview.Heading", font=("Helvetica", 10, "bold"), background=heading, foreground=foreground, relief="flat", padding=(8, 9))
        self.tree.tag_configure("online", foreground="#25c795")
        self.tree.tag_configure("offline", foreground="#ef6262")
        self.tree.tag_configure("warning", foreground="#f0bd4f")
        self.tree.tag_configure("unknown", foreground="#8b98aa")

    def start_scan(self) -> None:
        if self.monitor.running:
            return
        try:
            subnet = detect_local_subnet()
        except OSError as exc:
            messagebox.showerror("Network detection failed", f"Could not determine the local subnet:\n{exc}")
            return
        if subnet.num_addresses > 1024:
            messagebox.showwarning("Large network", f"The detected subnet {subnet} contains {subnet.num_addresses - 2} hosts and may take a while.")
        self.subnet_var.set(f"Scanning {subnet}")
        mode = "ARP + ICMP + TCP" if self.scanner.privileged and srp is not None else "ARP cache + ICMP + TCP fallback"
        try:
            interval = float(self.monitor_interval_var.get())
            if interval <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid interval", "Monitoring interval must be a positive number of seconds.")
            return
        self.monitor.interval_seconds = interval
        self.status_var.set(f"Monitoring network ({mode}) every {interval:g}s...")
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.start_button.configure(text="Monitoring…")
        self.monitor.start()
        self.port_monitor.start()
        self.event_hub.publish("SCAN_STARTED", {"subnet": str(subnet)})

    def stop_scan(self) -> None:
        self.monitor.stop()
        self.port_monitor.stop()
        self.status_var.set("Monitoring stopped")
        self.stop_button.configure(state="disabled")
        self.start_button.configure(state="normal", text="Start monitoring")

    def _process_events(self) -> None:
        try:
            while True:
                event, payload = self.events.get_nowait()
                if event == "progress":
                    done, total = payload  # type: ignore[misc]
                    self.status_var.set(f"Scanning hosts: {done}/{total}")
                elif event == "complete":
                    self._apply_scan(payload)  # type: ignore[arg-type]
                    self.event_hub.publish("SCAN_COMPLETED", {"device_count": len(payload)})
                elif event == "error":
                    self.status_var.set(f"Scan error: {payload}")
                    messagebox.showerror("Scan failed", str(payload))
                    if not self.monitor.running:
                        self.start_button.configure(state="normal", text="Start monitoring")
                        self.stop_button.configure(state="disabled")
                elif event == "health_update":
                    self._render_devices()
                    device = payload
                    self.event_hub.publish("DEVICE_UPDATED", device)
                elif event == "health_error":
                    self.status_var.set(f"Health check warning: {payload}")
                elif event == "port_events":
                    self.port_events = list(payload) + self.port_events
                    self.port_events = self.port_events[:20]
                    self._refresh_table()
                    self.status_var.set(f"Port changes detected: {len(payload)}")
                    for port_event in payload:
                        self.event_hub.publish("PORT_CHANGED", port_event)
                elif event == "alert_create":
                    alert_type, severity, message, ip = payload
                    self._create_alert(alert_type, severity, message, ip)
                elif event == "port_alert":
                    event_type = payload["event_type"]
                    alert_type = "NEW_OPEN_PORT" if event_type == "NEW_OPEN_PORT" else "PORT_CLOSED"
                    self._create_alert(
                        alert_type,
                        "MEDIUM",
                        f"{payload['ip']} port {payload['port']} changed: {event_type}",
                        payload["ip"],
                    )
                elif event == "discovery_transitions":
                    transitions = payload
                    for device in transitions.new:
                        self.event_hub.publish("DEVICE_DISCOVERED", device)
                        self._create_alert("NEW_DEVICE", "INFO", f"New device discovered: {device.ip}", device.ip)
                    for device in transitions.disappeared:
                        self.event_hub.publish("DEVICE_OFFLINE", device)
                        self._create_alert("DEVICE_OFFLINE", "HIGH", f"{device.ip} disappeared", device.ip)
                    for device in transitions.returned:
                        self.event_hub.publish("DEVICE_ONLINE", device)
                        self._create_alert("DEVICE_ONLINE", "INFO", f"{device.ip} returned online", device.ip)
                elif event == "stopped":
                    self.status_var.set("Scan stopped")
                    if not self.monitor.running:
                        self.start_button.configure(state="normal", text="Start monitoring")
                        self.stop_button.configure(state="disabled")
                elif event == "ports_complete":
                    ip, open_ports = payload  # type: ignore[misc]
                    self.open_ports[ip] = open_ports
                    self.open_port_counts[ip] = len(open_ports)
                    try:
                        self.database.record_port_observations(ip, open_ports)
                    except (OSError, sqlite3.Error, ValueError) as exc:
                        self.status_var.set(f"Port results not saved: {exc}")
                    self._refresh_table()
                    if self.tree.selection() == (ip,):
                        if open_ports:
                            self.port_status_var.set(f"{ip}: " + "  |  ".join(port.as_text() for port in open_ports))
                        else:
                            self.port_status_var.set(f"{ip}: No open common TCP ports found")
                elif event == "ports_error":
                    ip, error = payload  # type: ignore[misc]
                    if self.tree.selection() == (ip,):
                        self.port_status_var.set(f"{ip}: Port scan failed: {error}")
        except queue.Empty:
            pass
        self.after(100, self._process_events)

    def _on_device_selected(self, _event: object | None = None) -> None:
        selection = self.tree.selection()
        if not selection:
            self._show_device_details(None)
            return
        ip = selection[0]
        device = self.devices.get(ip)
        self._show_device_details(device)
        if device is None or device.status != "Online":
            self.port_status_var.set(f"{ip}: Port checks are available for online devices only")
            return
        if self.port_scan_thread is not None and self.port_scan_thread.is_alive():
            self.port_status_var.set(f"{ip}: Another port scan is still running")
            return
        self.port_status_var.set(f"{ip}: Checking common TCP ports...")

        def run_port_scan() -> None:
            try:
                results = self.port_monitor.scan_device(ip)
                self.open_ports[ip] = results
                self.events.put(("ports_complete", (ip, results)))
            except (OSError, ValueError) as exc:
                self.events.put(("ports_error", (ip, str(exc))))

        self.port_scan_thread = threading.Thread(target=run_port_scan, daemon=True, name="device-port-scan")
        self.port_scan_thread.start()

    def _create_alert(self, alert_type: str, severity: str, message: str, ip: str | None) -> None:
        try:
            alert = self.alert_service.create(alert_type, severity, message, ip)
            if alert is not None:
                self.alerts.insert(0, alert)
                self.alerts = self.alerts[:20]
                self.status_var.set(f"Alert: {message}")
                self._update_summary_cards()
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.status_var.set(f"Alert error: {exc}")

    def _acknowledge_latest_alert(self) -> None:
        if not self.alerts:
            self.status_var.set("No active alerts to acknowledge")
            return
        try:
            self.alert_service.acknowledge(int(self.alerts[0]["id"]))
            self.alerts = self.alert_service.active(20)
            self._update_summary_cards()
            self.status_var.set("Latest alert acknowledged")
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.status_var.set(f"Alert acknowledgement failed: {exc}")

    def _apply_scan(self, found: list[Device]) -> None:
        now_online = {device.ip for device in found}
        current_macs = {device.mac for device in found if device.mac != "Unknown"}
        new_macs = current_macs - self.previous_macs if self.has_completed_scan else set()
        for device in found:
            old = self.devices.get(device.ip)
            if old and device.mac == "Unknown":
                device.mac = old.mac
            if old and device.vendor == "Unknown":
                device.vendor = old.vendor
            self.devices[device.ip] = device
        for ip, device in self.devices.items():
            if ip not in now_online:
                device.status = "Offline"
                device.latency_ms = None
        joined = now_online - self.previous_online
        left = self.previous_online - now_online
        self.previous_online = now_online
        self.previous_macs = current_macs
        self.has_completed_scan = True
        notified_macs: set[str] = set()
        for device in found:
            if device.mac in new_macs and device.mac not in notified_macs:
                notify_new_device(device.ip, device.hostname)
                notified_macs.add(device.mac)
        self._render_devices()
        change = []
        if joined:
            change.append(f"{len(joined)} joined")
        if left:
            change.append(f"{len(left)} disconnected")
        suffix = f" | {', '.join(change)}" if change else ""
        self.status_var.set(f"Scan complete at {datetime.now().strftime('%H:%M:%S')}{suffix}")
        self.start_button.configure(state="normal", text="Start monitoring")
        self.stop_button.configure(state="disabled")

    def _render_devices(self) -> None:
        self._refresh_table()
        if hasattr(self, "topology_canvas"):
            self._render_topology()
        if hasattr(self, "history_view") and self.history_view.winfo_ismapped():
            self._render_history()

    def export_log(self) -> None:
        if not self.devices:
            messagebox.showinfo("Nothing to export", "Run a scan before exporting the device log.")
            return
        filename = filedialog.asksaveasfilename(
            title="Export device log",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"network-log-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv",
        )
        if not filename:
            return
        try:
            with Path(filename).open("w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow(self.headings)
                writer.writerows(device.as_row() for device in self.devices.values())
            self.status_var.set(f"Exported {len(self.devices)} device records")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))

    def _close(self) -> None:
        self.monitor.stop()
        self.port_monitor.stop()
        if self.websocket_server is not None:
            self.websocket_server.stop()
        self.database.close()
        self.destroy()


def main() -> None:
    app = NetworkMonitorApp()
    app.mainloop()


if __name__ == "__main__":
    main()
