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
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

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


@dataclass(slots=True)
class Device:
    ip: str
    mac: str = "Unknown"
    vendor: str = "Unknown"
    hostname: str = "Unknown"
    status: str = "Offline"
    latency_ms: float | None = None
    last_seen: str = "Never"
    device_type: str = "PC/Workstation"
    custom_name: str = ""
    notes: str = ""

    def as_row(self) -> tuple[str, str, str, str, str, str, str]:
        latency = f"{self.latency_ms:.1f} ms" if self.latency_ms is not None else "-"
        name_display = self.custom_name if self.custom_name else self.hostname
        return (self.ip, self.mac, self.vendor, name_display, self.status, latency, self.last_seen)


def infer_device_type(ip: str, hostname: str, vendor: str) -> str:
    """Infer a friendly device type classification from IP, hostname, and vendor."""
    ip_last = ip.split(".")[-1] if "." in ip else ""
    hn = (hostname or "").lower()
    vn = (vendor or "").lower()

    if ip_last in ("1", "254") or "router" in hn or "gateway" in hn or "pfsense" in hn or "openwrt" in hn:
        return "Router"
    if "switch" in hn or hn.startswith("sw-") or hn.startswith("sw_") or ("cisco" in vn and "catalyst" in hn):
        return "Switch"
    if "accesspoint" in hn or hn.startswith("ap-") or hn.startswith("ap_") or " wifi" in hn or ("ubiquiti" in vn and "ap" in hn):
        return "Access Point"
    if "srv" in hn or "server" in hn or "nas" in hn or "backup" in hn or "db" in hn or "proxmox" in hn or "synology" in vn or "qnap" in vn:
        return "Server"
    if "print" in hn or "epson" in vn or "brother" in vn or "canon" in vn:
        return "Printer"
    if "firewall" in hn or "fortinet" in vn or "paloalto" in vn:
        return "Firewall"
    if "apple" in vn or "intel" in vn or "dell" in vn or "hp" in vn or "lenovo" in vn or "pc" in hn or "laptop" in hn or "macbook" in hn:
        return "PC/Workstation"
    return "PC/Workstation"


def detect_local_subnet() -> ipaddress.IPv4Network:
    """Detect the active IPv4 interface by opening a UDP socket route lookup."""
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
        on_device_found: Callable[[Device], None] | None = None,
    ) -> None:
        if self.running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_scan,
            args=(subnet, on_progress, on_complete, on_error, on_stopped, on_device_found),
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
        on_device_found: Callable[[Device], None] | None = None,
    ) -> None:
        try:
            arp_devices: dict[str, str] = {}
            if self.privileged and srp is not None:
                try:
                    arp_devices = self._arp_scan(subnet)
                except Exception:
                    # Scapy raises platform-specific exceptions for missing raw-socket access.
                    self.privileged = False
            devices = self._layered_scan(subnet, arp_devices, on_progress, on_device_found)
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
        on_device_found: Callable[[Device], None] | None = None,
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
            hn = resolve_hostname(ip)
            vn = lookup_vendor(mac, self.oui_database, allow_api=True)
            d_type = infer_device_type(ip, hn, vn)
            dev = Device(
                ip=ip,
                mac=mac,
                vendor=vn,
                hostname=hn,
                status="Online",
                latency_ms=latency,
                last_seen=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                device_type=d_type,
            )
            if on_device_found is not None:
                on_device_found(dev)
            return dev

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
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.devices: dict[str, Device] = {}
        self.previous_online: set[str] = set()
        self.previous_macs: set[str] = set()
        self.has_completed_scan = False
        self.subnet_var = tk.StringVar(value="Detecting local subnet...")
        self.status_var = tk.StringVar(value="Ready")
        self.count_var = tk.StringVar(value="0 active devices")
        self.port_status_var = tk.StringVar(value="Select an online device to inspect its common TCP ports")
        self.port_scan_thread: threading.Thread | None = None
        self._build_ui()
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
        self.tree.tag_configure("offline", foreground="#8a99a4")

    def start_scan(self) -> None:
        if self.scanner.running:
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
        self.status_var.set(f"Scanning network ({mode})...")
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.scanner.scan(
            subnet,
            lambda done, total: self.events.put(("progress", (done, total))),
            lambda devices: self.events.put(("complete", devices)),
            lambda error: self.events.put(("error", error)),
            lambda: self.events.put(("stopped", None)),
        )

    def stop_scan(self) -> None:
        self.scanner.stop()
        self.status_var.set("Stopping scan...")
        self.stop_button.configure(state="disabled")

    def _process_events(self) -> None:
        try:
            while True:
                event, payload = self.events.get_nowait()
                if event == "progress":
                    done, total = payload  # type: ignore[misc]
                    self.status_var.set(f"Scanning hosts: {done}/{total}")
                elif event == "complete":
                    self._apply_scan(payload)  # type: ignore[arg-type]
                elif event == "error":
                    self.status_var.set(f"Scan error: {payload}")
                    messagebox.showerror("Scan failed", str(payload))
                    self.start_button.configure(state="normal")
                    self.stop_button.configure(state="disabled")
                elif event == "stopped":
                    self.status_var.set("Scan stopped")
                    self.start_button.configure(state="normal")
                    self.stop_button.configure(state="disabled")
                elif event == "ports_complete":
                    ip, open_ports = payload  # type: ignore[misc]
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

    def _on_device_selected(self, _event: object) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        ip = selection[0]
        device = self.devices.get(ip)
        if device is None or device.status != "Online":
            self.port_status_var.set(f"{ip}: Port checks are available for online devices only")
            return
        if self.port_scan_thread is not None and self.port_scan_thread.is_alive():
            self.port_status_var.set(f"{ip}: Another port scan is still running")
            return
        self.port_status_var.set(f"{ip}: Checking common TCP ports...")

        def run_port_scan() -> None:
            try:
                results = scan_ports(ip)
                self.events.put(("ports_complete", (ip, results)))
            except (OSError, ValueError) as exc:
                self.events.put(("ports_error", (ip, str(exc))))

        self.port_scan_thread = threading.Thread(target=run_port_scan, daemon=True, name="device-port-scan")
        self.port_scan_thread.start()

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
        try:
            self.database.record_scan(found, total_devices_online=len(now_online))
        except sqlite3.Error as exc:
            self.status_var.set(f"Scan saved with database error: {exc}")
        self._render_devices()
        change = []
        if joined:
            change.append(f"{len(joined)} joined")
        if left:
            change.append(f"{len(left)} disconnected")
        suffix = f" | {', '.join(change)}" if change else ""
        self.status_var.set(f"Scan complete at {datetime.now().strftime('%H:%M:%S')}{suffix}")
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")

    def _render_devices(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        for device in sorted(self.devices.values(), key=lambda item: ipaddress.ip_address(item.ip)):
            self.tree.insert("", "end", iid=device.ip, values=device.as_row(), tags=(device.status.lower(),))
        active = sum(device.status == "Online" for device in self.devices.values())
        self.count_var.set(f"{active} active device{'s' if active != 1 else ''}")

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
        self.scanner.stop()
        self.database.close()
        self.destroy()


def main() -> None:
    import sys
    if "--tk" in sys.argv or "--gui" in sys.argv:
        app = NetworkMonitorApp()
        app.mainloop()
    else:
        from web_server import run_server
        server = run_server(8000, open_browser=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down NOC Web Server...")
            server.server_close()


if __name__ == "__main__":
    main()
