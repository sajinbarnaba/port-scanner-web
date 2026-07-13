"""
scan_core.py
------------
Core scanning logic, kept separate from the web layer (app.py)
so it can be reused or tested independently.
"""

import socket
import threading
import queue
import time
from urllib.parse import urlparse


def resolve_target(raw_input):
    """
    Accepts an IP, hostname, or full URL (http://example.com/path)
    and returns (display_name, ip_address).
    Raises ValueError if it can't be resolved.
    """
    raw_input = raw_input.strip()

    # If it looks like a URL, extract just the hostname
    if "://" in raw_input:
        parsed = urlparse(raw_input)
        host = parsed.hostname
    else:
        # Could be "example.com/path" without scheme, or a bare host/IP
        host = raw_input.split("/")[0]

    if not host:
        raise ValueError("Could not parse a valid host from input.")

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        raise ValueError(f"Could not resolve host: {host}")

    return host, ip


def parse_ports(port_str):
    """Parse '1-1024' or '22,80,443' or a mix into a sorted list of ints."""
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p <= 65535)


def grab_banner(sock):
    try:
        sock.settimeout(1.0)
        banner = sock.recv(1024)
        return banner.decode(errors="ignore").strip()
    except Exception:
        return ""


def _scan_one(target_ip, port, timeout, banner_flag, results, lock):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((target_ip, port)) == 0:
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "unknown"
            banner = grab_banner(sock) if banner_flag else ""
            with lock:
                results.append({"port": port, "service": service, "banner": banner})
    except Exception:
        pass
    finally:
        sock.close()


def _worker(target_ip, timeout, banner_flag, results, lock, q):
    while not q.empty():
        try:
            port = q.get_nowait()
        except queue.Empty:
            return
        _scan_one(target_ip, port, timeout, banner_flag, results, lock)
        q.task_done()


def run_scan(target_ip, ports, threads=100, timeout=1.0, banner_flag=False):
    """
    Runs a threaded TCP connect scan.
    Returns a dict with open ports (sorted) and elapsed time.
    """
    q = queue.Queue()
    for p in ports:
        q.put(p)

    results = []
    lock = threading.Lock()
    thread_list = []

    start = time.time()
    thread_count = min(threads, len(ports)) or 1

    for _ in range(thread_count):
        t = threading.Thread(
            target=_worker, args=(target_ip, timeout, banner_flag, results, lock, q)
        )
        t.daemon = True
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()

    elapsed = time.time() - start
    results.sort(key=lambda r: r["port"])

    return {
        "open_ports": results,
        "elapsed_seconds": round(elapsed, 2),
        "ports_scanned": len(ports),
    }
