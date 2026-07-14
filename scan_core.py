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
import ipaddress
from urllib.parse import urlparse


def is_private_ip(ip_str):
    """
    Returns True if the IP is in a private/local/reserved range
    (RFC 1918 private ranges, loopback, link-local, etc).
    Used to restrict public deployments to safe, non-internet targets.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
    )


# --------------------------------------------------------------------------
# Risk classification for well-known ports.
# This is general, publicly documented security knowledge (e.g. "Telnet is
# unencrypted", "SMB has a history of major exploits") — not a vulnerability
# scanner. It flags port/service exposure risk, it does not detect or
# exploit specific vulnerabilities on the target.
# --------------------------------------------------------------------------
PORT_RISK_TABLE = {
    21:   ("critical", "FTP — transmits credentials and data unencrypted"),
    23:   ("critical", "Telnet — unencrypted remote login, no modern protections"),
    135:  ("high", "Windows RPC — historically targeted by major worms"),
    139:  ("high", "NetBIOS — legacy Windows file sharing, often exploited"),
    445:  ("high", "SMB — Windows file sharing, target of major ransomware worms"),
    512:  ("critical", "rexec — unencrypted remote execution"),
    513:  ("critical", "rlogin — unencrypted remote login"),
    514:  ("critical", "rsh — unencrypted remote shell"),
    1433: ("high", "MSSQL — database port, risky if exposed to the internet"),
    1521: ("high", "Oracle DB — database port, risky if exposed to the internet"),
    3306: ("high", "MySQL — database port, risky if exposed to the internet"),
    3389: ("critical", "RDP — remote desktop, frequent target of brute-force attacks"),
    5432: ("high", "PostgreSQL — database port, risky if exposed to the internet"),
    5900: ("high", "VNC — remote desktop, often runs with weak/no authentication"),
    6379: ("high", "Redis — frequently misconfigured with no authentication"),
    8080: ("medium", "Alternate HTTP — often an unhardened admin/proxy interface"),
    9200: ("high", "Elasticsearch — often exposed with no authentication"),
    27017: ("high", "MongoDB — frequently exposed with no authentication"),
    25:   ("medium", "SMTP — mail relay, can be abused for spam if misconfigured"),
    110:  ("medium", "POP3 — often unencrypted mail retrieval"),
    143:  ("medium", "IMAP — often unencrypted mail retrieval"),
    53:   ("low", "DNS — generally low risk, monitor for misuse"),
    80:   ("low", "HTTP — standard web traffic, unencrypted"),
    22:   ("low", "SSH — encrypted, but keep patched and use key auth"),
    443:  ("info", "HTTPS — standard encrypted web traffic"),
}

DEFAULT_RISK = ("info", "No specific risk data for this port — review manually")


def classify_risk(port):
    """Return (risk_level, reason) for a given port."""
    return PORT_RISK_TABLE.get(port, DEFAULT_RISK)


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
            risk_level, risk_reason = classify_risk(port)
            with lock:
                results.append({
                    "port": port,
                    "service": service,
                    "banner": banner,
                    "risk_level": risk_level,
                    "risk_reason": risk_reason,
                })
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

    risk_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in results:
        risk_summary[r["risk_level"]] = risk_summary.get(r["risk_level"], 0) + 1

    return {
        "open_ports": results,
        "elapsed_seconds": round(elapsed, 2),
        "ports_scanned": len(ports),
        "risk_summary": risk_summary,
    }
