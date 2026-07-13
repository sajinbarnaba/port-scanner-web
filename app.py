"""
app.py
------
Flask web app for the port scanner.

Run with:
    python3 app.py

Then open:
    http://127.0.0.1:5000
"""

from flask import Flask, render_template, request, jsonify
from scan_core import resolve_target, parse_ports, run_scan

app = Flask(__name__)

# Safety cap so someone can't accidentally (or deliberately) hammer
# the server with a scan of all 65535 ports and hundreds of threads.
MAX_PORTS_PER_SCAN = 5000
MAX_THREADS = 300


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(force=True)

    target_input = (data.get("target") or "").strip()
    port_input = (data.get("ports") or "1-1024").strip()
    banner_flag = bool(data.get("banner", False))

    if not target_input:
        return jsonify({"error": "Please enter an IP address, hostname, or URL."}), 400

    try:
        host_display, target_ip = resolve_target(target_input)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    try:
        ports = parse_ports(port_input)
    except ValueError:
        return jsonify({"error": "Invalid port format. Use e.g. 1-1024 or 22,80,443."}), 400

    if not ports:
        return jsonify({"error": "No valid ports to scan."}), 400

    if len(ports) > MAX_PORTS_PER_SCAN:
        return jsonify({
            "error": f"Too many ports requested ({len(ports)}). "
                     f"Max allowed per scan is {MAX_PORTS_PER_SCAN}."
        }), 400

    result = run_scan(
        target_ip=target_ip,
        ports=ports,
        threads=min(150, MAX_THREADS),
        timeout=1.0,
        banner_flag=banner_flag,
    )

    return jsonify({
        "target_input": host_display,
        "target_ip": target_ip,
        "ports_scanned": result["ports_scanned"],
        "elapsed_seconds": result["elapsed_seconds"],
        "open_ports": result["open_ports"],
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
