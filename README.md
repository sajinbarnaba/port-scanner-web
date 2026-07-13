# Port Scanner — Web App

A simple, browser-based port scanner. Type in an IP, hostname, or URL, hit **Scan**, and see open ports appear in real time. Hit **Clear** to reset and scan another target — no page reloads.

Built with a Python (Flask) backend and a lightweight HTML/CSS/JS frontend.

## Features

- Web UI — type a target into a box, click Scan, see results instantly
- Accepts IP addresses, hostnames, or full URLs (`http://example.com`)
- Flexible port input: ranges (`1-1024`), lists (`22,80,443`), or mixed
- Optional banner grabbing to identify running services
- Multi-threaded scanning on the backend for speed
- Clear button to reset and scan a new target
- Basic safety limits (max ports per scan) to prevent accidental abuse

## Project Structure

```
port-scanner-web/
├── app.py              # Flask routes (/  and  /scan)
├── scan_core.py         # Scanning logic (reusable, no Flask dependency)
├── templates/
│   └── index.html       # Frontend UI
├── static/
│   └── style.css         # Styling
├── requirements.txt
└── README.md
```

## Setup (in VS Code / terminal)

1. **Install Python 3.7+** if you don't already have it.

2. **Create a virtual environment** (recommended, keeps things clean):
   ```bash
   python3 -m venv venv
   source venv/bin/activate      # on Windows: venv\Scripts\activate
   ```

3. **Install dependencies** — this project needs only one package, Flask:
   ```bash
   pip install -r requirements.txt
   ```
   (or just `pip install flask`)

4. **Run the app**:
   ```bash
   python3 app.py
   ```

5. **Open your browser** to:
   ```
   http://127.0.0.1:5000
   ```

## How to Use

1. Type an IP, hostname, or URL into the box (e.g. `scanme.nmap.org`)
2. (Optional) Adjust the port range — defaults to `1-1024`
3. (Optional) Check "Grab banners" to try to identify services
4. Click **Scan**
5. Results appear below — open ports, their service name, and banner if grabbed
6. Click **Clear** to reset the form and scan a different target

## How It Works

- The frontend sends a `POST` request to `/scan` with the target and options as JSON.
- The Flask backend resolves the hostname to an IP, spins up a thread pool, and performs a TCP `connect()` scan across the requested ports (same technique as `nmap -sT`).
- Results are returned as JSON and rendered into a table dynamically with JavaScript — no page reload needed.

## Safety Limits

To keep this from being misused as a DoS tool against your own machine (or accidentally scanning way too much):
- Max **5,000 ports** per scan request
- Max **300 threads** used server-side

You can adjust these in `app.py` (`MAX_PORTS_PER_SCAN`, `MAX_THREADS`).

## ⚠️ Disclaimer

This tool is for **educational purposes and authorized testing only**. Only scan hosts and networks you own or have explicit written permission to test. Unauthorized scanning may be illegal under laws like the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), the IT Act 2000 (India), or equivalent legislation elsewhere.

## Ideas for Future Improvements

- [ ] Scan history / previous results log
- [ ] Export results as CSV/JSON download
- [ ] UDP scan support
- [ ] Progress indicator during long scans (via WebSockets)
- [ ] Dockerfile for easy deployment
- [ ] Dark/light theme toggle

## License

See [LICENSE](LICENSE).
