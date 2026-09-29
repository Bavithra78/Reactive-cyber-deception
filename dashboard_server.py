"""
dashboard/dashboard_server.py
Serves the DeceptAI real-time threat dashboard.

- GET /            -> dashboard/index.html
- GET /api/report  -> current contents of logs/forensic_report.json (live)

Stdlib-only (http.server), no extra pip installs needed -- consistent
with the rest of the prototype's "just plain Python 3" philosophy.

Run this alongside victim_server.py and sdn_controller.py, then open
http://127.0.0.1:8080 in a browser while attacker_simulator.py (or a real
telnet/nc client) runs against the Controller. The dashboard polls the
forensic report every 2 seconds, so redirections show up live.

    python3 dashboard/dashboard_server.py
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(DASHBOARD_DIR)
REPORT_PATH = os.path.join(PROJECT_ROOT, "logs", "forensic_report.json")
INDEX_PATH = os.path.join(DASHBOARD_DIR, "index.html")
PORT = 8080


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # keep the console quiet; the dashboard itself shows activity

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self._serve_file(INDEX_PATH, "text/html")
        elif self.path == "/api/report":
            self._serve_report()
        else:
            self.send_error(404, "Not found")

    def _serve_file(self, path, content_type):
        try:
            with open(path, "rb") as f:
                body = f.read()
        except OSError:
            self.send_error(404, "Not found")
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_report(self):
        data = {}
        if os.path.exists(REPORT_PATH):
            try:
                with open(REPORT_PATH, "r") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                data = {}
        body = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve():
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"[DASHBOARD] Serving at http://127.0.0.1:{PORT}")
    print(f"[DASHBOARD] Reading {REPORT_PATH}")
    srv.serve_forever()


if __name__ == "__main__":
    serve()
