"""
agents/deception_agent.py
Deception Agent -- spawns on-demand honeypot clones.

Mirrors the base paper's "deceptive clone generator": instead of a
pre-built static honeypot, a fresh clone is instantiated only when needed,
seeded with honeydata tailored to the pillar the Decision Agent flagged.
Each clone is a tiny fake-shell TCP server, functionally identical in
shape to victim_server.py, but serving fabricated data from the
Honeydata Agent instead of the real filesystem.
"""
import socket
import threading

from config import HOST, HONEYPOT_PORT_RANGE

# Baseline commands every clone answers identically to the real victim,
# so the attacker's very first few probes (whoami/pwd/ls/id) look
# unremarkable even before any honeydata is layered on top.
BASELINE_FS = {
    "whoami": "victim-prod-01",
    "pwd": "/home/appadmin",
    "ls": "app.py  config.yaml  requirements.txt  logs/",
    "id": "uid=1000(appadmin) gid=1000(appadmin) groups=1000(appadmin)",
}


class DeceptionAgent:
    def __init__(self, honeydata_agent, forensic_agent):
        self.honeydata_agent = honeydata_agent
        self.forensic_agent = forensic_agent
        self._next_port = HONEYPOT_PORT_RANGE[0]
        self._lock = threading.Lock()

    def _allocate_port(self):
        with self._lock:
            port = self._next_port
            self._next_port += 1
            if self._next_port > HONEYPOT_PORT_RANGE[1]:
                self._next_port = HONEYPOT_PORT_RANGE[0]
        return port

    def spawn_clone(self, session_id, pillar, inject_honeydata):
        """Instantiate a fresh honeypot clone and return the port it's
        listening on, so the Controller can transparently swap the
        attacker's backend connection to it."""
        port = self._allocate_port()
        fake_fs = dict(BASELINE_FS)
        if inject_honeydata:
            fake_fs.update(self.honeydata_agent.generate(pillar))

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, port))
        srv.listen(5)

        def handle_client(conn, addr):
            conn.sendall(f"Welcome to prod-server (SSH) -- HONEYPOT[{session_id}]\n$ ".encode())
            while True:
                try:
                    data = conn.recv(1024)
                except OSError:
                    break
                if not data:
                    break
                cmd = data.decode(errors="ignore").strip()
                if cmd in ("exit", "quit"):
                    conn.sendall(b"logout\n")
                    break
                self.forensic_agent.log_event(session_id, "attacker_command", {"command": cmd})
                response = fake_fs.get(cmd, f"bash: {cmd}: command not found")
                conn.sendall(f"{response}\n$ ".encode())
            conn.close()

        def accept_loop():
            while True:
                try:
                    conn, addr = srv.accept()
                except OSError:
                    break
                threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

        threading.Thread(target=accept_loop, daemon=True).start()
        self.forensic_agent.log_event(
            session_id, "honeypot_spawned", {"port": port, "pillar": pillar, "honeydata": inject_honeydata}
        )
        return port
