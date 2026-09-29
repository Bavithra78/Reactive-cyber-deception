"""
agents/forensic_agent.py
Forensic Agent -- NEW, proposed-work addition (not in the base paper).

Automatically builds a per-session JSON threat-intelligence timeline:
alert -> decision -> honeypot_spawned -> redirected -> attacker_command (x N)
and persists it to logs/forensic_report.json after every event, so the
report is always up to date even if the demo is stopped mid-session.
"""
import json
import os
import time

from config import LOG_DIR, FORENSIC_REPORT_PATH


class ForensicAgent:
    def __init__(self):
        os.makedirs(LOG_DIR, exist_ok=True)
        self._sessions = {}
        self._load()

    def _load(self):
        if os.path.exists(FORENSIC_REPORT_PATH):
            try:
                with open(FORENSIC_REPORT_PATH, "r") as f:
                    self._sessions = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._sessions = {}
        else:
            self._flush()

    def log_event(self, session_id, event_type, details=None):
        entry = {
            "event": event_type,
            "timestamp": round(time.time(), 3),
            "details": details or {},
        }
        self._sessions.setdefault(session_id, []).append(entry)
        self._flush()

    def summary(self, session_id):
        events = self._sessions.get(session_id, [])
        return {
            "session_id": session_id,
            "num_events": len(events),
            "timeline": [e["event"] for e in events],
        }

    def _flush(self):
        try:
            with open(FORENSIC_REPORT_PATH, "w") as f:
                json.dump(self._sessions, f, indent=2)
        except OSError:
            pass
