"""
agents/detection_agent.py
Detection Agent -- signature + count-based heuristic detection.

Mirrors the base paper's Snort IDS component: a real Snort rule fires on
the Nth packet of a flow (mimicked here by SUSPICIOUS_MESSAGE_COUNT_THRESHOLD)
or on a payload signature match (mimicked here by simple keyword lists in
config.py, standing in for real Snort rules).

This agent is intentionally "dumb" -- pure signature + count matching, no
ML -- exactly what the README lists as already implemented, with the
anomaly/ML half left for Review-II.
"""
from config import (
    CONFIDENTIALITY_INTEGRITY_KEYWORDS,
    AVAILABILITY_KEYWORDS,
    SUSPICIOUS_MESSAGE_COUNT_THRESHOLD,
)


class DetectionAgent:
    def __init__(self):
        # Per-session message counters (mirrors per-flow packet counters)
        self._message_counts = {}

    def inspect(self, session_id, message):
        """
        Inspect a single attacker message for this session.

        Returns a tuple: (is_suspicious, reason, category)
          category is one of "confidentiality_integrity", "availability",
          "anomaly", or None (when not suspicious).
        """
        self._message_counts[session_id] = self._message_counts.get(session_id, 0) + 1
        count = self._message_counts[session_id]
        lower = message.lower()

        for kw in CONFIDENTIALITY_INTEGRITY_KEYWORDS:
            if kw in lower:
                return True, f"signature match on '{kw.strip()}'", "confidentiality_integrity"

        for kw in AVAILABILITY_KEYWORDS:
            if kw in lower:
                return True, f"availability signature match on '{kw.strip()}'", "availability"

        if count >= SUSPICIOUS_MESSAGE_COUNT_THRESHOLD:
            return True, f"message count threshold exceeded ({count} messages in session)", "anomaly"

        return False, None, None

    def reset(self, session_id):
        """Clear counters once a session has been redirected, so the honeypot
        side doesn't keep re-triggering the same count-based rule."""
        self._message_counts.pop(session_id, None)
