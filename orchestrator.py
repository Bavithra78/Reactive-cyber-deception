"""
agents/orchestrator.py
Orchestrator -- NEW, proposed-work addition (not in the base paper).

The coordination bus that ties every agent together so sdn_controller.py
only ever has to call one method. This is the piece that turns the base
paper's single reactive pipeline into a coordinated multi-agent system:
Detection -> Decision -> Deception -> Forensic, with each stage handled by
its own independent, swappable agent.
"""
from agents.detection_agent import DetectionAgent
from agents.decision_agent import DecisionAgent
from agents.honeydata_agent import HoneydataAgent
from agents.deception_agent import DeceptionAgent
from agents.forensic_agent import ForensicAgent


class Orchestrator:
    def __init__(self):
        self.detection_agent = DetectionAgent()
        self.decision_agent = DecisionAgent()
        self.honeydata_agent = HoneydataAgent()
        self.forensic_agent = ForensicAgent()
        self.deception_agent = DeceptionAgent(self.honeydata_agent, self.forensic_agent)
        self._redirected = set()

    def process_message(self, session_id, message, real_fs_keys):
        """
        Inspect one attacker message for this session.

        Returns None if the message should just be forwarded to the real
        backend as-is. Returns a dict {"decision": ..., "honeypot_port": ...}
        the very first time this session is flagged as suspicious -- the
        Controller uses that to swap the backend connection to the
        honeypot clone. Every message after that returns None too (the
        session is already redirected, so the Controller just keeps
        relaying to the honeypot it already switched to).
        """
        if session_id in self._redirected:
            return None

        is_suspicious, reason, category = self.detection_agent.inspect(session_id, message)
        if not is_suspicious:
            return None

        self.forensic_agent.log_event(session_id, "alert", {"reason": reason, "message": message})

        decision = self.decision_agent.classify(category, reason, message)
        self.forensic_agent.log_event(session_id, "decision", decision)

        honeypot_port = self.deception_agent.spawn_clone(
            session_id, decision["pillar"], decision["inject_honeydata"]
        )
        self.forensic_agent.log_event(session_id, "redirected", {"honeypot_port": honeypot_port})

        self._redirected.add(session_id)
        self.detection_agent.reset(session_id)

        return {"decision": decision, "honeypot_port": honeypot_port}
