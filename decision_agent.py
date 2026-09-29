"""
agents/decision_agent.py
Decision Agent -- classifies a flagged event into the CIA triad pillar it
threatens (Confidentiality / Integrity / Availability) and decides whether
LLM-style honeydata injection is worthwhile for this case.

Mirrors the base paper's "Decision" module, which routes the alert toward
the appropriate honeydata-generation strategy depending on which asset
property (confidentiality, integrity, or availability) the attacker is
threatening.
"""

# Commands that look like they're trying to *change* something rather than
# just read it -- used to split the combined "confidentiality_integrity"
# detection category into the two separate pillars.
WRITE_LIKE_KEYWORDS = ["insert into", "update ", "drop table", "chmod", "sudo", "scp", "wget", "curl"]


class DecisionAgent:
    def classify(self, category, reason, message):
        lower = message.lower()

        if category == "availability":
            pillar = "availability"
            # Faking data doesn't help against a flood/DoS attempt -- the
            # honeypot clone itself (an isolated, disposable instance) is
            # the countermeasure, not fabricated documents.
            inject_honeydata = False

        elif category == "confidentiality_integrity":
            pillar = "integrity" if any(w in lower for w in WRITE_LIKE_KEYWORDS) else "confidentiality"
            inject_honeydata = True

        else:  # "anomaly" -- count-based trigger, no specific signature
            pillar = "confidentiality"
            inject_honeydata = True

        return {
            "pillar": pillar,
            "reason": reason,
            "inject_honeydata": inject_honeydata,
        }
