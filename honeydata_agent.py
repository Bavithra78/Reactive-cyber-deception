"""
agents/honeydata_agent.py
Honeydata Agent -- generates fake but coherent documents/logs/config values
for the honeypot clone to serve, tailored to the compromised pillar
(confidentiality / integrity / availability), the same tailoring strategy
the base paper uses its LLM for.

This is a FREE, LOCAL, template-based stand-in (no API key, no internet --
see README section 5). Swap `generate()`'s body for a real LLM API call
later without touching any other agent.
"""
import random


class HoneydataAgent:
    def generate(self, pillar):
        """Return a dict of {command: fake_response} for the honeypot's
        fake shell filesystem, tailored to the given pillar."""
        token = f"HP-{random.randint(1000, 9999)}"

        if pillar == "confidentiality":
            return {
                "whoami": "victim-prod-01",
                "pwd": "/home/appadmin",
                "ls": "app.py  config.yaml  requirements.txt  logs/  backup_2026.tar.gz",
                "cat config.yaml": (
                    "db_host: honey-db-internal.local\n"
                    f"api_key: {token}-FAKE-KEY\n"
                    "admin_email: admin@corp-internal.example\n"
                ),
                "cat secret.txt": (
                    "Internal memo (DRAFT) -- do not distribute\n"
                    f"ref: {token}\n"
                    "Q3 budget figures pending review.\n"
                ),
                "cat access.log": (
                    "10.0.0.14 - - [admin login] 200\n"
                    "10.0.0.22 - - [file download] 200\n"
                ),
                "id": "uid=1000(appadmin) gid=1000(appadmin) groups=1000(appadmin)",
            }

        if pillar == "integrity":
            return {
                "whoami": "victim-prod-01",
                "pwd": "/home/appadmin",
                "ls": "app.py  config.yaml  requirements.txt  logs/",
                "cat config.yaml": f"db_host: honey-db-internal.local\napi_key: {token}-FAKE-KEY\n",
                "id": "uid=1000(appadmin) gid=1000(appadmin) groups=1000(appadmin)",
            }

        # availability, or any unrecognized pillar: minimal fake surface,
        # since honeydata isn't injected for this case anyway
        return {
            "whoami": "victim-prod-01",
            "pwd": "/home/appadmin",
            "ls": "app.py  config.yaml  requirements.txt  logs/",
        }
