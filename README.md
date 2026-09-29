# AI-Orchestrated Multi-Agent Honeypot-Based Deception Framework
### Review-I Prototype Implementation

This is a **working, runnable prototype** of the proposed multi-agent
extension of the base paper *"Reactive Cyber Deception: Stealth-Based
Adaptive Redirection to On-Demand Honeypots with AI-Driven Data
Generation"* (Beltran-Lopez et al., Computer Networks, Elsevier, 2026).

No installation needed beyond **plain Python 3** (no Mininet, no Ryu,
no API keys, no internet). It runs identically on Windows / macOS /
Linux / this sandbox.

---

## 1. Why it looks different from "real" Mininet + Ryu

The base paper's data plane uses **OpenFlow + Open vSwitch + a Ryu SDN
controller**, with TCP sequence-number offsetting done at the transport
layer. That needs a Linux host with root access and kernel network
namespaces -- most student laptops (and this sandbox) can't run it
out of the box.

To keep this "easy to run" while **preserving every functional step**
of the base paper's Algorithm 1 (connection establishment -> suspicious
message -> alert & closure -> honey connection establishment -> restore
connection), this prototype implements the same steps as an
**application-layer transparent TCP proxy** in `sdn_controller.py`.
The attacker's own socket is never closed or changed across the
redirection -- exactly the undetectability property the base paper
targets -- so the demo genuinely reproduces the *behaviour*, just not
the OpenFlow plumbing underneath it.

**When you get real Mininet/Ryu access:** only `ControllerProxy` in
`sdn_controller.py` needs to be replaced with actual OpenFlow flow-mod
rules. Every agent in `agents/` stays exactly the same -- they were
built to be transport-layer-agnostic on purpose.

## 2. What's implemented (the proposed / modified work)

This is **not** a copy of the base paper's results -- it implements the
extension proposed in your Review-I PPT: a coordinated **multi-agent**
layer on top of the base paper's reactive SDN mechanism.

| File | Role | Maps to |
|---|---|---|
| `victim_server.py` | The real, protected asset | Base paper's "Victim" |
| `sdn_controller.py` | Transparent proxy / SDN Controller | Base paper's Ryu Controller |
| `agents/detection_agent.py` | Signature + heuristic detection | Base paper's Snort IDS |
| `agents/decision_agent.py` | Classifies confidentiality / integrity / availability | Base paper's "Decision" module |
| `agents/deception_agent.py` | Spawns on-demand honeypot clones | Base paper's "Deceptive clone generator" |
| `agents/honeydata_agent.py` | Free, local, template-based fake-document generator | Base paper's LLM honeydata generator |
| `agents/forensic_agent.py` | **New** -- automatic JSON threat-intel report | Proposed-work addition (not in base paper) |
| `agents/orchestrator.py` | **New** -- coordination bus between all agents | Proposed-work addition (not in base paper) |
| `attacker_simulator.py` | Demo attacker client | -- |

## 3. How to run the demo

Open **three terminals** in this folder.

```bash
# Terminal 1 -- start the real Victim server
python3 victim_server.py

# Terminal 2 -- start the Controller (detects, decides, redirects)
python3 sdn_controller.py

# Terminal 3 -- run a simulated attacker
python3 attacker_simulator.py
```

Watch Terminal 3: the attacker runs `whoami`, `pwd`, `ls`, `id`
normally against the real Victim. The moment it runs
`cat config.yaml`, the Detection Agent flags it, the Decision Agent
classifies it as a **confidentiality** threat, the Deception Agent
clones a honeypot on a new port and seeds it with **fake** honeydata,
and the Controller silently swaps the backend -- the attacker's prompt
never even blinks. Every command after that point is captured by the
Forensic Agent.

Check the auto-generated threat-intelligence report:

```bash
cat logs/forensic_report.json
```

You'll see the full timeline: `alert -> decision -> honeypot_spawned ->
redirected -> attacker_command (x N)`.

### Try your own attacker

Instead of `attacker_simulator.py`, connect with a plain TCP client and
type commands yourself:

```bash
python3 -c "import telnetlib; t=telnetlib.Telnet('127.0.0.1', 8000); t.interact()"
# or, if you have netcat:
nc 127.0.0.1 8000
```

Try `whoami`, then `cat config.yaml` (or any command containing
`sudo`, `passwd`, `wget`, `select `, etc. -- see
`config.CONFIDENTIALITY_INTEGRITY_KEYWORDS`) to trigger redirection
yourself.

## 4. Tuning the detection sensitivity

Edit `config.py`:

- `SUSPICIOUS_MESSAGE_COUNT_THRESHOLD` -- how many messages before the
  session is flagged even with no keyword match (mirrors the base
  paper's "100th packet" Snort rule, scaled down for a fast demo).
- `CONFIDENTIALITY_INTEGRITY_KEYWORDS` / `AVAILABILITY_KEYWORDS` --
  add/remove signature keywords.

## 5. What's left for Review-II (the remaining ~20%)

- Swap the application-layer proxy for real OpenFlow rules on an
  actual Mininet + Ryu testbed (once environment access is available).
- Replace `HoneydataAgent`'s template generator with a real LLM API
  call (OpenAI / Gemini) for higher-fidelity honeydata, and evaluate it
  with the same FC / CC / SS metrics used in the base paper.
- Add the anomaly/ML-based half of the Detection Agent (currently
  signature + count-based only).
- Build the Grafana/Kibana-style dashboard mentioned in the "Tools
  Required" slide, reading from `logs/forensic_report.json`.
- Benchmark latency/CPU/RAM the way the base paper's Experiments 1 and
  4 do, and compare against its published numbers (report the
  comparison -- never relabel the base paper's own numbers as yours).

## 6. Real-time dashboard (Review-I demo add-on)

A lightweight, dependency-free dashboard is included under `dashboard/`.
It polls `logs/forensic_report.json` every 2 seconds and shows sessions,
their CIA-pillar classification, and a live event timeline per session.

```bash
# Terminal 4 -- after victim_server.py, sdn_controller.py are running
python3 dashboard/dashboard_server.py
```

Then open **http://127.0.0.1:8080** in a browser. Run `attacker_simulator.py`
(or a real telnet/nc client) in another terminal and watch the session
appear and update live.
