# Mini-IDS — Rule-Based Intrusion Detection System (MVP)

A minimal, explainable Intrusion Detection System built as a FastAPI backend +
vanilla HTML/CSS/JS frontend. It observes network traffic — generated
simulations by default, or real packets via the optional live-capture mode —
matches it against four classic detection rules, and raises alerts on a live
dashboard.

Designed to be small enough to explain end-to-end in a project report: every
alert is traceable to an explicit rule and threshold.

---

## 1. Abstract

An Intrusion Detection System (IDS) monitors traffic or logs for malicious
activity and alerts an analyst. Unlike a firewall it does not block traffic —
it observes and reports (an IDS that also blocks is called an IPS). This
project implements a signature-based network IDS MVP: a synthetic traffic
generator produces events, a rule engine applies four classic intrusion
signatures (port scan, brute-force login, SQL injection, HTTP flood), and a
web dashboard visualises events, alerts and statistics in real time.

## 2. Objectives

- Detect common attack patterns automatically and raise alerts.
- Keep every detection **explainable**: rule → threshold → matched evidence.
- Separate **detection** (backend core) from **presentation** (web frontend).
- Stay minimal: no database, no ML — packet-capture privileges are only
  needed for the *optional* live-capture mode.

## 3. Architecture

```
 ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
 │   Traffic    │──▶│    Recent    │──▶│   Detection  │──▶│    Alert     │
 │  Generator   │   │   Events     │   │    Rules     │   │     Log      │
  │ traffic.py   │   │ last 4 sec   │   │   rules.py   │   │ main.py      │
 └──────────────┘   └──────────────┘   └──────────────┘   └──────┬───────┘
                                                                │ REST API
                                                       FastAPI + static FS
                                                                │
                                                        ┌───────▼───────┐
                                                        │   Dashboard   │
                                                        │  (frontend/)  │
                                                        └───────────────┘
```

- **Traffic Generator** (`backend/traffic.py`) — simulates benign users
  (browsing, logins) and attacker IPs (scans, brute-force, SQLi, floods).
  Every observation is one flat *event record* (timestamp, source IP, action,
  port, target, success).
- **Recent Events** (`backend/rules.py`) — a 4-second window of traffic that
  the counting rules evaluate over.
- **Detection Rules** (`backend/rules.py`) — threshold checks and pattern
  matching over that window; one alert per rule per source IP, sorted by
  severity.
- **Alert Deduplication** (`backend/main.py`) — after a rule fires on a
  source IP, the same (rule, IP) pair is suppressed for 30 seconds
  ("cooldown"), so one burst produces one alert instead of an alert per tick.
- **REST API** (FastAPI) — `POST /simulate`, `GET /events`, `GET /alerts`,
  `GET /rules`, `GET /stats`, `POST /reset` (interactive docs at `/docs`).
- **Dashboard** (`frontend/`) — four tabs: Dashboard (stats + alerts),
  Traffic Log (raw events), Rules (explains each rule + trigger counts),
  Info (explains the whole system: IDS concepts, pipeline, design decisions,
  limitations, glossary).

## 4. Detection methodology

| Rule | Looks like | Detection logic | Default threshold | Severity |
|---|---|---|---|---|
| Port Scan | Burst of connection attempts to many ports | Count distinct ports probed by one IP | ≥ 8 distinct ports | High |
| Brute Force Login | Repeated failed authentications | Count failed logins from one IP | ≥ 6 failures | High |
| SQL Injection | SQL fragments in request URLs | Match URL against known payloads (`' OR 1=1`, `UNION SELECT`, …) | any pattern | Critical |
| HTTP Flood (DoS) | Request flood to one host | Count HTTP requests from one IP; also counts ≥22 connection attempts (SYNs) to the **same port** (same-port SYN flood) | ≥ 22 events / 4 s | Critical |

All counting rules look at the last **4 seconds** of traffic; all thresholds
live in one `RULE_CONFIG` block at the top of `backend/rules.py`, so
sensitivity vs. false-positive trade-offs are easy to discuss and tune.

### Two observation sources, one engine

- **Simulated** (default) — `backend/traffic.py` generates benign users plus
  deterministic attack bursts from documentation-range IPs.
- **Live capture** — `backend/capture.py` sniffs real packets with `scapy`
  (the capture engine used by Wireshark/tcpdump). One capture handle per
  real network interface is opened — pseudo-ports (Apple diagnostics
  `anpi*`, `ap1`, `nan0`, …) are skipped — so loopback self-floods **and**
  physical-link traffic are both observed. Every TCP SYN becomes a
  `port_probe` event; plaintext HTTP requests become `http_request` events,
  so **Port Scan**, **DoS** (including same-port connection floods) and
  **SQL Injection** fire on genuinely observed traffic:

  ```bash
  ./run.sh capture     # sudo: capture mode needs /dev/bpf* on macOS
  # then switch source to "Live capture" on the dashboard
  # easy self-demo while it runs:  nmap 127.0.0.1  or:
  while true; do curl -s -o /dev/null http://127.0.0.1:8000/ & sleep 0.05; done
  ```

  The status chip reports how many interfaces are capturing; an interface
  that cannot open (or any run without root) reports the exact OS error per
  interface instead of failing silently.

### Example detection

1. Attacker IP `203.0.113.7` sends `/products?id=1' OR 1=1--`.
2. The URL contains the fragment `' OR 1=1` → SQL_INJECTION rule matches.
3. Alert raised: severity *Critical*, source IP, payload quoted in the detail.

## 5. Evaluating the system

Because the generator knows what it emitted, a demo can double as a test:
typically, over several ticks, each seeded attack burst produces exactly the
expected alert type (the "some attacks stay quiet for a while" gap in a demo
comes from the attacker's randomised pause — realistic and worth discussing as
a limitation of evaluation-by-simulation).

Limitations to state honestly in a report (all covered in the Info tab):

- Live capture is implemented (scapy per-interface sniffing), but encrypted
  traffic is opaque to payload matching; reading server/auth logs is the
  next step.
- **No persistence** — state is in memory and vanishes on restart.
- **Detection only** — no blocking (IPS) capability.
- **Rules only** — signature-based detection cannot catch novel attacks;
  adding an ML/anomaly detector is a natural extension.

## 6. Tech stack

| Layer | Choice | Why |
|---|---|---|
| Backend | Python + FastAPI | Small, typed REST server, auto docs |
| Detection | Pure Python functions | Zero magic, directly explainable |
| Frontend | HTML/CSS/JS, no build step | Transportable, easy to read |
| State | In-memory lists | MVP scope, no DB to install |

## 7. How to run

```bash
# from the project root
./run.sh             # normal run - dashboard + simulated traffic
./run.sh capture     # with sudo - enables the Live-capture toggle
```

The first run creates a `.venv`, installs the dependencies and starts on
http://127.0.0.1:8000 → **Generate Traffic** (or tick *auto-run*). The
backend serves the dashboard itself, so one command runs the whole stack.

Manual equivalent (no venv bootstrapping):

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m uvicorn backend.main:app --port 8000
```

Swagger docs: http://127.0.0.1:8000/docs

Demo attacker IPs use documentation-only ranges (203.0.113.x etc.); nothing
real is being scanned.

## 8. Project layout

```
├── README.md
├── requirements.txt
├── run.sh           # start the stack (./run.sh capture -> sudo)
├── backend/
│   ├── main.py      # FastAPI app: pipeline, REST API, in-memory state
│   ├── rules.py     # detection rules + thresholds + rule metadata
│   ├── capture.py   # optional live packet source (scapy -> event records)
│   └── traffic.py   # synthetic benign + attack traffic generator
├── frontend/
│   ├── index.html   # Dashboard / Traffic Log / Rules / Info tabs
│   ├── style.css
│   └── app.js       # fetches API, renders tables (no frameworks)
└── .venv/           # created on first run (see run.sh)
```
