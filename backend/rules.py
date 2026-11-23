"""Detection engine for Mini-IDS.

An IDS rule (a "signature") is a pattern of behaviour that is almost always
malicious. Each rule below defines:

  1. what a human attacker does (plain-English description),
  2. what distinctive trace that behaviour leaves in the event log,
  3. a simple threshold/regex check that spots the trace.

Every check receives recent events and returns a list of alerts.
Thresholds live in RULE_CONFIG so they are easy to find and tune.
"""

import time
from urllib.parse import unquote

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

# A rule is "recent" if it happened in the last WINDOW_SECONDS of traffic.
# Bursts happen on short timescales; one concept covers scan, brute-force
# and flood alike.
WINDOW_SECONDS = 4


def _recent(events):
    """Events seen in the last WINDOW_SECONDS, given the newest event."""
    if not events:
        return []
    latest = events[-1]["time"]
    return [e for e in events if e["time"] >= latest - WINDOW_SECONDS]

# When a rule fires, an alarm is raised. Single source of truth for thresholds.
RULE_CONFIG = {
    # Thresholds sit between benign traffic variance and attack burst sizes:
    # benign per-IP HTTP counts peak around 18 per 4-second window over long
    # simulations, so 22 flags floods without flagging users.
    "PORT_SCAN": {"distinct_ports": 8},
    "BRUTE_FORCE": {"max_failed_logins": 6},
    "SQL_INJECTION": {"patterns": ["' or 1=1", "union select", "' or '1'='1", "xp_cmdshell"]},
    "DOS": {"max_requests_per_window": 22},
}


def _group(events, key_fn):
    """Group events by a key (e.g. source IP) -> {key: [events]}."""
    groups = {}
    for e in events:
        groups.setdefault(e["src_ip"], []).append(e)
    return groups


def check_port_scan(events):
    """Rule 1 - Port Scan.

    A port scan is a burst of connection attempts to many *different* ports
    on one host. Attackers do it to map which services are open before
    attacking them. Signature: one source IP probing >= 8 distinct ports in
    a short time.
    """
    cfg = RULE_CONFIG["PORT_SCAN"]
    groups = _group(events, lambda e: e["src_ip"])
    alerts = []
    for ip, evs in groups.items():
        ports = {e["dst_port"] for e in evs if e["action"] == "port_probe"}
        if len(ports) >= cfg["distinct_ports"]:
            alerts.append({
                "rule_id": "PORT_SCAN",
                "rule_name": "Port Scan",
                "severity": "High",
                "src_ip": ip,
                "detail": (
                    f"{ip} probed {len(ports)} distinct ports "
                    f"(threshold: {cfg['distinct_ports']}) - service discovery attempt"
                ),
            })
    return alerts


def check_brute_force(events):
    """Rule 2 - Brute Force Login.

    Trying password after password creates a burst of *failed* login
    attempts. Signature: >= 6 failed login events from one source IP in
    a short time.
    """
    cfg = RULE_CONFIG["BRUTE_FORCE"]
    groups = _group(events, lambda e: e["src_ip"])
    alerts = []
    for ip, evs in groups.items():
        fails = [e for e in evs if e["action"] == "login_attempt" and not e["success"]]
        if len(fails) >= cfg["max_failed_logins"]:
            usernames = ", ".join(sorted({e["target"] for e in fails}))
            alerts.append({
                "rule_id": "BRUTE_FORCE",
                "rule_name": "Brute Force Login",
                "severity": "High",
                "src_ip": ip,
                "detail": (
                    f"{len(fails)} failed logins for [{usernames}] "
                    f"(threshold: {cfg['max_failed_logins']})"
                ),
            })
    return alerts


def check_sql_injection(events):
    """Rule 3 - SQL Injection Attempt.

    Malicious input embedded in a URL to trick the database, e.g.
    /products?id=1' OR 1=1--  (classic payload). Signature: the URL
    contains a known SQL-injection fragment. Payloads are URL-decoded
    before matching, so wire-level encodings (`%20` spaces, `%27` quotes,
    `+` for space) still trigger. One alert per source IP, listing the
    payloads seen.
    """
    cfg = RULE_CONFIG["SQL_INJECTION"]
    groups = _group(events, lambda e: e["src_ip"])
    alerts = []
    for ip, evs in groups.items():
        matches = [e["target"] for e in evs
                   if e["action"] == "http_request"
                   and any(p in unquote(e["target"].replace("+", " ")).lower()
                           for p in cfg["patterns"])]
        if matches:
            detail = f"Malicious payload in URL: {matches[0]}"
            if len(matches) > 1:
                detail += f" (+{len(matches) - 1} more)"
            alerts.append({
                "rule_id": "SQL_INJECTION",
                "rule_name": "SQL Injection Attempt",
                "severity": "Critical",
                "src_ip": ip,
                "detail": detail,
            })
    return alerts


def check_dos(events):
    """Rule 4 - Denial of Service.

    Overwhelming a server with an abnormal volume of traffic in a short
    time. Two signatures, one threshold:
      - 22+ HTTP requests from one IP (request flood), or
      - 22+ connection attempts to the SAME port from one IP (connection/
        SYN flood - the shape a real packet capture shows, where payloads
        may be absent and the repeated SYN is the only trace).
    """
    cfg = RULE_CONFIG["DOS"]
    groups = _group(events, lambda e: e["src_ip"])
    alerts = []
    for ip, evs in groups.items():
        reqs = [e for e in evs if e["action"] == "http_request"]
        per_port = {}
        for e in evs:
            if e["action"] == "port_probe":
                per_port.setdefault(e["dst_port"], 0)
                per_port[e["dst_port"]] += 1
        is_flood = len(reqs) >= cfg["max_requests_per_window"] or \
            any(n >= cfg["max_requests_per_window"] for n in per_port.values())
        if is_flood:
            if reqs:
                paths = ", ".join(sorted({e["target"] for e in reqs})[:3])
                detail = (
                    f"{len(reqs)} requests in the recent window "
                    f"(threshold: {cfg['max_requests_per_window']}) to {paths}"
                )
            else:
                port = max(per_port, key=per_port.get)
                detail = (
                    f"{per_port[port]} connection attempts to port {port} in "
                    f"the recent window (threshold: "
                    f"{cfg['max_requests_per_window']}) - flooding behaviour"
                )
            alerts.append({
                "rule_id": "DOS",
                "rule_name": "HTTP Flood (DoS)",
                "severity": "Critical",
                "src_ip": ip,
                "detail": detail,
            })
    return alerts


# Registry: the engine simply runs every rule over the recent events.
RULES = [check_port_scan, check_brute_force, check_sql_injection, check_dos]

# Metadata for the UI "Rules" tab and the report's methodology section.
RULE_INFO = [
    {
        "id": "PORT_SCAN",
        "name": "Port Scan",
        "severity": "High",
        "looks_like": "A burst of connection attempts to many different ports of one host.",
        "detect": "One source IP probing 8 or more distinct ports within a few seconds.",
        "matters": "Port scans are reconnaissance: attackers map open services before exploiting them.",
        "threshold": f">= {RULE_CONFIG['PORT_SCAN']['distinct_ports']} distinct ports",
    },
    {
        "id": "BRUTE_FORCE",
        "name": "Brute Force Login",
        "severity": "High",
        "looks_like": "Repeated failed authentication attempts against user accounts.",
        "detect": "Six or more failed login events from the same source IP within a few seconds.",
        "matters": "Automated password guessing is the most common way accounts get compromised.",
        "threshold": f">= {RULE_CONFIG['BRUTE_FORCE']['max_failed_logins']} failed logins",
    },
    {
        "id": "SQL_INJECTION",
        "name": "SQL Injection Attempt",
        "severity": "Critical",
        "looks_like": "URLs containing SQL fragments such as ' OR 1=1-- or UNION SELECT.",
        "detect": "Request URL matches known SQL-injection patterns.",
        "matters": "Successful injection can read or destroy the entire database.",
        "threshold": "URL matches any known payload pattern",
    },
    {
        "id": "DOS",
        "name": "HTTP Flood (DoS)",
        "severity": "Critical",
        "looks_like": "An abnormal flood of requests or connection attempts aimed at exhausting the service.",
        "detect": "One IP sending 22 or more requests, or 22 or more connection attempts to the same port, within a few seconds.",
        "matters": "Flooding makes the service unavailable to legitimate users.",
        "threshold": f">= {RULE_CONFIG['DOS']['max_requests_per_window']} requests / connections",
    },
]


def run_detection(events):
    """Run every rule over the traffic from the last few seconds and collect
    the alerts, most severe first."""
    alerts = []
    recent = _recent(events)
    for rule in RULES:
        alerts.extend(rule(recent))
    alerts.sort(key=lambda a: SEVERITY_ORDER[a["severity"]])
    return alerts
