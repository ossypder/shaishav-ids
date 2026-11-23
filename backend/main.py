"""Mini-IDS backend.

Pipeline:  traffic generator -> recent events -> detection rules -> alerts

The REST API exposes the four stages so the frontend can drive a
demonstration: simulate traffic, view raw events, view alerts, view stats.

Run from the project root with:
    uvicorn backend.main:app --reload
"""

import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import rules, traffic, capture

app = FastAPI(title="Mini-IDS", version="1.1")

MODES = ("simulated", "capture")
STATE = {
    "mode": "simulated",  # observation source: synthetic generator or pcap
    "events": [],        # recent traffic events (capped)
    "alerts": [],        # detections so far
    "cooldowns": {},     # (rule_id, src_ip) -> last alert epoch time
    "events_total": 0,   # monotonic counters, for the dashboard
    "alerts_total": 0,
    "next_event_id": 1,
    "next_alert_id": 1,
}

EVENT_CAP = 400        # how many raw events to keep for display

# After a rule fires on a source IP, the same (rule, IP) pair stays quiet for
# this long. Without this, a burst still inside the 4-second window would
# re-alert on every tick. Real IDSes call this aggressor logging/dedup.
COOLDOWN_SECONDS = 30

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


def _handle_tick(events):
    """Generate a tick of traffic, run detection, record the results."""
    out_events, out_alerts = [], []
    for e in events:
        e["id"] = STATE["next_event_id"]
        STATE["next_event_id"] += 1
        STATE["events"].append(e)
        STATE["events_total"] += 1
        out_events.append(e)

    timestamp = traffic.now()
    # rules.py decides what counts as "recent" (a 4-second window)
    for a in rules.run_detection(STATE["events"]):
        key = (a["rule_id"], a["src_ip"])
        if timestamp - STATE["cooldowns"].get(key, 0) < COOLDOWN_SECONDS:
            continue                                  # same burst, stay quiet
        STATE["cooldowns"][key] = timestamp
        a["id"] = STATE["next_alert_id"]
        a["ts"] = traffic.iso_now()
        STATE["next_alert_id"] += 1
        STATE["alerts"].insert(0, a)
        STATE["alerts_total"] += 1
        out_alerts.append(a)

    if len(STATE["events"]) > EVENT_CAP:
        STATE["events"] = STATE["events"][-EVENT_CAP:]
    return out_events, out_alerts


@app.post("/simulate")
def simulate():
    """Run one detection tick.

    In simulated mode this generates a tick of synthetic network traffic;
    in capture mode it drains up to a few hundred real packets that the
    sniffer collected on the interface(s) since the previous tick. Either
    way the events go through the same window and rule engine.
    """
    if STATE["mode"] == "capture":
        events = capture.drain()
    else:
        events = traffic.generate_tick()
    new_events, new_alerts = _handle_tick(events)
    return {"new_events": new_events, "new_alerts": new_alerts}


class ModeRequest(BaseModel):
    mode: str


@app.get("/mode")
def get_mode():
    """Current observation source plus live capture diagnostics."""
    return {"mode": STATE["mode"], "capture": capture.state()}


@app.post("/mode")
def set_mode(req: ModeRequest):
    """Switch the observation source: synthetic generator or live packets."""
    if req.mode not in MODES:
        return JSONResponse(
            {"ok": False, "error": f"mode must be one of {MODES}"}, status_code=400)
    if req.mode == STATE["mode"]:
        return {"ok": True, "mode": STATE["mode"], "capture": capture.state()}
    # Each observation source starts with a clean log: mixing simulated
    # attacker IPs with real captured traffic would make the dashboard
    # impossible to interpret.
    _reset_state()
    if req.mode == "capture":
        capture.start()                          # may report permission error
        for _ in range(10):                      # let the sniffer settle so the
            st = capture.state()                 # dashboard gets a real answer
            if st["iface"] or st["status"] == "error":
                break
            time.sleep(0.1)
        STATE["mode"] = "capture"
        return {"ok": True, "mode": "capture", "capture": capture.state()}
    capture.stop_capture()
    STATE["mode"] = "simulated"
    return {"ok": True, "mode": "simulated", "capture": capture.state()}


@app.get("/events")
def get_events(limit: int = 100):
    """Most recent raw traffic events, newest first."""
    return list(reversed(STATE["events"]))[:limit]


@app.get("/alerts")
def get_alerts(limit: int = 100):
    """All alerts raised so far, newest first."""
    return STATE["alerts"][:limit]


@app.get("/rules")
def get_rules():
    """Rule metadata for the Rules tab / methodology section."""
    counts = {}
    for a in STATE["alerts"]:
        counts[a["rule_id"]] = counts.get(a["rule_id"], 0) + 1
    out = []
    for r in rules.RULE_INFO:
        out.append({**r, "times_triggered": counts.get(r["id"], 0)})
    return out


@app.get("/stats")
def get_stats():
    """Dashboard summary numbers."""
    by_rule, alerts_by_ip = {}, {}
    for a in STATE["alerts"]:
        by_rule[a["rule_id"]] = by_rule.get(a["rule_id"], 0) + 1
        alerts_by_ip[a["src_ip"]] = alerts_by_ip.get(a["src_ip"], 0) + 1
    by_severity = {s: sum(1 for a in STATE["alerts"] if a["severity"] == s)
                   for s in ("Critical", "High", "Medium", "Low")}
    return {
        "mode": STATE["mode"],
        "events_total": STATE["events_total"],
        "alerts_total": STATE["alerts_total"],
        "by_rule": by_rule,
        "by_severity": by_severity,
        "alerts_by_ip": alerts_by_ip,
        "capture": capture.state(),
    }


def _reset_state():
    """Clear the session and counters."""
    STATE.update(events=[], alerts=[], cooldowns={}, events_total=0,
                 alerts_total=0, next_event_id=1, next_alert_id=1)


@app.post("/reset")
def reset():
    """Clear the session so a fresh demonstration can start."""
    _reset_state()
    return JSONResponse({"ok": True})


# Serve the frontend (index.html) at "/" once the API routes above are set.
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="static")
