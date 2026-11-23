"""Synthetic traffic generator for Mini-IDS.

A real IDS watches actual packets; for this MVP we *simulate* network
traffic so the detection logic can be demonstrated end-to-end without
special hardware or permissions.

The generator emits a standard event record for every observation:

    {
      "ts":      ISO timestamp,
      "src_ip":  source IP address,
      "action":  "http_request" | "login_attempt" | "port_probe",
      "dst_port": TCP port involved,
      "target":  request path / username probed / URL payload,
      "success": whether the action succeeded (always False for probes)
    }

Benign users browse normally; attacker IPs occasionally launch one of the
attack scenarios our rules are built to catch.
"""

import random
import time
import datetime

BENIGN_IPS = ["192.168.1.10", "192.168.1.23", "172.16.0.8", "10.0.0.44"]
ATTACKER_IPS = ["203.0.113.7", "185.220.101.55", "91.242.217.9"]

NORMAL_PATHS = ["/", "/products", "/products?id=42", "/login",
                "/about", "/search?q=laptop", "/cart", "/contact"]
ATTACK_PAYLOADS = [
    "/products?id=1' OR 1=1--",
    "/search?q=' UNION SELECT username, password FROM users--",
    "/login?user=admin' OR '1'='1",
]
USERS = ["admin", "alice", "bob", "carol", "root"]

rng = random.Random()


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def now():
    """Current epoch time (float seconds) - used for cooldown tracking."""
    return time.time()


def iso_now():
    """Current time as an ISO-8601 string - used for human-readable stamps."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _event(src_ip, action, dst_port, target, success, ts=None):
    t = ts or now()
    return {
        "ts": datetime.datetime.fromtimestamp(
            t, datetime.timezone.utc).isoformat(),  # display timestamp
        "time": t,                                   # ordering/recency check
        "src_ip": src_ip,
        "action": action,
        "dst_port": dst_port,
        "target": target,
        "success": success,
    }


def _benign(count):
    """Normal background traffic: page requests, logins, the odd typo."""
    events = []
    for _ in range(count):
        ip = rng.choice(BENIGN_IPS)
        if rng.random() < 0.2:
            events.append(_event(ip, "login_attempt", 443, rng.choice(USERS),
                                 rng.random() > 0.15))
        else:
            events.append(_event(ip, "http_request", 443,
                                 rng.choice(NORMAL_PATHS), True))
    return events


def _port_scan(ip):
    """12 rapid connection probes to random ports."""
    ports = rng.sample(range(20, 1024), 12)
    return [_event(ip, "port_probe", p, f"TCP/{p}", False) for p in ports]


def _brute_force(ip):
    """8 failed logins cycling through usernames."""
    return [_event(ip, "login_attempt", 443, rng.choice(USERS), False)
            for _ in range(8)]


def _sql_injection(ip):
    """3 requests carrying classic SQL-injection payloads."""
    return [_event(ip, "http_request", 443, rng.choice(ATTACK_PAYLOADS), True)
            for _ in range(3)]


def _dos_flood(ip):
    """35 rapid requests to the home page (HTTP flood)."""
    return [_event(ip, "http_request", 443, "/", True) for _ in range(35)]


ATTACKS = {"port_scan": _port_scan,
           "brute_force": _brute_force,
           "sql_injection": _sql_injection,
           "dos_flood": _dos_flood}


def generate_tick():
    """Produce one turn of simulated traffic: a batch of benign traffic plus,
    most of the time, an attack burst from a random attacker IP."""
    events = _benign(rng.randint(8, 12))
    if rng.random() < 0.65:
        ip = rng.choice(ATTACKER_IPS)
        attack = rng.choice(list(ATTACKS))
        events.extend(ATTACKS[attack](ip))
    return events
