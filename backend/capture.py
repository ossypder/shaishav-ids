"""Live packet capture for Mini-IDS (pcap-style, via scapy).

This is the "real traffic" observation source: actual packets captured on a
network interface through libpcap - the same capture engine Wireshark and
tcpdump use. It grows the MVP without changing the detection engine: every
packet is translated into the same flat event record the simulator produces,
so rules.py runs unchanged.

Packet -> event mapping (plain TCP only):

  - TCP SYN without ACK (and no payload): a connection attempt.
        -> action "port_probe", target "TCP/<port>", success False.
  - TCP payload starting with an HTTP method (GET, POST, ...):
        -> action "http_request", target = request path, success True.
        SQL-injection fragments in the URL become detectable on live traffic.
  - anything else (handshake steps, ACKs, TLS bytes, UDP): no event - it
    carries no signal our four signature rules can act on.

Honest limitation: password authentication is encrypted on the wire, so the
Brute Force rule (failed logins) cannot be observed in packet payloads -
it stays a simulated-traffic rule.

Capturing packets needs privileges (root, or operator-group access to the
/dev/bpf* devices on macOS). If the sniffer cannot start, state() reports
why instead of crashing.

Usage (from the project root):
    sudo uvicorn backend.main:app --reload      # capture mode available
"""

import queue
import threading
import time
import datetime

HTTP_METHODS = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
                "OPTIONS ", "PATCH ")

MAX_BACKLOG = 5000     # packets waiting for a detection tick
SYN_FLAG, ACK_FLAG = 0x02, 0x10


# ---------------------------------------------------------------- state ---
#
# status: "off" | "running" | "error"
# The sniffer runs in a daemon thread and pushes converted events (or the
# word None for skipped packets, to keep the packet counter honest) into a
# bounded queue; the detection tick drains it.
#
CAPTURE = {
    "status": "off",
    "detail": "",
    "iface": None,
    "thread": None,
    "queue": None,
    "sniffed": 0,        # packets seen by the filter (TCP)
    "converted": 0,      # packets that mapped to events
    "dropped": 0,        # packets dropped because the backlog was full
    "stop": None,        # threading.Event
    "active": [],        # interfaces currently capturing
    "failed": {},        # interface -> last failure message
    "threads": None,     # per-interface sniff threads
    "done": 0,           # opens finished (success or fail)
    "total": 0,          # planned opens
}


def state():
    """Snapshot for /mode and the dashboard status line."""
    return {
        "status": CAPTURE["status"],
        "detail": CAPTURE["detail"],
        "iface": CAPTURE["iface"],
        "sniffed": CAPTURE["sniffed"],
        "converted": CAPTURE["converted"],
        "dropped": CAPTURE["dropped"],
        "active": list(CAPTURE["active"]),
        "failed": {k: v for k, v in CAPTURE["failed"].items()},
        "done": CAPTURE["done"],
        "total": CAPTURE["total"],
    }


def _error(msg):
    CAPTURE["status"] = "error"
    CAPTURE["detail"] = msg


def _note(msg):
    CAPTURE["detail"] = msg


# ------------------------------------------------------------- mapping ---

def packet_to_event(pkt, time_epoch):
    """Translate one scapy TCP packet into the standard event record, or
    return None when the packet carries no signal for the signature rules.

    `time_epoch` is the capture time (float epoch), used by rules.py for
    the 4-second recency window.
    """
    if not pkt.haslayer("TCP"):
        return None
    try:
        tcp = pkt["TCP"]
    except Exception:
        return None

    flags = int(tcp.flags)
    if not pkt.haslayer("IP"):
        return None                      # IPv6 stays future work

    ts = datetime.datetime.fromtimestamp(
        time_epoch, datetime.timezone.utc).isoformat()
    src_ip = pkt["IP"].src
    dst_port = int(tcp.dport)
    payload = bytes(tcp.payload) if tcp.payload else b""

    if not (flags & ACK_FLAG) and (flags & SYN_FLAG):
        if not payload:
            return {"ts": ts, "time": time_epoch, "src_ip": src_ip,
                    "action": "port_probe", "dst_port": dst_port,
                    "target": f"TCP/{dst_port}", "success": False}
        return None

    for method in HTTP_METHODS:
        if payload.startswith(method.encode()):
            first_line = payload.split(b"\r\n")[0].decode("latin-1", "replace")
            parts = first_line.split(" ")
            path = parts[1] if len(parts) > 1 else "/"
            return {"ts": ts, "time": time_epoch, "src_ip": src_ip,
                    "action": "http_request", "dst_port": dst_port,
                    "target": path[:200], "success": True}
    return None


def _worker(ifaces, out_q, stop):
    """Spawn one sniffer thread per network interface.

    A single sniffer over a long iface list is fragile on macOS: if any one
    virtual interface (utun*, awdl0, ...) refuses to open, the whole capture
    dies. With a thread per interface, every healthy interface keeps
    capturing even when others fail, and failures are reported per device.
    """
    try:
        from scapy.all import sniff, conf        # optional dependency
        from scapy.arch import get_if_list
    except Exception as exc:                              # noqa: BLE001
        _error(f"scapy not available ({exc}) - install it with "
               "pip install scapy and restart the server")
        return

    names = list(dict.fromkeys(
        get_if_list() if ifaces is None else list(ifaces)))
    # Apple diagnostic/pseudo-ports (anpi*, aggregator ap1, nan0, gif0, stf0)
    # never carry user TCP traffic and some refuse BPF attach even as root -
    # skip them instead of poisoning the interface report.
    names = [n for n in names
             if not (n.startswith(("anpi", "gif0", "stf0"))
                     or n in ("ap1", "nan0"))]
    if not names:
        names = [str(conf.iface)]
    CAPTURE.update(active=[], failed={}, done=0, total=len(names))
    CAPTURE["iface"] = (f"{len(names)} interfaces"
                        if len(names) > 4 else "+".join(names))

    def _record(iface, ok, err=None):
        """Thread-safe bookkeeping of which interfaces are capturing."""
        CAPTURE["done"] += 1
        if ok:
            CAPTURE["active"].append(iface)
        else:
            CAPTURE["failed"][iface] = str(err or "unknown")[:140]
        active = CAPTURE["active"]
        CAPTURE["iface"] = (f"{len(active)}/{len(names)} interfaces"
                            if len(names) > 4 else "+".join(active) or "-")

    def _sniff_one(iface):
        def _prn(pkt):
            CAPTURE["sniffed"] += 1
            event = packet_to_event(pkt, float(pkt.time))
            if event is None:
                return
            event["origin"] = "live"          # dashboard LIVE badge
            try:
                out_q.put_nowait(event)
            except queue.Full:
                CAPTURE["dropped"] += 1
            else:
                CAPTURE["converted"] += 1
        try:
            sniff(
                iface=iface,
                filter="tcp",
                # Promiscuous mode on physical interfaces (WiFi recognises
                # other hosts' frames; loopback needs no privilege for us).
                promisc=(not str(iface).startswith("lo")),
                store=False,
                stop_filter=lambda _p: stop.is_set(),
                prn=_prn,
            )
        except Exception as exc:                          # noqa: BLE001
            _record(iface, False, f"{exc.__class__.__name__}: {exc}")
            return
        _record(iface, not stop.is_set())

    threads = []
    for name in names:
        t = threading.Thread(target=_sniff_one, args=(name,), daemon=True)
        t.start()
        threads.append(t)
        CAPTURE["threads"] = threads
        # Stagger the opens: scapy lazily initialises global tables (iface
        # cache, BPF device selection) on first socket creation, and 21
        # threads hitting that at the same moment caused opens to fail.
        if len(names) > 1:
            time.sleep(0.15)

    # Wait until every planned open has reported done (or grace expires),
    # then decide whether anything is actually capturing.
    for _ in range(60):                       # up to ~15 s of grace
        if stop.is_set() or CAPTURE["active"] or \
                CAPTURE["done"] >= CAPTURE["total"]:
            break
        time.sleep(0.25)
    if not CAPTURE["active"] and not stop.is_set():
        first_fail, first_err = (next(iter(CAPTURE["failed"].items()))
                                 if CAPTURE["failed"] else
                                 (None, "no packet permission"))
        _error(f"no interface could be opened - are you running the server "
               f"with sudo? ({first_fail}: {first_err})")
        return

    # Supervisor: stay alive while at least one interface keeps sniffing.
    while CAPTURE["status"] == "running" and not stop.is_set():
        if not any(t.is_alive() for t in threads):
            break
        stop.wait(0.5)
    for t in threads:
        t.join(timeout=2.0)
    if stop.is_set():
        CAPTURE["status"] = "off"
        _note("stopped from the dashboard")
    elif not CAPTURE["active"]:
        _error("all capturing threads stopped - switch the toggle off and "
               "back on to restart")
    else:
        _note(f"{len(CAPTURE['active'])} interface(s) capturing")


# ------------------------------------------------------------ lifecycle ---

def start(iface=None):
    """Start sniffing. Safe to call repeatedly while already running."""
    if CAPTURE["status"] == "running":
        return state()
    out_q = queue.Queue(maxsize=MAX_BACKLOG)
    stop = threading.Event()
    CAPTURE.update(queue=out_q, stop=stop, sniffed=0, converted=0,
                   dropped=0, status="running", detail="")
    # Visible evidence lives on TCP to any port; the loopback interface
    # matters because localhost attacks (curl, nmap) are the easiest way to
    # demonstrate capture mode.
    worker = threading.Thread(
        target=_worker, args=(iface, out_q, stop), daemon=True)
    worker.start()
    CAPTURE["thread"] = worker
    return state()


def stop_capture():
    """Ask the sniff thread to finish; drain() already gave out its packets."""
    if CAPTURE["stop"] is not None:
        CAPTURE["stop"].set()
    CAPTURE["status"] = "off"
    CAPTURE["detail"] = "stopped from the dashboard"
    return state()


def drain():
    """Return all packets captured since the last call (as event records)."""
    events, q = [], CAPTURE["queue"]
    if q is None:
        return []
    while True:
        try:
            e = q.get_nowait()
        except queue.Empty:
            break
        events.append(e)
    return events
