/* Mini-IDS frontend logic: icon-rail tab switching, Falco-style area
   charts, and rendering of API data. All state lives in the backend;
   the page just shows what the API returns. */

const $ = (id) => document.getElementById(id);

/* ---------- tab switching (icon rail) ---------- */
document.querySelectorAll(".tab").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    $(btn.dataset.tab).classList.add("active");
  });
});

/* ---------- render helpers ---------- */
function esc(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

function row(html) {
  const tr = document.createElement("tr");
  tr.innerHTML = html;
  return tr;
}

function fmtTime(iso) {
  return iso.replace("T", " ").split(".")[0];
}

function sevBadge(sev) {
  return `<span class="badge ${sev}">${sev}</span>`;
}

function alertRow(a) {
  return row(`
    <td>${a.id}</td>
    <td class="mono">${fmtTime(a.ts)}</td>
    <td>${sevBadge(a.severity)}</td>
    <td>${esc(a.rule_name)}</td>
    <td><span class="src">${esc(a.src_ip)}</span></td>
    <td>${esc(a.detail)}</td>`);
}

function eventRow(e) {
  const live = e.origin ? `<span class="live">LIVE</span>` : "";
  return row(`
    <td>${e.id}</td>
    <td class="mono">${fmtTime(e.ts)}</td>
    <td class="mono">${live}${esc(e.src_ip)}</td>
    <td>${esc(e.action)}</td>
    <td>${esc(e.target)}</td>
    <td>${e.dst_port}</td>
    <td class="${e.success ? "ok" : "fail"}">${e.success ? "yes" : "no"}</td>`);
}

function updateEmpty() {
  $("alerts-empty").style.display =
    document.querySelectorAll("#alerts-body tr").length ? "none" : "";
  $("events-empty").style.display =
    document.querySelectorAll("#events-body tr").length ? "none" : "";
}

/* ---------- area charts (Falco-style stacked series) ---------- */
const MAX_POINTS = 240;

function makeChart(canvasId, legendId, seriesDefs) {
  const canvas = $(canvasId), legendEl = $(legendId);
  const chart = {
    canvas, ctx: canvas.getContext("2d"),
    series: seriesDefs.map(s => ({ ...s, data: [], on: true, sum: 0 })),
    times: [], lastSample: null,
  };
  const legend = chart.series.map(s => {
    const el = document.createElement("div");
    el.className = "lrow";
    el.innerHTML =
      `<span class="dot" style="background:${s.color}"></span>` +
      `<span class="lname">${s.name}</span><span class="lval">0</span>`;
    el.title = "click to show/hide";
    el.addEventListener("click", () => {
      s.on = !s.on;
      el.classList.toggle("off", !s.on);
      drawChart(chart);
    });
    legendEl.append(el);
    return el;
  });
  chart.legend = legend;
  window.addEventListener("resize", () => drawChart(chart));
  drawChart(chart);
  return chart;
}

function sampleChart(chart, counts, ts) {
  if (chart.lastSample === null) chart.lastSample = ts;
  chart.times.push(ts);
  chart.series.forEach((s, i) => {
    const v = counts[i] || 0;
    s.data.push(v);
    s.sum += v;
    if (s.data.length > MAX_POINTS) s.data.shift();
  });
  if (chart.times.length > MAX_POINTS) chart.times.shift();
  chart.series.forEach((s, i) => {
    const valEl = chart.legend[i].querySelector(".lval");
    valEl.textContent = s.sum >= 10000 ? `${(s.sum / 1000).toFixed(1)}k` : s.sum;
  });
  drawChart(chart);
}

function drawChart(chart) {
  const { canvas, ctx, series, times } = chart;
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (!w || !h) return;
  canvas.width = w * dpr;
  canvas.height = h * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);

  const padL = 34, padR = 6, padT = 8, padB = 18;
  const gw = w - padL - padR, gh = h - padT - padB;

  const n = times.length;
  let peak = 4;
  series.forEach(s => { if (s.on) s.data.forEach(v => { if (v > peak) peak = v; }); });
  peak = Math.ceil(peak / 4) * 4;

  ctx.font = "10px " + getComputedStyle(document.body).getPropertyValue("--mono");
  ctx.textAlign = "right";
  ctx.strokeStyle = "#26292f";
  ctx.fillStyle = "#6c737d";
  ctx.lineWidth = 1;
  const rows = 4;
  for (let r = 0; r <= rows; r++) {
    const y = padT + gh - (gh * r) / rows;
    ctx.beginPath();
    ctx.moveTo(padL, y - .5);
    ctx.lineTo(padL + gw, y - .5);
    ctx.stroke();
    ctx.fillText(String(peak * r / rows), padL - 5, y + 3);
  }

  /* x axis: time labels about every 1/6 of the history */
  ctx.textAlign = "center";
  if (n > 1) {
    for (let k = 1; k < 6; k++) {
      const idx = Math.floor((n - 1) * k / 6);
      const x = padL + (gw * idx) / (n - 1);
      ctx.fillText(fmtClock(times[idx]), x, h - 5);
    }
  }

  /* stacked areas, bottom-up in series order */
  const nSeries = series.length;
  let base = new Array(n).fill(0);
  series.forEach(s => {
    if (!s.on) return;
    const layer = new Array(n).fill(0);
    for (let i = 0; i < n; i++) layer[i] = base[i] + s.data[i];
    ctx.beginPath();
    for (let i = 0; i < n; i++) {
      const x = padL + (n > 1 ? (gw * i) / (n - 1) : 0);
      const y = padT + gh - (Math.min(layer[i], peak) / peak) * gh;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    }
    for (let i = n - 1; i >= 0; i--) {
      const x = padL + (n > 1 ? (gw * i) / (n - 1) : 0);
      const y = padT + gh - (Math.min(base[i], peak) / peak) * gh;
      ctx.lineTo(x, y);
    }
    ctx.closePath();
    ctx.fillStyle = s.fill;
    ctx.fill();
    ctx.beginPath();
    for (let i = 0; i < n; i++) {
      const x = padL + (n > 1 ? (gw * i) / (n - 1) : 0);
      const y = padT + gh - (Math.min(layer[i], peak) / peak) * gh;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    }
    ctx.strokeStyle = s.color;
    ctx.lineWidth = 1.4;
    ctx.stroke();
    base = layer;
  });
}

function fmtClock(ts) {
  const d = typeof ts === "number" ? new Date(ts) : parseTs(ts);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  return `${hh}:${mm}`;
}

/* Safari parses naive "2026-10-27T18:44:53" inconsistently - build the
   Date explicitly so chart axes always show local wall-clock time. */
function parseTs(ts) {
  const m = ts.match(/^(\d+)-(\d+)-(\d+)T(\d+):(\d+):(\d+)/);
  if (m) return new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
  return new Date(ts);
}

/* event-type classifier for the first chart */
const SQLI_RE = /('|--|UNION SELECT|OR 1=1|SLEEP\(|;--)/i;
function eventSeriesIndex(e) {
  if (e.action === "port_probe") return 0;               // Port probes
  if (e.action === "http_request") {
    return (e.target && SQLI_RE.test(e.target)) ? 2 : 1; // SQLi : plain HTTP
  }
  if (e.action === "login_attempt") return e.success ? 4 : 3;
  return 1;
}

function alertSeriesIndex(a) {
  return ["Critical", "High", "Medium", "Low"].indexOf(a.severity);
}

let chartEvents, chartAlerts;

function sampleTick(events, alerts) {
  const now = Date.now();
  if (chartEvents) {
    const counts = [0, 0, 0, 0, 0];
    events.forEach(e => counts[eventSeriesIndex(e)]++);
    sampleChart(chartEvents, counts, now);
  }
  if (chartAlerts) {
    const counts = [0, 0, 0, 0];
    alerts.forEach(a => counts[alertSeriesIndex(a)]++);
    sampleChart(chartAlerts, counts, now);
  }
}

/* Backfill both charts from the recorded history the API returns on load,
   bucketed into ~2 s slots so the chart shows the real traffic shape
   before the first tick arrives. */
function backfillCharts(events, alerts) {
  try {
    const EVERY = 2000;
    const items = [
      ...events.map(e => ({ ts: e.ts, kind: "e", obj: e })),
      ...alerts.map(a => ({ ts: a.ts, kind: "a", obj: a })),
    ].sort((x, y) => (x.ts < y.ts ? -1 : 1));
    if (!items.length) return;

    /* Anchor the window to the newest recorded event and walk backwards,
       so the axis follows the data's own clock rather than the browser's. */
    const tEnd = parseTs(items[items.length - 1].ts).getTime();
    const tStart = tEnd - MAX_POINTS * EVERY;
    const nb = MAX_POINTS;
    const ev = Array.from({ length: nb }, () => [0, 0, 0, 0, 0]);
    const al = Array.from({ length: nb }, () => [0, 0, 0, 0]);
    items.forEach(it => {
      const bi = Math.max(0, Math.min(nb - 1,
        Math.floor((parseTs(it.ts).getTime() - tStart) / EVERY)));
      (it.kind === "e" ? ev : al)[bi]
        [it.kind === "e" ? eventSeriesIndex(it.obj) : alertSeriesIndex(it.obj)]++;
    });
    /* skip leading empty buckets so the series starts at the first activity */
    let first = 0;
    while (first < nb && ev[first].every(v => !v) && al[first].every(v => !v)) {
      first++;
    }
    for (let b = first; b < nb; b++) {
      sampleChart(chartEvents, ev[b], tStart + b * EVERY);
      sampleChart(chartAlerts, al[b], tStart + b * EVERY);
    }
  } catch (err) {
    document.title = "backfill error: " + err.message;
  }
}

/* ---------- API interaction ---------- */
async function refreshStats() {
  const stats = await (await fetch("/stats")).json();
  const rulesData = await (await fetch("/rules")).json();
  $("stat-events").textContent = stats.events_total;
  $("stat-alerts").textContent = stats.alerts_total;
  $("stat-critical").textContent = stats.by_severity.Critical || 0;
  $("stat-ips").textContent = Object.keys(stats.alerts_by_ip).length;
  renderRules(rulesData);
  renderCapture(stats.capture);
  const n = document.querySelectorAll("#alerts-body tr").length;
  $("alerts-count").textContent = n ? `showing latest ${Math.min(n, 100)}` : "";
}

/* ---------- observation source toggle ---------- */
let mode = "simulated";

function renderCapture(cap) {
  if (!cap) return;
  const chip = $("capture-status");
  if (mode !== "capture") { chip.classList.add("hidden"); return; }
  chip.classList.remove("hidden");
  if (cap.status === "running") {
    chip.className = "chip ok";
    chip.textContent = `capturing on ${cap.iface} · ${cap.sniffed} pkts · ${cap.converted} events`;
  } else if (cap.status === "error") {
    chip.className = "chip err";
    chip.textContent = cap.detail;
  } else {
    chip.className = "chip";
    chip.textContent = cap.detail || "capture stopped";
  }
}

function renderMode() {
  $("src-sim").classList.toggle("active", mode === "simulated");
  $("src-live").classList.toggle("active", mode === "capture");
  $("btn-simulate").textContent =
    mode === "capture" ? "Drain Packets" : "Generate Traffic";
}

async function initMode() {
  try {
    const data = await (await fetch("/mode")).json();
    mode = data.mode;
    renderMode();
  } catch { /* backend offline; default stays */ }
}

async function switchMode(m) {
  $("tick-status").textContent = `switching to ${m}…`;
  try {
    const data = await (await fetch("/mode", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: m }),
    })).json();
    mode = data.mode;
    renderMode();
    /* backend reset its log on the switch - mirror that client-side, or
       leftover synthetic events would still be shown as if they were live */
    clearClientState();
    await refreshStats();
    updateEmpty();
    applySevFilter();
    if (mode === "capture" && data.capture && data.capture.status === "error") {
      $("tick-status").textContent = "capture unavailable — see the status message";
    } else if (mode === "capture") {
      $("tick-status").textContent =
        "live capture running — traffic on the machine now flows into the engine";
    } else {
      $("tick-status").textContent = "back on the simulated generator";
    }
  } catch {
    $("tick-status").textContent = "API error — is the backend running?";
  }
}

function renderRules(rulesData) {
  $("rules-list").innerHTML = rulesData.map(r => `
    <div class="rule-card sev${r.severity}">
      <div class="rule-header">
        <h3>${esc(r.name)}</h3>
        ${sevBadge(r.severity)}
        <span class="rule-triggered">triggered ${r.times_triggered}×</span>
      </div>
      <p><span class="k">Looks like:</span> ${esc(r.looks_like)}</p>
      <p><span class="k">Detect:</span> ${esc(r.detect)}</p>
      <p><span class="k">Why it matters:</span> ${esc(r.matters)}</p>
      <p><span class="k">Threshold:</span> <span class="thr">${esc(r.threshold)}</span></p>
    </div>`).join("");
}

async function simulate() {
  const btn = $("btn-simulate");
  btn.disabled = true;
  $("tick-status").textContent =
    mode === "capture" ? "draining packets…" : "generating…";
  try {
    const data = await (await fetch("/simulate", { method: "POST" })).json();
    const aBody = $("alerts-body");
    const eBody = $("events-body");
    /* API returns oldest->newest; prepend reversed so newest ends up on top */
    [...data.new_alerts].reverse().forEach(a => aBody.prepend(alertRow(a)));
    [...data.new_events].reverse().forEach(e => eBody.prepend(eventRow(e)));
    while (eBody.children.length > 100) eBody.deleteRow(-1);
    await refreshStats();
    updateEmpty();
    applySevFilter();
    sampleTick(data.new_events, data.new_alerts);
    $("tick-status").textContent =
      `+${data.new_events.length} events · ${data.new_alerts.length} alert(s)`;
  } catch {
    $("tick-status").textContent = "API error — is the backend running?";
  } finally {
    btn.disabled = false;
  }
}

function clearClientState() {
  $("alerts-body").innerHTML = "";
  $("events-body").innerHTML = "";
  for (const c of [chartEvents, chartAlerts]) {
    c.series.forEach(s => { s.data = []; s.on = true; s.sum = 0; });
    c.times = [];
    c.legend.forEach(el => {
      el.classList.remove("off");
      el.querySelector(".lval").textContent = "0";
    });
    drawChart(c);
  }
}

async function clearAll() {
  await fetch("/reset", { method: "POST" });
  clearClientState();
  await refreshStats();
  updateEmpty();
  applySevFilter();
  $("tick-status").textContent = "state cleared";
}

async function loadInitial() {
  const [alerts, events] = await Promise.all([
    fetch("/alerts?limit=100").then(r => r.json()),
    fetch("/events?limit=100").then(r => r.json()),
  ]);
  alerts.forEach(a => $("alerts-body").append(alertRow(a)));
  events.forEach(e => $("events-body").append(eventRow(e)));
  await refreshStats();
  updateEmpty();
  applySevFilter();
  backfillCharts(events, alerts);
}

/* ---------- severity filter (sub bar) ---------- */
function applySevFilter() {
  const val = $("sev-filter").value;
  document.querySelectorAll("#alerts-body tr").forEach(tr => {
    const sev = tr.children[2] && tr.children[2].textContent;
    tr.style.display = (!val || sev === val) ? "" : "none";
  });
}
$("sev-filter").addEventListener("change", applySevFilter);

/* ---------- wiring ---------- */
$("btn-simulate").addEventListener("click", simulate);
$("btn-reset").addEventListener("click", clearAll);
$("src-sim").addEventListener("click", () => switchMode("simulated"));
$("src-live").addEventListener("click", () => switchMode("capture"));

/* in capture mode keep the status chip fresh even without ticks */
let capPoll = null;
function watchCapture() {
  clearInterval(capPoll);
  if (mode !== "capture") return;
  capPoll = setInterval(async () => {
    try { renderCapture((await (await fetch("/mode")).json()).capture); }
    catch { clearInterval(capPoll); }
  }, 1200);
}
const _switch = switchMode;
switchMode = async (m) => { await _switch(m); watchCapture(); };

let timer = null;
$("auto-run").addEventListener("change", (e) => {
  clearInterval(timer);
  if (e.target.checked) {
    simulate();
    timer = setInterval(simulate, 1200);
  }
});

chartEvents = makeChart("chart-events", "legend-events", [
  { name: "Port probes (SYN)",          color: "#4d8ff0", fill: "rgba(77,143,240,.25)"  },
  { name: "Plain HTTP requests",        color: "#f2a33c", fill: "rgba(242,163,60,.22)"  },
  { name: "SQL-injection probes",       color: "#e8c93d", fill: "rgba(232,201,61,.20)"  },
  { name: "Failed logins (brute-force)", color: "#e2574c", fill: "rgba(226,87,76,.20)"  },
  { name: "Successful logins",          color: "#66bb6a", fill: "rgba(102,187,106,.16)" },
]);
chartAlerts = makeChart("chart-alerts", "legend-alerts", [
  { name: "Priority 1 — Critical", color: "#e2574c", fill: "rgba(226,87,76,.25)" },
  { name: "Priority 2 — High",     color: "#f2a33c", fill: "rgba(242,163,60,.22)" },
  { name: "Priority 3 — Medium",   color: "#e8c93d", fill: "rgba(232,201,61,.18)" },
  { name: "Priority 4 — Low",      color: "#66bb6a", fill: "rgba(102,187,106,.16)" },
]);

loadInitial();
initMode();
