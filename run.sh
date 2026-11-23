#!/bin/zsh
# Start the Mini-IDS stack. The backend serves the dashboard, so one
# process runs "both" frontend and backend.
#
#   ./run.sh            normal run - dashboard + simulated traffic
#   ./run.sh capture    run with sudo so real packet capture is available
#                       (the dashboard's Live-capture toggle needs /dev/bpf*)

set -e

DIR="${0:A:h}"
cd "$DIR"

PY="$DIR/.venv/bin/python"
if [ ! -x "$PY" ]; then
    echo "Creating virtualenv (.venv) ..."
    python3 -m venv .venv
    echo "Installing dependencies (fastapi, uvicorn, scapy) ..."
    .venv/bin/pip -q install fastapi uvicorn scapy
fi
PORT="${PORT:-8000}"

if [ "$1" = "capture" ]; then
    CMD=(sudo "$PY" -m uvicorn backend.main:app --port "$PORT")
else
    CMD=("$PY" -m uvicorn backend.main:app --port "$PORT")
fi

if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN > /dev/null 2>&1; then
    echo "Port $PORT is already in use - kill the old server first, e.g.:"
    echo "  lsof -t -iTCP:$PORT -sTCP:LISTEN | xargs kill"
    exit 1
fi

echo "Mini-IDS starting on http://127.0.0.1:$PORT  (Ctrl+C to stop)"
(open "http://127.0.0.1:$PORT" 2>/dev/null || true) &

"${CMD[@]}"
