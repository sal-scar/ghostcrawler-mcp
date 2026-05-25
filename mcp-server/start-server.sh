#!/bin/bash
# GhostCrawler MCP server — starts as a true daemon (survives terminal close)
# Usage: ./start-server.sh [start|stop|restart|status]

NODE_BIN="/tmp/node-v20.19.1-darwin-x64/bin/node"
# Fallback to system node if the above doesn't exist
if [ ! -f "$NODE_BIN" ]; then
  NODE_BIN="$(command -v node)"
fi

SERVER_DIR="$(cd "$(dirname "$0")" && pwd)"
DIST="$SERVER_DIR/dist/index.js"
STDOUT_LOG="/tmp/gc-stdout.log"
STDERR_LOG="/tmp/gc-stderr.log"
PID_FILE="/tmp/gc-server.pid"
PORT=3200

# ── helpers ─────────────────────────────────────────────────────────────────
is_running() {
  [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

do_stop() {
  if is_running; then
    PID="$(cat "$PID_FILE")"
    echo "Stopping GhostCrawler server (PID $PID)…"
    kill "$PID" 2>/dev/null
    sleep 1
    # Force-kill if still alive
    if kill -0 "$PID" 2>/dev/null; then kill -9 "$PID" 2>/dev/null; fi
    rm -f "$PID_FILE"
    echo "Stopped."
  else
    echo "Server is not running."
    # Kill any stale process still holding the port
    STALE="$(lsof -ti tcp:$PORT 2>/dev/null)"
    if [ -n "$STALE" ]; then
      echo "Killing stale process on port $PORT (PID $STALE)"
      kill "$STALE" 2>/dev/null
      sleep 0.5
    fi
  fi
}

do_start() {
  if is_running; then
    echo "Server already running (PID $(cat $PID_FILE))."
    return 0
  fi

  # Make sure port is free
  STALE="$(lsof -ti tcp:$PORT 2>/dev/null)"
  if [ -n "$STALE" ]; then
    echo "Port $PORT held by PID $STALE — killing…"
    kill "$STALE" 2>/dev/null
    sleep 1
  fi

  echo "Starting GhostCrawler server (node: $NODE_BIN)…"
  # nohup prevents SIGHUP when the terminal closes (macOS compatible)
  nohup "$NODE_BIN" "$DIST" >> "$STDOUT_LOG" 2>> "$STDERR_LOG" &
  echo $! > "$PID_FILE"
  sleep 1
  if is_running; then
    echo "Server started (PID $(cat $PID_FILE))."
    echo "Logs: $STDOUT_LOG  $STDERR_LOG"
  else
    echo "ERROR: Server failed to start. Check $STDERR_LOG"
    exit 1
  fi
}

# ── main ────────────────────────────────────────────────────────────────────
CMD="${1:-start}"

case "$CMD" in
  start)   do_start ;;
  stop)    do_stop ;;
  restart) do_stop; sleep 2; do_start ;;
  status)
    if is_running; then
      echo "Running (PID $(cat $PID_FILE))"
    else
      echo "Not running"
    fi
    ;;
  *)
    echo "Usage: $0 [start|stop|restart|status]"
    exit 1
    ;;
esac
