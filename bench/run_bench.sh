#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
E2E_BIN="/tmp/e2e_server"
BENCH_DIR="$REPO_ROOT/bench/go_client/bench_h3"

SEQ_N="${SEQ_N:-300}"
CONC_N="${CONC_N:-1000}"
CONC_C="${CONC_C:-50}"
TP_N="${TP_N:-20}"

echo "==> Building Crystal e2e server (--release)..."
cd "$REPO_ROOT"
crystal build examples/e2e_server.cr -o "$E2E_BIN" --release

echo "==> Building Go benchmark..."
cd "$BENCH_DIR"
go build -o bench_h3 .

# Memory monitor function
monitor_mem() {
  local pids=("$@")
  local go_pid="${pids[-1]}"
  local len=${#pids[@]}
  local cry_pids=("${pids[@]:0:$((len-1))}")
  
  local peak_crystal=0
  local peak_go=0
  
  trap '
    echo "$peak_crystal" > /tmp/peak_crystal
    echo "$peak_go" > /tmp/peak_go
    exit 0
  ' TERM
  
  while true; do
    local cry_total=0
    for pid in "${cry_pids[@]}"; do
      local rss=$(ps -o rss= -p "$pid" 2>/dev/null | awk "{print \$1}" || echo 0)
      cry_total=$((cry_total + rss))
    done
    if [ "$cry_total" -gt "$peak_crystal" ]; then
      peak_crystal=$cry_total
    fi

    local go_rss=$(ps -o rss= -p "$go_pid" 2>/dev/null | awk "{print \$1}" || echo 0)
    if [ "$go_rss" -gt "$peak_go" ]; then
      peak_go=$go_rss
    fi
    sleep 0.05
  done
}

run_scenario() {
  local workers=$1
  local mode_desc=$2
  local server_pids=()

  echo ""
  echo "=========================================================================="
  echo " SCENARIO: Crystal ($mode_desc) vs Go"
  echo "=========================================================================="

  echo "==> Killing any leftover servers on :4433 / :4444..."
  pkill -f "/tmp/e2e_server" 2>/dev/null || true
  pkill -f "bench_h3" 2>/dev/null || true
  fuser -k 4433/udp 2>/dev/null || true
  fuser -k 4444/udp 2>/dev/null || true
  sleep 0.3

  echo "==> Starting Crystal server on :4433 ($workers workers)..."
  for ((i=1; i<=workers; i++)); do
    "$E2E_BIN" &
    server_pids+=($!)
  done

  echo "==> Starting Go server on :4444..."
  ./bench_h3 -server &
  server_pids+=($!)

  sleep 0.8
  
  # Check ports are active
  fuser 4433/udp >/dev/null 2>&1 || (echo "Crystal failed to start" && exit 1)
  fuser 4444/udp >/dev/null 2>&1 || (echo "Go failed to start" && exit 1)

  echo "==> Starting memory monitor..."
  monitor_mem "${server_pids[@]}" &
  local monitor_pid=$!

  echo "==> Running benchmark..."
  ./bench_h3 -seq-n "$SEQ_N" -conc-n "$CONC_N" -conc-c "$CONC_C" -tp-n "$TP_N"

  # Stop memory monitor
  kill -TERM "$monitor_pid" 2>/dev/null || true
  wait "$monitor_pid" 2>/dev/null || true

  # Stop servers
  for pid in "${server_pids[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  sleep 0.2

  local cry_rss=$(cat /tmp/peak_crystal || echo 0)
  local go_rss=$(cat /tmp/peak_go || echo 0)
  local crystal_mb=$(awk "BEGIN {printf \"%.1f\", $cry_rss/1024}")
  local go_mb=$(awk "BEGIN {printf \"%.1f\", $go_rss/1024}")

  echo ""
  echo "┌────────────────────────────────────────────────────────────────┐"
  echo "│         Memory Usage (Peak RSS) - $mode_desc           "
  echo "├──────────────────────────────┬──────────────────┬──────────────┤"
  echo "│  Crystal quic.cr ($workers workers) │  $crystal_mb MB         │"
  echo "│  Go quic-go (1 proc)         │  $go_mb MB         │"
  echo "└──────────────────────────────┴──────────────────┴──────────────┘"
  echo ""
}

# Scenario 1: Crystal Single Process (No SO_REUSEPORT)
run_scenario 1 "Single-Process / No SO_REUSEPORT"

# Scenario 2: Crystal Multi-Process (4 workers using SO_REUSEPORT)
run_scenario 4 "Multi-Process / SO_REUSEPORT"
