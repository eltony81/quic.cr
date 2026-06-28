#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
E2E_BIN="/tmp/e2e_server"
BENCH_DIR="$REPO_ROOT/bench/go_client/bench_h3"

SEQ_N="${SEQ_N:-300}"
CONC_N="${CONC_N:-1000}"
CONC_C="${CONC_C:-50}"
TP_N="${TP_N:-20}"

SERVER_PIDS=()
cleanup() {
  for pid in "${SERVER_PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT

echo "==> Killing any leftover servers on :4433 / :4444..."
pkill -f "/tmp/e2e_server" 2>/dev/null || true
pkill -f "bench_h3" 2>/dev/null || true
fuser -k 4433/udp 2>/dev/null || true
fuser -k 4444/udp 2>/dev/null || true
sleep 0.3

echo "==> Building Crystal e2e server (--release)..."
cd "$REPO_ROOT"
crystal build examples/e2e_server.cr -o "$E2E_BIN" --release

echo "==> Building Go benchmark..."
cd "$BENCH_DIR"
go build -o bench_h3 .

echo "==> Starting Crystal server on :4433 (4 instances, SO_REUSEPORT)..."
for i in {1..4}; do
  GC_INITIAL_HEAP_SIZE=100M "$E2E_BIN" &
  SERVER_PIDS+=($!)
done

echo "==> Starting Go server on :4444..."
cd "$BENCH_DIR"
./bench_h3 -server &
SERVER_PIDS+=($!)

sleep 0.8

# Memory monitor function
monitor_mem() {
  local pids=("$@")
  local go_pid="${pids[-1]}"
  local len=${#pids[@]}
  local cry_pids=("${pids[@]:0:$((len-1))}")
  
  local peak_crystal=0
  local peak_go=0
  
  # When killed, save results and exit
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

echo "==> Starting memory monitor..."
monitor_mem "${SERVER_PIDS[@]}" &
MONITOR_PID=$!

echo "==> Running benchmark..."
cd "$BENCH_DIR"
./bench_h3 -seq-n "$SEQ_N" -conc-n "$CONC_N" -conc-c "$CONC_C" -tp-n "$TP_N"

# Terminate memory monitor and read results
kill -TERM "$MONITOR_PID" 2>/dev/null || true
wait "$MONITOR_PID" 2>/dev/null || true

CRYSTAL_MB=$(awk "BEGIN {printf \"%.1f\", $(cat /tmp/peak_crystal || echo 0)/1024}")
GO_MB=$(awk "BEGIN {printf \"%.1f\", $(cat /tmp/peak_go || echo 0)/1024}")

echo ""
echo "┌────────────────────────────────────────────────────────────────┐"
echo "│         Memory Usage (Peak RSS) During Benchmark               │"
echo "├──────────────────────────────┬──────────────────┬──────────────┤"
echo "│  Crystal quic.cr (4 procs)   │  $CRYSTAL_MB MB         │"
echo "│  Go quic-go (1 proc)         │  $GO_MB MB         │"
echo "└──────────────────────────────┴──────────────────┴──────────────┘"

