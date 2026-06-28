#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
E2E_BIN="/tmp/e2e_server"
BENCH_DIR="$REPO_ROOT/bench/go_client/bench_h3"

SEQ_N="${SEQ_N:-300}"
CONC_N="${CONC_N:-1000}"
CONC_C="${CONC_C:-50}"
TP_N="${TP_N:-20}"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "==> Killing any leftover servers on :4433 / :4444..."
pkill -f "/tmp/e2e_server" 2>/dev/null || true
fuser -k 4433/udp 2>/dev/null || true
fuser -k 4444/udp 2>/dev/null || true
sleep 0.3

echo "==> Building Crystal e2e server (--release)..."
cd "$REPO_ROOT"
crystal build examples/e2e_server.cr -o "$E2E_BIN" --release

echo "==> Building Go benchmark..."
cd "$BENCH_DIR"
go build -o bench_h3 .

echo "==> Starting Crystal server on :4433..."
GC_INITIAL_HEAP_SIZE=100M "$E2E_BIN" &
SERVER_PID=$!
sleep 0.8

echo "==> Running benchmark..."
cd "$BENCH_DIR"
./bench_h3 -seq-n "$SEQ_N" -conc-n "$CONC_N" -conc-c "$CONC_C" -tp-n "$TP_N"
