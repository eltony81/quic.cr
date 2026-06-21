#!/usr/bin/env python3
"""
HTTP/3 Benchmark: quic.cr (Crystal) vs quic-go (Go)
=====================================================
Launches both servers, sends identical workloads via aioquic,
measures end-to-end latency, prints a comparison report.

Usage (from repo root):
    source venv/bin/activate
    python benchmark/bench.py [--requests N] [--concurrency C] [--warmup W]

Build servers first:
    crystal build benchmark/crystal_server.cr -o benchmark/crystal_server --release
    cd benchmark/go-server && go build -o ../go_server .
"""

import argparse
import asyncio
import json
import os
import signal
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

from aioquic.asyncio import QuicConnectionProtocol
from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR   = os.path.dirname(SCRIPT_DIR)
CERT       = os.path.join(REPO_DIR, "cert.pem")
KEY        = os.path.join(REPO_DIR, "key.pem")

CRYSTAL_BIN  = os.path.join(SCRIPT_DIR, "crystal_server")
GO_BIN       = os.path.join(SCRIPT_DIR, "go_server")
CRYSTAL_PORT = 4433
GO_PORT      = 4434

B  = "\033[1m"
R  = "\033[0m"
GR = "\033[32m"
CY = "\033[36m"
YE = "\033[33m"
RE = "\033[31m"


# ─── aioquic HTTP/3 client (matches working pattern in validate_cross_tests.py) ──

class H3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3_conn = H3Connection(self._quic)
        self.h3_events: list = []
        self.h3_stream_ended: set = set()

    def quic_event_received(self, event):
        for h3_event in self.h3_conn.handle_event(event):
            self.h3_events.append(h3_event)
            if getattr(h3_event, "stream_ended", False):
                self.h3_stream_ended.add(h3_event.stream_id)
        super().quic_event_received(event)


def make_config() -> QuicConfiguration:
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode   = False
    cfg.max_data      = 10_000_000
    cfg.max_stream_data = 10_000_000
    return cfg


async def h3_request(
    port: int, method: str, path: str,
    body: Optional[bytes] = None,
    content_type: str = "application/octet-stream",
) -> tuple[int, bytes]:
    """Single HTTP/3 request; returns (status_int, body_bytes)."""
    host = f"127.0.0.1:{port}"

    async with connect("127.0.0.1", port, configuration=make_config(),
                       create_protocol=H3ClientProtocol) as client:
        stream_id = client._quic.get_next_available_stream_id()

        req_headers = [
            (b":method",    method.encode()),
            (b":scheme",    b"https"),
            (b":authority", host.encode()),
            (b":path",      path.encode()),
            (b"user-agent", b"bench.py/1.0"),
        ]
        if body is not None:
            req_headers += [
                (b"content-type",   content_type.encode()),
                (b"content-length", str(len(body)).encode()),
            ]

        client.h3_conn.send_headers(stream_id=stream_id, headers=req_headers,
                                    end_stream=(body is None))
        if body is not None:
            client.h3_conn.send_data(stream_id=stream_id, data=body, end_stream=True)
        client.transmit()

        deadline = time.time() + 10.0
        while stream_id not in client.h3_stream_ended:
            await asyncio.sleep(0.005)
            if time.time() > deadline:
                raise TimeoutError(f"{method} {path} timed out")

        resp_headers = []
        resp_body    = bytearray()
        for ev in client.h3_events:
            if ev.stream_id != stream_id:
                continue
            if isinstance(ev, HeadersReceived):
                resp_headers = ev.headers
            elif isinstance(ev, DataReceived):
                resp_body.extend(ev.data)

        status = int(next((v for k, v in resp_headers if k == b":status"), b"500"))
        return status, bytes(resp_body)


async def timed_request(port: int, method: str, path: str, body: Optional[bytes]) -> Optional[float]:
    """Wraps h3_request and returns wall-clock latency in ms, or None on error."""
    t0 = time.perf_counter()
    try:
        await h3_request(port, method, path, body,
                         content_type="application/json" if body else "application/octet-stream")
        return (time.perf_counter() - t0) * 1000.0
    except Exception:
        return None


async def run_scenario(
    port: int, method: str, path: str,
    n: int, concurrency: int, body: Optional[bytes],
) -> list[float]:
    sem = asyncio.Semaphore(concurrency)

    async def bounded() -> Optional[float]:
        async with sem:
            return await timed_request(port, method, path, body)

    results = await asyncio.gather(*[bounded() for _ in range(n)])
    return [r for r in results if r is not None]


# ─── Process management ───────────────────────────────────────────────────────

def start_server(cmd: list[str], name: str, port: int, settle: float = 2.0) -> subprocess.Popen:
    log_path = os.path.join(SCRIPT_DIR, f"{name.lower()}_bench.log")
    with open(log_path, "w") as lf:
        proc = subprocess.Popen(cmd, stdout=lf, stderr=lf)
    time.sleep(settle)
    if proc.poll() is not None:
        raise RuntimeError(f"{name} exited immediately — see {log_path}")
    print(f"  {GR}✓{R} {name} started  (pid {proc.pid}, :{port})")
    return proc


def stop_server(proc: subprocess.Popen, name: str):
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    print(f"  {YE}•{R} {name} stopped")


# ─── Stats ────────────────────────────────────────────────────────────────────

@dataclass
class Stats:
    label: str
    latencies: list[float] = field(default_factory=list)

    @property
    def n(self):      return len(self.latencies)
    @property
    def mean(self):   return statistics.mean(self.latencies)   if self.latencies else float("nan")
    @property
    def median(self): return statistics.median(self.latencies) if self.latencies else float("nan")
    @property
    def p95(self):
        if not self.latencies: return float("nan")
        return sorted(self.latencies)[int(len(self.latencies) * 0.95)]
    @property
    def p99(self):
        if not self.latencies: return float("nan")
        return sorted(self.latencies)[int(len(self.latencies) * 0.99)]
    @property
    def stdev(self):  return statistics.stdev(self.latencies) if len(self.latencies) > 1 else 0.0
    @property
    def rps(self):    return 1000.0 / self.mean if self.mean else float("nan")


def print_comparison(c: Stats, g: Stats):
    def row(metric, cv, gv, unit="ms", lower_is_better=True):
        better_c = cv < gv if lower_is_better else cv > gv
        c_col = GR if better_c else (RE if cv != gv else CY)
        g_col = GR if not better_c else (RE if cv != gv else CY)
        delta = abs(cv - gv) / gv * 100 if gv else 0
        winner = "Crystal" if better_c else "Go"
        return (f"  {B}{metric:<14}{R}"
                f"  {c_col}{cv:>9.2f} {unit}{R}"
                f"  {g_col}{gv:>9.2f} {unit}{R}"
                f"  {delta:>5.1f}%  {winner}")

    print(f"\n  {B}{'Metric':<14}  {'Crystal quic.cr':>14}  {'Go quic-go':>13}  Δ     Winner{R}")
    print("  " + "─" * 65)
    print(row("Mean",        c.mean,   g.mean))
    print(row("Median p50",  c.median, g.median))
    print(row("p95",         c.p95,    g.p95))
    print(row("p99",         c.p99,    g.p99))
    print(row("Stdev",       c.stdev,  g.stdev))
    print(row("Req/s (est)", c.rps,    g.rps, unit="req/s", lower_is_better=False))
    print(f"  {'Samples':<14}  {c.n:>14}  {g.n:>13}")


# ─── Scenarios ────────────────────────────────────────────────────────────────

SCENARIOS = [
    ("GET /  (HTML)",         "GET",  "/",             None),
    ("GET /greet (JSON)",     "GET",  "/greet?name=Bench", None),
    ("GET /users/42 (param)", "GET",  "/users/42",     None),
    ("POST 1 KB JSON",        "POST", "/echo",         lambda: json.dumps({"k": "v" * 512}).encode()),
    ("POST 64 KB",            "POST", "/echo",         lambda: b'{"d":"' + b"x" * 65000 + b'"}'),
]


# ─── Main ─────────────────────────────────────────────────────────────────────

async def main_async(args):
    print(f"\n{B}{CY}{'═' * 68}{R}")
    print(f"{B}{CY}  HTTP/3 Benchmark  ·  quic.cr (Crystal)  vs  quic-go (Go){R}")
    print(f"{B}{CY}{'═' * 68}{R}")
    print(f"  n={args.requests}  concurrency={args.concurrency}  warmup={args.warmup}")

    for path, var in [(CRYSTAL_BIN, "crystal_server"), (GO_BIN, "go_server")]:
        if not os.path.isfile(path):
            print(f"\n  {RE}✗{R}  {path} not found.")
            sys.exit(1)

    print(f"\n{B}Starting servers…{R}")
    crystal_proc = start_server([CRYSTAL_BIN], "Crystal", CRYSTAL_PORT)
    go_proc      = start_server(
        [GO_BIN, f"-port={GO_PORT}", f"-cert={CERT}", f"-key={KEY}"],
        "Go", GO_PORT
    )

    all_results: dict = {}
    crystal_total_wins = 0
    go_total_wins = 0

    try:
        for (sc_label, method, path, body_fn) in SCENARIOS:
            body = body_fn() if body_fn else None

            print(f"\n{B}━━ {sc_label} ━━{R}")

            if args.warmup > 0:
                print(f"  warmup ({args.warmup}×)…", end="", flush=True)
                wc = asyncio.Semaphore(min(args.concurrency, 4))
                async def warm(port, bdy=body):
                    async with wc:
                        await timed_request(port, method, path, bdy)
                await asyncio.gather(*[warm(CRYSTAL_PORT) for _ in range(args.warmup)],
                                     *[warm(GO_PORT)      for _ in range(args.warmup)])
                print(" done")

            print(f"  Crystal …", end="", flush=True)
            c_lats = await run_scenario(CRYSTAL_PORT, method, path, args.requests, args.concurrency, body)
            print(f" {len(c_lats)}/{args.requests} ok")

            print(f"  Go      …", end="", flush=True)
            g_lats = await run_scenario(GO_PORT, method, path, args.requests, args.concurrency, body)
            print(f" {len(g_lats)}/{args.requests} ok")

            c_stats = Stats(f"Crystal {sc_label}", c_lats)
            g_stats = Stats(f"Go {sc_label}",      g_lats)
            print_comparison(c_stats, g_stats)

            if c_stats.median < g_stats.median:
                crystal_total_wins += 1
            elif g_stats.median < c_stats.median:
                go_total_wins += 1

            all_results[sc_label] = {
                "crystal": {k: round(v, 3) for k, v in {
                    "mean_ms": c_stats.mean, "median_ms": c_stats.median,
                    "p95_ms": c_stats.p95,   "p99_ms": c_stats.p99,
                    "stdev_ms": c_stats.stdev, "rps": c_stats.rps, "n": c_stats.n,
                }.items()},
                "go": {k: round(v, 3) for k, v in {
                    "mean_ms": g_stats.mean, "median_ms": g_stats.median,
                    "p95_ms": g_stats.p95,   "p99_ms": g_stats.p99,
                    "stdev_ms": g_stats.stdev, "rps": g_stats.rps, "n": g_stats.n,
                }.items()},
            }

        # ── Summary ─────────────────────────────────────────────────────────
        print(f"\n{B}{CY}{'═' * 68}{R}")
        print(f"{B}{CY}  Summary — median latency per scenario{R}")
        print(f"{B}{CY}{'═' * 68}{R}")
        print(f"\n  {B}{'Scenario':<28}  {'Crystal p50':>12}  {'Go p50':>10}  Winner{R}")
        print("  " + "─" * 65)
        for sc_label, sc in all_results.items():
            c_p50 = sc["crystal"]["median_ms"]
            g_p50 = sc["go"]["median_ms"]
            if c_p50 < g_p50:
                w = f"{GR}Crystal{R}"
            elif g_p50 < c_p50:
                w = f"{GR}Go{R}"
            else:
                w = f"{CY}Tie{R}"
            print(f"  {sc_label:<28}  {c_p50:>10.2f} ms  {g_p50:>8.2f} ms  {w}")

        total = len(all_results)
        print(f"\n  Crystal wins: {crystal_total_wins}/{total}  |  Go wins: {go_total_wins}/{total}")
        print()

        out_path = os.path.join(SCRIPT_DIR, "results", "benchmark.json")
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w") as f:
            json.dump({"meta": {"requests": args.requests, "concurrency": args.concurrency,
                                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                                "aioquic_client": True},
                       "scenarios": all_results}, f, indent=2)
        print(f"  Results → {out_path}")

    finally:
        print(f"\n{B}Stopping servers…{R}")
        stop_server(crystal_proc, "Crystal")
        stop_server(go_proc, "Go")


def main():
    p = argparse.ArgumentParser(description="HTTP/3 benchmark: quic.cr vs quic-go")
    p.add_argument("--requests",    "-n", type=int, default=50, help="Requests per scenario (default 50)")
    p.add_argument("--concurrency", "-c", type=int, default=5,  help="Concurrent connections (default 5)")
    p.add_argument("--warmup",      "-w", type=int, default=5,  help="Warmup requests (default 5)")
    asyncio.run(main_async(p.parse_args()))


if __name__ == "__main__":
    main()
