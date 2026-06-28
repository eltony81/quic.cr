#!/usr/bin/env python3
"""
3-Way HTTP Benchmark
====================
  • quic.cr  (Crystal, HTTP/3 via QUIC)  — port 4433
  • quic-go  (Go,      HTTP/3 via QUIC)  — port 4434
  • HTTP/1.1 (Crystal, HTTPS/TCP)        — port 4435

Usage (from repo root):
    source venv/bin/activate
    python bench/bench.py [--requests N] [--concurrency C] [--warmup W]

Build servers first:
    crystal build bench/crystal_server.cr        -o bench/crystal_server --release
    crystal build bench/crystal_http_server.cr   -o bench/crystal_http_server --release
    cd bench/go_server_3way && go build -o ../go_server_3way_bin .
"""

import argparse
import asyncio
import json
import os
import signal
import ssl
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

# aioquic StreamWriter.__del__ sends FIN on GC-collected uni-directional
# streams, which raises "Cannot send data on peer-initiated unidirectional
# stream". Suppress these non-fatal exceptions to keep output clean.
_AIOQUIC_GC_ERRORS = (
    "Cannot send data on peer-initiated unidirectional stream",
    "cannot call write() after FIN",
    "cannot call write() after",
)

def _quiet_unraisable(args):
    msg = str(getattr(args, "exc_value", ""))
    if any(e in msg for e in _AIOQUIC_GC_ERRORS):
        return
    sys.__unraisablehook__(args)
sys.unraisablehook = _quiet_unraisable

from aioquic.asyncio import QuicConnectionProtocol
from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
REPO_DIR     = os.path.dirname(SCRIPT_DIR)
CERT         = os.path.join(REPO_DIR, "cert.pem")
KEY          = os.path.join(REPO_DIR, "key.pem")

CRYSTAL_H3_BIN   = os.path.join(SCRIPT_DIR, "crystal_server")
GO_BIN           = os.path.join(SCRIPT_DIR, "go_server_3way_bin")
CRYSTAL_HTTP_BIN = os.path.join(SCRIPT_DIR, "crystal_http_server")

CRYSTAL_H3_PORT   = 4433
GO_PORT           = 4434
CRYSTAL_HTTP_PORT = 4435

B  = "\033[1m"
R  = "\033[0m"
GR = "\033[32m"
CY = "\033[36m"
YE = "\033[33m"
RE = "\033[31m"

# ─── aioquic HTTP/3 client ────────────────────────────────────────────────────

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
        from aioquic.quic.events import StreamDataReceived as _SDR
        if not isinstance(event, _SDR):
            super().quic_event_received(event)


def make_quic_config() -> QuicConfiguration:
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode     = False
    cfg.max_data        = 10_000_000
    cfg.max_stream_data = 10_000_000
    return cfg


async def h3_request(
    port: int, method: str, path: str,
    body: Optional[bytes] = None,
    content_type: str = "application/octet-stream",
) -> tuple[int, bytes]:
    """Single HTTP/3 request; returns (status_int, body_bytes)."""
    host = f"127.0.0.1:{port}"
    async with connect("127.0.0.1", port, configuration=make_quic_config(),
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

        resp_headers, resp_body = [], bytearray()
        for ev in client.h3_events:
            if ev.stream_id != stream_id:
                continue
            if isinstance(ev, HeadersReceived):
                resp_headers = ev.headers
            elif isinstance(ev, DataReceived):
                resp_body.extend(ev.data)

        status = int(next((v for k, v in resp_headers if k == b":status"), b"500"))
        return status, bytes(resp_body)


# ─── asyncio HTTP/1.1+TLS client (no external deps) ─────────────────────────

_SSL_CTX: Optional[ssl.SSLContext] = None

def _get_ssl_ctx() -> ssl.SSLContext:
    global _SSL_CTX
    if _SSL_CTX is None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        _SSL_CTX = ctx
    return _SSL_CTX


async def http11_request(
    port: int, method: str, path: str,
    body: Optional[bytes] = None,
    content_type: str = "application/json",
) -> tuple[int, bytes]:
    """Single HTTPS/1.1 request; returns (status_int, body_bytes)."""
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", port, ssl=_get_ssl_ctx()
    )
    req = f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n"
    if body is not None:
        req += f"Content-Type: {content_type}\r\nContent-Length: {len(body)}\r\n"
    req += "\r\n"

    writer.write(req.encode())
    if body is not None:
        writer.write(body)
    await writer.drain()

    # Connection: close → server closes after response; read until EOF
    chunks = []
    while True:
        chunk = await reader.read(65536)
        if not chunk:
            break
        chunks.append(chunk)
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass

    data = b"".join(chunks)
    sep  = data.find(b"\r\n\r\n")
    if sep == -1:
        raise ValueError("HTTP/1.1: no header/body separator in response")

    header_section = data[:sep].decode("utf-8", errors="replace")
    resp_body      = data[sep + 4:]
    status_line    = header_section.split("\r\n")[0]
    parts          = status_line.split(" ", 2)
    status         = int(parts[1]) if len(parts) >= 2 else 500
    return status, resp_body


# ─── Timed wrappers ───────────────────────────────────────────────────────────

async def timed_h3(port: int, method: str, path: str,
                   body: Optional[bytes]) -> Optional[float]:
    t0 = time.perf_counter()
    try:
        ct = "application/json" if body else "application/octet-stream"
        await h3_request(port, method, path, body, content_type=ct)
        return (time.perf_counter() - t0) * 1000.0
    except Exception:
        return None


async def timed_http11(port: int, method: str, path: str,
                       body: Optional[bytes]) -> Optional[float]:
    t0 = time.perf_counter()
    try:
        await http11_request(port, method, path, body)
        return (time.perf_counter() - t0) * 1000.0
    except Exception:
        return None


async def run_scenario(port: int, method: str, path: str,
                       n: int, concurrency: int, body: Optional[bytes],
                       use_h3: bool = True) -> list[float]:
    sem    = asyncio.Semaphore(concurrency)
    timed  = timed_h3 if use_h3 else timed_http11

    async def bounded() -> Optional[float]:
        async with sem:
            return await timed(port, method, path, body)

    results = await asyncio.gather(*[bounded() for _ in range(n)])
    return [r for r in results if r is not None]


# ─── Process management ───────────────────────────────────────────────────────

def start_server(cmd: list[str], name: str, port: int,
                 settle: float = 2.0) -> subprocess.Popen:
    log_path = os.path.join(SCRIPT_DIR, f"{name.lower().replace(' ', '_')}_bench.log")
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

    def as_dict(self) -> dict:
        return {k: round(v, 3) for k, v in {
            "mean_ms": self.mean, "median_ms": self.median,
            "p95_ms":  self.p95,  "p99_ms":   self.p99,
            "stdev_ms": self.stdev, "rps": self.rps, "n": self.n,
        }.items()}


# ─── Pretty table ─────────────────────────────────────────────────────────────

def _color_best(values: list[float], lower_is_better: bool) -> list[str]:
    """Return ANSI color codes: GR for best, RE for worst, CY for middle."""
    if not values or any(v != v for v in values):   # nan guard
        return [CY] * len(values)
    best  = min(values) if lower_is_better else max(values)
    worst = max(values) if lower_is_better else min(values)
    colors = []
    for v in values:
        if v == best:
            colors.append(GR)
        elif v == worst:
            colors.append(RE)
        else:
            colors.append(CY)
    return colors


def print_comparison(c_h3: Stats, go: Stats, c_http: Stats):
    labels = ["Crystal H3", "Go H3", "Crystal HTTP/1.1"]
    col_w  = 17

    def row(metric: str, vals: list[float], unit: str = "ms",
            lower_is_better: bool = True) -> str:
        colors = _color_best(vals, lower_is_better)
        cells  = "".join(
            f"  {colors[i]}{v:>{col_w - 2}.2f} {unit}{R}"
            for i, v in enumerate(vals)
        )
        return f"  {B}{metric:<12}{R}{cells}"

    header_cells = "".join(f"  {B}{lbl:>{col_w}}{R}" for lbl in labels)
    print(f"\n  {B}{'Metric':<12}{R}{header_cells}")
    print("  " + "─" * (14 + col_w * 3))

    ms  = "ms"
    rps = "req/s"
    print(row("Mean",        [c_h3.mean,   go.mean,   c_http.mean]))
    print(row("Median p50",  [c_h3.median, go.median, c_http.median]))
    print(row("p95",         [c_h3.p95,    go.p95,    c_http.p95]))
    print(row("p99",         [c_h3.p99,    go.p99,    c_http.p99]))
    print(row("Stdev",       [c_h3.stdev,  go.stdev,  c_http.stdev]))
    print(row("Req/s",       [c_h3.rps,    go.rps,    c_http.rps],
              unit=rps, lower_is_better=False))

    sample_cells = "".join(f"  {v:>{col_w}}" for v in [c_h3.n, go.n, c_http.n])
    print(f"  {'Samples':<12}{sample_cells}")


# ─── Scenarios ────────────────────────────────────────────────────────────────

SCENARIOS = [
    ("GET /  (HTML)",         "GET",  "/",                None),
    ("GET /greet (JSON)",     "GET",  "/greet?name=Bench",None),
    ("GET /users/42 (param)", "GET",  "/users/42",        None),
    ("POST 1 KB JSON",        "POST", "/echo",            lambda: json.dumps({"k": "v" * 512}).encode()),
    ("POST 64 KB",            "POST", "/echo",            lambda: b'{"d":"' + b"x" * 65000 + b'"}'),
]


# ─── Main ─────────────────────────────────────────────────────────────────────

async def main_async(args):
    print(f"\n{B}{CY}{'═' * 74}{R}")
    print(f"{B}{CY}  3-Way HTTP Benchmark: Crystal HTTP/3 · Go HTTP/3 · Crystal HTTP/1.1{R}")
    print(f"{B}{CY}{'═' * 74}{R}")
    print(f"  n={args.requests}  concurrency={args.concurrency}  warmup={args.warmup}")

    missing = []
    for path in [CRYSTAL_H3_BIN, GO_BIN, CRYSTAL_HTTP_BIN]:
        if not os.path.isfile(path):
            missing.append(path)
    if missing:
        for p in missing:
            print(f"\n  {RE}✗{R}  {p} not found.")
        print(f"\n  Build with:")
        print(f"    crystal build bench/crystal_server.cr      -o bench/crystal_server --release")
        print(f"    crystal build bench/crystal_http_server.cr -o bench/crystal_http_server --release")
        print(f"    cd bench/go_server_3way && go build -o ../go_server_3way_bin .")
        sys.exit(1)

    print(f"\n{B}Starting servers…{R}")
    crystal_h3_proc  = start_server([CRYSTAL_H3_BIN],  "Crystal H3",   CRYSTAL_H3_PORT)
    go_proc          = start_server(
        [GO_BIN, f"-port={GO_PORT}", f"-cert={CERT}", f"-key={KEY}"],
        "Go H3", GO_PORT,
    )
    crystal_http_proc = start_server([CRYSTAL_HTTP_BIN], "Crystal HTTP", CRYSTAL_HTTP_PORT)

    all_results: dict = {}
    wins = {"crystal_h3": 0, "go_h3": 0, "crystal_http": 0}

    try:
        for (sc_label, method, path, body_fn) in SCENARIOS:
            body = body_fn() if body_fn else None
            print(f"\n{B}━━ {sc_label} ━━{R}")

            if args.warmup > 0:
                print(f"  warmup ({args.warmup}×)…", end="", flush=True)
                wlim = asyncio.Semaphore(min(args.concurrency, 4))

                async def warm_h3(port, bdy=body):
                    async with wlim:
                        await timed_h3(port, method, path, bdy)

                async def warm_http(bdy=body):
                    async with wlim:
                        await timed_http11(CRYSTAL_HTTP_PORT, method, path, bdy)

                await asyncio.gather(
                    *[warm_h3(CRYSTAL_H3_PORT) for _ in range(args.warmup)],
                    *[warm_h3(GO_PORT)          for _ in range(args.warmup)],
                    *[warm_http()               for _ in range(args.warmup)],
                )
                print(" done")

            print(f"  Crystal H3  …", end="", flush=True)
            c_h3_lats = await run_scenario(CRYSTAL_H3_PORT, method, path,
                                           args.requests, args.concurrency, body, use_h3=True)
            print(f" {len(c_h3_lats)}/{args.requests} ok")

            print(f"  Go H3       …", end="", flush=True)
            go_lats = await run_scenario(GO_PORT, method, path,
                                         args.requests, args.concurrency, body, use_h3=True)
            print(f" {len(go_lats)}/{args.requests} ok")

            print(f"  Crystal HTTP…", end="", flush=True)
            c_http_lats = await run_scenario(CRYSTAL_HTTP_PORT, method, path,
                                              args.requests, args.concurrency, body, use_h3=False)
            print(f" {len(c_http_lats)}/{args.requests} ok")

            c_h3_s  = Stats(f"Crystal H3 {sc_label}",   c_h3_lats)
            go_s    = Stats(f"Go H3 {sc_label}",         go_lats)
            c_http_s = Stats(f"Crystal HTTP {sc_label}", c_http_lats)
            print_comparison(c_h3_s, go_s, c_http_s)

            best = min(c_h3_s.median, go_s.median, c_http_s.median)
            if c_h3_s.median  == best: wins["crystal_h3"]   += 1
            if go_s.median    == best: wins["go_h3"]        += 1
            if c_http_s.median == best: wins["crystal_http"] += 1

            all_results[sc_label] = {
                "crystal_h3":   c_h3_s.as_dict(),
                "go_h3":        go_s.as_dict(),
                "crystal_http": c_http_s.as_dict(),
            }

        # ── Summary ─────────────────────────────────────────────────────────
        print(f"\n{B}{CY}{'═' * 74}{R}")
        print(f"{B}{CY}  Summary — median latency (p50) per scenario{R}")
        print(f"{B}{CY}{'═' * 74}{R}")
        print(f"\n  {B}{'Scenario':<28}  {'Crystal H3':>12}  {'Go H3':>10}  {'Crystal HTTP':>14}  Winner{R}")
        print("  " + "─" * 74)

        for sc_label, sc in all_results.items():
            c_p50 = sc["crystal_h3"]["median_ms"]
            g_p50 = sc["go_h3"]["median_ms"]
            h_p50 = sc["crystal_http"]["median_ms"]
            best  = min(c_p50, g_p50, h_p50)
            def col(v): return GR if v == best else R
            winner = ("Crystal H3"  if c_p50 == best else
                      "Go H3"       if g_p50 == best else "Crystal HTTP")
            print(f"  {sc_label:<28}  {c_p50:>10.2f} ms  {g_p50:>8.2f} ms  {h_p50:>12.2f} ms  {GR}{winner}{R}")

        total = len(all_results)
        print(f"\n  Wins (by p50):  "
              f"Crystal H3 {wins['crystal_h3']}/{total}  |  "
              f"Go H3 {wins['go_h3']}/{total}  |  "
              f"Crystal HTTP/1.1 {wins['crystal_http']}/{total}")
        print()

        out_path = os.path.join(SCRIPT_DIR, "results", "benchmark.json")
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w") as f:
            json.dump({
                "meta": {
                    "requests":     args.requests,
                    "concurrency":  args.concurrency,
                    "timestamp":    time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "servers": {
                        "crystal_h3":   f"quic.cr HTTP/3 ::{CRYSTAL_H3_PORT}",
                        "go_h3":        f"quic-go HTTP/3 ::{GO_PORT}",
                        "crystal_http": f"Crystal HTTP/1.1+TLS ::{CRYSTAL_HTTP_PORT}",
                    },
                },
                "scenarios": all_results,
            }, f, indent=2)
        print(f"  Results → {out_path}")

    finally:
        print(f"\n{B}Stopping servers…{R}")
        stop_server(crystal_h3_proc,   "Crystal H3")
        stop_server(go_proc,           "Go H3")
        stop_server(crystal_http_proc, "Crystal HTTP")


def main():
    p = argparse.ArgumentParser(
        description="3-way HTTP benchmark: quic.cr HTTP/3, quic-go HTTP/3, Crystal HTTP/1.1"
    )
    p.add_argument("--requests",    "-n", type=int, default=50,
                   help="Requests per scenario (default 50)")
    p.add_argument("--concurrency", "-c", type=int, default=5,
                   help="Concurrent connections (default 5)")
    p.add_argument("--warmup",      "-w", type=int, default=5,
                   help="Warmup requests (default 5)")
    asyncio.run(main_async(p.parse_args()))


if __name__ == "__main__":
    main()
