#!/usr/bin/env python3
"""
HTTP/3 benchmark: quic.cr (Crystal) vs quic-go (Go)

Scenarios
---------
  A. Small GET /          — measures handshake + request overhead
  B. Small POST /echo     — 64-byte body echo
  C. Large POST /echo     — 1 MB body echo (throughput)

Each scenario is run N_ROUNDS times sequentially (one new QUIC connection
per request, just like the cross-tests), then statistics are printed.
"""

import asyncio, time, statistics, argparse, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..","examples"))

from aioquic.asyncio.client import connect
from aioquic.asyncio import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived

HOST = "127.0.0.1"
CRYSTAL_PORT = 4433
GO_PORT      = 4434

# ── aioquic client plumbing ───────────────────────────────────────────────────

class H3Client(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.h3 = H3Connection(self._quic)
        self._events: list = []
        self._ended: set = set()

    def quic_event_received(self, ev):
        for h3ev in self.h3.handle_event(ev):
            self._events.append(h3ev)
            if getattr(h3ev, "stream_ended", False):
                self._ended.add(h3ev.stream_id)
        super().quic_event_received(ev)


def _cfg():
    c = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    c.verify_mode = False
    c.max_data = 20_000_000
    c.max_stream_data = 20_000_000
    return c


async def request(port: int, path: str, method: str = "GET",
                  body: bytes | None = None, timeout: float = 15.0) -> tuple[int, bytes]:
    async with connect(HOST, port, configuration=_cfg(),
                       create_protocol=H3Client) as client:
        sid = client._quic.get_next_available_stream_id()
        hdrs = [
            (b":method", method.encode()),
            (b":scheme", b"https"),
            (b":authority", f"{HOST}:{port}".encode()),
            (b":path", path.encode()),
        ]
        client.h3.send_headers(sid, hdrs, end_stream=(body is None))
        if body is not None:
            client.h3.send_data(sid, body, end_stream=True)
        client.transmit()

        t0 = time.monotonic()
        while sid not in client._ended:
            if time.monotonic() - t0 > timeout:
                return 0, b""
            await asyncio.sleep(0.005)

        status = 0
        resp_body = bytearray()
        for ev in client._events:
            if ev.stream_id != sid:
                continue
            if isinstance(ev, HeadersReceived):
                for k, v in ev.headers:
                    if k == b":status":
                        status = int(v)
            elif isinstance(ev, DataReceived):
                resp_body.extend(ev.data)
        return status, bytes(resp_body)


# ── benchmark harness ─────────────────────────────────────────────────────────

async def bench(label: str, port: int, path: str,
                method: str = "GET", body: bytes | None = None,
                rounds: int = 30) -> dict:
    latencies = []
    errors = 0
    for _ in range(rounds):
        t0 = time.monotonic()
        status, _ = await request(port, path, method, body)
        elapsed = time.monotonic() - t0
        if status == 200:
            latencies.append(elapsed * 1000)   # ms
        else:
            errors += 1

    if not latencies:
        return {"label": label, "error": "all requests failed"}

    return {
        "label":   label,
        "rounds":  rounds,
        "errors":  errors,
        "min_ms":  min(latencies),
        "max_ms":  max(latencies),
        "mean_ms": statistics.mean(latencies),
        "p50_ms":  statistics.median(latencies),
        "p95_ms":  sorted(latencies)[int(len(latencies) * 0.95)],
        "rps":     1000.0 / statistics.mean(latencies),
    }


def fmt(r: dict) -> str:
    if "error" in r:
        return f"  {r['label']:<45} ERROR: {r['error']}"
    return (
        f"  {r['label']:<45} "
        f"mean={r['mean_ms']:6.1f}ms  "
        f"p50={r['p50_ms']:6.1f}ms  "
        f"p95={r['p95_ms']:6.1f}ms  "
        f"rps={r['rps']:6.1f}  "
        f"err={r['errors']}"
    )


async def main(rounds: int):
    small_body = b"hello quic benchmark"
    big_body   = b"X" * 1_000_000      # 1 MB

    print(f"\n{'='*90}")
    print(f"  HTTP/3 Benchmark: quic.cr (Crystal, :{CRYSTAL_PORT}) vs quic-go (Go, :{GO_PORT})")
    print(f"  {rounds} sequential requests per scenario (one connection per request)")
    print(f"{'='*90}\n")

    scenarios = [
        ("A. GET /  [Crystal]",         CRYSTAL_PORT, "/",     "GET",  None),
        ("A. GET /  [Go]",              GO_PORT,      "/",     "GET",  None),
        ("B. POST /echo 20B [Crystal]", CRYSTAL_PORT, "/echo", "POST", small_body),
        ("B. POST /echo 20B [Go]",      GO_PORT,      "/echo", "POST", small_body),
        ("C. POST /echo 1MB [Crystal]", CRYSTAL_PORT, "/echo", "POST", big_body),
        ("C. POST /echo 1MB [Go]",      GO_PORT,      "/echo", "POST", big_body),
    ]

    results = {}
    for label, port, path, method, body in scenarios:
        r = rounds if "1MB" not in label else max(5, rounds // 6)
        print(f"  Running: {label} ({r} rounds)...", end=" ", flush=True)
        res = await bench(label, port, path, method, body, rounds=r)
        results[label] = res
        print("done")

    print(f"\n{'─'*90}")
    print("  RESULTS")
    print(f"{'─'*90}")
    for label, _, _, _, _ in scenarios:
        print(fmt(results[label]))

    # Summary: Crystal vs Go speedup
    print(f"\n{'─'*90}")
    print("  SPEEDUP  (Crystal mean / Go mean — >1 means Crystal is faster)")
    print(f"{'─'*90}")
    pairs = [
        ("GET /",       "A. GET /  [Crystal]",         "A. GET /  [Go]"),
        ("POST /echo 20B", "B. POST /echo 20B [Crystal]", "B. POST /echo 20B [Go]"),
        ("POST /echo 1MB", "C. POST /echo 1MB [Crystal]", "C. POST /echo 1MB [Go]"),
    ]
    for name, cr_key, go_key in pairs:
        cr = results.get(cr_key, {})
        go = results.get(go_key, {})
        if "mean_ms" in cr and "mean_ms" in go and go["mean_ms"] > 0:
            ratio = go["mean_ms"] / cr["mean_ms"]
            winner = "Crystal" if ratio > 1 else "Go"
            print(f"  {name:<22} Crystal {cr['mean_ms']:.1f}ms  Go {go['mean_ms']:.1f}ms  "
                  f"→ {winner} is {max(ratio,1/ratio):.2f}× faster")
    print()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", "--rounds", type=int, default=30,
                    help="sequential requests per scenario (default 30)")
    args = ap.parse_args()
    asyncio.run(main(args.rounds))
