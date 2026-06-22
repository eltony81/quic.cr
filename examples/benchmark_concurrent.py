"""
HTTP/3 benchmark for quic.cr — measures TPS and latency percentiles.

Usage:
  python examples/benchmark_concurrent.py [--port 4433] [--conns 8] [--reps 3]

Each "rep" sends one round of concurrent GET /, POST /echo (20 B) and POST /echo (1 MB)
using separate QUIC connections.  Results show TPS, avg, p50, p95, p99, and max latency.
"""

import asyncio
import argparse
import statistics
import time
from aioquic.asyncio import QuicConnectionProtocol
from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived

HOST = "127.0.0.1"


class H3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3_conn = H3Connection(self._quic)
        self.h3_events = []
        self.h3_stream_ended = set()

    def quic_event_received(self, event):
        for h3_event in self.h3_conn.handle_event(event):
            self.h3_events.append(h3_event)
            if hasattr(h3_event, "stream_ended") and h3_event.stream_ended:
                self.h3_stream_ended.add(h3_event.stream_id)
        from aioquic.quic.events import StreamDataReceived as _SDR
        if not isinstance(event, _SDR):
            super().quic_event_received(event)


async def single_request(port: int, path: str, method: str = "GET", body: bytes = b"") -> tuple:
    """Opens one QUIC connection, sends one request, returns (status, latency_ms)."""
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = False
    cfg.max_data = 50_000_000
    cfg.max_stream_data = 10_000_000

    t0 = time.perf_counter()
    try:
        async with connect(HOST, port, configuration=cfg, create_protocol=H3ClientProtocol) as client:
            sid = client._quic.get_next_available_stream_id()
            hdrs = [
                (b":method", method.encode()),
                (b":scheme", b"https"),
                (b":authority", f"{HOST}:{port}".encode()),
                (b":path", path.encode()),
                (b"user-agent", b"bench-client"),
            ]
            if body:
                hdrs.append((b"content-length", str(len(body)).encode()))
            client.h3_conn.send_headers(sid, hdrs, end_stream=(not body))
            if body:
                client.h3_conn.send_data(sid, body, end_stream=True)
            client.transmit()

            deadline = time.time() + 15.0
            while sid not in client.h3_stream_ended and time.time() < deadline:
                await asyncio.sleep(0.001)

            elapsed = (time.perf_counter() - t0) * 1000
            if sid not in client.h3_stream_ended:
                return 0, elapsed

            status = 500
            for ev in client.h3_events:
                if ev.stream_id == sid and isinstance(ev, HeadersReceived):
                    for k, v in ev.headers:
                        if k == b":status":
                            status = int(v)
            return status, elapsed
    except Exception:
        elapsed = (time.perf_counter() - t0) * 1000
        return 0, elapsed


async def run_concurrent(port: int, n: int, path: str, method: str = "GET", body: bytes = b"") -> list:
    tasks = [asyncio.create_task(single_request(port, path, method, body)) for _ in range(n)]
    return await asyncio.gather(*tasks)


def percentile(data: list, p: float) -> float:
    if not data:
        return 0.0
    sorted_data = sorted(data)
    idx = (len(sorted_data) - 1) * p / 100
    lo = int(idx)
    hi = min(lo + 1, len(sorted_data) - 1)
    return sorted_data[lo] + (sorted_data[hi] - sorted_data[lo]) * (idx - lo)


def print_stats(label: str, results: list, wall_time_s: float):
    latencies = [lat for _, lat in results]
    statuses  = [s for s, _ in results]
    ok        = sum(1 for s in statuses if s == 200)
    failed    = len(results) - ok

    if not latencies:
        print(f"  {label}  → no data")
        return

    avg  = statistics.mean(latencies)
    p50  = percentile(latencies, 50)
    p95  = percentile(latencies, 95)
    p99  = percentile(latencies, 99)
    pmax = max(latencies)
    tps  = ok / wall_time_s if wall_time_s > 0 else 0

    status_str = f"{ok}/{len(results)} OK" + (f"  ⚠ {failed} failed" if failed else "")
    print(f"\n  ┌─ {label}")
    print(f"  │  Requests : {status_str}")
    print(f"  │  TPS      : {tps:.1f} req/s")
    print(f"  │  Latency  : avg={avg:.0f}ms  p50={p50:.0f}ms  p95={p95:.0f}ms  p99={p99:.0f}ms  max={pmax:.0f}ms")
    print(f"  └─────────────────────────────────────────────────")


async def bench(port: int, n_conns: int, reps: int):
    PAYLOAD_1MB = b"x" * 1_048_576
    PAYLOAD_SMALL = b'{"msg":"hello"}'

    print(f"\n{'═'*56}")
    print(f"  quic.cr HTTP/3 benchmark")
    print(f"  Port {port}  │  {n_conns} concurrent conns  │  {reps} reps each")
    print(f"{'═'*56}")

    # Warm-up (not counted)
    print("  Warming up…", end="", flush=True)
    await run_concurrent(port, 1, "/")
    print(" done\n")

    categories = [
        ("GET  /          ", "/", "GET",  b""),
        ("POST /echo  20B ", "/echo", "POST", PAYLOAD_SMALL),
        ("POST /echo  1MB ", "/echo", "POST", PAYLOAD_1MB),
    ]

    for label, path, method, body in categories:
        all_results = []
        t_start = time.perf_counter()
        for _ in range(reps):
            r = await run_concurrent(port, n_conns, path, method, body)
            all_results.extend(r)
        wall = time.perf_counter() - t_start
        print_stats(f"{label}  ({n_conns}×{reps} = {n_conns*reps} reqs)", all_results, wall)


async def main():
    p = argparse.ArgumentParser(description="HTTP/3 benchmark for quic.cr")
    p.add_argument("--port",  type=int, default=4433, help="Server port (default: 4433)")
    p.add_argument("--conns", type=int, default=8,    help="Concurrent connections per round (default: 8)")
    p.add_argument("--reps",  type=int, default=3,    help="Repetitions per scenario (default: 3)")
    args = p.parse_args()
    await bench(args.port, args.conns, args.reps)
    print()


if __name__ == "__main__":
    asyncio.run(main())
