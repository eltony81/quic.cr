#!/usr/bin/env python3
"""
Stress test: N concurrent HTTP/3 connections to Crystal server.
Each connection makes 2 requests. Reports pass rate and timing.

Usage:
    python examples/stress_test.py [--host 127.0.0.1] [--port 4433] [--n 50]
"""
import asyncio
import argparse
import sys
import time

from aioquic.asyncio.client import connect
from aioquic.asyncio import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived


class H3Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3 = H3Connection(self._quic)
        self._events = []
        self._ended = set()

    def quic_event_received(self, event):
        for ev in self.h3.handle_event(event):
            self._events.append(ev)
            if getattr(ev, "stream_ended", False):
                self._ended.add(ev.stream_id)
        from aioquic.quic.events import StreamDataReceived as SDR
        if not isinstance(event, SDR):
            super().quic_event_received(event)

    async def get(self, host, port, path="/") -> tuple[int, bytes]:
        stream_id = self._quic.get_next_available_stream_id()
        self.h3.send_headers(stream_id, [
            (b":method", b"GET"),
            (b":path", path.encode()),
            (b":scheme", b"https"),
            (b":authority", f"{host}:{port}".encode()),
        ], end_stream=True)
        self.transmit()

        for _ in range(200):
            await asyncio.sleep(0.05)
            if stream_id in self._ended:
                break

        status, body = None, b""
        for ev in self._events:
            if getattr(ev, "stream_id", None) == stream_id:
                if isinstance(ev, HeadersReceived):
                    for k, v in ev.headers:
                        if k == b":status":
                            status = int(v)
                elif isinstance(ev, DataReceived):
                    body += ev.data
        return (status or 0), body


async def one_connection(session_id: int, host: str, port: int, cfg: QuicConfiguration) -> bool:
    try:
        async with connect(host, port, configuration=cfg, create_protocol=H3Client) as proto:
            status1, _ = await proto.get(host, port, "/")
            status2, _ = await proto.get(host, port, "/healthz")
            return status1 == 200 and status2 == 200
    except Exception as e:
        return False


async def main(host: str, port: int, n: int):
    cfg = QuicConfiguration(is_client=True, verify_mode=False)
    cfg.alpn_protocols = ["h3"]

    print(f"Stress test: {n} concurrent connections to {host}:{port}...")
    start = time.time()

    tasks = [one_connection(i, host, port, cfg) for i in range(n)]
    results = await asyncio.gather(*tasks, return_exceptions=False)

    elapsed = time.time() - start
    passed = sum(1 for r in results if r is True)
    failed = n - passed

    rate = passed / n * 100
    avg_ms = elapsed / n * 1000

    print()
    print("═" * 55)
    print(f"  Stress Test  {passed}/{n} passed  ({rate:.0f}%)  in {elapsed:.2f}s")
    print(f"  avg latency per connection: {avg_ms:.1f} ms")
    print("═" * 55)

    if failed > 0:
        print(f"FAIL: {failed}/{n} connections failed")
        sys.exit(1)
    else:
        print("ALL PASSED ✓")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4433)
    parser.add_argument("--n", type=int, default=50)
    args = parser.parse_args()
    asyncio.run(main(args.host, args.port, args.n))
