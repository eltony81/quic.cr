#!/usr/bin/env python3
"""
Benchmark QPACK static vs dynamic per quic.cr.

Uso:
    python3 examples/bench_qpack.py [--n N] [--batch B] [--static BIN] [--dynamic BIN]

Esempio:
    python3 examples/bench_qpack.py
    python3 examples/bench_qpack.py --n 500 --batch 60
"""
import argparse, asyncio, os, signal, statistics, subprocess, sys, time

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--n",       type=int, default=300,                    help="richieste per scenario (default 300)")
    p.add_argument("--batch",   type=int, default=80,                     help="richieste per connessione, < 128 (default 80)")
    p.add_argument("--warmup",  type=int, default=20,                     help="richieste di warmup (default 20)")
    p.add_argument("--static",  default="/tmp/h3testsrv_static",          help="binario server STATIC")
    p.add_argument("--dynamic", default="/tmp/h3testsrv_dynamic",         help="binario server DYNAMIC")
    p.add_argument("--host",    default="127.0.0.1")
    p.add_argument("--port",    type=int, default=4433)
    return p.parse_args()

# ── Client H3 ─────────────────────────────────────────────────────────────────

class Cli(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.h3 = H3Connection(self._quic)
        self.ev: dict[int, asyncio.Event] = {}
        self.hb: dict[int, int] = {}

    def quic_event_received(self, e):
        for ev in self.h3.handle_event(e):
            sid = ev.stream_id
            if isinstance(ev, HeadersReceived):
                self.hb[sid] = sum(len(k) + len(v) for k, v in ev.headers)
                self.ev.setdefault(sid, asyncio.Event())
                if ev.stream_ended:
                    self.ev[sid].set()
            elif isinstance(ev, DataReceived):
                if ev.stream_ended:
                    self.ev.setdefault(sid, asyncio.Event())
                    self.ev[sid].set()
        from aioquic.quic.events import StreamDataReceived as _SDR
        if not isinstance(e, _SDR):
            super().quic_event_received(e)

    async def do(self, method: str, path: str, body: bytes | None = None) -> tuple[float, int]:
        sid = self._quic.get_next_available_stream_id()
        headers = [
            (b":method",    method.encode()),
            (b":path",      path.encode()),
            (b":scheme",    b"https"),
            (b":authority", b"localhost"),
        ]
        if body:
            headers.append((b"content-type", b"application/json"))
        self.h3.send_headers(sid, headers, end_stream=(body is None))
        if body:
            self.h3.send_data(sid, body, end_stream=True)
        self.transmit()
        self.ev.setdefault(sid, asyncio.Event())
        t0 = time.perf_counter()
        await asyncio.wait_for(self.ev[sid].wait(), timeout=8)
        return (time.perf_counter() - t0) * 1000, self.hb.get(sid, 0)

# ── Scenari ───────────────────────────────────────────────────────────────────

SCENARIOS: list[tuple[str, str, str, bytes | None]] = [
    ("GET /",          "GET",  "/",                None),
    ("GET /greet",     "GET",  "/greet?name=World", None),
    ("GET /users/42",  "GET",  "/users/42",         None),
    ("POST /echo 1KB", "POST", "/echo",             b'{"d":"' + b"x" * 1000 + b'"}'),
]

# ── Runner ────────────────────────────────────────────────────────────────────

async def run_batch(host, port, method, path, body, n) -> list[float]:
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = False
    lats: list[float] = []
    async with connect(host, port, configuration=cfg, create_protocol=Cli) as c:
        for _ in range(n):
            ms, _ = await c.do(method, path, body)
            lats.append(ms)
    return lats


async def bench_scenario(host, port, method, path, body, n, warmup, batch) -> dict:
    # warmup: un batch isolato, risultati scartati
    await run_batch(host, port, method, path, body, min(warmup, batch))

    all_lats: list[float] = []
    remaining = n
    while remaining > 0:
        b = min(batch, remaining)
        lats = await run_batch(host, port, method, path, body, b)
        all_lats.extend(lats)
        remaining -= b

    s = sorted(all_lats)
    return {
        "mean": statistics.mean(all_lats),
        "p50":  statistics.median(all_lats),
        "p95":  s[int(n * 0.95)],
        "p99":  s[int(n * 0.99)],
        "rps":  1000 / statistics.mean(all_lats),
    }


async def bench_binary(binary, label, host, port, n, warmup, batch) -> dict:
    if not os.path.isfile(binary):
        print(f"  ERRORE: binario non trovato: {binary}", file=sys.stderr)
        print(f"  Compila con: crystal build examples/h3_server_routed.cr -o {binary}", file=sys.stderr)
        return {}

    proc = subprocess.Popen([binary], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    await asyncio.sleep(2.0)   # attendi avvio

    results = {}
    try:
        for name, method, path, body in SCENARIOS:
            sys.stdout.write(f"    {name:<17} ... ")
            sys.stdout.flush()
            results[name] = await bench_scenario(host, port, method, path, body, n, warmup, batch)
            r = results[name]
            print(f"p50={r['p50']:.2f}ms  p95={r['p95']:.2f}ms  {r['rps']:.0f} rps")
    except Exception as e:
        print(f"\n  ERRORE durante il benchmark: {e}", file=sys.stderr)
        import traceback; traceback.print_exc()
    finally:
        os.kill(proc.pid, signal.SIGTERM)
        proc.wait()
        await asyncio.sleep(0.3)

    return results

# ── Output ────────────────────────────────────────────────────────────────────

def print_table(all_res: dict, scenarios):
    labels = list(all_res.keys())
    print()
    print(f"  {'Scenario':<17}  {'Modalità':<24}  {'mean':>8}  {'p50':>8}  {'p95':>8}  {'p99':>8}  {'rps':>7}")
    print("  " + "─" * 85)
    for name, _, _, _ in scenarios:
        ref_p50 = None
        for label in labels:
            r = all_res[label].get(name)
            if not r:
                continue
            pct = ""
            if ref_p50 is None:
                ref_p50 = r["p50"]
            else:
                pct = f"  ({(r['p50'] - ref_p50) / ref_p50 * 100:+.1f}%)"
            tag = name if label == labels[0] else " " * 17
            print(f"  {tag:<17}  {label:<24}  {r['mean']:>7.2f}ms  {r['p50']:>7.2f}ms"
                  f"  {r['p95']:>7.2f}ms  {r['p99']:>7.2f}ms  {r['rps']:>6.0f}/s{pct}")
        print()

# ── Main ──────────────────────────────────────────────────────────────────────

async def main():
    args = parse_args()
    configs = [
        ("STATIC  (cap=0)",    args.static),
        ("DYNAMIC (cap=4096)", args.dynamic),
    ]

    print(f"\nBenchmark QPACK static vs dynamic")
    print(f"  N={args.n} req/scenario  warmup={args.warmup}  batch={args.batch}  host={args.host}:{args.port}\n")

    all_res = {}
    for label, binary in configs:
        print(f"  [{label}]  {binary}")
        all_res[label] = await bench_binary(binary, label, args.host, args.port,
                                            args.n, args.warmup, args.batch)

    if any(all_res.values()):
        print_table(all_res, SCENARIOS)
    else:
        print("\n  Nessun risultato — controlla che i binari esistano.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
