# Testing — operational instructions

## Prerequisites

```bash
# Crystal >= 1.15 (check version)
crystal --version

# Activate the Python venv for interop tests (aioquic)
source venv/bin/activate
```

TLS certificates for local development are in `cert.pem` / `key.pem` at the repo root.

---

## 1. Crystal unit tests

Run all specs (QUIC + H3 + QPACK):

```bash
crystal spec
```

QPACK only (60 cases, RFC 9204):

```bash
crystal spec spec/qpack_spec.cr
```

H3 only:

```bash
crystal spec spec/h3_spec.cr
```

---

## 2. Interoperability cross-validation (27 tests)

Verifies that the Crystal server and the aioquic client talk to each other correctly.
The script starts the servers itself — no need to run them manually.

```bash
source venv/bin/activate
python3 examples/validate_cross_tests.py
```

Expected output:

```
════════════════════════════════════════════════════════════
  SUMMARY  27/27 passed   ✓ all green
════════════════════════════════════════════════════════════
```

The script runs three phases:

| Phase | What it tests |
|-------|---------------|
| Phase 1 | aioquic client → Crystal server (routing, body, headers, concurrency) |
| Phase 2 | Crystal client → aioquic server (handshake, stream, GOAWAY) |
| Phase 3 | Robustness: malformed frames, stream violations, large payload |

---

## 3. QPACK benchmark: static vs dynamic

Compares latency with the dynamic table disabled (cap=0) vs enabled (cap=4096).
Requires compiling two separate binaries.

### 3a. Compile the binaries

```bash
# Dynamic (current default — cap=4096)
crystal build examples/h3_server_routed.cr -o /tmp/h3testsrv_dynamic

# Static (comment out set_capacity and set SETTINGS 0x01 => 0 — see connection.cr)
# Or use a compile-time define if you added one
crystal build examples/h3_server_routed.cr -o /tmp/h3testsrv_static
```

> For details on reverting to static see the comment in `src/h3/connection.cr`
> in the `open_qpack_streams` method.

### 3b. Run the benchmark

```bash
source venv/bin/activate
python3 examples/bench_qpack.py
```

Available options:

```bash
python3 examples/bench_qpack.py --n 500          # more requests per scenario (default 300)
python3 examples/bench_qpack.py --batch 60        # requests per connection (default 80, max 127)
python3 examples/bench_qpack.py --static  /path/to/static_binary
python3 examples/bench_qpack.py --dynamic /path/to/dynamic_binary
```

Expected output:

```
  Scenario           Mode                          mean       p50       p95       p99      rps
  ─────────────────────────────────────────────────────────────────────────────────────
  GET /              STATIC  (cap=0)              1.66ms     1.40ms     2.64ms     8.06ms     603/s
                     DYNAMIC (cap=4096)           1.50ms     1.11ms     2.88ms     8.38ms     666/s  (-20.3%)

  POST /echo 1KB     STATIC  (cap=0)              2.22ms     2.27ms     3.46ms     8.32ms     450/s
                     DYNAMIC (cap=4096)           1.79ms     1.35ms     3.12ms     9.05ms     558/s  (-40.3%)
```

> The `ValueError: Cannot send data on peer-initiated unidirectional stream` warnings
> that occasionally appear are a Python 3.14 + aioquic GC bug and do not affect results.

---

## 4. Manual test with curl

```bash
# Start the server
crystal run examples/h3_server_routed.cr

# In another terminal — requires curl with HTTP/3 (curl >= 7.88 with quiche or ngtcp2)
curl -v --http3 "https://127.0.0.1:4433/" --insecure
curl -v --http3 "https://127.0.0.1:4433/greet?name=World" --insecure
curl -v --http3 "https://127.0.0.1:4433/users/42" --insecure
curl -v --http3 "https://127.0.0.1:4433/echo" --insecure -X POST \
     -H "content-type: application/json" -d '{"hello":"world"}'
```

---

## 5. Go/quic-go E2E test suite (461 tests)

Full end-to-end test suite verifying interoperability between quic.cr and quic-go.
Covers HTTP verbs, status codes, large data, concurrency, key update, multi-connection, and QUIC v2.

### 5a. Compile the e2e server

```bash
crystal build examples/e2e_server.cr -o /tmp/e2e_server
```

### 5b. Start the server

```bash
/tmp/e2e_server &
```

### 5c. Run the test suite

```bash
cd bench/go_client
go run main.go
```

Expected output:

```
  HTTP Verbs:                              9/9
  Status Codes:                            5/5
  Large Data:                              4/4
  Response Headers:                        3/3
  Concurrent GET ×50:                      50/50
  Concurrent POST ×20:                     20/20
  Concurrent Large ×10:                    10/10
  Sequential Load 200 reqs (Key Update):   200/200
  Key Update: ✓ triggered and handled correctly (pn > 100)
  Multiple Connections (5 QUIC conns):     25/25
  QUIC v2 (RFC 9369):                      4/4
  Data Integrity:                          3/3
  10MB Large Transfer:                     1/1
  Custom Request Headers:                  3/3
  Sequential 100 Reqs (pipelining):        100/100
  Concurrent Mix (large+small):            10/10
  Connection Churn (10 conns):             10/10
  Slow Endpoint (200ms sleep):             1/1 (took 307ms)
  Digest Upload Correctness:               3/3

════════════════════════════════════════════════════
  QUIC/HTTP3 E2E Suite   899/899  in 16.973s
════════════════════════════════════════════════════
ALL PASSED ✓
```

| Suite | What it tests |
|-------|---------------|
| 1: HTTP Verbs | GET, POST, PUT, PATCH, DELETE, HEAD |
| 2: Status Codes | 200, 201, 400, 404, 500 |
| 3: Large Data | 1MB download, 64KB/256KB/128KB upload |
| 4: Response Headers | content-type text, json, custom headers |
| 5: Concurrent GET ×50 | 50 parallel GET /ping |
| 6: Concurrent POST ×20 | 20 parallel POST /echo 4KB |
| 7: Concurrent Large ×10 | 10 parallel GET /large 64KB |
| 8: Sequential 200 reqs | Key Update triggered and handled |
| 9: Multiple Connections | 5 independent QUIC connections |
| 10: QUIC v2 | RFC 9369 version 2 handshake |
| 11: Data Integrity | Exact byte match, SHA256 digest, /repeat |
| 12: 10MB Transfer | Full 10MB download, stresses flow control |
| 13: Custom Headers | Request headers echoed via QPACK |
| 14: Sequential 100 reqs | Pipelining on 1 QUIC connection |
| 15: Concurrent Mix | Large + small requests interleaved |
| 16: Connection Churn | 10 connections opened and closed in parallel |
| 17: Slow Endpoint | Timer correctness with 200ms server sleep |
| 18: Digest Upload | SHA256 correctness for 11B, 64B, 1KB payloads |

> The e2e server listens on `127.0.0.1:4433` with the repo's `cert.pem`/`key.pem`.
> Kill it with `pkill -f /tmp/e2e_server` or `ps aux | grep e2e_server` + `kill <PID>`.

---

## 6. Crystal HTTP/3 vs Go benchmark (aioquic client)

Direct comparison between quic.cr and quic-go on three scenarios: small GET, small POST, large POST (1 MB).
The script measures each scenario with N sequential rounds, **one new QUIC connection per request**
(includes handshake overhead — measures the real-world case, not keep-alive).

### 6a. Compile the Crystal server

```bash
crystal build examples/h3_server_routed.cr -o /tmp/crystal_h3_srv
```

### 6b. Compile the Go server

```bash
cd bench/go_server
go build -o go_h3_server .
cd ../..
```

> The Go server uses `../../cert.pem` / `../../key.pem` by default (relative to `bench/go_server/`).
> You can pass alternative paths as arguments: `./go_h3_server /path/cert.pem /path/key.pem`

### 6c. Start both servers

Open two terminals (or use `&`):

```bash
# Terminal 1 — Crystal on port 4433
/tmp/crystal_h3_srv

# Terminal 2 — Go on port 4434
cd bench/go_server && ./go_h3_server
```

### 6d. Run the benchmark

```bash
source venv/bin/activate
python3 bench/benchmark.py          # default: 30 rounds per scenario
python3 bench/benchmark.py -n 100   # more rounds for more stable statistics
```

Expected output (indicative values from loopback, includes ~120ms aioquic GC overhead):

```
==========================================================================================
  HTTP/3 Benchmark: quic.cr (Crystal, :4433) vs quic-go (Go, :4434)
  25 sequential requests per scenario (one connection per request)
==========================================================================================

──────────────────────────────────────────────────────────────────────────────────────────
  RESULTS
──────────────────────────────────────────────────────────────────────────────────────────
  A. GET /  [Crystal]                           mean=121.5ms  p50=124.8ms  p95=126.2ms  p99=127.1ms  rps=  8.2  err=0
  A. GET /  [Go]                                mean=118.7ms  p50=120.3ms  p95=125.5ms  p99=126.8ms  rps=  8.4  err=0
  B. POST /echo 20B [Crystal]                   mean=122.5ms  p50=124.5ms  p95=131.4ms  p99=131.7ms  rps=  8.2  err=0
  B. POST /echo 20B [Go]                        mean=117.6ms  p50=120.2ms  p95=126.2ms  p99=126.3ms  rps=  8.5  err=0
  C. POST /echo 1MB [Crystal]                   mean=260.6ms  p50=258.5ms  p95=281.6ms  p99=281.6ms  rps=  3.8  err=0
  C. POST /echo 1MB [Go]                        mean=262.9ms  p50=261.5ms  p95=273.4ms  p99=273.4ms  rps=  3.8  err=0

──────────────────────────────────────────────────────────────────────────────────────────
  SPEEDUP  (Crystal mean / Go mean — >1 means Crystal is faster)
──────────────────────────────────────────────────────────────────────────────────────────
  GET /                  Crystal 121.5ms  Go 118.7ms  → Go is 1.02× faster
  POST /echo 20B         Crystal 122.5ms  Go 117.6ms  → Go is 1.04× faster
  POST /echo 1MB         Crystal 260.6ms  Go 262.9ms  → Crystal is 1.01× faster
```

> Note: the Python (aioquic) benchmark introduces ~120ms of fixed overhead per connection
> due to Python 3.14 GC exceptions. The numbers include this overhead.
>
> On POST 1MB Crystal is now on par with Go (pacing + dynamic timer implemented).

---

## 7. Go-native benchmark: Crystal quic.cr vs Go quic-go

Direct Go-vs-Crystal benchmark with no Python/aioquic overhead.
The `bench/go_client/bench_h3/` program starts a quic-go server inline on `:4444`
and measures three scenarios against the Crystal server on `:4433`.

### 7a. Build the servers

```bash
# Crystal — ALWAYS use --release for real numbers
crystal build examples/e2e_server.cr -o /tmp/e2e_server --release

# Multi-thread option (preview_mt):
crystal build examples/e2e_server.cr -o /tmp/e2e_server_mt --release -Dpreview_mt
```

### 7b. Start the Crystal server

```bash
# Single-thread (default)
/tmp/e2e_server

# Multi-thread (4 OS threads)
CRYSTAL_WORKERS=4 /tmp/e2e_server_mt
```

### 7c. Run the benchmark

The Go server is started inline — no separate process needed.

```bash
cd bench/go_client/bench_h3
go build -o bench_h3 .
./bench_h3

# Higher load:
./bench_h3 -seq-n 1000 -conc-n 5000 -conc-c 100
```

### Available flags

| Flag | Default | Description |
|------|---------|-------------|
| `-crystal-port` | 4433 | Crystal port |
| `-go-port` | 4444 | Go port (started inline) |
| `-seq-n` | 300 | Sequential requests (latency test) |
| `-conc-n` | 1000 | Total requests (concurrent RPS test) |
| `-conc-c` | 50 | Concurrency (concurrent RPS test) |
| `-tp-n` | 20 | Throughput requests (GET /100k) |

### Reference results (loopback, 2026-06-28)

**Build**: `--release` + BatchSender (sendmmsg) + BatchReceiver (recvmmsg + UDP GRO) + ResponseRing (lock-free MPSC) + AEAD/HP cipher caching

```
┌────────────────────────────────────────────────────────────────┐
│         HTTP/3 Benchmark: Crystal quic.cr vs Go quic-go        │
├──────────────────────────────┬──────────────────┬──────────────┤
│  Metric                      │  Crystal quic.cr │  Go quic-go   │
├──────────────────────────────┼──────────────────┼──────────────┤
│  Sequential latency (GET /ping)                               │
      avg                         516µs            154µs
      p50                         139µs            134µs
      p99                         562µs            417µs
│                                                               │
│  Concurrent (GET /ping)                                       │
      req/s                   21643 req/s       24979 req/s
      p99 latency               3.4ms             4.4ms
│                                                               │
│  Throughput (GET /100k)                                       │
      MB/s                     45.1 MB/s        187.5 MB/s
├──────────────────────────────────────────────────────────────┤
  RPS Crystal/Go:        0.87x
  Throughput Crystal/Go: 0.24x
└──────────────────────────────────────────────────────────────┘
```

**With `-Dpreview_mt` (4 workers)**: RPS ~15.5k, throughput ~35 MB/s — numbers
nearly identical to single-thread because the benchmark uses **a single QUIC
connection** for transport (everything on the same actor). `preview_mt` pays off
on multi-connection workloads where different actors run on different OS threads.

### Optimization progression (same machine, loopback)

| Build | RPS | Throughput | Notes |
|-------|-----|------------|-------|
| debug (no `--release`) | 2,906 | 5.2 MB/s | wrong baseline |
| `--release` + `@udp.send` per-packet | — | — | starting point |
| `--release` + BatchSender (`sendmmsg`) | 10,585 | 43.7 MB/s | batch syscall |
| `--release` + BatchSender + ResponseRing | 15,620 | 36.2 MB/s | lock-free ring |
| `--release` + BatchSender + ResponseRing + **UDP GRO** | 14,697 | 42.5 MB/s | GRO receive |
| `--release` + BatchSender + ResponseRing + UDP GRO + **cipher cache** | **21,643** | **45.1 MB/s** | current build |
| Go quic-go (reference) | 24,979 | 187.5 MB/s | reference implementation |

> The remaining gap (1.15x RPS, 4.2x throughput) is dominated by Boehm GC
> stop-the-world pauses vs Go's concurrent GC. quic.cr is a pure-Crystal
> implementation; Go has assembly-optimised crypto and can saturate the UDP
> send buffer in a few syscalls.
>
> Cipher caching (+47% RPS): caching `OpenSSL::Cipher` contexts per AEAD and
> HeaderProtection instance eliminates 4× `EVP_CIPHER_CTX_new()` per packet on
> the hot path. The decrypt output buffer (`@decrypt_buf`) is pre-allocated to
> avoid one ~1244-byte alloc per received packet.
>
> UDP GRO (+17% throughput): groups multiple UDP datagrams per recvmmsg call.
> MAX_PKT=65536 (64KB) allows up to 51 QUIC packets of 1280 bytes per slot
> without truncation.
