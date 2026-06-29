# quic.cr

> [!WARNING]
> This project was generated with AI.

A native, pure-Crystal implementation of the QUIC transport protocol (RFC 9000) and HTTP/3 (RFC 9114). Features a sans-I/O QUIC core, QPACK compression, and a robust HTTP/3 client and server. No external Crystal shard dependencies.

Crystal >= 1.20.2 required.  TLS is handled through OpenSSL via LibSSL's native QUIC API.

---

## Quick start

```bash
# Run the example routed HTTP/3 server
crystal run examples/h3_server_routed.cr

# Send a request (requires curl with HTTP/3 support)
curl -v --http3 https://127.0.0.1:4433/ --insecure
curl -v --http3 https://127.0.0.1:4433/users/42 --insecure
curl -v --http3 -X POST -d '{"msg":"hello"}' -H "Content-Type: application/json" \
     https://127.0.0.1:4433/echo --insecure
```

TLS certificates for local development are at `cert.pem` / `key.pem` (repo root).

---

## Router API

```crystal
require "../src/quic"

router = H3::Router.new

# Middleware (runs in insertion order)
router.use do |ctx, next_handler|
  Log.info { "#{ctx.request.method} #{ctx.request.path}" }
  next_handler.call(ctx)
end

# Routes
router.get "/"           { |ctx| ctx.html "<h1>Hello HTTP/3!</h1>" }
router.get "/users/:id"  { |ctx| ctx.json %({"id":"#{ctx.request.path_params["id"]}"}) }
router.post "/echo"      { |ctx| ctx.text ctx.body_string }

# Start the server (auto-generates self-signed cert.pem/key.pem if missing)
# You can also manually specify them:
# H3::Server.new(router).listen(host: "0.0.0.0", port: 4433, cert: "cert.pem", key: "key.pem")
H3::Server.new(router).listen(host: "0.0.0.0", port: 4433)
```

---

## Client API

```crystal
require "../src/quic"

config = QUIC::Config.new
client = H3::Client.new("127.0.0.1", 4433, config)

# GET Request
headers, body, trailers = client.get("/greet?name=Crystal")
puts "Status: #{headers[":status"]}"
puts "Body: #{String.new(body)}"

# POST Request
headers, body, trailers = client.post("/echo", %({"msg": "hello"}), {"content-type" => "application/json"})
puts "Response: #{String.new(body)}"

client.close
```

---

## QUIC Configuration

Both the client and server use `QUIC::Config` to define connection parameters. You can customize the behavior of the transport layer by modifying these properties before starting a connection or server.

| Property | Default | Description |
|---|---|---|
| `max_idle_timeout` | `30_000` | Maximum idle timeout in milliseconds. |
| `max_udp_payload_size` | `1200` | Maximum UDP payload size. |
| `initial_max_data` | `0` | Initial connection-level flow control window. |
| `initial_max_stream_data_bidi_local` | `0` | Initial flow control window for local bidirectional streams. |
| `initial_max_stream_data_bidi_remote` | `0` | Initial flow control window for remote bidirectional streams. |
| `initial_max_stream_data_uni` | `0` | Initial flow control window for unidirectional streams. |
| `initial_max_streams_bidi` | `0` | Maximum number of concurrent bidirectional streams. |
| `initial_max_streams_uni` | `0` | Maximum number of concurrent unidirectional streams. |
| `ack_delay_exponent` | `3` | Exponent used to decode the ACK Delay field. |
| `max_ack_delay` | `25` | Maximum amount of time in milliseconds to delay an ACK. |
| `max_datagram_frame_size` | `0` | Maximum size of a DATAGRAM frame. |
| `initial_cwnd_packets` | `128` | Initial congestion window in MTU-sized packets. |
| `cert_file` | `"cert.pem"` | Path to the TLS certificate file. |
| `key_file` | `"key.pem"` | Path to the TLS private key file. |
| `session_ticket` | `nil` | Optional TLS session ticket for 0-RTT client resumption (`Bytes?`). |

*(Note: `H3::Server` overrides several of the `initial_max_*` flow control defaults internally for HTTP/3 optimization.)*

### Example: Customizing the Config

```crystal
require "../src/quic"

config = QUIC::Config.new
config.max_idle_timeout = 60_000 # 60 seconds
config.initial_max_streams_bidi = 256
config.initial_cwnd_packets = 200

# Passing the config to a Client:
client = H3::Client.new("127.0.0.1", 4433, config)
```

---

## Running the validation tests

The validation suite checks interoperability between the Crystal server and a Go HTTP/3 client (`quic-go`).

```bash
# Compile and run the cross-validation tests
cd bench/go_client/cross_test
go build -o cross_test .

# Run with auto-start of the Crystal server
./cross_test -start-server
```

### What the tests cover

**Phase 1 — HTTP/3 Request Correctness (18 cases)**
Basic functionality testing, GET/POST/PUT/PATCH/DELETE routing, header echoing, payload size edge cases (100k, 1MB), SHA256 payload integrity, and concurrent request handling.

**Phase 2 — Robustness & Edge Cases (6 cases)**
Handling sequential requests, 404 routing, multi-connection isolation, 64k payload testing, and dynamic QPACK state persistence across requests.

**Phase 3 — RFC 9114 Rejection Behaviors (5 cases)**
Low-level injection of raw HTTP/3 frames. Validates connection rejection behaviors such as `DATA` before `HEADERS`, missing `:method`, or `SETTINGS` frames inappropriately sent on request streams.

---

## Running the benchmark

The benchmark measures TPS (requests/second) and latency percentiles for three scenarios:
`GET /`, `POST /echo` with a 20-byte body, and `POST /echo` with a 1 MB body.

```bash
# Build the server (release mode for accurate numbers)
crystal build examples/h3_server_routed.cr -o examples/h3_server_routed --release

# Start the server
CRYSTAL_LOG_LEVEL=WARN ./examples/h3_server_routed &

# Run the benchmark
source venv/bin/activate
python examples/benchmark_concurrent.py --conns 8 --reps 3

# Multi-threaded build (experimental)
crystal build examples/h3_server_routed.cr -o examples/h3_server_routed_mt \
       --release -Dpreview_mt
CRYSTAL_LOG_LEVEL=WARN ./examples/h3_server_routed_mt &
python examples/benchmark_concurrent.py --port 4433 --conns 8 --reps 3
```

### Benchmark options

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | 4433 | Server port |
| `--conns` | 8 | Concurrent connections per round |
| `--reps` | 3 | Repetitions per scenario |

### Expected output

```
════════════════════════════════════════════════════════
  quic.cr HTTP/3 benchmark
  Port 4433  │  8 concurrent conns  │  3 reps each
════════════════════════════════════════════════════════
  Warming up… done

  ┌─ GET  /           (8×3 = 24 reqs)
  │  Requests : 24/24 OK
  │  TPS      : 42.1 req/s
  │  Latency  : avg=107ms  p50=105ms  p95=130ms  p99=145ms  max=158ms
  └─────────────────────────────────────────────────

  ┌─ POST /echo  20B  (8×3 = 24 reqs)
  │  Requests : 24/24 OK
  │  TPS      : 43.8 req/s
  │  Latency  : avg=103ms  p50=101ms  p95=125ms  p99=138ms  max=152ms
  └─────────────────────────────────────────────────

  ┌─ POST /echo  1MB  (8×3 = 24 reqs)
  │  Requests : 24/24 OK
  │  TPS      : 5.2 req/s
  │  Latency  : avg=1540ms  p50=1480ms  p95=2100ms  p99=2350ms  max=2700ms
  └─────────────────────────────────────────────────
```

> **Note on latency**: each request opens a fresh QUIC connection (TLS handshake ~50 ms on
> loopback).  The 100 ms+ baseline per request reflects handshake time, not application
> processing time.  Persistent-connection benchmarking (multiple H3 streams per connection)
> would show much lower per-request latency.

---

## Go vs Crystal HTTP/3 benchmark

`bench/go_client/bench_h3/` is a standalone Go program that starts an inline
**quic-go HTTP/3 server** on port 4444, then runs identical workloads against
both servers and prints a side-by-side comparison.

### Prerequisites

```bash
# Go ≥ 1.23 required
go version

# Build the Crystal server — --release is required for accurate numbers
crystal build examples/e2e_server.cr -o /tmp/e2e_server --release

# Optional: multi-threaded build (gains on multi-connection workloads)
crystal build examples/e2e_server.cr -o /tmp/e2e_server_mt --release -Dpreview_mt
```

### Steps

```bash
# 1. Start the Crystal server (keep this terminal open)
/tmp/e2e_server
# or for multi-thread: CRYSTAL_WORKERS=4 /tmp/e2e_server_mt

# 2. In another terminal — build and run the benchmark
cd bench/go_client/bench_h3
go build -o bench_h3 .
./bench_h3
```

The Go server is started **inline** by the benchmark — no separate process needed.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-crystal-port` | 4433 | Crystal server port |
| `-go-port` | 4444 | Go server port (started inline) |
| `-seq-n` | 300 | Sequential requests for latency test |
| `-conc-n` | 1000 | Total requests for concurrent RPS test |
| `-conc-c` | 50 | Worker concurrency for RPS test |
| `-tp-n` | 20 | Requests for throughput test (100 kB each) |

Example with higher load:

```bash
./bench_h3 -seq-n 1000 -conc-n 5000 -conc-c 100
```

### What it measures

| Scenario | Endpoint | Metric |
|----------|----------|--------|
| Sequential latency | `GET /ping` | avg / p50 / p99 |
| Concurrent throughput | `GET /ping` | req/s, p99 latency |
| Bandwidth | `GET /100k` | MB/s |

### Sample output

Build the Crystal server with `--release` before running (see steps above).

```
Crystal server OK on :4433
Go server started on :4444
Config: seq=300  conc=1000/50 workers  tp=20×100k
Warming up.. done

Benchmarking Crystal quic.cr…
Benchmarking Go quic-go…

┌────────────────────────────────────────────────────────────────┐
│         HTTP/3 Benchmark: Crystal quic.cr vs Go quic-go        │
├──────────────────────────────┬──────────────────┬──────────────┤
│  Metric                      │  Crystal quic.cr │  Go quic-go  │
├──────────────────────────────┼──────────────────┼──────────────┤
│  Sequential latency (GET /ping)                               │
      avg                         531µs            150µs
      p50                         152µs            126µs
      p99                         881µs            767µs
│                                                               │
│  Concurrent (GET /ping)                                       │
      req/s                   14697 req/s       27616 req/s
      p99 latency               6.3ms             4.3ms
│                                                               │
│  Throughput (GET /100k)                                       │
      MB/s                     42.5 MB/s        203.9 MB/s
├──────────────────────────────────────────────────────────────┤
  RPS Crystal/Go:        0.53x
  Throughput Crystal/Go: 0.21x
└──────────────────────────────────────────────────────────────┘
```

> quic-go is ~1.9× faster on RPS and ~4.8× faster on bulk throughput. The gap
> is expected: quic-go uses native goroutines with a concurrent GC and
> assembly-optimised send paths; quic.cr is a pure-Crystal implementation with
> Boehm GC and a single actor per connection. UDP GRO (Generic Receive Offload)
> is now active: the receiver batches multiple QUIC datagrams per recvmmsg slot,
> improving throughput by +17% vs the previous build.

---

## RFC / IETF compliance

The following standards are implemented.  Partial support is noted inline.

### QUIC Transport — RFC 9000

| Clause | Feature |
|--------|---------|
| §2 | Variable-length integer (VarInt) encoding |
| §3.4 | `RESET_STREAM` — abrupt stream termination |
| §3.5 | `STOP_SENDING` — request peer to stop sending |
| §4.1 | Connection-level flow control (`MAX_DATA`, `DATA_BLOCKED`) |
| §4.2 | Stream-level flow control (`MAX_STREAM_DATA`, `STREAM_DATA_BLOCKED`) |
| §4.6 | Stream count limits (`MAX_STREAMS`, `STREAMS_BLOCKED`) |
| §5.1 | Connection IDs (initial + server-issued alternatives) |
| §6 | Version negotiation packet |
| §8.1 | Address validation — stateless Retry with HMAC-SHA256 token |
| §8.1 | Retry Integrity Tag (AES-128-GCM, fixed RFC 9001 §5.8 key) |
| §9.4 | Path validation (`PATH_CHALLENGE` / `PATH_RESPONSE`) |
| §9.6 | Active connection migration with path re-validation |
| §12.2 | Coalesced packets (Initial + Handshake + 1-RTT in one UDP datagram) |
| §14.1 | Client Initial packet padded to ≥ 1200 bytes |
| §17 | Long-header packets (Initial, Handshake, 0-RTT, Retry) |
| §17 | Short-header (1-RTT) packets |
| §19 | All standard frame types: `PADDING`, `PING`, `CRYPTO`, `ACK`, `ACK_ECN`, `STREAM`, `MAX_DATA`, `MAX_STREAM_DATA`, `MAX_STREAMS`, `DATA_BLOCKED`, `STREAM_DATA_BLOCKED`, `STREAMS_BLOCKED`, `NEW_CONNECTION_ID`, `RETIRE_CONNECTION_ID`, `PATH_CHALLENGE`, `PATH_RESPONSE`, `CONNECTION_CLOSE`, `HANDSHAKE_DONE`, `NEW_TOKEN`, `RESET_STREAM`, `STOP_SENDING` |

### TLS 1.3 for QUIC — RFC 9001

| Clause | Feature |
|--------|---------|
| §4.4 | TLS handshake via OpenSSL QUIC-native BIO (`SSL_set_quic_tls_cbs`) |
| §4.9.2 | `HANDSHAKE_DONE` frame — server confirmation + key discard |
| §5.2 | Initial secret derivation (`INITIAL_SALT_V1`, HKDF-Extract/Expand) |
| §5.3 | AEAD algorithms: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` |
| §5.4 | Header protection (AES-128-ECB / AES-256-ECB / ChaCha20) |
| §5.5 | Packet number space separation (Initial / Handshake / 0-RTT / 1-RTT) |
| §5.8 | Retry Integrity Tag (AES-128-GCM, fixed key+nonce) |
| §6 | Key Update (`trigger_key_update` — derive next-generation traffic secrets) |
| §7 | 0-RTT early data (encrypt/decrypt 0-RTT packet number space) |
| §8 | TLS session resumption (NewSessionTicket, session cache) |

### Loss Detection and Congestion Control — RFC 9002

| Clause | Feature |
|--------|---------|
| §5.3 | RTT estimation: `latest_rtt`, `smoothed_rtt` (EWMA), `rttvar` |
| §6.1 | Packet loss detection — time threshold (×9/8 SRTT) and packet threshold (≥3) |
| §6.2 | PTO (Probe Timeout) timers with exponential backoff (capped at 8×) |
| §7 | NewReno congestion control (slow start, congestion avoidance, recovery) |
| §7.6 | `ACK_ECN` frame decoding; persistent congestion detection and response |
| — | BBR congestion control (alternative, enabled via `bbr_enabled=true`) |

### HTTP/3 — RFC 9114

| Clause | Feature |
|--------|---------|
| §4.1 | HTTP request/response lifecycle (HEADERS + DATA frames) |
| §4.3 | Mandatory header field ordering and pseudo-header validation |
| §6.1 | Bidirectional request streams (client-initiated, ID mod 4 = 0) |
| §6.2 | Unidirectional streams: control (type 0x00), QPACK encoder (0x02), QPACK decoder (0x03) |
| §6.2.1 | Control stream + `SETTINGS` frame sent on handshake completion |
| §7.2 | Frame types: `DATA`, `HEADERS`, `SETTINGS`, `PUSH_PROMISE` (reject), `GOAWAY` |
| §7.2.6 | `GOAWAY` — graceful shutdown with last-processed stream ID |
| §8 | Error codes (`H3_NO_ERROR`, `H3_GENERAL_PROTOCOL_ERROR`, `H3_FRAME_UNEXPECTED`, `H3_ID_ERROR`, `H3_SETTINGS_ERROR`, `H3_MISSING_SETTINGS`, `H3_MESSAGE_ERROR`) |

### QPACK Header Compression — RFC 9204

| Clause | Feature |
|--------|---------|
| §2 | Static table (99 entries, RFC 9204 Appendix A) |
| §3.2.2 | Dynamic table capacity — `Set Dynamic Table Capacity` encoder instruction |
| §3.2.4 | Dynamic table entry eviction on capacity reduction |
| §4.5 | Static table indexed field lines |
| §4.5.2 | Literal field lines with name reference |
| §4.5.6 | Literal field lines without name reference |
| §4.6 | Header block prefix (Required Insert Count + Base) |
| — | Encoder stream instructions (insert with static/dynamic name ref, insert without name ref) |
| — | Decoder stream instructions (Section Acknowledgment, Insert Count Increment) |
| — | Huffman string encoding/decoding (per RFC 7541 §5.2) |
| — | Blocked stream handling (wait for dynamic table sync before decoding) |

### Extensions

| RFC / Draft | Feature |
|-------------|---------|
| RFC 7541 | Huffman coding (used by QPACK) |
| RFC 8701 | QUIC greasing — reserved frame/transport-parameter IDs |
| RFC 9221 | Unreliable QUIC Datagram extension (`DATAGRAM` frames, type 0x30/0x31) |
| RFC 9297 | HTTP Datagrams — Quarter Stream ID prefix, `H3_DATAGRAM` SETTINGS (0x33) |
| RFC 9218 | Extensible Prioritization Scheme — `PRIORITY_UPDATE` frame parse (0xF0700/0xF0701) |
| Draft Multipath | Multi-path QUIC — per-path congestion control, active path selection |

### Path MTU Discovery

Custom implementation: PMTUD probes via oversized `PING`-padded packets; MTU ratchets up on ACK, stays on loss.

---

## Architecture

Two layers: a QUIC transport layer (`src/quic/`) and an HTTP/3 layer (`src/h3/`).

```
src/
├── quic/
│   ├── connection.cr     # QUIC state machine (sans-I/O)
│   ├── tls.cr            # LibSSL QUIC-native BIO wrapper
│   ├── crypto.cr         # AEAD (AES-128/256-GCM, ChaCha20-Poly1305) + header protection
│   ├── recovery.cr       # Loss detection & congestion control (NewReno / BBR)
│   ├── stream.cr         # QUIC stream state machine
│   └── server.cr         # Low-level UDP server (not used by H3::Server)
└── h3/
    ├── server.cr          # H3::Server + actor-per-connection dispatcher
    ├── connection_actor.cr# Per-connection fiber (one per QUIC connection)
    ├── connection.cr      # HTTP/3 framing over QUIC streams
    ├── router.cr          # H3::Router — middleware + named-param routing
    ├── context.cr         # H3::Context (request + response per handler call)
    ├── request.cr         # H3::Request
    ├── response.cr        # H3::Response
    └── qpack/             # QPACK header compression (static table, Huffman)
```

The QUIC core follows a **sans-I/O** design: `QUIC::Connection` never owns a socket.
Callers feed UDP datagrams in via `connection.recv(bytes)` and drain outgoing bytes via
`connection.send(buf)`.  Each HTTP/3 connection is owned by a dedicated `ConnectionActor`
fiber; with `-Dpreview_mt` actors run on multiple OS threads without mutexes.

---

## Development

```bash
# Run all specs
crystal spec

# Run a single spec file
crystal spec spec/h3_spec.cr

# Build & run an example
crystal build examples/h3_server_routed.cr -o examples/h3_server_routed
./examples/h3_server_routed
```

See `TODO.md` for known limitations and planned work.

---

## Contributing

1. Fork → feature branch → commit → pull request.
2. Run `crystal spec` and `cd bench/go_client/cross_test && go build . && ./cross_test -start-server` before opening a PR.

## License

MIT
