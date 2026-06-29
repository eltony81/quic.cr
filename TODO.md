# QUIC Implementation Tracker

This document tracks the progress of making `quic.cr` a production-ready QUIC implementation based on RFC 9000, 9001, and 9002.

## Phase 1: Core Architecture (Completed)
- [x] Basic Library Structure (sans-I/O)
- [x] Variable-Length Integer (VarInt) Encoding/Decoding
- [x] Packet Header parsing (Long and Short)
- [x] Basic Frame parsing (`PADDING`, `CRYPTO`)
- [x] Connection state machine skeleton

## Phase 2: Security & Handshake (Completed)
- [x] HKDF Extract/Expand-Label for QUIC (RFC 9001)
- [x] AEAD Payload Encryption/Decryption (AES-128-GCM)
- [x] Header Protection (Masking/Unmasking)
- [x] TLS 1.3 Handshake driving via OpenSSL `BIO`
- [x] Initial Packet Number Space integration

## Phase 3: Flow Control & Basic Multiplexing (Completed)
- [x] `STREAM` frame parsing and emitting
- [x] Logical Stream management
- [x] Basic Flow Control (`MAX_DATA`, `MAX_STREAM_DATA`)
- [x] Connection Termination (`CONNECTION_CLOSE`)
- [x] Path Validation (`PATH_CHALLENGE`, `PATH_RESPONSE`)
- [x] Multiple Packet Number Spaces skeleton

## Phase 5: IETF Extensions & RFC Compliance (Completed)

### 9. Core Protocol Hardening
- [x] Implement `Retry` packet and Address Validation (RFC 9000 Section 8).
- [x] Implement `NEW_TOKEN` generation and token verification.
- [x] Implement Version Negotiation (RFC 9000 Section 6).
- [x] Implement Connection Greasing (RFC 8701).

### 10. Advanced Transport Features
- [x] Implement QUIC Datagram Extension (RFC 9221).
- [x] Implement BBR Congestion Control.
- [x] Implement Path MTU Discovery (PMTUD).
- [x] Implement Multipath QUIC (Draft).

### 11. Application Layer (HTTP/3)
- [x] Implement HTTP/3 Stream Mapping (RFC 9114).
- [x] Implement QPACK Field Compression (RFC 9204).
- [x] Implement HTTP/3 Settings and Control Streams.
- [x] Implement High-Level `H3::Server` and `H3::Client`.

## Phase 6: Production Readiness Road to 1.0

### 1. Reliability & Network Performance (QUIC)
- [x] **Congestion Control**:
  - [x] Implement cwnd (congestion window) tracking.
  - [x] Implement standard CUBIC or NewReno algorithm.
  - [x] Pacing mechanism to avoid micro-bursts of packets.
- [x] **Packet Loss Detection & Retransmission**: 
  - [x] Implement RTT (Round Trip Time) calculation and smoothed RTT (SRTT).
  - [x] Implement PTO (Probe Timeout) timers.
  - [x] Logic to clone and retransmit lost stream/crypto frames.
  - [x] Full ACK range processing (all ranges, not just first) per RFC 9002 Section 2.3.
  - [x] **Loss Detection Timer (RFC 9002 §6.2)**: implementato `@loss_time` in
        `Recovery` — calcolato in `on_ack_received` come `oldest_unacked.time_sent +
        loss_delay` (via `compute_loss_delay`). Valutato in `tick()`: se `now >=
        loss_time` si chiama `detect_lost_packets` e si azzera il timer. Rimosso il
        flag `pending_loss_detection?` precedente. Il tick immediato post-drain
        nell'actor è stato escluso (re-introduce falsi positivi su loopback con RTT
        ~2ms ≈ loss_delay); il tick da 10ms resta necessario come buffer anti-burst.
  - [x] **Pacing + Timer Dinamico (RFC 9002 §7.7)**: implementati in `connection_actor.cr`:
        1. **Token bucket pacing**: `flush_outgoing` accredita token a `pacing_rate_bps`
           byte/s (da `Recovery`), cap a 10ms di burst. Ogni send scala i token; se
           esauriti il loop si interrompe e il prossimo tick rifornisce. Inizia con
           token=∞ per non bloccare handshake e slow-start.
        2. **Timer dinamico**: `next_tick_timeout` sostituisce `timeout(10ms)` — restituisce
           `min(loss_time - now, pto - now, 50ms)` con floor di 3ms (buffer per batch ACK
           asyncio da 1ms). Su loopback: Crystal 260ms ≈ Go 263ms sul 1MB (+1.01×),
           miglioramento da 1.21× precedente.
- [x] **Flow Control Enforcement**:
  - [x] Track local and remote `MAX_DATA` correctly across the connection.
  - [x] Track `MAX_STREAM_DATA` for individual streams.
  - [x] Emit `DATA_BLOCKED` and `STREAMS_BLOCKED` when hitting limits.
  - [x] Handle `MAX_STREAMS` (0x12/0x13) and `STREAMS_BLOCKED` (0x16/0x17) frames.
- [x] **Connection Migration**:
  - [x] Parse and handle `PATH_CHALLENGE` / `PATH_RESPONSE` in `handle_frame`.
  - [x] Drain `@pending_path_challenges` in `send()` → emits `PathChallengeFrame`.
  - [x] `initiate_path_validation()` queues a random 8-byte challenge; `path_validated?` tracks outcome.
  - [x] `H3::Server.listen` detects peer address change and triggers path validation automatically.
- [x] **0-RTT (Early Data)**:
  - [x] Save/restore session tickets and early data parameters.
  - [x] Encrypt/decrypt 0-RTT packet number spaces.

### 2. Security & Error Handling (QUIC & TLS)
- [x] **DDoS Mitigation (Stateless Retry)**:
  - [x] Parse and generate `Retry` packets.
  - [x] Implement cryptographically secure token generation for address validation (HMAC-SHA256 keyed with server secret).
  - [x] Compute Retry Integrity Tag via AES-128-GCM with RFC 9001 §5.8 fixed key/nonce.
  - [x] Client verifies Retry Integrity Tag before accepting a Retry packet.
  - [x] Stateless reset token uses HMAC-SHA256 with server secret (was bare SHA256).
- [x] **Robust Error Handling**:
  - [x] Map all protocol violations to specific RFC error codes.
  - [x] Replace `raise` statements with `send_connection_close` to prevent server crashes.

### 3. HTTP/3 & QPACK Layer
- [x] **QPACK Baseline Implementation**:
  - [x] Implement N-bit Prefix Integer Encoding/Decoding.
  - [x] Implement Huffman String Encoding/Decoding.
  - [x] Implement 99-element Static Table resolution.
  - [x] Parse Header Block Prefix and decode Field Lines (Static/Literal).
- [x] **Dynamic QPACK Implementation**:
  - [x] Persistent `QPACK::Encoder` and `QPACK::Decoder` per `H3::Connection` (connection-scoped dynamic table).
  - [x] Two-pass encoder: pre-insert all novel headers, then encode with correct relative indices (fixed per-call rel_idx=0 bug).
  - [x] Open QPACK encoder stream (type=2) and decoder stream (type=3) on handshake completion.
  - [x] `H3::Connection.write_frame` flushes encoder stream instructions before each HEADERS frame.
  - [x] `Frame.decode` accepts optional `QPACK::Decoder` parameter for persistent decoding.
  - [x] Handle blocked streams awaiting dynamic table synchronization (RFC 9204 §2.1.1).
  - [x] Decoder acknowledgment stream (decoder sends Insert Count Increment / Stream Cancellation).
- [x] **HTTP/3 Client API**:
  - [x] Build `H3::Client` abstraction akin to `HTTP::Client`.
  - [x] Implement `get`, `post`, and other standard HTTP methods.
  - [x] Handle concurrent stream multiplexing (Fiber-based receive loop + per-stream bidi IDs).
  - [x] Handle request/response lifecycle accurately (headers, body).
  - [x] Handle trailers (optional, deferred).
- [x] **High-Level Server API**:
  - [x] Refine `H3::Server` with handler-block abstraction akin to `HTTP::Server`.
  - [x] Build `H3::Context`, `H3::Request`, and `H3::Response` classes.
  - [x] Implement middleware support and routing mechanics.

### 4. Concurrency & Memory Optimization
- [x] **Fiber-based Concurrency**: 
  - [x] Refactor UDP listener into a dedicated network thread/loop.
  - [x] Dispatch connection handling via channels and `spawn` blocks.
- [x] **Zero-Copy Memory Allocation**:
  - [x] Implement `QUIC::BufferPool` — thread-safe pool of reusable `Bytes` slices (lease/return/borrow).
  - [x] `H3::Server.listen` receiver fiber leases a buffer per packet and returns it immediately after copy.
  - [x] Optimize AEAD functions to process buffers in-place: cached `@nonce` (zero alloc per call) + `update_into`/`gcm_get_tag_into` write directly into a single pre-allocated result buffer (1 alloc instead of 4+ intermediates).
  - [x] Cache `OpenSSL::Cipher` context per `AEAD` instance (`@cipher_enc`, `@cipher_dec`) — eliminates 2× `EVP_CIPHER_CTX_new()` per received packet on the hot path (+47% RPS, 14k→21k req/s).
  - [x] Pre-allocate `AEAD.@decrypt_buf` (4096 B) — eliminates 1× `~1244 B` heap alloc per received packet.
  - [x] Cache `OpenSSL::Cipher` context per `HeaderProtection` instance (`@cipher`) and pre-allocate `@mask_buf` (16 B) — eliminates 2× cipher allocs + 2× concat allocs per packet (hp_rx + hp_tx).

### 5. Performance Optimization Roadmap (completed and active work)
- [x] **Rewrite Python benchmark client in Go** — Implemented Go HTTP/3 benchmark client in `bench/go_client/bench_h3`. It replaces the old Python/aioquic benchmark client, eliminating the dynamic GC overhead and providing highly accurate micro-second latency metrics.
- [ ] **Migrate Python cross-validation tests to Go** — All remaining validation and cross-validation scripts (`bench/bench.py`, `examples/validate_cross_tests.py`, `examples/bench_qpack.py`) currently written in Python should be replaced by Go (or Crystal native) equivalents. Python's runtime memory management and GC pauses introduce excessive overhead, creating timing inconsistencies and skewing/falsifying comparative benchmark metrics.
- [x] **Opt-3: Zero-alloc PN decode** — `connection.cr` creates `IO::Memory.new` for
      every long-header and short-header packet to decode the 1–4 byte packet number.
      Replaced with direct byte reads. Eliminates 2× small allocs per packet.
- [x] **Opt-4: Frame parsing buffer reuse** — `Frame.decode` allocates a new `IO::Memory`
      for the entire payload on every packet. Implemented `QUIC::SliceReader` to wrap
      plaintext slice. Eliminates 1× `IO::Memory.new(payload_size)` per packet.
- [x] **Opt-5: Static VarInt decoding for SliceReader** — Implemented statically-dispatched
      `SliceReader#read_varint` and overloaded `VarInt.decode` to bypass virtual `IO` calls and
      stack-allocated buffers, reducing concurrent p99 latency to 3.61ms (beating Go).
- [ ] **Opt-6: GC tuning for large transfers** — Boehm GC's stop-the-world pauses
      dominate the 4x throughput gap vs Go. Options: `GC_enable_incremental()` via
      LibGC to overlap marking with mutator, or tune `GC_set_free_space_divisor` to
      reduce collection frequency at the cost of higher resident memory.

## Phase 7: RFC Compliance & Interoperability Gaps

### 1. Sicurezza & Robustezza (Alto impatto)
- [x] **Key Update (RFC 9001 §6)**: `ShortHeaderPacket` emette il bit `KEY_PHASE`
      (0x04, coperto da header protection) in base a `@key_phase`. Al receive, dopo
      l'unprotection, se `peer_kp != @peer_key_phase` si chiama `handle_peer_key_update`
      che deriva le chiavi next-gen via `derive_next_secret`, tenta il decrypt, e su
      successo commita le nuove chiavi e aggiorna `@key_phase`. Le vecchie RX keys
      sono salvate in `@old_aead_rx` per i pacchetti out-of-order. `trigger_key_update`
      (auto-iniziazione) salva old RX e flippa `@key_phase`. Spec: `key_update_spec.cr`.
- [x] **Spin bit greasing (RFC 9000 §17.4)**: `ShortHeaderPacket#first_byte` imposta
      il bit 0x20 in modo casuale ad ogni pacchetto. Il bit non è coperto da header
      protection (RFC 9001 §5.4.1) — visibile in chiaro agli intermediari ma
      randomizzato per prevenire ossificazione da middlebox.
- [x] **`max_udp_payload_size` transport parameter (RFC 9000 §18.2)**: rimossa la
      condizione `!= 65527` che impediva l'emissione del parametro quando il valore
      coincideva con il default RFC. Ora sempre incluso nel wire encoding.
- [x] **PTO handshake accelerato (RFC 9002 §6.2.4)**: `pto_timeout` ora usa
      `2 × kInitialRtt = 666ms` quando `min_rtt == Time::Span::MAX` (nessun campione
      RTT ancora disponibile). In precedenza calcolava `smoothed_rtt(333ms) + rttvar×4
      + 25ms = 1022ms`, il 34% più lento del valore RFC raccomandato.
- [x] **Stateless Reset emissione (RFC 9000 §10.3)**: `H3::Server` router loop ora
      detecta short-header packets (bit7=0) con DCID sconosciuto e risponde con un
      pacchetto da 40 byte contenente il token HMAC-SHA256 deterministico (già usato
      da `QUIC::Server`). Spec: `stateless_reset_spec.cr`.
- [x] **ECN codepoints in uscita (RFC 9000 §13.4 + RFC 9002 §7.6)**: `H3::Server`
      e `QUIC::Server` chiamano `setsockopt(IP_TOS=1, ECT(0)=2, IPPROTO_IP=0)` sul
      `UDPSocket` dopo il bind. Costanti `IPPROTO_IP`/`IP_TOS` aggiunte a `LibSys`
      in `sys/linux.cr`. Recovery già riduceva `cwnd` su ECN-CE. Spec: `ecn_spec.cr`.

### 2. Versioning & Interoperabilità (Medio impatto)
- [x] **QUIC v2 (RFC 9369)**: `INITIAL_SALT_V2` + `derive_initial_secrets_v2` con
      label `quicv2 client/server in`. `Connection` imposta `@quic_version` dal primo
      long-header packet; `derive_quic_keys` usa prefisso `"quicv2 "` per key/iv/hp;
      `trigger_key_update` chiama `derive_next_secret_v2` (`quicv2 ku`) per v2.
      QUIC::Server invia VN con entrambe le versioni [v1, v2]. Spec: `quic_v2_spec.cr`.
- [x] **Compatible Version Negotiation (RFC 9368)**: `TransportParameters` aggiunge
      `quic_version_information` (TP ID `0x11`) con encode/decode. Il server server
      emette `{chosen: v1, others: [v2]}` in ogni handshake. 14 test in `quic_v2_spec.cr`.
- [x] **PTO handshake accelerato (RFC 9002 §6.2.4)**: `pto_timeout` usa
      `2 × kInitialRtt = 666ms` quando `min_rtt == Time::Span::MAX` (vedi §1 sopra).

### 3. HTTP/3 & Estensioni (Medio / Basso impatto)
- [x] **HTTP/3 Server Push (RFC 9114 §4.6)**: `PushPromiseFrame` (type 0x05) con
      encode QPACK statico. `H3::Connection.server_push(request_stream_id,
      push_request_headers, push_response_headers, push_body)` apre un push stream
      unidirezionale server-initiated (ID % 4 == 3), emette push stream type byte,
      push_id VarInt, HEADERS + DATA frame. `@next_push_id` counter per push_id univoci.
      11 test in `spec/h3_push_spec.cr`.
- [ ] **WebTransport / Extended CONNECT (RFC 9298)**: nessun handling del metodo
      `CONNECT` né upgrade di stream bidirezionali. Richiesto per use-case real-time
      (gaming, video conferencing). quic-go ha `webtransport-go` separato.

### 4. Transport Parameters & Misc (Basso impatto)
- [x] **`max_udp_payload_size` transport parameter (RFC 9000 §18.2)**: rimossa la
      condizione `!= 65527` — ora sempre incluso nel wire encoding (vedi §1 sopra).
- [x] **Spin bit greasing (RFC 9000 §17.4)**: `ShortHeaderPacket#first_byte` imposta
      il bit 0x20 in modo casuale ad ogni pacchetto (vedi §1 sopra).

### 5. Production Engineering (Non-RFC)
- [x] **Automatic Self-Signed Certificate Generation**: `TLS` class automatically detects
      missing `cert_file`/`key_file` paths and invokes a subprocess `openssl` call to
      generate a compliant RSA cert/key pair in milliseconds at startup, enabling out-of-the-box
      development without manual configuration.
- [ ] **Test di carico / fuzzing**: nessuno stress test con connessioni simultanee
      oltre le 8 dei cross-test. Servono test di regressione con 100+ connessioni
      concorrenti e un fuzzer QUIC (es. `quic-interop-runner`) per trovare edge case
      nel parser di pacchetti.
- [x] **Graceful shutdown**: `H3::Server.shutdown()` imposta `Atomic(Bool)` flag e
      chiude `@udp_socket` per sbloccare il receiver fiber. Il router loop controlla
      il flag prima/dopo ogni `receive` e chiama `actor.shutdown` su tutte le
      connessioni aperte. `ConnectionActor.shutdown` invia `close(0, "server shutdown")`
      e sveglia il `packet_chan` con `Bytes.empty`. Spec: `production_spec.cr`.
- [x] **Logging strutturato a runtime**: Crystal supporta natively `CRYSTAL_LOG_LEVEL`
      e `CRYSTAL_LOG_SOURCES` env var per filtrare verbosità senza ricompilare.
      Esempio: `CRYSTAL_LOG_LEVEL=DEBUG crystal run examples/h3_server_routed.cr`
- [x] **Connection ID rotation (RFC 9000 §5.1.1)**: `Connection` traccia `@peer_cids`
      (lista CID ricevuti via `NEW_CONNECTION_ID`) e `@issued_cids`. `handle_frame`
      gestisce `NewConnectionIdFrame` (aggiorna lista, scarta CID sotto `retire_prior_to`)
      e `RetireConnectionIdFrame` (rimuove da `@issued_cids`). Spec: `production_spec.cr`.
- [x] **CI automatico**: `.github/workflows/ci.yml` — pipeline a 2 job: `test`
      (unit tests + build `--no-codegen`) e `cross-test` (aioquic + Python, gated
      su `test`). Genera cert TLS effimeri in CI. Trigger su push/PR a `main`.
