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
  - [ ] **Loss Detection Timer (RFC 9002 §6.2)**: attualmente `detect_lost_packets` è
        chiamato ogni 10ms dal `tick()` (fix anti-false-positive). Sostituire con un
        timer dedicato: `@loss_time = oldest_unacked.time_sent + loss_delay`. Il timer
        si aggiorna in `on_ack_received` e si valuta in `tick()`; si cancella se lo
        spazio è vuoto. Questo eliminerebbe il delay fisso di 10ms per ciclo che
        oggi penalizza il 1MB di ~55ms rispetto a quic-go.
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
- [ ] **Fiber-based Concurrency**: 
  - [x] Refactor UDP listener into a dedicated network thread/loop.
  - [x] Dispatch connection handling via channels and `spawn` blocks.
- [x] **Zero-Copy Memory Allocation**:
  - [x] Implement `QUIC::BufferPool` — thread-safe pool of reusable `Bytes` slices (lease/return/borrow).
  - [x] `H3::Server.listen` receiver fiber leases a buffer per packet and returns it immediately after copy.
  - [x] Optimize AEAD functions to process buffers in-place: cached `@nonce` (zero alloc per call) + `update_into`/`gcm_get_tag_into` write directly into a single pre-allocated result buffer (1 alloc instead of 4+ intermediates).
