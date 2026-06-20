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
- [x] **Flow Control Enforcement**:
  - [x] Track local and remote `MAX_DATA` correctly across the connection.
  - [x] Track `MAX_STREAM_DATA` for individual streams.
  - [x] Emit `DATA_BLOCKED` and `STREAMS_BLOCKED` when hitting limits.
- [ ] **Connection Migration**:
  - [ ] Parse and handle `PATH_CHALLENGE` / `PATH_RESPONSE`.
  - [ ] Allow endpoint IP changes during active connections.
- [ ] **0-RTT (Early Data)**:
  - [ ] Save/restore session tickets and early data parameters.
  - [ ] Encrypt/decrypt 0-RTT packet number spaces.

### 2. Security & Error Handling (QUIC & TLS)
- [ ] **DDoS Mitigation (Stateless Retry)**:
  - [ ] Parse and generate `Retry` packets.
  - [ ] Implement cryptographically secure token generation for address validation.
- [x] **Robust Error Handling**:
  - [x] Map all protocol violations to specific RFC error codes.
  - [x] Replace `raise` statements with `send_connection_close` to prevent server crashes.

### 3. HTTP/3 & QPACK Layer
- [x] **QPACK Baseline Implementation**:
  - [x] Implement N-bit Prefix Integer Encoding/Decoding.
  - [x] Implement Huffman String Encoding/Decoding.
  - [x] Implement 99-element Static Table resolution.
  - [x] Parse Header Block Prefix and decode Field Lines (Static/Literal).
- [ ] **Dynamic QPACK Implementation** (Deferred):
  - [ ] Build QPACK Encoder and Decoder streams.
  - [ ] Support dynamic table insertion and eviction.
  - [ ] Handle blocked streams awaiting dynamic table synchronization.
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
- [ ] **Zero-Copy Memory Allocation**:
  - [ ] Implement a custom `BufferPool` to avoid native GC allocations.
  - [ ] Read directly into reusable slices.
  - [ ] Optimize AEAD functions to process buffers in-place without `.dup`.
