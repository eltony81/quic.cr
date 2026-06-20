# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run all specs
crystal spec

# Run a single spec file
crystal spec spec/h3_spec.cr

# Run a specific spec by name
crystal spec spec/h3_spec.cr --example "some test name"

# Build an example binary
crystal build examples/h3_server_routed.cr -o examples/h3_server_routed

# Run an example directly
crystal run examples/h3_server_routed.cr

# Test with curl (HTTP/3)
curl -v --http3 "https://127.0.0.1:4433/" --insecure

# Python cross-tests (requires aioquic via venv)
source venv/bin/activate
python examples/validate_cross_tests.py
```

TLS certs for local dev are `cert.pem` / `key.pem` at the repo root.

Crystal >= 1.20.2 required. No external Crystal shard dependencies.

## Architecture

The library has two layers: a QUIC transport layer (`src/quic/`) and an HTTP/3 layer (`src/h3/`). The QUIC core follows a "sans-I/O" design — `QUIC::Connection` does not own a socket; callers feed UDP datagrams in via `connection.recv(bytes)` and drain outgoing bytes via `connection.send(buf)`.

### QUIC Layer (`src/quic/`)

**`connection.cr`** — The central state machine. Key concepts:
- Three `PacketNumberSpace` instances (`@space_initial`, `@space_handshake`, `@space_app`) isolate crypto keys and packet numbers per encryption level.
- Each `PacketNumberSpace` carries its own `AEAD` (rx/tx) and `HeaderProtection` (rx/tx) keys, which are installed by `TLS` as the handshake progresses.
- Multiple `Path` objects support multipath QUIC; `@active_path_id` tracks the current path.
- `handshake_chan` and `stream_chans` are Crystal `Channel(Bool)` used to signal completion events between fibers (avoid sleep-polling).

**`tls.cr`** — LibSSL wrapper using QUIC-native BIO mode (`SSL_set_quic_method` / QUIC BIO callbacks). TLS does not run over a normal socket; instead static callbacks (`crypto_send_cb`, `crypto_recv_rcd_cb`, etc.) shuttle `CRYPTO` frame bytes between the TLS engine and `QUIC::Connection`. Derived secrets are delivered via `yield_secret_cb`, which installs AEAD keys into the appropriate `PacketNumberSpace`.

**`crypto.cr`** — `QUIC::Crypto::AEAD` wraps AES-128-GCM via `OpenSSL::Cipher` (with custom `update_ad`/`gcm_get_tag`/`gcm_set_tag` extensions). `QUIC::Crypto::HeaderProtection` handles packet header masking/unmasking. Initial keys are derived from the DCID using the `INITIAL_SALT_V1` constant.

**`recovery.cr`** — Loss detection and congestion control per RFC 9002. Implements both NewReno and BBR (toggle via `bbr_enabled`). Tracks RTT (smoothed + variance), PTO timers, `SentPacket` records, and congestion window.

**`server.cr`** — Low-level `QUIC::Server` binds a `UDPSocket`, routes incoming datagrams to existing or new `QUIC::Connection` instances by DCID, and calls back into each connection's state machine.

**`stream_socket.cr`** — `QUIC::StreamSocket` wraps a `QUIC::Connection` + stream ID and inherits from `IO`, making streams usable with any Crystal IO-aware API (`gets`, `puts`, etc.).

### HTTP/3 Layer (`src/h3/`)

**`server.cr`** — `H3::Server` has two modes:
1. Low-level block: `H3::Server.new { |headers, body| { response_headers, body } }`
2. Router-based: `H3::Server.new(router).listen(host:, port:, cert:, key:)`

`listen` manages its own `UDPSocket`, spawns a background receiver fiber, and uses a `Channel` (capacity 1000) to decouple I/O from request handling.

**`router.cr`** — `H3::Router` is a linear-scan router (not a real trie despite the doc comment). Supports named parameters (`:id`), middleware chains (`router.use { |ctx, next| ... }`), and all standard HTTP verbs via Crystal macros. Middleware is called in insertion order and must call `next_handler.call(ctx)` to continue the chain.

**`connection.cr`** — `H3::Connection` maps QUIC streams to HTTP/3 semantics: unidirectional control/encoder/decoder streams, and bidirectional request streams. Uses client-initiated bidi stream IDs starting at 0 (incrementing by 4).

**`context.cr` / `request.cr` / `response.cr`** — `H3::Context` wraps `H3::Request` + `H3::Response` for a single request cycle. Convenience responders: `ctx.text(...)`, `ctx.json(...)`, `ctx.html(...)`, `ctx.redirect(...)`.

**`qpack/`** — QPACK field compression: static table (99 entries), Huffman coding, and N-bit prefix integer encoding/decoding are fully implemented. The dynamic table (`qpack/dynamic_table.cr`) is a stub — dynamic QPACK is not yet supported, so only static-table and literal header encoding is used.

### Key Invariants

- All numeric wire-format fields use `QUIC::VarInt` (variable-length integers per RFC 9000 Section 16).
- Frame parsing is in `src/quic/frame.cr` (`Frame.decode`) and `src/h3/frame.cr` for H3 frames; they share no code.
- Protocol errors must call `send_connection_close` rather than `raise`, to avoid crashing the server on misbehaving clients.
- 0-RTT and connection migration are not yet implemented (see TODO.md).
- Dynamic QPACK is deferred — the encoder always emits static-table or literal representations.

### Cross-Testing

`examples/` contains Python scripts (`client_aioquic.py`, `server_aioquic.py`, `validate_cross_tests.py`) that use `aioquic` to validate interoperability. The Python environment lives in `venv/`. The Crystal server listens on port 4433; the Python server uses 4434.
