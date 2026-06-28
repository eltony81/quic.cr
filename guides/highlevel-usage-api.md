# QUIC.cr High-Level API Usage Guide

This guide describes how to use the high-level API of `quic.cr` to build QUIC-based servers and clients. The library follows a "sans-I/O" core but provides `QUIC::Server` and `QUIC::StreamSocket` for easy integration with Crystal's standard library.

---

## 1. Configuration

Every connection or server requires a `QUIC::Config` object to define protocol limits and timeouts.

```crystal
require "quic"

config = QUIC::Config.new
config.max_idle_timeout = 30_000_u64                # 30 seconds
config.initial_max_data = 10_000_000_u64           # 10 MB connection window
config.initial_max_stream_data_bidi_local = 1_000_000_u64 # 1 MB per stream
```

---

## 2. Implementing a Server

The `QUIC::Server` manages a `UDPSocket`, handles the complex routing of QUIC packets based on Destination Connection IDs (DCIDs), and manages the lifecycle of multiple `QUIC::Connection` instances.

### Basic Server Loop
```crystal
server = QUIC::Server.new(config, address: "0.0.0.0", port: 4433)

# The listen method is a blocking loop that:
# 1. Receives UDP datagrams.
# 2. Routes them to existing or new Connections.
# 3. Automatically handles the TLS 1.3 Handshake.
# 4. Sends responses back to clients.
server.listen
```

### Handling Streams (Concurrency)
To handle data on individual streams, you can currently access the `@connections` map or extend the server to yield new connections/streams. Since QUIC is multiplexed, usually you want a Fiber per stream:

```crystal
# Inside a custom server logic or connection handler:
conn = server.connections[client_cid]
stream_io = QUIC::StreamSocket.new(conn, stream_id: 4_u64)

spawn do
  while line = stream_io.gets
    stream_io.puts "Echo: #{line}"
  end
end
```

---

## 3. Interacting with Streams (`QUIC::StreamSocket`)

The `StreamSocket` class inherits from `IO`, making it compatible with all standard Crystal IO operations.

| Feature | Method | Description |
| :--- | :--- | :--- |
| **Read** | `read(slice)` | Reads available data from the QUIC stream buffer. |
| **Write** | `write(slice)` | Writes data to the stream (subject to flow control). |
| **Puts** | `puts(string)` | Standard formatted output. |
| **Gets** | `gets` | Reads until newline. |

---

## 4. Security & TLS

The library automatically handles:
- **Initial Keys**: Derived from the Destination Connection ID.
- **Handshake Keys**: Extracted automatically from the TLS stack during handshake.
- **1-RTT Keys**: Automatically applied for application data once the handshake is confirmed.
- **Transport Parameters**: Automatically exchanged during the `EncryptedExtensions` phase of TLS 1.3.

---

## 5. Low-Level "Sans-I/O" Integration

If you don't want to use `QUIC::Server` and prefer to manage your own socket loop (e.g., inside an existing event loop):

```crystal
# 1. Ingest bytes
processed_bytes = connection.recv(udp_payload)

# 2. Generate responses
out_buffer = Bytes.new(2048)
while (size = connection.send(out_buffer)) > 0
  udp_socket.send(out_buffer[0, size], remote_addr)
end

# 3. Check for timeouts
if Time.local >= connection.recovery.timeout
  # Trigger retransmissions/PTO logic
end
```

---

## 6. Architecture Summary for Sub-Agents

If you are a Gemini sub-agent tasked with extending this library:
1.  **State Machine**: All logic lives in `QUIC::Connection`. It uses `PacketNumberSpace` to isolate Initial/Handshake/App data.
2.  **Binary**: Use `QUIC::VarInt` for all numeric fields. Use `QUIC::Frame.decode` and `QUIC::Frame#encode` for payload units.
3.  **Crypto**: `QUIC::Crypto::AEAD` handles encryption. `QUIC::Crypto::HeaderProtection` handles masking.
4.  **TLS**: `QUIC::TLS` is a wrapper around LibSSL. It uses `keylog_callback` to leak secrets back to `QUIC::Connection`.
