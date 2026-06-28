# Actor Model in quic.cr

> **Server-side only.** The pattern is used exclusively by `H3::Server.listen`
> via `H3::ConnectionActor` (`src/h3/connection_actor.cr`, `src/h3/server.cr`).
> `H3::Client` **does not use** the actor model: it manages the connection directly
> in the calling fiber with a `Channel(Bool)` to synchronise the handshake and
> `spawn` for the receive loop — a simpler design suited to a single outbound connection.

The server needs the actor model because it handles **N simultaneous connections
from different peers** on a single `UDPSocket`. Each connection has its own
independent QUIC state (TLS keys, packet number spaces, streams, recovery) that
cannot be shared between fibers without mutexes. Assigning a dedicated fiber per
connection eliminates the problem at the root: no sharing, no locks.

Each QUIC connection has a dedicated fiber (`ConnectionActor`) that exclusively owns
its state — communication only via `Channel`.

---

## Component overview

```mermaid
graph TD
    NET(["UDP Network"])
    RF["Receiver Fiber\n1 per server\nUDPSocket.receive\nBatchReceiver.drain"]
    RL["Router Loop\n1 per server\nconnections : Hash\nsole owner of map"]
    CA["ConnectionActor fiber\n1 per connection\nQUIC::Connection\nH3::Connection\npacing token bucket"]
    HF["Handler Fiber\n1 per bidi stream\nrouter/middleware\nctx.json / ctx.text"]

    NET -->|"UDP datagram"| RF
    RF -->|"router_chan\nRouterPacket\ncap=4608"| RL
    RL -->|"actor.deliver()\npacket_chan\ncap=512"| CA
    CA -->|"data_chan\nHTTP bytes\ncap=512"| HF
    HF -->|"response_chan\n{stream_id, bytes}\ncap=256"| CA
    CA -->|"RouterReg / RouterClean\nrouter_chan"| RL
    CA -->|"udp.send()\nencrypted QUIC packet"| NET
```

---

## Full flow — from UDP datagram to HTTP response

This section describes step by step everything that happens from the arrival of a
UDP datagram to sending the HTTP/3 response to the client.

### 1. Receiver Fiber — listening on the network

The `Receiver Fiber` is the sole point of contact with the UDP socket. It blocks on
`blocking_drain(udp)`, which internally uses `epoll` (Linux) and does not consume CPU
while waiting. When a datagram arrives, the OS wakes the fiber.

`blocking_drain` calls `recvmmsg` with `MSG_DONTWAIT` to read in one shot all
datagrams already present in the kernel receive buffer, without additional syscalls.
With UDP GRO enabled, the kernel coalesces equal-size datagrams from the same source
into one large buffer per slot; `each_segment` splits them by `gso_size`. Each
datagram is copied and sent to `router_chan` as a `RouterPacket`.

The Receiver Fiber knows nothing about QUIC — it works only with raw bytes and IP
addresses. This keeps it simple and fast.

### 2. Router Loop — routing connections

The Router Loop receives messages from `router_chan` and is the sole fiber that reads
and writes the `connections : Hash(String, ConnectionActor)` map. No mutex is needed
on this map because only this fiber touches it.

When a `RouterPacket` arrives, the Router extracts the DCID (Destination Connection
ID) from the first bytes of the QUIC datagram and uses it as a lookup key. If no
actor is found for that DCID, it checks whether there is an actor associated with the
source IP address (fallback for packets that arrive before the SCID is registered).

If no actor exists for this connection, the Router creates:
- a `QUIC::Connection` with the TLS configuration
- an `H3::Connection` that maps QUIC streams to HTTP/3 semantics
- a `ConnectionActor` that spawns the fiber and starts running

The Router then calls `actor.deliver(data)`, a non-blocking send on the actor's
`packet_chan`. If the channel were full (beyond 512 slots), the datagram would be
silently dropped — UDP is unreliable by design and QUIC handles retransmission at
the application level.

The Router also handles two control messages from the actor:
- `RouterReg`: the actor has completed the handshake and knows its definitive SCID —
  the Router adds the new alias to the map for future lookups.
- `RouterClean`: the actor has closed — the Router removes all entries.

### 3. ConnectionActor — the heart of the connection

The actor is a single Crystal fiber running in a `select` loop with three arms. It
exclusively owns `QUIC::Connection` and `H3::Connection` — no other fiber ever
touches them.

```mermaid
flowchart TD
    S([" select "]) --> A1["arm 1\npacket_chan.receive\nQUIC datagram"]
    S --> A2["arm 2\nresponse_chan.receive\nHTTP response"]
    S --> A3["arm 3\ntimeout(next_tick_timeout)\nloss detection / PTO"]

    A1 --> D["recv_packet(data)\nQUIC::Connection.recv\ndecrypt + parse frames"]
    D --> DR["drain loop\nflush packet_chan\nnon-blocking"]
    DR --> FW["forward_stream_data\nbytes → data_chan handler"]
    FW --> FO1["flush_outgoing\npacing → udp.send"]

    A2 --> HR["handle_response\nstream.write + close_local"]
    HR --> FO2["flush_outgoing"]

    A3 --> TK["quic_conn.tick\nPTO / loss detection"]
    TK --> FO3["flush_outgoing"]

    FO1 & FO2 & FO3 --> CK{"closed?"}
    CK -->|"no"| S
    CK -->|"yes"| END([" ensure cleanup "])
```

**Arm 1 — incoming packet**: The raw datagram is passed to `QUIC::Connection.recv`,
which unmasks the header (header protection), decrypts the payload (AEAD AES-128-GCM),
and dispatches the contained frames: `CRYPTO` for the TLS handshake, `STREAM` for
HTTP data, `ACK` for recovery updates, etc.

After `recv_packet`, the drain loop flushes all of `packet_chan` with a non-blocking
`select+else`. This is critical for performance: instead of making a round-trip in
`select` for every packet (700 times for 1 MB), all bytes are accumulated in the
stream buffers and `flush_outgoing` is called just once.

**Arm 2 — HTTP response**: A handler fiber has finished building the response and
sends it on `response_chan`. The actor writes the bytes to the QUIC stream object
and calls `close_local` to append the FIN bit.

**Arm 3 — timer**: Fires when the timeout computed by `next_tick_timeout` expires.
Calls `quic_conn.tick`, which evaluates whether the Loss Detection Timer has expired
(declare packets lost) or whether the PTO (Probe Timeout) has expired (send a probe
to verify the network is alive).

### 4. HTTP/3 stream dispatch

When `recv_packet` sees a stream with ID % 4 == 0 (client-initiated bidirectional
stream, RFC 9000 §2.1), it spawns a new handler fiber.

```mermaid
sequenceDiagram
    participant Actor as ConnectionActor
    participant SC as stream_channels (Map)
    participant HF as Handler Fiber (req-N)
    participant Sck as ActorStreamSocket

    Actor->>SC: data_chan = Channel(Bytes).new(512)
    Actor->>SC: stream_channels[stream_id] = data_chan
    Actor->>Sck: sock = ActorStreamSocket.new(stream_id, data_chan, self)
    Actor->>HF: spawn { server.handle_request(h3_conn, sock) }

    note over Actor,HF: Handler fiber reads HTTP/3 headers via sock.read()
    note over Actor,HF: which blocks on data_chan.receive

    Actor->>SC: forward_stream_data: stream.read → data_chan.send
    data_chan-->>HF: bytes received from peer
    HF->>HF: router/middleware dispatch
    HF->>Actor: response_chan.send({stream_id, bytes})
    Actor->>Actor: handle_response: stream.write + close_local
    Actor->>Actor: flush_outgoing → udp.send(STREAM frame + FIN)
```

`ActorStreamSocket` is an `IO` that reads from `data_chan` and writes to
`response_chan`. Handlers can use it with any Crystal IO-aware API (`gets`, `puts`,
etc.) without knowing anything about QUIC or the underlying actor.

### 5. Pacing — rate-limited sending

`flush_outgoing` implements a token bucket to avoid micro-bursts:

```mermaid
flowchart LR
    subgraph "Token Bucket"
        T["@pacing_tokens\nFloat64"]
        R["pacing_rate_bps\ncwnd / srtt\nor BBR"]
        B["max_burst\nrate × 10ms"]
        R -->|"+ rate × elapsed"| T
        B -->|"clamp max"| T
    end

    T -->|"> 0"| SND["send_coalesced\nudp.send\n@pacing_tokens -= n"]
    T -->|"≤ 0"| STOP["break\nwait for next tick"]
```

`@pacing_tokens` starts at `Float64::MAX` so the handshake and slow-start are never
throttled. The rate is provided by `Recovery.pacing_rate_bps`: uses BBR
`max_bandwidth × 1.25` when available, otherwise `cwnd / srtt`.

### 6. Dynamic timer — waking up at the right time

The `timeout(next_tick_timeout)` computes when the next event is expected:

```mermaid
flowchart TD
    NE{"next_event_time\n= min(loss_time,\n  pto_deadline)"}
    NE -->|"present"| D{"delta\n= t - now"}
    NE -->|"absent\nno packets in flight"| I["50ms\nidle"]
    D -->|"≤ 3ms"| F["3ms\nanti-burst floor"]
    D -->|"> 3ms"| M["min(delta, 50ms)"]
```

The 3ms floor is necessary on loopback: aioquic sends ACKs in batches every ~1ms
(asyncio event loop). With RTT ~2ms, `loss_time = T+2.25ms`. Without the floor the
timer would fire at T+2.25ms, before the second ACK batch at T+3ms → false positives
→ `cwnd` halved → PTO stall. The floor ensures the next batch has already arrived
when the timer wakes up.

---

## Full sequence diagram — UDP in → HTTP response out

```mermaid
sequenceDiagram
    participant NET as UDP Network
    participant RF as Receiver Fiber
    participant RC as router_chan
    participant RL as Router Loop
    participant PC as packet_chan
    participant CA as ConnectionActor
    participant QC as QUIC::Connection
    participant DC as data_chan
    participant HF as Handler Fiber
    participant RPC as response_chan

    NET->>RF: UDP datagram
    RF->>RF: batch_receiver.blocking_drain (GRO)
    RF->>RC: RouterPacket{data, addr}

    RC->>RL: msg = router_chan.receive
    RL->>RL: conn_key = extract_dcid(data)
    RL->>RL: actor = connections[key]? (create if nil)
    RL->>PC: actor.deliver(data) → packet_chan.send

    PC->>CA: select arm 1: data = packet_chan.receive
    CA->>CA: drain loop (flush packet_chan)
    CA->>QC: recv(data) — decrypt + parse frames
    QC-->>CA: stream data available
    CA->>DC: forward_stream_data → data_chan.send(bytes)
    CA->>NET: flush_outgoing → udp.send (ACK, HANDSHAKE)

    DC->>HF: handler reads HTTP/3 headers
    HF->>HF: router dispatch + middleware
    HF->>RPC: response_chan.send({stream_id, response_bytes})

    RPC->>CA: select arm 2: resp = response_chan.receive
    CA->>QC: stream.write(response_bytes) + close_local
    CA->>NET: flush_outgoing → udp.send (STREAM frame + FIN)
```

---

## Channels and types

| Channel | Type | Capacity | From → To | Purpose |
|---------|------|----------|-----------|---------|
| `router_chan` | `Channel(RouterMsg)` | 4608 | Receiver / Actor → Router | all messages to the router |
| `packet_chan` | `Channel(Bytes)` | 512 | Router → Actor | raw QUIC datagrams |
| `response_chan` | `Channel({UInt64, Bytes})` | 256 | Handler fiber → Actor | encoded HTTP response |
| `data_chan` (bidi stream) | `Channel(Bytes)` | 512 | Actor → Handler fiber | bytes received from peer |
| `data_chan` (uni stream) | `Channel(Bytes)` | 16 | Actor → Uni handler | QPACK encoder/decoder/control |

### RouterMsg — structured union type

```crystal
record RouterPacket, data : Bytes, addr : Socket::IPAddress
record RouterReg,    key : String, actor : ConnectionActor
record RouterClean,  key : String, addr_key : String
alias RouterMsg = RouterPacket | RouterReg | RouterClean
```

Three `record` types instead of tuples allow the Crystal compiler to narrow types
in `case/when` without ambiguity in `select` unions.

---

## No-mutex invariant

```mermaid
graph LR
    subgraph "Router fiber"
        RL2["connections Hash\nread/write"]
    end
    subgraph "Actor fiber"
        QC2["QUIC::Connection\nH3::Connection\nstream buffers"]
    end
    subgraph "Handler fiber N"
        HF2["reads data_chan\nwrites response_chan"]
    end

    RL2 <-->|"packet_chan\n(Channel)"| QC2
    QC2 <-->|"data_chan / response_chan\n(Channel)"| HF2
    RL2 -.->|"NEVER direct access"| QC2
    HF2 -.->|"NEVER direct access"| QC2
```

`QUIC::Connection` and `H3::Connection` never need locks because they are only
accessible from the actor's fiber. Router and handlers communicate exclusively via
channels. Crystal channels are thread-safe by design.

---

## Actor lifecycle

```mermaid
stateDiagram-v2
    [*] --> Spawned : ConnectionActor.new\nspawn { run }
    Spawned --> Handshake : packet_chan.receive\nrecv_packet → CRYPTO frames
    Handshake --> H3Init : handshake_complete?\nopen control/QPACK streams
    H3Init --> Active : dispatch_new_streams\nspawn handler fibers
    Active --> Active : arm1 packets\narm2 responses\narm3 tick
    Active --> Closing : quic_conn.closed?
    Closing --> [*] : ensure\nstream_channels EOF\nRouterClean → router
```

The `ensure` at the end of `run` guarantees cleanup even on exception: it sends
`Bytes.empty` on all open `data_chan`s (EOF signal to handlers) and sends
`RouterClean` to the Router to remove entries from the map.

---

## Multithreading with `-Dpreview_mt`

With the `-Dpreview_mt` build flag, Crystal assigns fibers to OS threads from the
system pool. Different actors run on different cores without code changes — `Channel`s
are thread-safe by design.

```mermaid
graph TD
    subgraph "OS Thread 0"
        RF3["Receiver Fiber"]
        RL3["Router Loop"]
    end
    subgraph "OS Thread 1"
        CA3["Actor conn A"]
        HF3["Handler A"]
    end
    subgraph "OS Thread 2"
        CA4["Actor conn B"]
        HF4["Handler B"]
    end

    RF3 -->|"router_chan"| RL3
    RL3 -->|"packet_chan A"| CA3
    RL3 -->|"packet_chan B"| CA4
    CA3 <-->|"data/response chan"| HF3
    CA4 <-->|"data/response chan"| HF4
```

Reference files: `src/h3/connection_actor.cr`, `src/h3/server.cr`
