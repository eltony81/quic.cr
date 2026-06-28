# Technical Glossary — quic.cr

Technical terms used in the code, commits, and project discussions.
Each entry explains what it is, the problem it solves, and where it appears in quic.cr.

---

## QUIC Protocol — Fundamentals

### Sans-I/O
Architecture in which the protocol core (`QUIC::Connection`) does not own a socket.
The caller feeds incoming datagrams via `recv(bytes)` and reads outgoing datagrams
via `send(buf)`. This makes the core testable without a real network and reusable
across different transports (UDP, simulator, tests).

### VarInt (Variable-length Integer)
A 1–8 byte variable-length integer defined by RFC 9000 §16. The 2 most significant
bits of the first byte encode the length (1/2/4/8 bytes). Used throughout the QUIC
wire format to avoid fixed-size fields.
File: `src/quic/varint.cr`

### Packet Number Space
QUIC maintains three independent number spaces (Initial, Handshake, App), each with
its own AEAD keys and packet number counters. This prevents an attacker from
correlating packets from different handshake phases.
File: `src/quic/connection.cr` — `@space_initial`, `@space_handshake`, `@space_app`

### Coalesced Packets
RFC 9000 §12.2 allows multiple QUIC packets to be packed into a single UDP datagram.
A server can send Initial + Handshake in the same datagram to save an RTT. The
`recv()` parser uses an offset loop to process all packets contained in the datagram.
File: `src/quic/connection.cr` — `recv()`

---

## Cryptography and TLS

### AEAD (Authenticated Encryption with Associated Data)
Authenticated encryption that guarantees both confidentiality and integrity. QUIC uses
AES-128-GCM. The nonce is derived from the packet number + IV key. The 16-byte tag
at the end of the payload detects tampering.
File: `src/quic/crypto.cr` — `QUIC::Crypto::AEAD`

### Header Protection
RFC 9001 §5.4: the bits of the first byte and the 4 bytes of the packet number are
masked using AES-ECB applied to a sample of the encrypted payload. This hides the
packet number from middleboxes to prevent traffic analysis.
File: `src/quic/crypto.cr` — `QUIC::Crypto::HeaderProtection`

### Key Phase (KEY_PHASE bit)
A bit in the short header indicating which set of 1-RTT keys is in use. Required for
Key Update (RFC 9001 §6): the receiver distinguishes packets using "current" keys
from those using "new" keys without a new handshake.

### Spin Bit Greasing
RFC 9000 §17.4: the 0x20 bit of the short header is used by network operators to
passively measure RTT. If not actively implemented, it must be randomised ("greased")
to prevent ossification: middleboxes must not be able to assume a fixed value.
File: `src/quic/packet.cr` — `ShortHeaderPacket#first_byte`

### Protocol Ossification
The phenomenon where middleboxes (firewalls, NATs, proxies) start assuming fixed
protocol behaviours, making it impossible to change them in the future. QUIC fights
ossification with version greasing, GREASE frames, and randomised spin bit.

### 0-RTT (Early Data)
A mechanism that allows the client to send application data in the first datagram
(before the handshake is complete) by reusing a previous session ticket. Eliminates
the setup round-trip for repeated connections, at the cost of no forward secrecy for
that data.
File: `src/quic/connection.cr`, `src/quic/tls.cr`

### Stateless Reset
If the server loses the state of a connection, it sends a SHORT packet with a
deterministic HMAC-SHA256 token (computed from the DCID). The client recognises the
token and closes the connection instead of timing out.
File: `src/quic/server.cr`

---

## Congestion Control and Loss Detection

### cwnd (Congestion Window)
The maximum number of bytes that can be "in flight" (sent but not yet ACKed) at any
one time. Regulated by NewReno or BBR. Small cwnd = slow but safe sending; large
cwnd = high throughput but risk of congestion.
File: `src/quic/recovery.cr`

### Slow Start
The initial phase of NewReno: cwnd grows exponentially (doubles every RTT) until it
exceeds `ssthresh` or a loss is detected. Allows quickly finding available bandwidth.

### NewReno
Classic congestion control algorithm: slow start → congestion avoidance (cwnd += 1
MSS per RTT) → halve cwnd on loss.
File: `src/quic/recovery.cr`

### BBR (Bottleneck Bandwidth and Round-trip propagation time)
Google's modern congestion control algorithm. Instead of reacting to losses, it
estimates the maximum available bandwidth and minimum RTT to compute the optimal
sending rate. Reduces latency and buffer bloat compared to NewReno.
File: `src/quic/recovery.cr` — `bbr_enabled`

### Smoothed RTT / SRTT
Exponentially weighted moving average of RTT samples: `srtt = srtt * 7/8 + rtt * 1/8`.
Filters jitter and outliers. The basis for computing PTO and loss_delay.
File: `src/quic/recovery.cr` — `@smoothed_rtt`

### RTTVar
RTT variance (RTTVAR in RFC 9002): estimates how much RTT deviates from its mean.
Used to size the PTO margin: `pto = srtt + 4 × rttvar`. Accounts for network
variability.
File: `src/quic/recovery.cr` — `@rttvar`

### PTO (Probe Timeout)
A timer that fires when no ACK is received within `smoothed_rtt + 4 × rttvar +
max_ack_delay`. Triggers sending a "probe" to verify whether the network is alive or
packets have been lost. RFC 9002 §6.2.
File: `src/quic/recovery.cr` — `pto_timeout`

### kInitialRtt
The initial RTT value used before the first real sample arrives: 333ms per RFC 9002.
Determines the initial PTO: `2 × 333ms = 666ms`. Before a recent fix, quic.cr
computed `srtt + rttvar×4 = 1022ms` (too conservative).

### Loss Detection Timer
RFC 9002 §6.2: instead of calling `detect_lost_packets` on every ACK (false
positives), `loss_time = oldest_unacked.time_sent + loss_delay` is computed and
evaluated only when the timer expires. Avoids declaring in-flight packets lost when
they will be ACKed in the next batch.
File: `src/quic/recovery.cr` — `@loss_time`

### False-Positive Loss Detection
A specific problem with aioquic: it sends ACKs in 1ms batches (asyncio). If the
first batch ACKs only 283–287 of 700 packets, packets 0–282 were immediately declared
lost → cwnd halved → 9 PTO × 100ms = 9 seconds of stall. Fixed by moving
`detect_lost_packets` into the 10ms `tick()`.

### ECN (Explicit Congestion Notification)
An IP mechanism that allows routers to signal congestion without dropping packets.
Routers set ECT(0)/ECT(1) bits in IP packets; receivers report CE (Congestion
Experienced) in QUIC ACKs. The sender reduces cwnd upon receiving CE signals.

### PMTUD (Path MTU Discovery)
The process of finding the maximum MTU along the network path. quic.cr sends probes
with progressive padding and checks which ones are ACKed to determine `@path_mtu`.
File: `src/quic/connection.cr`

---

## Pacing and Performance

### Pacing
Spreading outgoing packets over time instead of sending them in a burst. Without
pacing: 700 packets sent in 0.8ms → router buffer overflow → losses. With pacing:
inter-packet gap = `packet_size / pacing_rate_bps`. Improves RTT estimation and
reduces losses on real networks.
File: `src/h3/connection_actor.cr` — `flush_outgoing`, token bucket

### Token Bucket
A rate-limiting mechanism: a "bucket" accumulates tokens at a constant rate
(`pacing_rate_bps`); each packet consumes tokens proportional to its size. If the
bucket is empty, sending pauses until it refills. The bucket cap bounds the maximum
allowed burst.
File: `src/h3/connection_actor.cr` — `@pacing_tokens`

### Dynamic Timer
Replacement of the fixed `timeout(10ms)` in the actor loop with
`min(loss_time - now, pto_deadline - now, 50ms)`. The select wakes up exactly when
a meaningful event is expected instead of every 10ms. Reduces latency on real
networks without introducing false positives on loopback.
File: `src/h3/connection_actor.cr` — `next_tick_timeout`

---

## Architecture

### Actor Model
A concurrency pattern: each QUIC connection is managed by a single fiber
(`ConnectionActor`) that exclusively owns its state. No mutex required —
communication happens via `Channel`. With `-Dpreview_mt`, different actors run on
different OS threads.
File: `src/h3/connection_actor.cr`

### MAX_STREAMS Replenishment
RFC 9000 §4.6: the server tracks how many streams the peer has opened. When the peer
exceeds 50% of the current limit, a `MAX_STREAMS` frame is sent to raise the limit.
Prevents the client from stalling while waiting for permission to open new streams.
File: `src/quic/connection.cr` — `check_max_streams_replenishment`

### Flow Control
A two-level mechanism: connection (`MAX_DATA`) and stream (`MAX_STREAM_DATA`). The
sender cannot send more bytes than the receiver has authorised. Prevents receiver
buffer overflow.

### QPACK
HTTP/3 header compression algorithm (RFC 9204). Alternative to HPACK (HTTP/2),
designed for QUIC: supports a dynamic table without head-of-line blocking. Static
table of 99 predefined entries; dynamic table updated via dedicated encoder/decoder
streams.
File: `src/h3/qpack/`

### Huffman Encoding
Variable-length coding used by QPACK to compress HTTP header strings. Common strings
(e.g. "application/json") occupy fewer bytes. Implemented with a 257-symbol table
per RFC 7541.
File: `src/h3/qpack/huffman.cr`

### Multipath QUIC
An extension (draft) that allows a QUIC connection to use multiple network paths
simultaneously (e.g. WiFi + 5G). quic.cr maintains a `@paths` array with independent
recovery state per path.
File: `src/quic/connection.cr` — `@paths`, `@active_path_id`

### BatchSender
An optimisation that accumulates UDP packets into a batch and sends them with a
single `sendmmsg` syscall instead of one `sendto` per packet. Reduces the number of
kernel/userspace context switches on high-throughput sends.
File: `src/quic/batch_sender.cr`

### BatchReceiver
An optimisation that receives multiple UDP datagrams per `recvmmsg` syscall. With
UDP GRO (Generic Receive Offload) enabled, the kernel coalesces equal-size datagrams
from the same 5-tuple into one large buffer per slot, reporting the segment size via
a `UDP_GRO` cmsg. `each_segment` splits the buffer by `gso_size` and yields each
individual QUIC datagram. `MAX_PKT = 65536` (64KB) ensures the buffer is never
truncated by GRO (Linux `GRO_MAX_SIZE = 65535`).
File: `src/quic/batch_receiver.cr`
