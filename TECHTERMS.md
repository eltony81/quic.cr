# Glossario Tecnico — quic.cr

Termini tecnici usati nel codice, nei commit e nelle discussioni del progetto.
Ogni voce spiega cos'è, il problema che risolve e dove appare in quic.cr.

---

## Protocollo QUIC — Fondamentali

### Sans-I/O
Architettura in cui il core del protocollo (`QUIC::Connection`) non possiede
un socket. Il chiamante passa datagram in ingresso via `recv(bytes)` e legge
datagram in uscita via `send(buf)`. Questo rende il core testabile senza rete
reale e riutilizzabile da diversi transport (UDP, simulatore, test).

### VarInt (Variable-length Integer)
Intero a lunghezza variabile 1-8 byte definito da RFC 9000 §16. I 2 bit più
significativi del primo byte indicano la lunghezza (1/2/4/8 byte). Usato
ovunque nel wire format QUIC per evitare campi a dimensione fissa.
File: `src/quic/varint.cr`

### Packet Number Space
QUIC mantiene tre spazi numerici indipendenti (Initial, Handshake, App) con
chiavi AEAD e contatori di packet number propri. Evita che un attacker possa
correlare pacchetti di fasi diverse dell'handshake.
File: `src/quic/connection.cr` — `@space_initial`, `@space_handshake`, `@space_app`

### Coalesced Packets
RFC 9000 §12.2 permette di impacchettare più QUIC packet in un singolo UDP
datagram. Un server può inviare Initial + Handshake nello stesso datagram per
risparmiare RTT. Il parser di `recv()` usa un loop con offset per processare
tutti i packet contenuti.
File: `src/quic/connection.cr` — `recv()`

---

## Crittografia e TLS

### AEAD (Authenticated Encryption with Associated Data)
Cifratura autenticata: garantisce sia confidenzialità che integrità. QUIC usa
AES-128-GCM. Il nonce è derivato da packet number + chiave IV. Il tag a 16
byte alla fine del payload detecta manomissioni.
File: `src/quic/crypto.cr` — `QUIC::Crypto::AEAD`

### Header Protection
RFC 9001 §5.4: i bit del primo byte e i 4 byte del packet number vengono
mascherati con AES-ECB applicato al campione del payload cifrato. Nasconde il
packet number ai middlebox per impedire traffic analysis.
File: `src/quic/crypto.cr` — `QUIC::Crypto::HeaderProtection`

### Key Phase (KEY_PHASE bit)
Bit nella short header che indica quale set di chiavi 1-RTT è in uso.
Necessario per Key Update (RFC 9001 §6): il receiver distingue i pacchetti
con le chiavi "correnti" da quelli con le chiavi "nuove" senza un nuovo
handshake.

### Spin Bit Greasing
RFC 9000 §17.4: il bit 0x20 della short header è usato per misurare l'RTT
in modo passivo dagli operatori di rete. Se non implementato attivamente, va
randomizzato ("greased") per prevenire ossificazione: i middlebox non devono
poter assumere un valore fisso.
File: `src/quic/packet.cr` — `ShortHeaderPacket#first_byte`

### Ossificazione (Protocol Ossification)
Fenomeno per cui middlebox (firewall, NAT, proxy) iniziano ad assumere
comportamenti fissi di un protocollo, rendendo impossibile modificarli in
futuro. QUIC combatte l'ossificazione con greasing di versioni, GREASE frame
e spin bit randomizzato.

### 0-RTT (Early Data)
Meccanismo che consente al client di inviare dati applicativi nel primo
datagram (prima che l'handshake sia completato) riutilizzando un session
ticket precedente. Elimina il round-trip di setup per connessioni ripetute,
al costo di non fornire forward secrecy per quei dati.
File: `src/quic/connection.cr`, `src/quic/tls.cr`

### Stateless Reset
Se il server perde lo stato di una connessione, invia un SHORT packet con un
token HMAC-SHA256 deterministico (calcolato dal DCID). Il client riconosce il
token e chiude la connessione invece di restare in timeout.
File: `src/quic/server.cr`

---

## Controllo della Congestione e Loss Detection

### cwnd (Congestion Window)
Numero massimo di byte che possono essere "in volo" (inviati ma non ancora
ACKati) contemporaneamente. Regolato da NewReno o BBR. Piccolo cwnd = invio
lento ma sicuro; grande cwnd = throughput alto ma rischio di congestione.
File: `src/quic/recovery.cr`

### Slow Start
Fase iniziale di NewReno: cwnd cresce esponenzialmente (raddoppia ogni RTT)
finché non supera `ssthresh` o si rileva una perdita. Permette di trovare
rapidamente la banda disponibile.

### NewReno
Algoritmo di controllo della congestione classico: slow start → congestion
avoidance (cwnd += 1 MSS per RTT) → halve cwnd su perdita.
File: `src/quic/recovery.cr`

### BBR (Bottleneck Bandwidth and Round-trip propagation time)
Algoritmo moderno di controllo della congestione di Google. Invece di
reagire alle perdite, stima la banda massima disponibile e l'RTT minimo per
calcolare il rate di invio ottimale. Riduce latenza e buffer bloat rispetto
a NewReno.
File: `src/quic/recovery.cr` — `bbr_enabled`

### Smoothed RTT / SRTT
Media esponenzialmente ponderata dei campioni RTT: `srtt = srtt * 7/8 + rtt *
1/8`. Filtra jitter e outlier. Base per calcolare PTO e loss_delay.
File: `src/quic/recovery.cr` — `@smoothed_rtt`

### RTTVar
Varianza dell'RTT (RTTVAR in RFC 9002): stima la deviazione dell'RTT dal suo
valore medio. Usata per dimensionare il margine del PTO: `pto = srtt + 4 ×
rttvar`. Tiene conto della variabilità della rete.
File: `src/quic/recovery.cr` — `@rttvar`

### PTO (Probe Timeout)
Timer che scatta quando non si riceve ACK entro `smoothed_rtt + 4 × rttvar +
max_ack_delay`. Triggera l'invio di un "probe" per verificare se la rete è
attiva o se i pacchetti sono persi. RFC 9002 §6.2.
File: `src/quic/recovery.cr` — `pto_timeout`

### kInitialRtt
Valore RTT iniziale usato prima che arrivi il primo campione reale: 333ms per
RFC 9002. Determina il PTO iniziale: `2 × 333ms = 666ms`. Prima del fix
recente, quic.cr calcolava `srtt + rttvar×4 = 1022ms` (troppo conservativo).

### Loss Detection Timer
RFC 9002 §6.2: invece di chiamare `detect_lost_packets` ad ogni ACK (falsi
positivi), si calcola `loss_time = oldest_unacked.time_sent + loss_delay` e
si valuta solo quando il timer scade. Evita di dichiarare persi pacchetti in
volo che saranno ACKati nel batch successivo.
File: `src/quic/recovery.cr` — `@loss_time`

### False-Positive Loss Detection
Problema specifico con aioquic: invia ACK in batch da 1ms (asyncio). Se il
primo batch ACKa solo 283-287 di 700 pacchetti, i pacchetti 0-282 venivano
dichiarati persi immediatamente → cwnd dimezzato → 9 PTO × 100ms = 9 secondi
di stallo. Risolto spostando `detect_lost_packets` nel `tick()` da 10ms.

### ECN (Explicit Congestion Notification)
Meccanismo IP che permette ai router di segnalare congestione senza scartare
pacchetti. I router settano bit ECT(0)/ECT(1) nei pacchetti IP; i receiver
riportano CE (Congestion Experienced) negli ACK QUIC. Il sender riduce cwnd
alla ricezione di segnali CE.

### PMTUD (Path MTU Discovery)
Processo per trovare il MTU massimo del percorso di rete. quic.cr invia
probe con padding progressivo e verifica quali vengono ACKati per determinare
`@path_mtu`.
File: `src/quic/connection.cr`

---

## Pacing e Performance

### Pacing
Distribuzione temporale dei pacchetti in uscita invece di inviarli in burst.
Senza pacing: 700 pacchetti inviati in 0.8ms → router buffer overflow →
perdite. Con pacing: inter-packet gap = `packet_size / pacing_rate_bps`.
Migliora RTT stima e riduce perdite su reti reali.
File: `src/h3/connection_actor.cr` — `flush_outgoing`, token bucket

### Token Bucket
Meccanismo di rate limiting: un "secchio" accumula token a velocità costante
(`pacing_rate_bps`), ogni pacchetto consumano token proporzionali alla sua
dimensione. Se il secchio è vuoto, il sending si interrompe finché non si
riempie. Cap sul secchio = bound sul burst massimo consentito.
File: `src/h3/connection_actor.cr` — `@pacing_tokens`

### Dynamic Timer (Timer Dinamico)
Sostituzione del `timeout(10ms)` fisso nel loop dell'actor con
`min(loss_time - now, pto_deadline - now, 50ms)`. Il select si sveglia
esattamente quando un evento significativo è atteso, invece di ogni 10ms.
Riduce latenza su reti reali senza introdurre falsi positivi su loopback.
File: `src/h3/connection_actor.cr` — `next_tick_timeout`

---

## Architettura

### Actor Model
Pattern di concorrenza: ogni connessione QUIC è gestita da un singolo fiber
(`ConnectionActor`) che possiede in esclusiva il suo stato. Nessun mutex
necessario — la comunicazione avviene tramite `Channel`. Con `-Dpreview_mt`,
actor diversi girano su OS thread diversi.
File: `src/h3/connection_actor.cr`

### MAX_STREAMS Replenishment (Rifornimento)
RFC 9000 §4.6: il server tiene traccia degli stream aperti dal peer. Quando
il peer supera il 50% del limite corrente, invia un `MAX_STREAMS` frame per
alzare il limite. Evita che il client resti bloccato ad aspettare permesso
per aprire nuovi stream.
File: `src/quic/connection.cr` — `check_max_streams_replenishment`

### Flow Control (Controllo del Flusso)
Meccanismo a doppio livello: connessione (`MAX_DATA`) e stream
(`MAX_DATA_STREAM`). Il sender non può inviare più byte di quanto il receiver
abbia autorizzato. Previene overflow del buffer del receiver.

### QPACK
Algoritmo di compressione degli header HTTP/3 (RFC 9204). Alternativa a
HPACK (HTTP/2) progettata per QUIC: supporta una tabella dinamica senza
blocco head-of-line. Static table di 99 entry predefinite; dynamic table
aggiornata tramite stream encoder/decoder dedicati.
File: `src/h3/qpack/`

### Huffman Encoding
Codifica a lunghezza variabile usata da QPACK per comprimere le stringhe
degli header HTTP. Le stringhe comuni (es. "application/json") occupano meno
byte. Implementato con tabella di 257 simboli RFC 7541.
File: `src/h3/qpack/huffman.cr`

### Multipath QUIC
Estensione (draft) che permette a una connessione QUIC di usare più percorsi
di rete simultaneamente (es. WiFi + 5G). quic.cr mantiene array `@paths` con
recovery indipendente per percorso.
File: `src/quic/connection.cr` — `@paths`, `@active_path_id`

### BatchSender
Ottimizzazione che accumula pacchetti UDP in un batch e li invia con una
singola syscall `sendmmsg` invece di un `sendto` per pacchetto. Riduce il
numero di context switch kernel/userspace su invii ad alto throughput.
File: `src/quic/batch_sender.cr`
