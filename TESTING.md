# Testing — istruzioni operative

## Prerequisiti

```bash
# Crystal >= 1.15 (controlla versione)
crystal --version

# Attiva il venv Python per i test interop (aioquic)
source venv/bin/activate
```

I certificati TLS per lo sviluppo locale si trovano in `cert.pem` / `key.pem` nella root del repo.

---

## 1. Unit test Crystal

Lancia tutti gli spec (QUIC + H3 + QPACK):

```bash
crystal spec
```

Solo i test QPACK (60 casi, RFC 9204):

```bash
crystal spec spec/qpack_spec.cr
```

Solo i test H3:

```bash
crystal spec spec/h3_spec.cr
```

---

## 2. Cross-validation interoperabilità (27 test)

Verifica che il server Crystal e il client aioquic si parlino correttamente.
Lo script avvia i server da solo — non serve farli girare a mano.

```bash
source venv/bin/activate
python3 examples/validate_cross_tests.py
```

Output atteso:

```
════════════════════════════════════════════════════════════
  SUMMARY  27/27 passed   ✓ all green
════════════════════════════════════════════════════════════
```

Lo script esegue tre fasi:

| Fase | Cosa testa |
|------|------------|
| Phase 1 | aioquic client → Crystal server (routing, body, headers, concorrenza) |
| Phase 2 | Crystal client → aioquic server (handshake, stream, GOAWAY) |
| Phase 3 | Robustezza: frame malformati, stream violation, large payload |

---

## 3. Benchmark QPACK: static vs dynamic

Confronta la latenza con dynamic table disabilitato (cap=0) contro abilitato (cap=4096).
Richiede di compilare due binari separati.

### 3a. Compila i binari

```bash
# Dynamic (default attuale — cap=4096)
crystal build examples/h3_server_routed.cr -o /tmp/h3testsrv_dynamic

# Static (commenta set_capacity e riporta SETTINGS 0x01 => 0 — vedi connection.cr)
# Oppure usa un define di compilazione se lo hai aggiunto
crystal build examples/h3_server_routed.cr -o /tmp/h3testsrv_static
```

> Per i dettagli su come tornare allo statico vedi il commento in `src/h3/connection.cr`
> nel metodo `open_qpack_streams`.

### 3b. Lancia il benchmark

```bash
source venv/bin/activate
python3 examples/bench_qpack.py
```

Opzioni disponibili:

```bash
python3 examples/bench_qpack.py --n 500          # più richieste per scenario (default 300)
python3 examples/bench_qpack.py --batch 60        # richieste per connessione (default 80, max 127)
python3 examples/bench_qpack.py --static  /percorso/binario_static
python3 examples/bench_qpack.py --dynamic /percorso/binario_dynamic
```

Output atteso:

```
  Scenario           Modalità                      mean       p50       p95       p99      rps
  ─────────────────────────────────────────────────────────────────────────────────────
  GET /              STATIC  (cap=0)              1.66ms     1.40ms     2.64ms     8.06ms     603/s
                     DYNAMIC (cap=4096)           1.50ms     1.11ms     2.88ms     8.38ms     666/s  (-20.3%)

  POST /echo 1KB     STATIC  (cap=0)              2.22ms     2.27ms     3.46ms     8.32ms     450/s
                     DYNAMIC (cap=4096)           1.79ms     1.35ms     3.12ms     9.05ms     558/s  (-40.3%)
```

> I warning `ValueError: Cannot send data on peer-initiated unidirectional stream` che
> compaiono a volte sono un bug del GC di Python 3.14 + aioquic e non influenzano i risultati.

---

## 4. Test manuale con curl

```bash
# Avvia il server
crystal run examples/h3_server_routed.cr

# In un altro terminale — richiede curl con HTTP/3 (curl >= 7.88 con quiche o ngtcp2)
curl -v --http3 "https://127.0.0.1:4433/" --insecure
curl -v --http3 "https://127.0.0.1:4433/greet?name=World" --insecure
curl -v --http3 "https://127.0.0.1:4433/users/42" --insecure
curl -v --http3 "https://127.0.0.1:4433/echo" --insecure -X POST \
     -H "content-type: application/json" -d '{"hello":"world"}'
```

---

## 5. Benchmark Crystal HTTP/3 vs Go (quic-go)

Confronto diretto tra quic.cr e quic-go su tre scenari: small GET, small POST, large POST (1 MB).
Lo script misura ogni scenario con N round sequenziali, **una nuova connessione QUIC per richiesta**
(include overhead handshake — misura il caso reale, non il keep-alive).

### 5a. Compila il server Crystal

```bash
crystal build examples/h3_server_routed.cr -o /tmp/crystal_h3_srv
```

### 5b. Compila il server Go

```bash
cd bench/go_server
go build -o go_h3_server .
cd ../..
```

> Il server Go usa `../../cert.pem` / `../../key.pem` per default (relativo a `bench/go_server/`).
> Puoi passare percorsi alternativi come argomenti: `./go_h3_server /path/cert.pem /path/key.pem`

### 5c. Avvia entrambi i server

Apri due terminali (o usa `&`):

```bash
# Terminale 1 — Crystal su porta 4433
/tmp/crystal_h3_srv

# Terminale 2 — Go su porta 4434
cd bench/go_server && ./go_h3_server
```

### 5d. Lancia il benchmark

```bash
source venv/bin/activate
python3 bench/benchmark.py          # default: 30 round per scenario
python3 bench/benchmark.py -n 100   # più round per statistiche più stabili
```

Output atteso (valori indicativi da loopback):

```
==========================================================================================
  HTTP/3 Benchmark: quic.cr (Crystal, :4433) vs quic-go (Go, :4434)
  30 sequential requests per scenario (one connection per request)
==========================================================================================

  Running: A. GET /  [Crystal] (30 rounds)... done
  Running: A. GET /  [Go] (30 rounds)... done
  ...

──────────────────────────────────────────────────────────────────────────────────────────
  RESULTS
──────────────────────────────────────────────────────────────────────────────────────────
  A. GET /  [Crystal]                           mean=  2.1ms  p50=  1.9ms  p95=  3.4ms  rps= 476.2  err=0
  A. GET /  [Go]                                mean=  3.8ms  p50=  3.5ms  p95=  6.1ms  rps= 263.2  err=0
  B. POST /echo 20B [Crystal]                   mean=  2.3ms  p50=  2.1ms  p95=  3.7ms  rps= 434.8  err=0
  B. POST /echo 20B [Go]                        mean=  4.1ms  p50=  3.9ms  p95=  6.4ms  rps= 243.9  err=0
  C. POST /echo 1MB [Crystal]                   mean= 18.4ms  p50= 17.2ms  p95= 28.1ms  rps=  54.3  err=0
  C. POST /echo 1MB [Go]                        mean= 22.7ms  p50= 21.5ms  p95= 31.9ms  rps=  44.1  err=0

──────────────────────────────────────────────────────────────────────────────────────────
  SPEEDUP  (Crystal mean / Go mean — >1 means Crystal is faster)
──────────────────────────────────────────────────────────────────────────────────────────
  GET /                  Crystal  2.1ms  Go  3.8ms  → Crystal is 1.81× faster
  POST /echo 20B         Crystal  2.3ms  Go  4.1ms  → Crystal is 1.78× faster
  POST /echo 1MB         Crystal 18.4ms  Go 22.7ms  → Crystal is 1.23× faster
```

> Il vantaggio di Crystal è maggiore sui piccoli payload (handshake + scheduling più leggero)
> e si riduce su payload grandi dove la larghezza di banda diventa il collo di bottiglia.
