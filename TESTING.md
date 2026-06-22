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
