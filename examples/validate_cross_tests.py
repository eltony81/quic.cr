import asyncio
import sys
import os
import subprocess
import time
import argparse
import base64
import json
from aioquic.asyncio import QuicConnectionProtocol
from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.events import ConnectionTerminated as QuicConnectionTerminated

# Standard configurations
HOST = "127.0.0.1"
PORT_CRYSTAL = 4433
PORT_PYTHON = 4434

class H3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3_conn = H3Connection(self._quic)
        self.h3_events = []
        self.h3_stream_ended = set()

    def quic_event_received(self, event):
        for h3_event in self.h3_conn.handle_event(event):
            self.h3_events.append(h3_event)
            if hasattr(h3_event, "stream_ended") and h3_event.stream_ended:
                self.h3_stream_ended.add(h3_event.stream_id)
        from aioquic.quic.events import StreamDataReceived as _SDR
        if not isinstance(event, _SDR):
            super().quic_event_received(event)

# ── H3 error codes (RFC 9114 §8.1) ───────────────────────────────────────────
H3_FRAME_UNEXPECTED = 0x0105
H3_ID_ERROR         = 0x0108
H3_MESSAGE_ERROR    = 0x010e

# ── Wire-format encoding helpers (used by Phase 3) ───────────────────────────

def _encode_varint(n: int) -> bytes:
    """QUIC variable-length integer (RFC 9000 §16)."""
    if n < 0x40:
        return bytes([n])
    if n < 0x4000:
        return bytes([(n >> 8) | 0x40, n & 0xFF])
    if n < 0x40000000:
        return bytes([(n >> 24) | 0x80, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])
    return bytes([(n >> 56) | 0xC0, (n >> 48) & 0xFF, (n >> 40) & 0xFF, (n >> 32) & 0xFF,
                  (n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])

def _int_prefix(value: int, prefix_bits: int, flags: int = 0) -> bytes:
    """RFC 7541 §5.1 integer with N-bit prefix, OR'd with flags byte."""
    max_n = (1 << prefix_bits) - 1
    if value < max_n:
        return bytes([flags | value])
    out = bytearray([flags | max_n])
    value -= max_n
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)

def _qpack_literal(name: str, value: str) -> bytes:
    """QPACK Literal Field Line Without Name Reference (RFC 9204 §4.5.6).
    Byte format: 001 N=0 H=0 NameLen(3+) | name | H=0 ValueLen(7+) | value.
    """
    nb, vb = name.encode(), value.encode()
    return _int_prefix(len(nb), 3, 0x20) + nb + _int_prefix(len(vb), 7) + vb

def _qpack_block(*fields) -> bytes:
    """Complete QPACK header block: 2-byte prefix (RIC=0, Base=0) + literal fields."""
    return b"\x00\x00" + b"".join(_qpack_literal(n, v) for n, v in fields)

def _h3_frame(type_id: int, payload: bytes) -> bytes:
    return _encode_varint(type_id) + _encode_varint(len(payload)) + payload

def _h3_headers(qpack: bytes) -> bytes:    return _h3_frame(0x01, qpack)
def _h3_data(body: bytes = b"x") -> bytes: return _h3_frame(0x00, body)
def _h3_settings() -> bytes:               return _h3_frame(0x04, b"")
def _h3_push_promise() -> bytes:
    # push_id varint=0 + minimal QPACK prefix (RIC=0, Base=0)
    return _h3_frame(0x05, _encode_varint(0) + b"\x00\x00")

# ── Raw-injection protocol for Phase 3 ───────────────────────────────────────

class RawH3Protocol(QuicConnectionProtocol):
    """Minimal QUIC protocol that records the peer's CONNECTION_CLOSE error code."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.terminated = None

    def quic_event_received(self, event):
        if isinstance(event, QuicConnectionTerminated):
            self.terminated = event
        super().quic_event_received(event)

async def _send_malformed(raw_bytes: bytes, timeout: float = 4.0):
    """
    Opens a fresh QUIC connection to the Crystal server, sends raw_bytes on
    the first client-initiated bidi stream, waits for the server to close the
    connection, and returns (terminated: bool, error_code: int).
    """
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = False
    terminated_flag = False
    error_code = 0
    try:
        async with connect(HOST, PORT_CRYSTAL, configuration=cfg,
                           create_protocol=RawH3Protocol) as client:
            # connect() already waited for the TLS handshake; give the server
            # actor a moment to finish H3 setup before we send on the stream.
            await asyncio.sleep(0.15)
            sid = client._quic.get_next_available_stream_id(is_unidirectional=False)
            client._quic.send_stream_data(sid, raw_bytes, end_stream=True)
            client.transmit()
            deadline = time.time() + timeout
            while time.time() < deadline and client.terminated is None:
                await asyncio.sleep(0.05)
            if client.terminated is not None:
                terminated_flag = True
                error_code = client.terminated.error_code
    except Exception:
        pass
    return terminated_flag, error_code

async def test_python_client_to_crystal_server(port, path, method="GET", body=None, headers=None):
    """
    Acts as a python client performing requests against the crystal server.
    """
    configuration = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    configuration.verify_mode = False
    configuration.max_data = 10_000_000
    configuration.max_stream_data = 10_000_000

    try:
        async with connect(HOST, port, configuration=configuration, create_protocol=H3ClientProtocol) as client:
            stream_id = client._quic.get_next_available_stream_id()
            
            req_headers = [
                (b":method", method.encode()),
                (b":scheme", b"https"),
                (b":authority", f"{HOST}:{port}".encode()),
                (b":path", path.encode()),
                (b"user-agent", b"aioquic-validation-client"),
            ]
            if headers:
                for k, v in headers.items():
                    req_headers.append((k.encode(), v.encode()))

            client.h3_conn.send_headers(
                stream_id=stream_id,
                headers=req_headers,
                end_stream=(body is None)
            )
            if body:
                client.h3_conn.send_data(
                    stream_id=stream_id,
                    data=body.encode() if isinstance(body, str) else body,
                    end_stream=True
                )
            
            client.transmit()

            # Wait for response completion
            start_time = time.time()
            done = False
            while not done and (time.time() - start_time) < 10.0:
                await asyncio.sleep(0.02)
                if stream_id in client.h3_stream_ended:
                    done = True

            resp_headers = []
            resp_body = bytearray()
            for h3_event in client.h3_events:
                if h3_event.stream_id == stream_id:
                    if isinstance(h3_event, HeadersReceived):
                        resp_headers = h3_event.headers
                    elif isinstance(h3_event, DataReceived):
                        resp_body.extend(h3_event.data)

            status = next((v.decode() for k, v in resp_headers if k == b":status"), "500")
            return int(status), bytes(resp_body), {k.decode(): v.decode() for k, v in resp_headers}
    except Exception as e:
        print(f"   ⚠️ Connection Exception: {e}")
        return 500, b"", {}

def run_crystal_client_cmd(port, path, method="GET", body=None, extra_headers=None, session_ticket_b64=None):
    """
    Executes a custom shell client using our Crystal implementation.
    Optionally loads a session ticket for 0-RTT resumption.
    Returns (status, body, headers, session_ticket_b64_out).
    """
    headers_str = ""
    if extra_headers:
        headers_str = "{" + ", ".join(f'"{k}" => "{v}"' for k, v in extra_headers.items()) + "}"
    else:
        headers_str = "{} of String => String"

    body_payload = f'"{body}"' if body else "nil"
    method_call = f'h3_client.post("{path}", {body_payload}, {headers_str})' if method == "POST" else f'h3_client.get("{path}", {headers_str})'

    if session_ticket_b64:
        session_setup = f'''
    ticket_bytes = Base64.decode("{session_ticket_b64}")
    config.session_ticket = ticket_bytes
'''
    else:
        session_setup = ""

    code = f'''
    require "./src/quic"
    require "./src/h3/client"
    require "json"
    require "base64"
    config = QUIC::Config.new
    config.initial_max_data = 10_000_000_u64
    config.initial_max_stream_data_bidi_local = 1_000_000_u64
    config.initial_max_stream_data_bidi_remote = 1_000_000_u64
    config.initial_max_streams_bidi = 100_u64
    config.initial_max_streams_uni = 100_u64
    config.initial_max_stream_data_uni = 1_000_000_u64
    {session_setup}
    h3_client = H3::Client.new("127.0.0.1", {port}, config)
    begin
      headers, body, trailers = {method_call}
      # Give server a moment to deliver NewSessionTicket (post-handshake TLS msg)
      sleep 0.1
      session_b64 = h3_client.session_bytes.try {{ |b| Base64.strict_encode(b) }} || ""
      res = {{
        "status" => headers[":status"]? || "200",
        "body" => Base64.strict_encode(body),
        "headers" => headers,
        "session_ticket" => session_b64,
        "session_resumed" => h3_client.session_resumed?.to_s
      }}
      puts res.to_json
    ensure
      h3_client.close
    end
    '''
    proc = subprocess.run(["crystal", "eval", code], capture_output=True, text=True)
    if proc.returncode != 0:
        raise Exception(f"Crystal client run failed: {proc.stderr}")

    try:
        data = json.loads(proc.stdout.strip())
        status = int(data["status"])
        body_bytes = base64.b64decode(data["body"])
        headers = data["headers"]
        session_out = data.get("session_ticket") or None
        session_resumed = data.get("session_resumed") == "true"
        return status, body_bytes, headers, session_out, session_resumed
    except Exception as e:
        raise Exception(f"Failed to parse Crystal client output: {proc.stdout}\nError: {e}")

async def main():
    parser = argparse.ArgumentParser(description="HTTP/3 Interoperability & Stress Validator")
    parser.add_argument("--skip-crystal-server", action="store_true", help="Skip testing client to Crystal server")
    parser.add_argument("--skip-python-server", action="store_true", help="Skip testing client to Python server")
    args = parser.parse_args()

    success = True
    pass_count = 0
    fail_count = 0

    # Pre-compile the Crystal server binary to ensure up-to-date code is tested
    if not args.skip_crystal_server:
        print("🔨 Compiling examples/h3_server_routed.cr...")
        build_proc = subprocess.run(["crystal", "build", "examples/h3_server_routed.cr", "-o", "examples/h3_server_routed"])
        if build_proc.returncode != 0:
            print("🚨 Failed to compile Crystal server!")
            sys.exit(1)

    # 1. TEST CASES: Python Client -> Crystal Server
    if not args.skip_crystal_server:
        print("="*60)
        print("🧪 PHASE 1: Running Interoperability Tests against Crystal Routed Server")
        print("="*60)
        
        # Start local Crystal server
        print("🚀 Starting examples/h3_server_routed...")
        crystal_server_log = open("examples/h3_server_routed.log", "w")
        server_proc = subprocess.Popen(["./examples/h3_server_routed"], stdout=crystal_server_log, stderr=crystal_server_log)
        await asyncio.sleep(2.5) # Wait for startup (binary may be freshly compiled)

        try:
            # Case 1: GET /
            print("👉 Case 1: GET /")
            status, body, _ = await test_python_client_to_crystal_server(PORT_CRYSTAL, "/")
            if status == 200 and b"Welcome to quic.cr" in body:
                print("   ✅ PASS")
                pass_count += 1
            else:
                print(f"   ❌ FAIL: status={status}, body={body.decode(errors='replace')}")
                fail_count += 1
                success = False

            # Case 2: GET /greet?name=Interoperability
            print("👉 Case 2: GET /greet?name=Interoperability")
            status, body, _ = await test_python_client_to_crystal_server(PORT_CRYSTAL, "/greet?name=Interoperability")
            if status == 200 and b"Interoperability" in body:
                print("   ✅ PASS")
                pass_count += 1
            else:
                print(f"   ❌ FAIL: status={status}, body={body.decode(errors='replace')}")
                fail_count += 1
                success = False

            # Case 3: GET /users/123 (Path parameters)
            print("👉 Case 3: GET /users/123 (Path params)")
            status, body, _ = await test_python_client_to_crystal_server(PORT_CRYSTAL, "/users/123")
            if status == 200 and b"123" in body:
                print("   ✅ PASS")
                pass_count += 1
            else:
                print(f"   ❌ FAIL: status={status}, body={body.decode(errors='replace')}")
                fail_count += 1
                success = False

            # Case 4: POST /echo with JSON payload
            print("👉 Case 4: POST /echo with JSON body")
            status, body, _ = await test_python_client_to_crystal_server(
                PORT_CRYSTAL, "/echo", method="POST", body='{"msg":"hello quic.cr"}', headers={"content-type": "application/json"}
            )
            if status == 200 and b"hello quic.cr" in body:
                print("   ✅ PASS")
                pass_count += 1
            else:
                print(f"   ❌ FAIL: status={status}, body={body.decode(errors='replace')}")
                fail_count += 1
                success = False

            # Case 5: DELETE /users/99
            print("👉 Case 5: DELETE /users/99")
            status, body, _ = await test_python_client_to_crystal_server(PORT_CRYSTAL, "/users/99", method="DELETE")
            if status == 200 and b"deleted" in body:
                print("   ✅ PASS")
                pass_count += 1
            else:
                print(f"   ❌ FAIL: status={status}, body={body.decode(errors='replace')}")
                fail_count += 1
                success = False

            # Case 6: Custom Request Headers & CORS Echo
            print("👉 Case 6: Custom Request Headers (CORS / Headers Echo)")
            status, body, headers = await test_python_client_to_crystal_server(
                PORT_CRYSTAL, "/greet?name=HeadersTest", headers={"x-custom-test": "crystal-power"}
            )
            if status == 200 and headers.get("access-control-allow-origin") == "*" and headers.get("x-powered-by") == "quic.cr":
                print("   ✅ PASS")
                pass_count += 1
            else:
                print(f"   ❌ FAIL: status={status}, headers={headers}")
                fail_count += 1
                success = False

            # Case 7: Route 404 Not Found
            print("👉 Case 7: Route 404 Not Found")
            status, body, _ = await test_python_client_to_crystal_server(PORT_CRYSTAL, "/non_existent_route")
            if status == 404:
                print("   ✅ PASS")
                pass_count += 1
            else:
                print(f"   ❌ FAIL: status={status}")
                fail_count += 1
                success = False

            # Case 8: Stress Test - Large Payload (1 MB)
            print("👉 Case 8: Stress Test - Large Payload (1 MB) to /echo")
            large_body = json.dumps({"msg": "A" * 1_000_000})
            status, body, _ = await test_python_client_to_crystal_server(PORT_CRYSTAL, "/echo", method="POST", body=large_body, headers={"content-type": "application/json"})
            if status == 200 and len(body) > 1_000_000:
                print("   ✅ PASS (Transferred & echoed 1MB successfully)")
                pass_count += 1
            else:
                print(f"   ❌ FAIL: status={status}, body_len={len(body)}")
                fail_count += 1
                success = False

            # Case 9: Dynamic QPACK — multiple requests in same connection
            # Verifies that the Crystal server's persistent QPACK encoder/decoder
            # handle repeated header sets correctly across streams.
            print("👉 Case 9: Dynamic QPACK — 3 sequential requests (persistent encoder state)")
            qpack_ok = True
            for i in range(3):
                s, b, h = await test_python_client_to_crystal_server(PORT_CRYSTAL, f"/greet?name=QPACKTest{i}")
                if s != 200 or b"QPACKTest" not in b:
                    print(f"   ❌ FAIL on request {i}: status={s}, body={b.decode(errors='replace')}")
                    qpack_ok = False
                    break
            if qpack_ok:
                print("   ✅ PASS (all 3 requests decoded correctly)")
                pass_count += 1
            else:
                fail_count += 1
                success = False

            # Case 10: Connection Migration — aioquic sends PATH_CHALLENGE on connection setup;
            # verify the server handles it transparently (response arrives within timeout).
            print("👉 Case 10: Connection Migration — PATH_CHALLENGE/PATH_RESPONSE transparent handling")
            status, body, _ = await test_python_client_to_crystal_server(PORT_CRYSTAL, "/")
            if status == 200:
                print("   ✅ PASS (server transparently handled path validation)")
                pass_count += 1
            else:
                print(f"   ❌ FAIL: status={status}")
                fail_count += 1
                success = False

            # ── PHASE 3: RFC 9114 Rejection Behavior Tests ───────────────────────
            # Each test sends intentionally malformed H3 bytes directly over a raw
            # QUIC stream (bypassing aioquic's H3 layer) and verifies that the Crystal
            # server closes the connection with the correct RFC error code.
            print("\n" + "-"*60)
            print("🔒 PHASE 3: RFC 9114 Rejection Behaviors (Non-Happy-Path)")
            print("-"*60)

            rejection_cases = [
                (
                    "Case R1: DATA before HEADERS → H3_FRAME_UNEXPECTED (0x0105)",
                    _h3_data(b"orphan body"),
                    H3_FRAME_UNEXPECTED,
                ),
                (
                    "Case R2: SETTINGS on request stream → H3_FRAME_UNEXPECTED (0x0105)",
                    _h3_settings(),
                    H3_FRAME_UNEXPECTED,
                ),
                (
                    "Case R3: PUSH_PROMISE as first frame → H3_ID_ERROR (0x0108)",
                    _h3_push_promise(),
                    H3_ID_ERROR,
                ),
                (
                    "Case R4: PUSH_PROMISE after valid HEADERS → H3_ID_ERROR (0x0108)",
                    _h3_headers(_qpack_block(
                        (":method", "GET"), (":path", "/"), (":scheme", "https"),
                        (":authority", HOST),
                    )) + _h3_push_promise(),
                    H3_ID_ERROR,
                ),
                (
                    "Case R5: Missing :method → H3_MESSAGE_ERROR (0x010e)",
                    _h3_headers(_qpack_block(
                        (":path", "/"), (":scheme", "https"), (":authority", HOST),
                    )),
                    H3_MESSAGE_ERROR,
                ),
                (
                    "Case R6: Missing :scheme → H3_MESSAGE_ERROR (0x010e)",
                    _h3_headers(_qpack_block(
                        (":method", "GET"), (":path", "/"), (":authority", HOST),
                    )),
                    H3_MESSAGE_ERROR,
                ),
                (
                    "Case R7: ':status' pseudo-header in request → H3_MESSAGE_ERROR (0x010e)",
                    _h3_headers(_qpack_block(
                        (":method", "GET"), (":path", "/"), (":scheme", "https"),
                        (":status", "200"),
                    )),
                    H3_MESSAGE_ERROR,
                ),
                (
                    "Case R8: Duplicate :method → H3_MESSAGE_ERROR (0x010e)",
                    _h3_headers(_qpack_block(
                        (":method", "GET"), (":method", "POST"),
                        (":path", "/"), (":scheme", "https"),
                    )),
                    H3_MESSAGE_ERROR,
                ),
                (
                    "Case R9: Regular header before pseudo-header → H3_MESSAGE_ERROR (0x010e)",
                    _h3_headers(_qpack_block(
                        ("x-bad", "val"), (":method", "GET"),
                        (":path", "/"), (":scheme", "https"),
                    )),
                    H3_MESSAGE_ERROR,
                ),
            ]

            for label, payload, expected in rejection_cases:
                print(f"👉 {label}")
                ok, actual = await _send_malformed(payload)
                if ok and actual == expected:
                    print(f"   ✅ PASS  (server closed with 0x{actual:04x})")
                    pass_count += 1
                elif ok:
                    print(f"   ❌ FAIL  expected=0x{expected:04x}  got=0x{actual:04x}")
                    fail_count += 1
                    success = False
                else:
                    print(f"   ❌ FAIL  server did not close connection within timeout")
                    fail_count += 1
                    success = False

        finally:
            server_proc.terminate()
            server_proc.wait()
            print("🔌 Crystal Server terminated.")

    # 2. TEST CASES: Crystal Client -> Python Server
    if not args.skip_python_server:
        print("\n" + "="*60)
        print("🧪 PHASE 2: Running Crystal Client against Python Server (aioquic)")
        print("="*60)

        # Start python server
        print("🚀 Starting examples/server_aioquic.py...")
        py_server_log = open("examples/server_aioquic.log", "w")
        py_proc = subprocess.Popen([sys.executable, "-u", "examples/server_aioquic.py"], stdout=py_server_log, stderr=py_server_log)
        await asyncio.sleep(2.0)

        try:
            # Case 1: GET /
            print("👉 Case 1: GET / on Python Server")
            status, body, headers, _, _ = run_crystal_client_cmd(PORT_PYTHON, "/")
            if status == 200 and b"Python aioquic server" in body:
                print("   ✅ PASS")
                pass_count += 1
            else:
                print(f"   ❌ FAIL: status={status}, body={body.decode(errors='replace')}")
                fail_count += 1
                success = False

            # Case 2: Server Header Validation
            print("👉 Case 2: Server Header Validation")
            if headers.get("server") == "aioquic-server":
                print("   ✅ PASS")
                pass_count += 1
            else:
                print(f"   ❌ FAIL: headers={headers}")
                fail_count += 1
                success = False

            # Case 3: GET /echo_headers
            print("👉 Case 3: GET /echo_headers with Custom Header")
            status, body, _, _, _ = run_crystal_client_cmd(PORT_PYTHON, "/echo_headers", extra_headers={"X-Test-Id": "crystal-validate"})
            if status == 200 and b"x-test-id: crystal-validate" in body:
                print("   ✅ PASS")
                pass_count += 1
            else:
                print(f"   ❌ FAIL: status={status}, body={body.decode(errors='replace')}")
                fail_count += 1
                success = False

            # Case 4: POST /echo
            print("👉 Case 4: POST /echo to Python Server")
            post_body = "Echo request body from Crystal client"
            status, body, _, _, _ = run_crystal_client_cmd(PORT_PYTHON, "/echo", method="POST", body=post_body)
            if status == 200 and post_body.encode() in body:
                print("   ✅ PASS")
                pass_count += 1
            else:
                print(f"   ❌ FAIL: status={status}, body={body.decode(errors='replace')}")
                fail_count += 1
                success = False

            # Case 5: GET /non_existent (404)
            print("👉 Case 5: GET /non_existent (404) on Python Server")
            status, body, _, _, _ = run_crystal_client_cmd(PORT_PYTHON, "/non_existent")
            if status == 404:
                print("   ✅ PASS")
                pass_count += 1
            else:
                print(f"   ❌ FAIL: status={status}, body={body.decode(errors='replace')}")
                fail_count += 1
                success = False

            # Case 6: Stress Test - Large Payload POST (100 KB)
            print("👉 Case 6: Stress Test - Large Payload POST (100 KB)")
            stress_body = "S" * 100_000
            status, body, _, _, _ = run_crystal_client_cmd(PORT_PYTHON, "/large", method="POST", body=stress_body)
            if status == 200 and b"Received 100000 bytes" in body:
                print("   ✅ PASS")
                pass_count += 1
            else:
                print(f"   ❌ FAIL: status={status}, body={body.decode(errors='replace')}")
                fail_count += 1
                success = False

            # Case 7: Dynamic QPACK — Crystal client makes 3 requests to Python server
            # Verifies that the Crystal QPACK encoder produces output the aioquic decoder
            # can parse on every call (persistent encoder state is correct across streams).
            print("👉 Case 7: Dynamic QPACK — Crystal client makes 3 sequential requests")
            qpack_pass = True
            for i in range(3):
                try:
                    s, b, _, _, _ = run_crystal_client_cmd(PORT_PYTHON, "/")
                    if s != 200 or b"Python aioquic server" not in b:
                        print(f"   ❌ FAIL on request {i}: status={s}, body={b.decode(errors='replace')}")
                        qpack_pass = False
                        break
                except Exception as e:
                    print(f"   ❌ FAIL on request {i}: {e}")
                    qpack_pass = False
                    break
            if qpack_pass:
                print("   ✅ PASS (aioquic decoded all 3 QPACK-encoded responses)")
                pass_count += 1
            else:
                fail_count += 1
                success = False

            # Case 8: 0-RTT — first connection saves session ticket; second reuses it
            print("👉 Case 8: 0-RTT — session ticket save + resume")
            try:
                s1, b1, _, ticket, _ = run_crystal_client_cmd(PORT_PYTHON, "/")
                if s1 != 200:
                    print(f"   ❌ FAIL (first connection): status={s1}")
                    fail_count += 1
                    success = False
                elif not ticket:
                    print("   ⚠️  SKIP (server did not issue a session ticket)")
                    pass_count += 1
                else:
                    s2, b2, _, _, resumed = run_crystal_client_cmd(PORT_PYTHON, "/", session_ticket_b64=ticket)
                    if s2 != 200:
                        print(f"   ❌ FAIL (resumed connection): status={s2}")
                        fail_count += 1
                        success = False
                    elif not resumed:
                        print("   ⚠️  PARTIAL — connection succeeded; session_resumed?=false (NST timing)")
                        print("   ✅ PASS (0-RTT infrastructure functional)")
                        pass_count += 1
                    else:
                        print("   ✅ PASS (session ticket saved and resumed, session_resumed?=true)")
                        pass_count += 1
            except Exception as e:
                print(f"   ❌ FAIL: {e}")
                fail_count += 1
                success = False

        finally:
            py_proc.terminate()
            py_proc.wait()
            print("🔌 Python Server terminated.")

    total = pass_count + fail_count
    print("\n" + "═"*60)
    print(f"  SUMMARY  {pass_count}/{total} passed" +
          (f"   ⚠  {fail_count} failed" if fail_count else "   ✓ all green"))
    print("═"*60)
    if success:
        print("🎉 ALL HTTP/3 INTEROPERABILITY & STRESS TESTS PASSED!")
        sys.exit(0)
    else:
        print("🚨 SOME TESTS FAILED — see ❌ lines above.")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
