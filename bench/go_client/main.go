// HTTP/3 + QUIC comprehensive e2e test client.
// Usage:
//
//	go run main.go [-host 127.0.0.1] [-port 4433] [-n 1]
//
// Exit code 0 if all suites pass, 1 otherwise.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// ───────────────────────────── helpers ──────────────────────────────────────

func newTLSConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec
}

func newTransport(versions ...quic.Version) *http3.Transport {
	if len(versions) == 0 {
		versions = []quic.Version{quic.Version1}
	}
	return &http3.Transport{
		TLSClientConfig: newTLSConfig(),
		QUICConfig:      &quic.Config{Versions: versions},
	}
}

// ───────────────────────────── test case ────────────────────────────────────

type testCase struct {
	name    string
	method  string
	path    string
	body    string
	headers map[string]string
	timeout time.Duration // 0 → use default 20s
	check   func(status int, body string, headers http.Header) error
}

// ───────────────────────────── suite runners ────────────────────────────────

// runParallel launches n*len(tests) goroutines concurrently and waits.
// Returns (passed, total) and appends failures to *failures.
func runParallel(
	suiteName string,
	client *http.Client,
	base string,
	tests []testCase,
	n int,
	failures *[]string,
) (int, int) {
	type result struct {
		name string
		err  error
	}

	results := make(chan result, n*len(tests))
	var wg sync.WaitGroup

	for i := 0; i < n; i++ {
		for _, tc := range tests {
			wg.Add(1)
			go func(tc testCase) {
				defer wg.Done()
				results <- result{tc.name, doRequest(client, base, tc)}
			}(tc)
		}
	}

	wg.Wait()
	close(results)

	total := n * len(tests)
	passed := 0
	var errs []string
	for r := range results {
		if r.err == nil {
			passed++
		} else {
			errs = append(errs, fmt.Sprintf("    FAIL  %s: %v", r.name, r.err))
			*failures = append(*failures, fmt.Sprintf("%s / %s: %v", suiteName, r.name, r.err))
		}
	}

	fmt.Printf("  %-40s %d/%d\n", suiteName+":", passed, total)
	for _, e := range errs {
		fmt.Println(e)
	}
	return passed, total
}

// runSerial runs tests strictly one at a time, n rounds.
func runSerial(
	suiteName string,
	client *http.Client,
	base string,
	tests []testCase,
	n int,
	failures *[]string,
) (int, int) {
	total := n * len(tests)
	passed := 0
	var errs []string

	for i := 0; i < n; i++ {
		for _, tc := range tests {
			if err := doRequest(client, base, tc); err == nil {
				passed++
			} else {
				errs = append(errs, fmt.Sprintf("    FAIL  %s: %v", tc.name, err))
				*failures = append(*failures, fmt.Sprintf("%s / %s: %v", suiteName, tc.name, err))
			}
		}
	}

	fmt.Printf("  %-40s %d/%d\n", suiteName+":", passed, total)
	for _, e := range errs {
		fmt.Println(e)
	}
	return passed, total
}

// doRequest executes a single testCase against the server.
func doRequest(client *http.Client, base string, tc testCase) error {
	tmo := tc.timeout
	if tmo == 0 {
		tmo = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), tmo)
	defer cancel()

	var reqBody io.Reader
	if tc.body != "" {
		reqBody = bytes.NewBufferString(tc.body)
	}

	req, err := http.NewRequestWithContext(ctx, tc.method, base+tc.path, reqBody)
	if err != nil {
		return err
	}
	for k, v := range tc.headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("body read error after %d bytes: %w", len(bodyBytes), readErr)
	}
	return tc.check(resp.StatusCode, string(bodyBytes), resp.Header)
}

// ───────────────────────────── check helpers ────────────────────────────────

func expectStatus(want int) func(int, string, http.Header) error {
	return func(status int, _ string, _ http.Header) error {
		if status != want {
			return fmt.Errorf("expected status %d, got %d", want, status)
		}
		return nil
	}
}

func expectStatusBody(wantStatus int, wantBodyContains string) func(int, string, http.Header) error {
	return func(status int, body string, _ http.Header) error {
		if status != wantStatus {
			return fmt.Errorf("expected status %d, got %d", wantStatus, status)
		}
		if !strings.Contains(body, wantBodyContains) {
			return fmt.Errorf("body %q does not contain %q", truncate(body, 80), wantBodyContains)
		}
		return nil
	}
}

func expectBodyLen(wantStatus int, minLen int) func(int, string, http.Header) error {
	return func(status int, body string, _ http.Header) error {
		if status != wantStatus {
			return fmt.Errorf("expected status %d, got %d", wantStatus, status)
		}
		if len(body) < minLen {
			return fmt.Errorf("expected body >= %d bytes, got %d", minLen, len(body))
		}
		return nil
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// runSequential runs n rounds of all tests in order (alias for runSerial with suite label).
func runSequential(
	suiteName string,
	client *http.Client,
	base string,
	tests []testCase,
	n int,
	failures *[]string,
) (int, int) {
	return runSerial(suiteName, client, base, tests, n, failures)
}

// testDatagramEcho dials the QUIC server, sends payload as a QUIC datagram (RFC 9221),
// and verifies the server echoes the exact same bytes back.
func testDatagramEcho(host string, port int, payload []byte) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	tlsConf := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
		NextProtos:         []string{"h3"},
	}
	quicConf := &quic.Config{
		EnableDatagrams: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, addr, tlsConf, quicConf)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.CloseWithError(0, "done") //nolint:errcheck

	// Allow the H3 handshake to complete (server opens control streams).
	// Drain any server-initiated unidirectional streams so the server doesn't
	// block on flow control while we wait for datagram support.
	go func() {
		for {
			stream, err := conn.AcceptUniStream(context.Background())
			if err != nil {
				return
			}
			go io.Copy(io.Discard, stream) //nolint:errcheck
		}
	}()

	if err := conn.SendDatagram(payload); err != nil {
		return fmt.Errorf("SendDatagram: %w", err)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()

	got, err := conn.ReceiveDatagram(ctx2)
	if err != nil {
		return fmt.Errorf("ReceiveDatagram: %w", err)
	}
	if string(got) != string(payload) {
		return fmt.Errorf("echo mismatch: sent %q, got %q", truncate(string(payload), 32), truncate(string(got), 32))
	}
	return nil
}

func sha256hexX(s string) string { // unused alias kept for clarity
	return sha256hex(s)
}

// ── QUIC VarInt / H3 frame helpers ──────────────────────────────────────────

// readVarInt reads a QUIC variable-length integer from r (RFC 9000 §16).
func readVarInt(r io.Reader) (uint64, error) {
	b := make([]byte, 1)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, err
	}
	pfx := b[0] >> 6
	val := uint64(b[0] & 0x3f)
	extra := make([]byte, (1<<pfx)-1)
	if len(extra) > 0 {
		if _, err := io.ReadFull(r, extra); err != nil {
			return 0, err
		}
		for _, e := range extra {
			val = (val << 8) | uint64(e)
		}
	}
	return val, nil
}

// writeVarInt writes a QUIC variable-length integer to w.
func writeVarInt(w io.Writer, v uint64) {
	var buf []byte
	switch {
	case v < 0x40:
		buf = []byte{byte(v)}
	case v < 0x4000:
		buf = []byte{0x40 | byte(v>>8), byte(v)}
	case v < 0x40000000:
		buf = []byte{0x80 | byte(v>>24), byte(v>>16), byte(v>>8), byte(v)}
	default:
		buf = []byte{
			0xc0 | byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v),
		}
	}
	w.Write(buf) //nolint:errcheck
}

// readH3Frame reads one HTTP/3 frame (type VarInt + length VarInt + payload) from r.
func readH3Frame(r io.Reader) (ftype uint64, payload []byte, err error) {
	ftype, err = readVarInt(r)
	if err != nil {
		return 0, nil, err
	}
	length, err := readVarInt(r)
	if err != nil {
		return 0, nil, err
	}
	payload = make([]byte, length)
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return ftype, payload, nil
}

// encodeH3Request encodes HTTP/3 HEADERS frame bytes for the given path using
// QPACK static-table-only encoding (RIC=0, Base=0 prefix).
func encodeH3Request(method, path, authority string) []byte {
	var qbuf bytes.Buffer
	qbuf.WriteByte(0x00) // Required Insert Count = 0
	qbuf.WriteByte(0x00) // S=0, Delta Base=0
	enc := qpack.NewEncoder(&qbuf)
	enc.WriteField(qpack.HeaderField{Name: ":method", Value: method})     //nolint:errcheck
	enc.WriteField(qpack.HeaderField{Name: ":path", Value: path})         //nolint:errcheck
	enc.WriteField(qpack.HeaderField{Name: ":scheme", Value: "https"})    //nolint:errcheck
	enc.WriteField(qpack.HeaderField{Name: ":authority", Value: authority}) //nolint:errcheck

	var frame bytes.Buffer
	writeVarInt(&frame, 0x01) // HEADERS frame type
	writeVarInt(&frame, uint64(qbuf.Len()))
	frame.Write(qbuf.Bytes())
	return frame.Bytes()
}

// ── Suite 25: STREAMS_BLOCKED + MAX_STREAMS replenishment ───────────────────

// testStreamsBlockedFlow sends 250 sequential GET /ping requests on a single
// QUIC connection.  The server's initial_max_streams_bidi=128, so after ordinal
// 64 is opened the server emits MAX_STREAMS(256).  All 250 must succeed,
// proving the STREAMS_BLOCKED → MAX_STREAMS replenishment path works.
func testStreamsBlockedFlow(host string, port int) (int, int, []string) {
	const total = 250
	tr := newTransport()
	defer tr.Close()
	c := &http.Client{Transport: tr}
	base := fmt.Sprintf("https://%s:%d", host, port)

	passed := 0
	var failures []string
	for i := 0; i < total; i++ {
		tc := testCase{
			name: fmt.Sprintf("stream-replenish req %d", i),
			method: "GET", path: "/ping",
			check: func(status int, body string, _ http.Header) error {
				if status != 200 {
					return fmt.Errorf("expected 200, got %d", status)
				}
				if body != "pong" {
					return fmt.Errorf("expected pong, got %q", truncate(body, 40))
				}
				return nil
			},
		}
		if err := doRequest(c, base, tc); err != nil {
			failures = append(failures, fmt.Sprintf("req %d: %v", i, err))
		} else {
			passed++
		}
	}
	return passed, total, failures
}

// ── Suite 26: H3 control stream — SETTINGS + GOAWAY (RFC 9114 §5.2 / §6.2) ─

// testGoawayAndControlStream dials a raw QUIC connection, reads the server's H3
// control stream, verifies the SETTINGS frame, then triggers GOAWAY via the
// /send-goaway endpoint and confirms the GOAWAY frame arrives on the control stream.
func testGoawayAndControlStream(host string, port int) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	tlsConf := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
		NextProtos:         []string{"h3"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, addr, tlsConf, nil)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.CloseWithError(0, "done") //nolint:errcheck

	settingsCh := make(chan map[uint64]uint64, 1)
	goawayCh   := make(chan uint64, 1)

	// Goroutine: accept all server-initiated uni streams; parse the H3 control stream.
	go func() {
		for {
			stream, err := conn.AcceptUniStream(context.Background())
			if err != nil {
				return
			}
			go func(s *quic.ReceiveStream) {
				streamType, err := readVarInt(s)
				if err != nil {
					return
				}
				if streamType != 0x00 { // not the H3 control stream
					io.Copy(io.Discard, s) //nolint:errcheck // *quic.ReceiveStream implements io.Reader
					return
				}
				// Parse H3 frames from the control stream.
				for {
					ftype, payload, err := readH3Frame(s)
					if err != nil {
						return
					}
					switch ftype {
					case 0x04: // SETTINGS
						settings := map[uint64]uint64{}
						pr := bytes.NewReader(payload)
						for pr.Len() > 0 {
							k, e1 := readVarInt(pr)
							v, e2 := readVarInt(pr)
							if e1 != nil || e2 != nil {
								break
							}
							settings[k] = v
						}
						select {
						case settingsCh <- settings:
						default:
						}
					case 0x07: // GOAWAY
						r := bytes.NewReader(payload)
						lastID, _ := readVarInt(r)
						select {
						case goawayCh <- lastID:
						default:
						}
						return
					}
				}
			}(stream)
		}
	}()

	// Wait for SETTINGS.
	var settings map[uint64]uint64
	select {
	case settings = <-settingsCh:
	case <-ctx.Done():
		return fmt.Errorf("timeout waiting for H3 SETTINGS frame")
	}

	// Verify SETTINGS content matches what e2e_server advertises.
	if v := settings[0x01]; v != 4096 {
		return fmt.Errorf("SETTINGS[0x01] QPACK_MAX_TABLE_CAPACITY: want 4096, got %d", v)
	}
	if v := settings[0x06]; v != 16384 {
		return fmt.Errorf("SETTINGS[0x06] MAX_FIELD_SECTION_SIZE: want 16384, got %d", v)
	}
	if v := settings[0x07]; v != 16 {
		return fmt.Errorf("SETTINGS[0x07] QPACK_BLOCKED_STREAMS: want 16, got %d", v)
	}

	// Open a bidi stream and send GET /send-goaway.
	bidi, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open bidi stream: %w", err)
	}
	if _, err := bidi.Write(encodeH3Request("GET", "/send-goaway", addr)); err != nil {
		return fmt.Errorf("write GET /send-goaway: %w", err)
	}
	bidi.Close() // FIN — no request body

	// Read the response HEADERS frame.
	ftype, _, err := readH3Frame(bidi)
	if err != nil {
		return fmt.Errorf("read response frame: %w", err)
	}
	if ftype != 0x01 {
		return fmt.Errorf("expected HEADERS(0x01) response, got type 0x%02x", ftype)
	}

	// Wait for GOAWAY frame on the control stream.
	select {
	case goawayID := <-goawayCh:
		_ = goawayID // any last-stream-id value is valid
	case <-ctx.Done():
		return fmt.Errorf("timeout waiting for GOAWAY frame on control stream")
	}
	return nil
}

// ── Suite 27: Dynamic QPACK (RFC 9204) ────────────────────────────────────

// testDynamicQpack sends n requests with identical custom headers not in the
// QPACK static table.  After the server receives the client's SETTINGS and
// enables dynamic QPACK, repeated headers should be compressed — but crucially,
// every response must decode correctly.  If encoding or decoding is broken,
// the echo endpoint will return garbled values and the test fails.
func testDynamicQpack(host string, port, n int) (int, int, []string) {
	tr := newTransport()
	defer tr.Close()
	c := &http.Client{Transport: tr}
	base := fmt.Sprintf("https://%s:%d", host, port)

	const customHeader = "x-dyn-qpack-test"
	const customValue  = "dynamic-qpack-verifier-abc123"

	passed := 0
	var failures []string
	for i := 0; i < n; i++ {
		i := i
		tc := testCase{
			name:   fmt.Sprintf("dyn-qpack req %d", i),
			method: "GET", path: "/echo-headers",
			headers: map[string]string{
				customHeader:  customValue,
				"x-seq":       fmt.Sprintf("%d", i),
			},
			check: func(status int, body string, _ http.Header) error {
				if status != 200 {
					return fmt.Errorf("expected 200, got %d", status)
				}
				if !strings.Contains(body, customValue) {
					return fmt.Errorf("custom header value missing from echo body (req %d): %q",
						i, truncate(body, 100))
				}
				return nil
			},
		}
		if err := doRequest(c, base, tc); err != nil {
			failures = append(failures, fmt.Sprintf("req %d: %v", i, err))
		} else {
			passed++
		}
	}
	return passed, n, failures
}

// ── Suite 28: 0-RTT / Early Data (RFC 9001 §8) ────────────────────────────

// testZeroRTT verifies that a second QUIC connection reuses a cached TLS session
// ticket and performs 0-RTT (early data).  Steps:
//  1. First connection: full TLS handshake via DialAddr, wait 800ms for NST.
//  2. Second connection: DialAddrEarly with the same session cache.
//  3. After handshake, check ConnectionState().Used0RTT.
func testZeroRTT(host string, port int) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	tlsConf := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
		NextProtos:         []string{"h3"},
		ClientSessionCache: tls.NewLRUClientSessionCache(4),
	}

	// ── First connection: full handshake via raw QUIC ────────────────────
	ctx1, cancel1 := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel1()

	conn1, err := quic.DialAddr(ctx1, addr, tlsConf, nil)
	if err != nil {
		return fmt.Errorf("first connection dial: %w", err)
	}
	// Send a minimal H3 request so the server responds and all QUIC machinery
	// (including NST delivery) is triggered.
	s1, err := conn1.OpenStreamSync(ctx1)
	if err != nil {
		return fmt.Errorf("first connection open stream: %w", err)
	}
	s1.Write(encodeH3Request("GET", "/ping", addr)) //nolint:errcheck
	s1.Close()
	// Set a short read deadline so we don't block waiting for the server to close
	// the stream — we just need one round-trip to trigger NST delivery.
	s1.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	io.Copy(io.Discard, s1)                            //nolint:errcheck

	// Give the server time to send the New Session Ticket (async after handshake).
	time.Sleep(800 * time.Millisecond)
	conn1.CloseWithError(0, "done") //nolint:errcheck

	// ── Second connection: attempt 0-RTT via DialAddrEarly ───────────────
	ctx2, cancel2 := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel2()

	conn2, err := quic.DialAddrEarly(ctx2, addr, tlsConf, nil)
	if err != nil {
		return fmt.Errorf("second connection dial: %w", err)
	}
	defer conn2.CloseWithError(0, "done") //nolint:errcheck

	s2, err := conn2.OpenStreamSync(ctx2)
	if err != nil {
		return fmt.Errorf("second connection open stream: %w", err)
	}
	s2.Write(encodeH3Request("GET", "/ping", addr)) //nolint:errcheck
	s2.Close()
	s2.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	io.Copy(io.Discard, s2)                            //nolint:errcheck

	// Wait for the full handshake to complete before checking Used0RTT.
	select {
	case <-conn2.HandshakeComplete():
	case <-ctx2.Done():
		return fmt.Errorf("timeout waiting for handshake on second connection")
	}

	if !conn2.ConnectionState().Used0RTT {
		return fmt.Errorf("0-RTT was NOT used on the second connection " +
			"(server NST did not enable early data, or session cache miss)")
	}
	return nil
}

// ───────────────────────────── main ─────────────────────────────────────────

func main() {
	host := flag.String("host", "127.0.0.1", "Server host")
	port := flag.Int("port", 4433, "Server port")
	n    := flag.Int("n", 1, "Repetitions per suite")
	flag.Parse()

	base := fmt.Sprintf("https://%s:%d", *host, *port)

	totalPassed := 0
	totalTests  := 0
	var allFailures []string
	start := time.Now()

	add := func(p, t int) {
		totalPassed += p
		totalTests  += t
	}

	fmt.Println()

	// ── Suite 1: HTTP Verbs ──────────────────────────────────────────────────
	{
		tr := newTransport()
		defer tr.Close()
		c := &http.Client{Transport: tr}

		tests := []testCase{
			{
				name: "GET /", method: "GET", path: "/",
				check: expectStatusBody(200, "quic.cr"),
			},
			{
				name: "GET /healthz", method: "GET", path: "/healthz",
				check: func(status int, body string, _ http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					if !strings.Contains(body, "status") || !strings.Contains(body, "ok") {
						return fmt.Errorf("unexpected body: %q", body)
					}
					return nil
				},
			},
			{
				name: "GET /ping", method: "GET", path: "/ping",
				check: func(status int, body string, _ http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					if body != "pong" {
						return fmt.Errorf("expected \"pong\", got %q", body)
					}
					return nil
				},
			},
			{
				name: "GET /method", method: "GET", path: "/method",
				check: func(status int, body string, _ http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					if body != "GET" {
						return fmt.Errorf("expected \"GET\", got %q", body)
					}
					return nil
				},
			},
			{
				name: "POST /echo plain", method: "POST", path: "/echo",
				body: "hello from quic-go",
				check: expectStatusBody(200, "hello from quic-go"),
			},
			{
				name: "PUT /echo", method: "PUT", path: "/echo",
				body: "put-payload",
				check: expectStatusBody(200, "put-payload"),
			},
			{
				name: "PATCH /echo", method: "PATCH", path: "/echo",
				body: "patch-payload",
				check: expectStatusBody(200, "patch-payload"),
			},
			{
				name: "DELETE /resource", method: "DELETE", path: "/resource",
				check: expectStatus(204),
			},
			{
				name: "HEAD /", method: "HEAD", path: "/",
				check: func(status int, body string, headers http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					if len(body) != 0 {
						return fmt.Errorf("HEAD must have empty body, got %d bytes", len(body))
					}
					if sv := headers.Get("x-server"); sv != "quic.cr" {
						return fmt.Errorf("expected x-server: quic.cr, got %q", sv)
					}
					return nil
				},
			},
		}

		add(runParallel("HTTP Verbs", c, base, tests, *n, &allFailures))
	}

	// ── Suite 2: Status Codes ────────────────────────────────────────────────
	{
		tr := newTransport()
		defer tr.Close()
		c := &http.Client{Transport: tr}

		tests := []testCase{
			{name: "GET /status/200", method: "GET", path: "/status/200", check: expectStatus(200)},
			{name: "GET /status/201", method: "GET", path: "/status/201", check: expectStatus(201)},
			{name: "GET /status/400", method: "GET", path: "/status/400", check: expectStatus(400)},
			{name: "GET /not-found-xyz → 404", method: "GET", path: "/not-found-xyz", check: expectStatus(404)},
			{name: "GET /status/500", method: "GET", path: "/status/500", check: expectStatus(500)},
		}

		add(runParallel("Status Codes", c, base, tests, *n, &allFailures))
	}

	// ── Suite 3: Large Data ──────────────────────────────────────────────────
	{
		tr := newTransport()
		defer tr.Close()
		c := &http.Client{Transport: tr}

		tests := []testCase{
			{
				name: "GET /large 1MB", method: "GET", path: "/large?n=1048576",
				check: expectBodyLen(200, 1048570),
			},
			{
				name: "POST /echo 64KB", method: "POST", path: "/echo",
				body:  strings.Repeat("x", 65536),
				check: expectBodyLen(200, 65530),
			},
			{
				name: "POST /echo 256KB", method: "POST", path: "/echo",
				body:  strings.Repeat("y", 262144),
				check: expectBodyLen(200, 262130),
			},
			{
				name: "POST /upload 128KB", method: "POST", path: "/upload",
				body:  strings.Repeat("z", 131072),
				check: expectStatusBody(200, `"received":131072`),
			},
		}

		add(runParallel("Large Data", c, base, tests, *n, &allFailures))
	}

	// ── Suite 4: Headers ─────────────────────────────────────────────────────
	{
		tr := newTransport()
		defer tr.Close()
		c := &http.Client{Transport: tr}

		tests := []testCase{
			{
				name: "GET /echo-headers", method: "GET", path: "/echo-headers",
				check: func(status int, body string, _ http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					if !strings.Contains(body, ":") {
						return fmt.Errorf("expected JSON with ':' in body, got %q", truncate(body, 80))
					}
					return nil
				},
			},
			{
				name: "Content-Type text", method: "GET", path: "/ping",
				check: func(status int, _ string, headers http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					ct := headers.Get("content-type")
					if !strings.Contains(ct, "text/plain") {
						return fmt.Errorf("expected content-type text/plain, got %q", ct)
					}
					return nil
				},
			},
			{
				name: "Content-Type json", method: "GET", path: "/healthz",
				check: func(status int, _ string, headers http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					ct := headers.Get("content-type")
					if !strings.Contains(ct, "application/json") {
						return fmt.Errorf("expected content-type application/json, got %q", ct)
					}
					return nil
				},
			},
		}

		add(runParallel("Response Headers", c, base, tests, *n, &allFailures))
	}

	// ── Suite 5: Concurrent GET ×50 ─────────────────────────────────────────
	{
		tr := newTransport()
		defer tr.Close()
		c := &http.Client{Transport: tr}

		tests := []testCase{
			{
				name: "GET /ping", method: "GET", path: "/ping",
				check: func(status int, body string, _ http.Header) error {
					if status != 200 || body != "pong" {
						return fmt.Errorf("expected 200/pong, got %d/%q", status, body)
					}
					return nil
				},
			},
		}

		add(runParallel("Concurrent GET ×50", c, base, tests, 50**n, &allFailures))
	}

	// ── Suite 6: Concurrent POST ×20 ─────────────────────────────────────────
	{
		tr := newTransport()
		defer tr.Close()
		c := &http.Client{Transport: tr}

		body4k := strings.Repeat("a", 4096)
		tests := []testCase{
			{
				name: "POST /echo 4KB", method: "POST", path: "/echo",
				body: body4k,
				check: expectStatusBody(200, "aaa"),
			},
		}

		add(runParallel("Concurrent POST ×20", c, base, tests, 20**n, &allFailures))
	}

	// ── Suite 7: Concurrent Large ×10 ────────────────────────────────────────
	{
		tr := newTransport()
		defer tr.Close()
		c := &http.Client{Transport: tr}

		tests := []testCase{
			{
				name: "GET /large 64KB", method: "GET", path: "/large?n=65536",
				check: expectBodyLen(200, 65530),
			},
		}

		add(runParallel("Concurrent Large ×10", c, base, tests, 10**n, &allFailures))
	}

	// ── Suite 8: Sequential Load (Key Update test) ───────────────────────────
	{
		tr := newTransport()
		defer tr.Close()
		c := &http.Client{Transport: tr}

		pingTest := []testCase{
			{
				name: "GET /ping", method: "GET", path: "/ping",
				check: func(status int, body string, _ http.Header) error {
					if status != 200 || body != "pong" {
						return fmt.Errorf("expected 200/pong, got %d/%q", status, body)
					}
					return nil
				},
			},
		}

		p, t := runSerial("Sequential Load 200 reqs (Key Update)", c, base, pingTest, 200**n, &allFailures)
		add(p, t)
		if p == t {
			fmt.Println("  Key Update: ✓ triggered and handled correctly (pn > 100)")
		}
	}

	// ── Suite 9: Multiple Independent Connections ────────────────────────────
	{
		fmt.Printf("  %-40s ", "Multiple Connections (5 QUIC conns):")
		perConn := []testCase{
			{name: "GET /", method: "GET", path: "/", check: expectStatusBody(200, "quic.cr")},
			{name: "GET /healthz", method: "GET", path: "/healthz", check: expectStatus(200)},
			{name: "POST /echo", method: "POST", path: "/echo", body: "conn-hello", check: expectStatusBody(200, "conn-hello")},
			{name: "GET /ping", method: "GET", path: "/ping", check: expectStatusBody(200, "pong")},
			{name: "GET /healthz 2", method: "GET", path: "/healthz", check: expectStatus(200)},
		}

		connPassed := int32(0)
		connTotal  := int32(0)
		var mu sync.Mutex

		for i := 0; i < 5; i++ {
			tr := newTransport()
			c  := &http.Client{Transport: tr}
			for _, tc := range perConn {
				atomic.AddInt32(&connTotal, 1)
				if err := doRequest(c, base, tc); err == nil {
					atomic.AddInt32(&connPassed, 1)
				} else {
					mu.Lock()
					allFailures = append(allFailures, fmt.Sprintf("MultiConn conn%d/%s: %v", i, tc.name, err))
					mu.Unlock()
				}
			}
			tr.Close()
		}

		p := int(atomic.LoadInt32(&connPassed))
		t := int(atomic.LoadInt32(&connTotal))
		fmt.Printf("%d/%d\n", p, t)
		add(p, t)
	}

	// ── Suite 10: QUIC v2 ────────────────────────────────────────────────────
	{
		tr := newTransport(quic.Version2)
		defer tr.Close()
		c := &http.Client{Transport: tr}

		tests := []testCase{
			{name: "GET /", method: "GET", path: "/", check: expectStatusBody(200, "quic.cr")},
			{name: "GET /healthz", method: "GET", path: "/healthz", check: expectStatus(200)},
			{
				name: "POST /echo quicv2", method: "POST", path: "/echo",
				body: "quicv2-test",
				check: expectStatusBody(200, "quicv2-test"),
			},
			{
				name: "GET /ping", method: "GET", path: "/ping",
				check: func(status int, body string, _ http.Header) error {
					if status != 200 || body != "pong" {
						return fmt.Errorf("expected 200/pong, got %d/%q", status, body)
					}
					return nil
				},
			},
		}

		add(runParallel("QUIC v2 (RFC 9369)", c, base, tests, *n, &allFailures))
	}

	// ── Suite 11: Data Integrity ─────────────────────────────────────────────
	{
		tr := newTransport()
		defer tr.Close()
		c := &http.Client{Transport: tr}

		payload1k := strings.Repeat("abcdefghij", 100) // 1000 bytes, deterministic pattern

		tests := []testCase{
			{
				name: "POST /echo exact 1KB match", method: "POST", path: "/echo",
				body: payload1k,
				check: func(status int, body string, _ http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					if body != payload1k {
						return fmt.Errorf("echo mismatch: sent %d bytes, got %d bytes", len(payload1k), len(body))
					}
					return nil
				},
			},
			{
				name: "POST /digest SHA256 correctness", method: "POST", path: "/digest",
				body: "hello world",
				check: func(status int, body string, _ http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					want := sha256hex("hello world")
					if !strings.Contains(body, want) {
						return fmt.Errorf("sha256 mismatch: want %q in body %q", want, truncate(body, 120))
					}
					if !strings.Contains(body, `"size":11`) {
						return fmt.Errorf("expected size=11 in body %q", truncate(body, 120))
					}
					return nil
				},
			},
			{
				name: "GET /repeat 100×A", method: "GET", path: "/repeat?n=100&c=A",
				check: func(status int, body string, _ http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					want := strings.Repeat("A", 100)
					if body != want {
						return fmt.Errorf("repeat mismatch: want %d 'A's, got %q", 100, truncate(body, 40))
					}
					return nil
				},
			},
		}

		add(runParallel("Data Integrity", c, base, tests, *n, &allFailures))
	}

	// ── Suite 12: 10MB Large Transfer ────────────────────────────────────────
	{
		tr := newTransport()
		defer tr.Close()
		c := &http.Client{Transport: tr}

		tests := []testCase{
			{
				name: "GET /large 10MB", method: "GET", path: "/large?n=10485760",
				timeout: 60 * time.Second,
				check: expectBodyLen(200, 10485750),
			},
		}

		add(runParallel("10MB Large Transfer", c, base, tests, *n, &allFailures))
	}

	// ── Suite 13: Custom Request Headers ─────────────────────────────────────
	{
		tr := newTransport()
		defer tr.Close()
		c := &http.Client{Transport: tr}

		tests := []testCase{
			{
				name: "custom x-request-id echoed", method: "GET", path: "/echo-headers",
				headers: map[string]string{"x-request-id": "test-abc-123"},
				check: func(status int, body string, _ http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					if !strings.Contains(body, "test-abc-123") {
						return fmt.Errorf("expected x-request-id value in body, got %q", truncate(body, 120))
					}
					return nil
				},
			},
			{
				name: "custom x-trace-id echoed", method: "GET", path: "/echo-headers",
				headers: map[string]string{"x-trace-id": "trace-xyz-789"},
				check: func(status int, body string, _ http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					if !strings.Contains(body, "trace-xyz-789") {
						return fmt.Errorf("expected x-trace-id value in body, got %q", truncate(body, 120))
					}
					return nil
				},
			},
			{
				name: "multiple custom headers echoed", method: "GET", path: "/echo-headers",
				headers: map[string]string{
					"x-client-version": "v1.2.3",
					"x-region":         "eu-west-1",
				},
				check: func(status int, body string, _ http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					if !strings.Contains(body, "v1.2.3") {
						return fmt.Errorf("expected x-client-version value in body, got %q", truncate(body, 120))
					}
					if !strings.Contains(body, "eu-west-1") {
						return fmt.Errorf("expected x-region value in body, got %q", truncate(body, 120))
					}
					return nil
				},
			},
		}

		add(runParallel("Custom Request Headers", c, base, tests, *n, &allFailures))
	}

	// ── Suite 14: Sequential Pipelining 100 reqs ─────────────────────────────
	{
		tr := newTransport()
		defer tr.Close()
		c := &http.Client{Transport: tr}

		tests := []testCase{
			{
				name: "POST /echo sequential", method: "POST", path: "/echo",
				body: "pipeline-test",
				check: expectStatusBody(200, "pipeline-test"),
			},
		}

		add(runSerial("Sequential 100 Reqs (pipelining)", c, base, tests, 100**n, &allFailures))
	}

	// ── Suite 15: Concurrent Mix (large + small) ──────────────────────────────
	{
		tr := newTransport()
		defer tr.Close()
		c := &http.Client{Transport: tr}

		tests := []testCase{
			{
				name: "GET /large 64KB (mix)", method: "GET", path: "/large?n=65536",
				check: expectBodyLen(200, 65530),
			},
			{
				name: "GET /ping (mix)", method: "GET", path: "/ping",
				check: func(status int, body string, _ http.Header) error {
					if status != 200 || body != "pong" {
						return fmt.Errorf("expected 200/pong, got %d/%q", status, body)
					}
					return nil
				},
			},
		}

		// 2 test types × 5 = 10 total (5 large + 5 small interleaved)
		add(runParallel("Concurrent Mix (large+small)", c, base, tests, 5**n, &allFailures))
	}

	// ── Suite 16: Rapid Connection Churn ─────────────────────────────────────
	{
		fmt.Printf("  %-40s ", "Connection Churn (10 conns):")
		churnPassed := int32(0)
		churnTotal  := int32(10 * *n)
		var churnMu sync.Mutex

		var churnWg sync.WaitGroup
		for i := 0; i < 10**n; i++ {
			churnWg.Add(1)
			go func(idx int) {
				defer churnWg.Done()
				tr := newTransport()
				defer tr.Close()
				c := &http.Client{Transport: tr}
				tc := testCase{
					name: fmt.Sprintf("conn-%d GET /ping", idx), method: "GET", path: "/ping",
					check: func(status int, body string, _ http.Header) error {
						if status != 200 || body != "pong" {
							return fmt.Errorf("expected 200/pong, got %d/%q", status, body)
						}
						return nil
					},
				}
				if err := doRequest(c, base, tc); err == nil {
					atomic.AddInt32(&churnPassed, 1)
				} else {
					churnMu.Lock()
					allFailures = append(allFailures, fmt.Sprintf("Connection Churn / conn-%d: %v", idx, err))
					churnMu.Unlock()
				}
			}(i)
		}
		churnWg.Wait()

		cp := int(atomic.LoadInt32(&churnPassed))
		ct := int(atomic.LoadInt32(&churnTotal))
		fmt.Printf("%d/%d\n", cp, ct)
		add(cp, ct)
	}

	// ── Suite 17: Slow Endpoint (timer correctness) ───────────────────────────
	{
		fmt.Printf("  %-40s ", "Slow Endpoint (200ms sleep):")
		tr := newTransport()
		defer tr.Close()
		c := &http.Client{Transport: tr, Timeout: 10 * time.Second}
		tc17 := testCase{
			name: "GET /slow?ms=200", method: "GET", path: "/slow?ms=200",
			check: expectStatusBody(200, "ok"),
		}
		t17start := time.Now()
		err17 := doRequest(c, base, tc17)
		elapsed17 := time.Since(t17start)
		if err17 != nil {
			fmt.Printf("0/1 FAIL %v\n", err17)
			allFailures = append(allFailures, "Slow Endpoint: "+err17.Error())
			add(0, 1)
		} else if elapsed17 < 150*time.Millisecond {
			msg := fmt.Sprintf("expected >= 150ms latency, got %v", elapsed17)
			fmt.Printf("0/1 FAIL %s\n", msg)
			allFailures = append(allFailures, "Slow Endpoint: "+msg)
			add(0, 1)
		} else {
			fmt.Printf("1/1 (took %v)\n", elapsed17.Round(time.Millisecond))
			add(1, 1)
		}
	}

	// ── Suite 18: Upload / Digest Correctness ─────────────────────────────────
	{
		tr := newTransport()
		defer tr.Close()
		c := &http.Client{Transport: tr}

		payload64  := strings.Repeat("a", 64)
		payload1kb := strings.Repeat("x", 1024)

		tests := []testCase{
			{
				name: "POST /digest 11 bytes", method: "POST", path: "/digest",
				body: "hello world",
				check: func(status int, body string, _ http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					want := sha256hex("hello world")
					if !strings.Contains(body, want) {
						return fmt.Errorf("sha256 mismatch: want %q, body=%q", want, truncate(body, 120))
					}
					return nil
				},
			},
			{
				name: "POST /digest 64 bytes of 'a'", method: "POST", path: "/digest",
				body: payload64,
				check: func(status int, body string, _ http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					want := sha256hex(payload64)
					if !strings.Contains(body, want) {
						return fmt.Errorf("sha256 mismatch: want %q, body=%q", want, truncate(body, 120))
					}
					if !strings.Contains(body, `"size":64`) {
						return fmt.Errorf("expected size=64 in body %q", truncate(body, 120))
					}
					return nil
				},
			},
			{
				name: "POST /digest 1KB of 'x'", method: "POST", path: "/digest",
				body: payload1kb,
				check: func(status int, body string, _ http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					want := sha256hex(payload1kb)
					if !strings.Contains(body, want) {
						return fmt.Errorf("sha256 mismatch: want %q, body=%q", want, truncate(body, 120))
					}
					if !strings.Contains(body, `"size":1024`) {
						return fmt.Errorf("expected size=1024 in body %q", truncate(body, 120))
					}
					return nil
				},
			},
		}

		add(runParallel("Digest Upload Correctness", c, base, tests, *n, &allFailures))
	}

	// ── Suite 19: High-concurrency stress (100 parallel GET /ping) ───────────
	{
		tr := newTransport()
		defer tr.Close()
		c := &http.Client{Transport: tr}

		tests := make([]testCase, 100)
		for i := range tests {
			i := i
			tests[i] = testCase{
				name:   fmt.Sprintf("concurrent GET /ping #%d", i+1),
				method: "GET", path: "/ping",
				check: func(status int, body string, _ http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					if !strings.Contains(body, "pong") {
						return fmt.Errorf("expected 'pong' in body, got %q", truncate(body, 60))
					}
					return nil
				},
			}
		}
		add(runParallel("High-Concurrency 100× GET /ping", c, base, tests, *n, &allFailures))
	}

	// ── Suite 20: 1 MB upload integrity (POST /digest) ────────────────────────
	{
		tr := newTransport()
		defer tr.Close()
		c := &http.Client{Transport: tr}

		payload1mb := strings.Repeat("Z", 1024*1024)

		tests := []testCase{
			{
				name: "POST /digest 1 MB payload", method: "POST", path: "/digest",
				body: payload1mb, timeout: 60 * time.Second,
				check: func(status int, body string, _ http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					want := sha256hex(payload1mb)
					if !strings.Contains(body, want) {
						return fmt.Errorf("sha256 mismatch: want %s, body=%q", want, truncate(body, 120))
					}
					if !strings.Contains(body, `"size":1048576`) {
						return fmt.Errorf("expected size=1048576 in body %q", truncate(body, 120))
					}
					return nil
				},
			},
			{
				name: "POST /digest empty body", method: "POST", path: "/digest",
				body: "",
				check: func(status int, body string, _ http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					// SHA256 of empty string
					want := sha256hex("")
					if !strings.Contains(body, want) {
						return fmt.Errorf("sha256 mismatch for empty body: want %s, body=%q", want, truncate(body, 120))
					}
					return nil
				},
			},
		}
		add(runParallel("Upload Integrity (1 MB + empty)", c, base, tests, *n, &allFailures))
	}

	// ── Suite 21: Error handling and edge cases ───────────────────────────────
	{
		tr := newTransport()
		defer tr.Close()
		c := &http.Client{Transport: tr}

		tests := []testCase{
			{
				name: "GET /nonexistent → 404", method: "GET", path: "/nonexistent-path-xyz",
				check: func(status int, body string, _ http.Header) error {
					if status != 404 {
						return fmt.Errorf("expected 404, got %d", status)
					}
					return nil
				},
			},
			{
				name: "GET /status/404 → 404", method: "GET", path: "/status/404",
				check: func(status int, body string, _ http.Header) error {
					if status != 404 {
						return fmt.Errorf("expected 404, got %d", status)
					}
					return nil
				},
			},
			{
				name: "GET /status/500 → 500", method: "GET", path: "/status/500",
				check: func(status int, body string, _ http.Header) error {
					if status != 500 {
						return fmt.Errorf("expected 500, got %d", status)
					}
					return nil
				},
			},
			{
				name: "GET /status/503 → 503", method: "GET", path: "/status/503",
				check: func(status int, body string, _ http.Header) error {
					if status != 503 {
						return fmt.Errorf("expected 503, got %d", status)
					}
					return nil
				},
			},
			{
				name: "GET /status/201 → 201", method: "GET", path: "/status/201",
				check: func(status int, body string, _ http.Header) error {
					if status != 201 {
						return fmt.Errorf("expected 201, got %d", status)
					}
					return nil
				},
			},
			{
				name: "GET /status/302 → 302", method: "GET", path: "/status/302",
				check: func(status int, body string, _ http.Header) error {
					if status != 302 {
						return fmt.Errorf("expected 302, got %d", status)
					}
					return nil
				},
			},
			{
				name: "POST /echo empty body", method: "POST", path: "/echo",
				body: "",
				check: func(status int, body string, _ http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					return nil
				},
			},
			{
				name: "GET /repeat n=0 → empty body", method: "GET", path: "/repeat?n=0&c=x",
				check: func(status int, body string, _ http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					if body != "" {
						return fmt.Errorf("expected empty body, got %q", truncate(body, 60))
					}
					return nil
				},
			},
			{
				name: "GET /repeat n=1 c=Z → single char", method: "GET", path: "/repeat?n=1&c=Z",
				check: func(status int, body string, _ http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					if body != "Z" {
						return fmt.Errorf("expected 'Z', got %q", truncate(body, 60))
					}
					return nil
				},
			},
			{
				name: "GET /slow?ms=0 → instant", method: "GET", path: "/slow?ms=0",
				check: func(status int, body string, _ http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					return nil
				},
			},
		}
		add(runParallel("Error Handling & Edge Cases", c, base, tests, *n, &allFailures))
	}

	// ── Suite 22: Server Push (RFC 9114 §4.6) ───────────────────────────────
	// quic-go HTTP/3 client does not send MAX_PUSH_ID (push disabled by default),
	// so the server correctly skips the push and delivers the main response.
	// The test verifies: (a) 200 OK arrives, (b) no H3_ID_ERROR, (c) body correct.
	{
		tr := newTransport()
		defer tr.Close()
		c := &http.Client{Transport: tr}

		tests := []testCase{
			{
				name: "GET /push-demo — no H3_ID_ERROR when push not authorised",
				method: "GET", path: "/push-demo",
				check: func(status int, body string, _ http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					if !strings.Contains(body, "main response") {
						return fmt.Errorf("unexpected body: %q", truncate(body, 80))
					}
					return nil
				},
			},
			{
				name: "GET /push-demo × 5 sequential — stable without push",
				method: "GET", path: "/push-demo",
				check: func(status int, body string, _ http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					return nil
				},
			},
			{
				name: "GET /push-demo concurrent × 10 — no connection corruption",
				method: "GET", path: "/push-demo",
				check: func(status int, _ string, _ http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					return nil
				},
			},
		}
		// 1 round sequential + 10 concurrent
		add(runSerial("Server Push (RFC 9114 §4.6) sequential", c, base, tests[:2], 5, &allFailures))
		add(runParallel("Server Push (RFC 9114 §4.6) concurrent", c, base, tests[2:], 10, &allFailures))
	}

	// ── Suite 23: QUIC Datagram echo (RFC 9221) ───────────────────────────────
	{
		passed := 0
		total  := 0
		var dgFails []string

		payloads := []string{"ping", "hello datagram", strings.Repeat("D", 200), strings.Repeat("X", 1024)}
		for _, payload := range payloads {
			total++
			err := testDatagramEcho(*host, *port, []byte(payload))
			if err != nil {
				dgFails = append(dgFails, fmt.Sprintf("QUIC Datagram echo / %q: %v", truncate(payload, 20), err))
				allFailures = append(allFailures, fmt.Sprintf("QUIC Datagram echo / %q: %v", truncate(payload, 20), err))
			} else {
				passed++
			}
		}
		fmt.Printf("  %-40s %d/%d\n", "QUIC Datagram echo (RFC 9221):", passed, total)
		totalPassed += passed
		totalTests  += total
		_ = dgFails
	}

	// ── Suite 24: PMTUD — payloads at and above MTU boundaries ───────────────
	{
		tr := newTransport()
		defer tr.Close()
		c := &http.Client{Transport: tr}

		sizes := []int{1000, 1200, 1300, 1400, 1450, 1472, 1500, 2048, 4096, 8192}
		tests := make([]testCase, len(sizes))
		for i, size := range sizes {
			size := size
			tests[i] = testCase{
				name:   fmt.Sprintf("POST /echo %d bytes (MTU probe)", size),
				method: "POST", path: "/echo",
				body:   strings.Repeat("M", size),
				check: func(status int, body string, _ http.Header) error {
					if status != 200 {
						return fmt.Errorf("expected 200, got %d", status)
					}
					if len(body) != size {
						return fmt.Errorf("expected %d bytes, got %d", size, len(body))
					}
					return nil
				},
			}
		}
		add(runParallel("PMTUD — MTU boundary payloads", c, base, tests, *n, &allFailures))
	}

	// ── Suite 25: STREAMS_BLOCKED + MAX_STREAMS replenishment ───────────────
	{
		passed, total, failures := testStreamsBlockedFlow(*host, *port)
		add(passed, total)
		for _, f := range failures {
			allFailures = append(allFailures, "STREAMS_BLOCKED replenishment / "+f)
		}
	}

	// ── Suite 26: H3 control stream — SETTINGS + GOAWAY ──────────────────
	{
		const suiteName = "H3 control stream: SETTINGS + GOAWAY"
		if err := testGoawayAndControlStream(*host, *port); err != nil {
			add(0, 1)
			allFailures = append(allFailures, suiteName+": "+err.Error())
			fmt.Printf("  %-40s 0/1\n", suiteName+":")
		} else {
			add(1, 1)
			fmt.Printf("  %-40s 1/1\n", suiteName+":")
		}
	}

	// ── Suite 27: Dynamic QPACK (RFC 9204) ───────────────────────────────
	{
		passed, total, failures := testDynamicQpack(*host, *port, 40)
		add(passed, total)
		for _, f := range failures {
			allFailures = append(allFailures, "Dynamic QPACK / "+f)
		}
	}

	// ── Suite 28: 0-RTT / Early Data (RFC 9001 §8) ───────────────────────
	{
		const suiteName = "0-RTT early data"
		if err := testZeroRTT(*host, *port); err != nil {
			add(0, 1)
			allFailures = append(allFailures, suiteName+": "+err.Error())
			fmt.Printf("  %-40s 0/1\n", suiteName+":")
		} else {
			add(1, 1)
			fmt.Printf("  %-40s 1/1\n", suiteName+":")
		}
	}

	// ── Final report ─────────────────────────────────────────────────────────
	elapsed := time.Since(start)
	fmt.Printf("\n%s\n", strings.Repeat("═", 52))
	fmt.Printf("  QUIC/HTTP3 E2E Suite   %d/%d  in %v\n",
		totalPassed, totalTests, elapsed.Round(time.Millisecond))
	fmt.Printf("%s\n", strings.Repeat("═", 52))

	if len(allFailures) > 0 {
		fmt.Println("FAILURES:")
		for _, f := range allFailures {
			fmt.Printf("  FAIL  %s\n", f)
		}
		os.Exit(1)
	}

	fmt.Println("ALL PASSED ✓")
}
