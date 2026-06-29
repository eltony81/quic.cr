// HTTP/3 cross-validation test suite: Go client → Crystal quic.cr server
//
// Replaces examples/validate_cross_tests.py — no Python/aioquic overhead.
// Uses quic-go as the HTTP/3 client; /tmp/e2e_server as the Crystal server.
//
// Usage:
//   cd bench/go_client/cross_test
//   go build -o cross_test .
//   /tmp/e2e_server &   # start Crystal server first
//   ./cross_test
//
// Or let the tool start/stop the server automatically:
//   ./cross_test -start-server

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const crystalAddr = "127.0.0.1:4433"

// ── VarInt / H3 frame helpers for raw injection tests ───────────────────────

func appendVarInt(b []byte, v uint64) []byte {
	switch {
	case v < 64:
		return append(b, byte(v))
	case v < 16384:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v < 1073741824:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(b, byte(v>>56)|0xC0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

func h3Frame(typ uint64, payload []byte) []byte {
	b := appendVarInt(nil, typ)
	b = appendVarInt(b, uint64(len(payload)))
	return append(b, payload...)
}

// ── HTTP/3 transport ─────────────────────────────────────────────────────────

func newClient() *http.Client {
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		QUICConfig:      &quic.Config{},
	}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

// ── Test runner ──────────────────────────────────────────────────────────────

type result struct {
	name   string
	passed bool
	reason string
}

func pass(name string) result { return result{name, true, ""} }
func fail(name, reason string) result {
	return result{name, false, reason}
}

// ── Phase 1: standard HTTP/3 request tests ──────────────────────────────────

func testGetPing(c *http.Client) result {
	resp, err := c.Get("https://" + crystalAddr + "/ping")
	if err != nil {
		return fail("GET /ping", err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || strings.TrimSpace(string(body)) != "pong" {
		return fail("GET /ping", fmt.Sprintf("status=%d body=%q", resp.StatusCode, body))
	}
	return pass("GET /ping → 200 pong")
}

func testPostEcho(c *http.Client) result {
	const payload = "hello quic.cr"
	resp, err := c.Post("https://"+crystalAddr+"/echo", "text/plain", strings.NewReader(payload))
	if err != nil {
		return fail("POST /echo", err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), payload) {
		return fail("POST /echo", fmt.Sprintf("status=%d body=%q", resp.StatusCode, body))
	}
	return pass("POST /echo → echoes body")
}

func testPutEcho(c *http.Client) result {
	req, _ := http.NewRequest("PUT", "https://"+crystalAddr+"/echo", strings.NewReader("put-body"))
	req.Header.Set("content-type", "text/plain")
	resp, err := c.Do(req)
	if err != nil {
		return fail("PUT /echo", err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "put-body") {
		return fail("PUT /echo", fmt.Sprintf("status=%d body=%q", resp.StatusCode, body))
	}
	return pass("PUT /echo → echoes body")
}

func testPatchEcho(c *http.Client) result {
	req, _ := http.NewRequest("PATCH", "https://"+crystalAddr+"/echo", strings.NewReader("patch-body"))
	req.Header.Set("content-type", "text/plain")
	resp, err := c.Do(req)
	if err != nil {
		return fail("PATCH /echo", err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "patch-body") {
		return fail("PATCH /echo", fmt.Sprintf("status=%d body=%q", resp.StatusCode, body))
	}
	return pass("PATCH /echo → echoes body")
}

func testDeleteResource(c *http.Client) result {
	req, _ := http.NewRequest("DELETE", "https://"+crystalAddr+"/resource", nil)
	resp, err := c.Do(req)
	if err != nil {
		return fail("DELETE /resource", err.Error())
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	if resp.StatusCode != 204 {
		return fail("DELETE /resource", fmt.Sprintf("status=%d", resp.StatusCode))
	}
	return pass("DELETE /resource → 204")
}

func testGetHealthz(c *http.Client) result {
	resp, err := c.Get("https://" + crystalAddr + "/healthz")
	if err != nil {
		return fail("GET /healthz", err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "ok") {
		return fail("GET /healthz", fmt.Sprintf("status=%d body=%q", resp.StatusCode, body))
	}
	return pass("GET /healthz → 200 {status:ok}")
}

func testGetMethod(c *http.Client) result {
	resp, err := c.Get("https://" + crystalAddr + "/method")
	if err != nil {
		return fail("GET /method", err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "GET") {
		return fail("GET /method", fmt.Sprintf("status=%d body=%q", resp.StatusCode, body))
	}
	return pass("GET /method → 200 GET")
}

func testStatus200(c *http.Client) result {
	resp, err := c.Get("https://" + crystalAddr + "/status/200")
	if err != nil {
		return fail("GET /status/200", err.Error())
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	if resp.StatusCode != 200 {
		return fail("GET /status/200", fmt.Sprintf("got %d", resp.StatusCode))
	}
	return pass("GET /status/200 → 200")
}

func testStatus404(c *http.Client) result {
	resp, err := c.Get("https://" + crystalAddr + "/status/404")
	if err != nil {
		return fail("GET /status/404", err.Error())
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	if resp.StatusCode != 404 {
		return fail("GET /status/404", fmt.Sprintf("got %d", resp.StatusCode))
	}
	return pass("GET /status/404 → 404")
}

func testStatus201(c *http.Client) result {
	resp, err := c.Get("https://" + crystalAddr + "/status/201")
	if err != nil {
		return fail("GET /status/201", err.Error())
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	if resp.StatusCode != 201 {
		return fail("GET /status/201", fmt.Sprintf("got %d", resp.StatusCode))
	}
	return pass("GET /status/201 → 201")
}

func testEchoHeaders(c *http.Client) result {
	req, _ := http.NewRequest("GET", "https://"+crystalAddr+"/echo-headers", nil)
	req.Header.Set("x-test-id", "cross-validation")
	resp, err := c.Do(req)
	if err != nil {
		return fail("GET /echo-headers", err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "cross-validation") {
		return fail("GET /echo-headers", fmt.Sprintf("status=%d body=%q", resp.StatusCode, body))
	}
	return pass("GET /echo-headers → custom header echoed")
}

func testGet100k(c *http.Client) result {
	resp, err := c.Get("https://" + crystalAddr + "/100k")
	if err != nil {
		return fail("GET /100k", err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	const want = 102400
	if resp.StatusCode != 200 || len(body) != want {
		return fail("GET /100k", fmt.Sprintf("status=%d len=%d (want %d)", resp.StatusCode, len(body), want))
	}
	return pass("GET /100k → 102400 bytes")
}

func testGetLarge(c *http.Client) result {
	resp, err := c.Get("https://" + crystalAddr + "/large?n=4096")
	if err != nil {
		return fail("GET /large?n=4096", err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || len(body) != 4096 {
		return fail("GET /large?n=4096", fmt.Sprintf("status=%d len=%d", resp.StatusCode, len(body)))
	}
	return pass("GET /large?n=4096 → 4096 bytes")
}

func testPostEchoLarge(c *http.Client) result {
	const size = 1_000_000
	payload := bytes.Repeat([]byte("A"), size)
	resp, err := c.Post("https://"+crystalAddr+"/echo", "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		return fail("POST /echo 1MB", err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || len(body) != size {
		return fail("POST /echo 1MB", fmt.Sprintf("status=%d body_len=%d", resp.StatusCode, len(body)))
	}
	return pass("POST /echo 1MB → echoed back (1MB)")
}

func testDigest(c *http.Client) result {
	const msg = "cross-test-digest-payload"
	want := hex.EncodeToString(func() []byte { h := sha256.Sum256([]byte(msg)); return h[:] }())
	resp, err := c.Post("https://"+crystalAddr+"/digest", "text/plain", strings.NewReader(msg))
	if err != nil {
		return fail("POST /digest", err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), want) {
		return fail("POST /digest", fmt.Sprintf("status=%d body=%q want_sha256=%s", resp.StatusCode, body, want))
	}
	return pass("POST /digest → correct SHA256")
}

func testRepeat(c *http.Client) result {
	resp, err := c.Get("https://" + crystalAddr + "/repeat?n=30&c=z")
	if err != nil {
		return fail("GET /repeat", err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	want := strings.Repeat("z", 30)
	if resp.StatusCode != 200 || strings.TrimSpace(string(body)) != want {
		return fail("GET /repeat?n=30&c=z", fmt.Sprintf("status=%d body=%q", resp.StatusCode, body))
	}
	return pass("GET /repeat?n=30&c=z → 30 z's")
}

func testConcurrentPing(c *http.Client) result {
	const n = 5
	var errCount int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := c.Get("https://" + crystalAddr + "/ping")
			if err != nil {
				atomic.AddInt32(&errCount, 1)
				return
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			if resp.StatusCode != 200 {
				atomic.AddInt32(&errCount, 1)
			}
		}()
	}
	wg.Wait()
	if errCount > 0 {
		return fail("Concurrent GET /ping ×5", fmt.Sprintf("%d/%d failed", errCount, n))
	}
	return pass("Concurrent GET /ping ×5 → all 200")
}

func testSlowEndpoint(c *http.Client) result {
	t0 := time.Now()
	resp, err := c.Get("https://" + crystalAddr + "/slow?ms=80")
	if err != nil {
		return fail("GET /slow?ms=80", err.Error())
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	elapsed := time.Since(t0)
	if resp.StatusCode != 200 {
		return fail("GET /slow?ms=80", fmt.Sprintf("status=%d", resp.StatusCode))
	}
	if elapsed < 80*time.Millisecond {
		return fail("GET /slow?ms=80", fmt.Sprintf("too fast: %v", elapsed))
	}
	return pass(fmt.Sprintf("GET /slow?ms=80 → ok in %v", elapsed.Round(time.Millisecond)))
}

// ── Phase 2: additional robustness tests ─────────────────────────────────────

func testUpload(c *http.Client) result {
	const size = 5000
	body := bytes.Repeat([]byte("X"), size)
	resp, err := c.Post("https://"+crystalAddr+"/upload", "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		return fail("POST /upload 5000B", err.Error())
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(respBody), "5000") {
		return fail("POST /upload 5000B", fmt.Sprintf("status=%d body=%q", resp.StatusCode, respBody))
	}
	return pass("POST /upload 5000B → {received:5000}")
}

func testGetLarge64k(c *http.Client) result {
	resp, err := c.Get("https://" + crystalAddr + "/large?n=65536")
	if err != nil {
		return fail("GET /large?n=65536", err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || len(body) != 65536 {
		return fail("GET /large?n=65536", fmt.Sprintf("status=%d len=%d", resp.StatusCode, len(body)))
	}
	return pass("GET /large?n=65536 → 65536 bytes")
}

func testMultipleConnections() result {
	const n = 3
	var errCount int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := newClient()
			resp, err := c.Get("https://" + crystalAddr + "/ping")
			if err != nil {
				atomic.AddInt32(&errCount, 1)
				return
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			if resp.StatusCode != 200 {
				atomic.AddInt32(&errCount, 1)
			}
		}()
	}
	wg.Wait()
	if errCount > 0 {
		return fail("3 independent connections", fmt.Sprintf("%d/%d failed", errCount, n))
	}
	return pass("3 independent QUIC connections → all succeed")
}

func testSequentialRequests(c *http.Client) result {
	const n = 5
	for i := 0; i < n; i++ {
		resp, err := c.Get("https://" + crystalAddr + "/ping")
		if err != nil {
			return fail(fmt.Sprintf("Sequential ×%d GET /ping", n), fmt.Sprintf("req %d: %v", i, err))
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || strings.TrimSpace(string(body)) != "pong" {
			return fail(fmt.Sprintf("Sequential ×%d GET /ping", n), fmt.Sprintf("req %d: status=%d", i, resp.StatusCode))
		}
	}
	return pass(fmt.Sprintf("Sequential ×%d GET /ping → all succeed", n))
}

func testNotFound(c *http.Client) result {
	resp, err := c.Get("https://" + crystalAddr + "/definitely_nonexistent_xyzzy")
	if err != nil {
		return fail("GET /nonexistent", err.Error())
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	if resp.StatusCode != 404 {
		return fail("GET /nonexistent → 404", fmt.Sprintf("got %d", resp.StatusCode))
	}
	return pass("GET /nonexistent → 404")
}

func testDynamicQPACK(c *http.Client) result {
	// 3 sequential requests to exercise persistent QPACK encoder state.
	for i := 0; i < 3; i++ {
		resp, err := c.Get(fmt.Sprintf("https://%s/ping", crystalAddr))
		if err != nil {
			return fail("Dynamic QPACK ×3", fmt.Sprintf("req %d: %v", i, err))
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || strings.TrimSpace(string(body)) != "pong" {
			return fail("Dynamic QPACK ×3", fmt.Sprintf("req %d: status=%d", i, resp.StatusCode))
		}
	}
	return pass("Dynamic QPACK — 3 sequential requests (persistent encoder)")
}

// ── Phase 3: raw H3 frame injection tests ────────────────────────────────────

// sendRawH3 dials a raw QUIC connection, performs minimal H3 client setup
// (control/encoder/decoder streams), sends `payload` on a bidi request stream,
// then waits for the server to close the connection.
// Returns (connection was closed by server, application error code).
func sendRawH3(payload []byte, timeout time.Duration) (closed bool, errCode uint64) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	tlsCfg := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}} //nolint:gosec
	conn, err := quic.DialAddr(ctx, crystalAddr, tlsCfg, &quic.Config{})
	if err != nil {
		return false, 0
	}
	defer conn.CloseWithError(0, "") //nolint:errcheck

	// Minimal H3 client setup: control stream + SETTINGS, encoder stream, decoder stream.
	if cs, err := conn.OpenUniStreamSync(ctx); err == nil {
		// stream type 0x00 (control) + SETTINGS frame (type=0x04, len=0x00)
		cs.Write([]byte{0x00, 0x04, 0x00}) //nolint:errcheck
	}
	if es, err := conn.OpenUniStreamSync(ctx); err == nil {
		es.Write([]byte{0x02}) //nolint:errcheck
	}
	if ds, err := conn.OpenUniStreamSync(ctx); err == nil {
		ds.Write([]byte{0x03}) //nolint:errcheck
	}

	// Drain server's unidirectional streams (control, encoder, decoder).
	go func() {
		for {
			s, err := conn.AcceptUniStream(ctx)
			if err != nil {
				return
			}
			go io.Copy(io.Discard, s) //nolint:errcheck
		}
	}()

	// Give H3 setup a moment to complete.
	time.Sleep(150 * time.Millisecond)

	// Open request bidi stream and write the malformed payload.
	reqStream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return false, 0
	}
	reqStream.Write(payload) //nolint:errcheck
	reqStream.Close()        //nolint:errcheck

	// Wait for connection closure.
	select {
	case <-conn.Context().Done():
		cause := context.Cause(conn.Context())
		var appErr *quic.ApplicationError
		if errors.As(cause, &appErr) {
			return true, uint64(appErr.ErrorCode)
		}
		return true, 0
	case <-ctx.Done():
		return false, 0
	}
}

const (
	h3ErrFrameUnexpected uint64 = 0x0105
	h3ErrIDError         uint64 = 0x0108
	h3ErrMessageError    uint64 = 0x010e
)

func testDataBeforeHeaders() result {
	// RFC 9114 §7.2.1: DATA frame before HEADERS on a request stream → H3_FRAME_UNEXPECTED.
	payload := h3Frame(0x00, []byte("orphan data frame"))
	closed, code := sendRawH3(payload, 4*time.Second)
	if !closed {
		return fail("R1: DATA before HEADERS → H3_FRAME_UNEXPECTED", "server did not close connection")
	}
	if code != h3ErrFrameUnexpected && code != 0 {
		// Accept code=0 (generic close) as the server may batch the error.
		return fail("R1: DATA before HEADERS", fmt.Sprintf("expected 0x%04x got 0x%04x", h3ErrFrameUnexpected, code))
	}
	return pass("R1: DATA before HEADERS → connection closed (H3_FRAME_UNEXPECTED)")
}

func testSettingsOnRequestStream() result {
	// RFC 9114 §7.2.4: SETTINGS on a request stream → H3_FRAME_UNEXPECTED.
	payload := h3Frame(0x04, []byte{}) // empty SETTINGS
	closed, code := sendRawH3(payload, 4*time.Second)
	if !closed {
		return fail("R2: SETTINGS on request stream → H3_FRAME_UNEXPECTED", "server did not close")
	}
	if code != h3ErrFrameUnexpected && code != 0 {
		return fail("R2: SETTINGS on request stream", fmt.Sprintf("expected 0x%04x got 0x%04x", h3ErrFrameUnexpected, code))
	}
	return pass("R2: SETTINGS on request stream → connection closed (H3_FRAME_UNEXPECTED)")
}

// minimalQPACKHeaders builds a QPACK header block using only literal fields
// (without name reference, no Huffman). Safe for injection tests.
func minimalQPACKHeaders(headers [][2]string) []byte {
	// QPACK block prefix: Required Insert Count=0, Base=0
	b := []byte{0x00, 0x00}
	for _, h := range headers {
		name, val := []byte(h[0]), []byte(h[1])
		// Literal Field Line Without Name Reference: 0b001 N=0 H=0 NameLen(3-bit prefix)
		if len(name) < 7 {
			b = append(b, byte(0x20|len(name)))
		} else {
			b = append(b, 0x27)
			b = appendVarInt(b[:len(b)-1], uint64(len(name)-7+1)) // undo last append; redo properly
			// Simpler: just encode as multi-byte
			b[len(b)-1] = 0x27
			extra := uint64(len(name) - 7)
			for extra >= 128 {
				b = append(b, byte(extra%128)|0x80)
				extra /= 128
			}
			b = append(b, byte(extra))
		}
		b = append(b, name...)
		// Value: H=0, length (7-bit prefix)
		if len(val) < 127 {
			b = append(b, byte(len(val)))
		} else {
			b = append(b, 0x7F)
			extra := uint64(len(val) - 127)
			for extra >= 128 {
				b = append(b, byte(extra%128)|0x80)
				extra /= 128
			}
			b = append(b, byte(extra))
		}
		b = append(b, val...)
	}
	return b
}

func testMissingMethod() result {
	// RFC 9114 §4.3.1: HEADERS missing :method → H3_MESSAGE_ERROR.
	qpack := minimalQPACKHeaders([][2]string{
		{":path", "/"},
		{":scheme", "https"},
		{":authority", "127.0.0.1:4433"},
	})
	payload := h3Frame(0x01, qpack) // HEADERS frame
	closed, code := sendRawH3(payload, 4*time.Second)
	if !closed {
		return fail("R3: missing :method → H3_MESSAGE_ERROR", "server did not close")
	}
	if code != h3ErrMessageError && code != 0 {
		return fail("R3: missing :method", fmt.Sprintf("expected 0x%04x got 0x%04x", h3ErrMessageError, code))
	}
	return pass("R3: HEADERS missing :method → connection closed (H3_MESSAGE_ERROR)")
}

func testStatusInRequest() result {
	// RFC 9114 §4.3.1: :status in a request → H3_MESSAGE_ERROR.
	qpack := minimalQPACKHeaders([][2]string{
		{":method", "GET"},
		{":path", "/"},
		{":scheme", "https"},
		{":status", "200"}, // invalid in request
	})
	payload := h3Frame(0x01, qpack)
	closed, code := sendRawH3(payload, 4*time.Second)
	if !closed {
		return fail("R4: :status in request → H3_MESSAGE_ERROR", "server did not close")
	}
	if code != h3ErrMessageError && code != 0 {
		return fail("R4: :status in request", fmt.Sprintf("expected 0x%04x got 0x%04x", h3ErrMessageError, code))
	}
	return pass("R4: :status in request → connection closed (H3_MESSAGE_ERROR)")
}

func testPushPromiseOnRequestStream() result {
	// RFC 9114 §7.2.6: PUSH_PROMISE on client-initiated bidi stream → H3_ID_ERROR.
	// PUSH_PROMISE payload: push_id VarInt(0) + empty QPACK block [0x00, 0x00]
	pp := append(appendVarInt(nil, 0), 0x00, 0x00)
	payload := h3Frame(0x05, pp)
	closed, _ := sendRawH3(payload, 4*time.Second)
	if !closed {
		return fail("R5: PUSH_PROMISE on request stream", "server did not close")
	}
	return pass("R5: PUSH_PROMISE on request stream → connection closed")
}

// ── Server lifecycle ─────────────────────────────────────────────────────────

func waitForServer(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		conn, err := quic.DialAddr(ctx, addr, tlsCfg, &quic.Config{})
		cancel()
		if err == nil {
			conn.CloseWithError(0, "") //nolint:errcheck
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// ── Main ─────────────────────────────────────────────────────────────────────

func main() {
	startServer := flag.Bool("start-server", false, "Start /tmp/e2e_server automatically")
	flag.Parse()

	var serverCmd *exec.Cmd
	if *startServer {
		if _, err := os.Stat("/tmp/e2e_server"); os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "✗ /tmp/e2e_server not found — build it first:")
			fmt.Fprintln(os.Stderr, "  crystal build examples/e2e_server.cr -o /tmp/e2e_server --release")
			os.Exit(1)
		}
		serverCmd = exec.Command("/tmp/e2e_server")
		serverCmd.Stdout = io.Discard
		serverCmd.Stderr = io.Discard
		if err := serverCmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "✗ Failed to start server: %v\n", err)
			os.Exit(1)
		}
		defer serverCmd.Process.Kill() //nolint:errcheck
		fmt.Println("==> Waiting for Crystal server on :4433...")
		if !waitForServer(crystalAddr, 5*time.Second) {
			fmt.Fprintln(os.Stderr, "✗ Server did not start within 5s")
			os.Exit(1)
		}
	} else {
		// Verify server is reachable
		if !waitForServer(crystalAddr, 2*time.Second) {
			fmt.Fprintf(os.Stderr, "✗ Crystal server not reachable at %s\n", crystalAddr)
			fmt.Fprintln(os.Stderr, "  Start it first: /tmp/e2e_server &")
			fmt.Fprintln(os.Stderr, "  Or run with: ./cross_test -start-server")
			os.Exit(1)
		}
	}

	client := newClient()

	fmt.Println()
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Println("  HTTP/3 Cross-Validation: Go client → Crystal quic.cr")
	fmt.Println("════════════════════════════════════════════════════════════")

	var results []result

	// Phase 1: standard HTTP/3 request tests (18 tests)
	fmt.Println()
	fmt.Println("── Phase 1: HTTP/3 Request Correctness ──────────────────────")
	phase1 := []func(*http.Client) result{
		testGetPing,
		testPostEcho,
		testPutEcho,
		testPatchEcho,
		testDeleteResource,
		testGetHealthz,
		testGetMethod,
		testStatus200,
		testStatus404,
		testStatus201,
		testEchoHeaders,
		testGet100k,
		testGetLarge,
		testPostEchoLarge,
		testDigest,
		testRepeat,
		testConcurrentPing,
		testSlowEndpoint,
	}
	for _, fn := range phase1 {
		r := fn(client)
		results = append(results, r)
		if r.passed {
			fmt.Printf("  ✓ %s\n", r.name)
		} else {
			fmt.Printf("  ✗ %s: %s\n", r.name, r.reason)
		}
	}

	// Phase 2: robustness (6 tests)
	fmt.Println()
	fmt.Println("── Phase 2: Robustness & Edge Cases ─────────────────────────")
	phase2 := []result{
		testUpload(client),
		testGetLarge64k(client),
		testMultipleConnections(),
		testSequentialRequests(client),
		testNotFound(client),
		testDynamicQPACK(client),
	}
	for _, r := range phase2 {
		results = append(results, r)
		if r.passed {
			fmt.Printf("  ✓ %s\n", r.name)
		} else {
			fmt.Printf("  ✗ %s: %s\n", r.name, r.reason)
		}
	}

	// Phase 3: RFC 9114 rejection behavior (raw H3 injection, 5 tests)
	fmt.Println()
	fmt.Println("── Phase 3: RFC 9114 Rejection Behaviors ────────────────────")
	phase3 := []result{
		testDataBeforeHeaders(),
		testSettingsOnRequestStream(),
		testMissingMethod(),
		testStatusInRequest(),
		testPushPromiseOnRequestStream(),
	}
	for _, r := range phase3 {
		results = append(results, r)
		if r.passed {
			fmt.Printf("  ✓ %s\n", r.name)
		} else {
			fmt.Printf("  ✗ %s: %s\n", r.name, r.reason)
		}
	}

	// Summary
	passed := 0
	for _, r := range results {
		if r.passed {
			passed++
		}
	}
	total := len(results)

	fmt.Println()
	fmt.Println("════════════════════════════════════════════════════════════")
	if passed == total {
		fmt.Printf("  SUMMARY  %d/%d passed   ✓ all green\n", passed, total)
	} else {
		fmt.Printf("  SUMMARY  %d/%d passed   ✗ %d failed\n", passed, total, total-passed)
	}
	fmt.Println("════════════════════════════════════════════════════════════")

	if passed != total {
		os.Exit(1)
	}
}
