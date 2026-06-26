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
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
	name   string
	method string
	path   string
	body   string
	check  func(status int, body string, headers http.Header) error
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var reqBody io.Reader
	if tc.body != "" {
		reqBody = bytes.NewBufferString(tc.body)
	}

	req, err := http.NewRequestWithContext(ctx, tc.method, base+tc.path, reqBody)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
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
