// HTTP/3 concurrent benchmark for quic.cr
// Replaces examples/benchmark_concurrent.py
//
// Usage:
//   go build -o bench_concurrent .
//   ./bench_concurrent [-port 4433] [-conns 8] [-reps 3]
//
// Start the server first:
//   crystal build examples/e2e_server.cr -o /tmp/e2e_server --release && /tmp/e2e_server
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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func newTransport() *http3.Transport {
	return &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		QUICConfig:      &quic.Config{},
	}
}

func doRequest(base, method, path string, body []byte) (int, time.Duration) {
	tr := newTransport()
	defer tr.Close()
	client := &http.Client{Transport: tr}

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, base+path, bodyReader)
	if err != nil {
		return 0, 0
	}
	if body != nil {
		req.Header.Set("content-type", "application/octet-stream")
		req.ContentLength = int64(len(body))
	}

	t0 := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(t0)
	if err != nil {
		return 0, elapsed
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()
	return resp.StatusCode, elapsed
}

func percentile(lats []time.Duration, p float64) time.Duration {
	if len(lats) == 0 {
		return 0
	}
	idx := int(float64(len(lats)) * p)
	if idx >= len(lats) {
		idx = len(lats) - 1
	}
	return lats[idx]
}

func avgDur(lats []time.Duration) time.Duration {
	if len(lats) == 0 {
		return 0
	}
	var sum time.Duration
	for _, l := range lats {
		sum += l
	}
	return sum / time.Duration(len(lats))
}

type scenario struct {
	label  string
	method string
	path   string
	body   []byte
}

func runScenario(base string, sc scenario, conns, reps int) {
	total := conns * reps
	fmt.Printf("\n  ┌─ %s  (%d×%d = %d reqs)\n", sc.label, conns, reps, total)

	var mu sync.Mutex
	var wg sync.WaitGroup
	lats := make([]time.Duration, 0, total)
	ok := 0

	t0 := time.Now()
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, lat := doRequest(base, sc.method, sc.path, sc.body)
			mu.Lock()
			defer mu.Unlock()
			lats = append(lats, lat)
			if status == 200 {
				ok++
			}
		}()
	}
	wg.Wait()
	wall := time.Since(t0)

	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })

	tps := float64(ok) / wall.Seconds()
	p50 := percentile(lats, 0.50)
	p95 := percentile(lats, 0.95)
	p99 := percentile(lats, 0.99)
	maxLat := time.Duration(0)
	if len(lats) > 0 {
		maxLat = lats[len(lats)-1]
	}

	failed := total - ok
	reqStr := fmt.Sprintf("%d/%d OK", ok, total)
	if failed > 0 {
		reqStr += fmt.Sprintf("  ⚠ %d failed", failed)
	}

	fmt.Printf("  │  Requests : %s\n", reqStr)
	fmt.Printf("  │  TPS      : %.1f req/s\n", tps)
	fmt.Printf("  │  Latency  : avg=%v  p50=%v  p95=%v  p99=%v  max=%v\n",
		avgDur(lats).Round(time.Millisecond),
		p50.Round(time.Millisecond),
		p95.Round(time.Millisecond),
		p99.Round(time.Millisecond),
		maxLat.Round(time.Millisecond))
	fmt.Printf("  └%s\n", strings.Repeat("─", 56))
}

func main() {
	port  := flag.Int("port",  4433, "Server port")
	conns := flag.Int("conns", 8,    "Concurrent goroutines per round")
	reps  := flag.Int("reps",  3,    "Repetitions per scenario")
	flag.Parse()

	base := fmt.Sprintf("https://127.0.0.1:%d", *port)

	body1MB := make([]byte, 1048576)
	for i := range body1MB {
		body1MB[i] = 'x'
	}

	fmt.Printf("\n%s\n", strings.Repeat("═", 56))
	fmt.Printf("  quic.cr HTTP/3 concurrent benchmark\n")
	fmt.Printf("  Port %d  │  %d concurrent conns  │  %d reps each\n", *port, *conns, *reps)
	fmt.Printf("%s\n", strings.Repeat("═", 56))

	fmt.Print("  Warming up…")
	status, _ := doRequest(base, "GET", "/", nil)
	if status == 0 {
		fmt.Fprintf(os.Stderr, "\nServer not reachable at %s — start it first\n", base)
		os.Exit(1)
	}
	fmt.Println(" done")

	scenarios := []scenario{
		{"GET  /          ", "GET",  "/",     nil},
		{"POST /echo  20B ", "POST", "/echo", []byte(`{"msg":"hello"}`)},
		{"POST /echo  1MB ", "POST", "/echo", body1MB},
	}

	for _, sc := range scenarios {
		runScenario(base, sc, *conns, *reps)
	}
	fmt.Println()
}
