// QPACK static vs dynamic benchmark for quic.cr
// Replaces examples/bench_qpack.py
//
// Compares header compression efficiency and latency between a Crystal server
// compiled with QPACK dynamic table disabled (static, cap=0) vs enabled (dynamic, cap=4096).
//
// Usage:
//   go build -o bench_qpack .
//   ./bench_qpack [-static /tmp/h3testsrv_static] [-dynamic /tmp/h3testsrv_dynamic]
//
// Build server binaries:
//   crystal build examples/h3_server_routed.cr -o /tmp/h3testsrv_static  # with cap=0
//   crystal build examples/h3_server_routed.cr -o /tmp/h3testsrv_dynamic  # with cap=4096
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
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// ── transport ────────────────────────────────────────────────────────────────

func newTransport() *http3.Transport {
	return &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		QUICConfig:      &quic.Config{},
	}
}

// ── request helpers ──────────────────────────────────────────────────────────

func doReq(client *http.Client, method, url string, body []byte) (int, time.Duration, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return 0, 0, err
	}
	if body != nil {
		req.Header.Set("content-type", "application/json")
		req.ContentLength = int64(len(body))
	}
	t0 := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(t0)
	if err != nil {
		return 0, elapsed, err
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()
	return resp.StatusCode, elapsed, nil
}

// ── stats ────────────────────────────────────────────────────────────────────

func pct(lats []time.Duration, p float64) time.Duration {
	if len(lats) == 0 {
		return 0
	}
	idx := int(float64(len(lats)) * p)
	if idx >= len(lats) {
		idx = len(lats) - 1
	}
	return lats[idx]
}

func mean(lats []time.Duration) time.Duration {
	if len(lats) == 0 {
		return 0
	}
	var sum time.Duration
	for _, l := range lats {
		sum += l
	}
	return sum / time.Duration(len(lats))
}

type benchResult struct {
	n    int
	mean time.Duration
	p50  time.Duration
	p95  time.Duration
	p99  time.Duration
	rps  float64
}

// ── scenario ─────────────────────────────────────────────────────────────────

type scenario struct {
	label  string
	method string
	url    string
	body   []byte
}

// runBatch sends `batchN` requests serially over ONE http3 transport (one QUIC conn)
// and returns the latencies.
func runBatch(base string, sc scenario, batchN int) []time.Duration {
	tr := newTransport()
	defer tr.Close()
	client := &http.Client{Transport: tr}

	lats := make([]time.Duration, 0, batchN)
	for i := 0; i < batchN; i++ {
		_, elapsed, err := doReq(client, sc.method, base+sc.url, sc.body)
		if err == nil {
			lats = append(lats, elapsed)
		}
	}
	return lats
}

func benchScenario(base string, sc scenario, n, warmup, batch int) benchResult {
	// Warmup (discarded)
	wn := warmup
	if wn > batch {
		wn = batch
	}
	runBatch(base, sc, wn)

	// Collect n latencies in ceil(n/batch) connections
	all := make([]time.Duration, 0, n)
	remaining := n
	for remaining > 0 {
		b := batch
		if b > remaining {
			b = remaining
		}
		lats := runBatch(base, sc, b)
		all = append(all, lats...)
		remaining -= b
	}

	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	m := mean(all)
	rps := 0.0
	if m > 0 {
		rps = float64(time.Second) / float64(m)
	}
	return benchResult{
		n:    len(all),
		mean: m,
		p50:  pct(all, 0.50),
		p95:  pct(all, 0.95),
		p99:  pct(all, 0.99),
		rps:  rps,
	}
}

// ── server management ────────────────────────────────────────────────────────

func startServer(binary, host string, port int) (*exec.Cmd, error) {
	cmd := exec.Command(binary)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// Wait for server to be ready
	time.Sleep(2 * time.Second)
	return cmd, nil
}

func stopServer(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		cmd.Process.Kill() //nolint:errcheck
		cmd.Wait()         //nolint:errcheck
	}
	time.Sleep(300 * time.Millisecond)
}

// ── benchmarking one binary ──────────────────────────────────────────────────

func benchBinary(binary, label, host string, port, n, warmup, batch int, scenarios []scenario) (map[string]benchResult, bool) {
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		fmt.Printf("  SKIP: binary not found: %s\n", binary)
		fmt.Printf("  Build with: crystal build examples/h3_server_routed.cr -o %s\n\n", binary)
		return nil, false
	}

	fmt.Printf("\n  [%s]  %s\n", label, binary)
	cmd, err := startServer(binary, host, port)
	if err != nil {
		fmt.Printf("  ERROR starting server: %v\n", err)
		return nil, false
	}
	defer stopServer(cmd)

	base := fmt.Sprintf("https://%s:%d", host, port)
	results := make(map[string]benchResult)

	for _, sc := range scenarios {
		fmt.Printf("    %-17s ... ", sc.label)
		r := benchScenario(base, sc, n, warmup, batch)
		results[sc.label] = r
		fmt.Printf("p50=%v  p95=%v  %.0f rps\n",
			r.p50.Round(10*time.Microsecond),
			r.p95.Round(10*time.Microsecond),
			r.rps)
	}

	return results, true
}

// ── output table ─────────────────────────────────────────────────────────────

func printTable(allResults map[string]map[string]benchResult, labels []string, scenarios []scenario) {
	fmt.Println()
	fmt.Printf("  %-17s  %-24s  %8s  %8s  %8s  %8s  %7s\n",
		"Scenario", "Mode", "mean", "p50", "p95", "p99", "rps")
	fmt.Printf("  %s\n", strings.Repeat("─", 88))

	for _, sc := range scenarios {
		var refP50 time.Duration
		first := true
		for _, label := range labels {
			res, ok := allResults[label]
			if !ok {
				continue
			}
			r, ok := res[sc.label]
			if !ok {
				continue
			}

			pctStr := ""
			if first {
				refP50 = r.p50
				first = false
			} else if refP50 > 0 {
				delta := float64(r.p50-refP50) / float64(refP50) * 100
				pctStr = fmt.Sprintf("  (%+.1f%%)", delta)
			}

			scLabel := sc.label
			if !first || label != labels[0] {
				scLabel = strings.Repeat(" ", 17)
			}
			// Reset scLabel: show scenario only for first label
			if label == labels[0] {
				scLabel = sc.label
			} else {
				scLabel = strings.Repeat(" ", 17)
			}

			fmt.Printf("  %-17s  %-24s  %7v  %7v  %7v  %7v  %6.0f/s%s\n",
				scLabel, label,
				r.mean.Round(10*time.Microsecond),
				r.p50.Round(10*time.Microsecond),
				r.p95.Round(10*time.Microsecond),
				r.p99.Round(10*time.Microsecond),
				r.rps,
				pctStr)
		}
		fmt.Println()
	}
}

// ── main ─────────────────────────────────────────────────────────────────────

func main() {
	staticBin  := flag.String("static",  "/tmp/h3testsrv_static",  "Crystal binary with static QPACK (cap=0)")
	dynamicBin := flag.String("dynamic", "/tmp/h3testsrv_dynamic", "Crystal binary with dynamic QPACK (cap=4096)")
	n          := flag.Int("n",      300, "Requests per scenario")
	batch      := flag.Int("batch",  80,  "Requests per connection (<128)")
	warmup     := flag.Int("warmup", 20,  "Warmup requests (discarded)")
	host       := flag.String("host", "127.0.0.1", "Server host")
	port       := flag.Int("port",   4433, "Server port")
	flag.Parse()

	echoBody := append([]byte(`{"d":"`), append(bytes.Repeat([]byte("x"), 1000), []byte(`"}`)...)...)

	scenarios := []scenario{
		{"GET /",           "GET",  "/",               nil},
		{"GET /greet",      "GET",  "/greet?name=World", nil},
		{"GET /users/42",   "GET",  "/users/42",       nil},
		{"POST /echo 1KB",  "POST", "/echo",           echoBody},
	}

	fmt.Printf("\nBenchmark QPACK static vs dynamic\n")
	fmt.Printf("  N=%d req/scenario  warmup=%d  batch=%d  host=%s:%d\n\n",
		*n, *warmup, *batch, *host, *port)

	configs := []struct {
		label  string
		binary string
	}{
		{"STATIC  (cap=0)", *staticBin},
		{"DYNAMIC (cap=4096)", *dynamicBin},
	}

	allResults := make(map[string]map[string]benchResult)
	labels := make([]string, 0)

	for _, cfg := range configs {
		res, ok := benchBinary(cfg.binary, cfg.label, *host, *port, *n, *warmup, *batch, scenarios)
		if ok {
			allResults[cfg.label] = res
			labels = append(labels, cfg.label)
		}
	}

	if len(allResults) == 0 {
		fmt.Fprintln(os.Stderr, "\nNo results — check that binaries exist.")
		os.Exit(1)
	}

	printTable(allResults, labels, scenarios)
}
