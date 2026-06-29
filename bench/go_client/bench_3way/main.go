// 3-way HTTP/3 benchmark: Crystal quic.cr vs Go quic-go, multiple scenarios.
// Replaces bench/bench.py
//
// Starts an inline quic-go server on -go-port, runs scenarios against
// Crystal (:crystal-port) and Go side-by-side.
//
// Usage:
//   go build -o bench_3way .
//   ./bench_3way [-crystal-port 4433] [-go-port 4444] [-n 50] [-c 5] [-warmup 5]
//
// Crystal server must be running:
//   crystal build examples/e2e_server.cr -o /tmp/e2e_server --release && /tmp/e2e_server
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// ── self-signed cert ─────────────────────────────────────────────────────────

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "bench-3way"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// ── inline Go server ─────────────────────────────────────────────────────────

func startGoServer(port int) (*http3.Server, error) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("content-type", "application/json")
		w.Write([]byte(`{"message":"Welcome to quic.cr","version":"1.0"}`)) //nolint:errcheck
	})

	mux.HandleFunc("/greet", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			name = "World"
		}
		w.Header().Set("content-type", "application/json")
		resp, _ := json.Marshal(map[string]string{"message": "Hello, " + name + "!"})
		w.Write(resp) //nolint:errcheck
	})

	mux.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/users/")
		w.Header().Set("content-type", "application/json")
		resp, _ := json.Marshal(map[string]string{"id": id, "name": "User " + id})
		w.Write(resp) //nolint:errcheck
	})

	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("content-type", "application/octet-stream")
		w.Write(body) //nolint:errcheck
	})

	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/plain")
		w.Write([]byte("pong")) //nolint:errcheck
	})

	srv := &http3.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h3"},
		},
		QUICConfig: &quic.Config{},
	}

	go srv.ListenAndServe() //nolint:errcheck
	time.Sleep(200 * time.Millisecond)
	return srv, nil
}

// ── transport ────────────────────────────────────────────────────────────────

func newTransport() *http3.Transport {
	return &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		QUICConfig:      &quic.Config{},
	}
}

// ── request ──────────────────────────────────────────────────────────────────

func doRequest(base, method, path string, body []byte) (int, time.Duration) {
	tr := newTransport()
	defer tr.Close()
	client := &http.Client{Transport: tr}

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, base+path, bodyReader)
	if err != nil {
		return 0, 0
	}
	if body != nil {
		req.Header.Set("content-type", "application/json")
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

func meanDur(lats []time.Duration) time.Duration {
	if len(lats) == 0 {
		return 0
	}
	var sum time.Duration
	for _, l := range lats {
		sum += l
	}
	return sum / time.Duration(len(lats))
}

type stats struct {
	n      int
	mean   time.Duration
	p50    time.Duration
	p95    time.Duration
	p99    time.Duration
	rps    float64
}

func computeStats(lats []time.Duration) stats {
	if len(lats) == 0 {
		return stats{}
	}
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	m := meanDur(lats)
	rps := 0.0
	if m > 0 {
		rps = float64(time.Second) / float64(m)
	}
	return stats{
		n:    len(lats),
		mean: m,
		p50:  pct(lats, 0.50),
		p95:  pct(lats, 0.95),
		p99:  pct(lats, 0.99),
		rps:  rps,
	}
}

// ── scenario runner ───────────────────────────────────────────────────────────

type scenario struct {
	label  string
	method string
	path   string
	body   []byte
}

func runScenario(base string, sc scenario, n, c int) stats {
	lats := make([]time.Duration, 0, n)
	var mu sync.Mutex
	sem := make(chan struct{}, c)
	var wg sync.WaitGroup

	for i := 0; i < n; i++ {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			status, lat := doRequest(base, sc.method, sc.path, sc.body)
			if status == 200 {
				mu.Lock()
				lats = append(lats, lat)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return computeStats(lats)
}

// ── output ───────────────────────────────────────────────────────────────────

func dur(d time.Duration) string {
	return d.Round(10 * time.Microsecond).String()
}

func printScenario(label string, cr, go_ stats) {
	fmt.Printf("\n━━ %s ━━\n", label)
	fmt.Printf("  %-14s  %-16s  %s\n", "Metric", "Crystal H3", "Go H3")
	fmt.Printf("  %s\n", strings.Repeat("─", 46))
	row := func(metric, cv, gv string) {
		fmt.Printf("  %-14s  %-16s  %s\n", metric, cv, gv)
	}
	row("Mean", dur(cr.mean), dur(go_.mean))
	row("Median p50", dur(cr.p50), dur(go_.p50))
	row("p95", dur(cr.p95), dur(go_.p95))
	row("p99", dur(cr.p99), dur(go_.p99))
	row("Req/s", fmt.Sprintf("%.1f", cr.rps), fmt.Sprintf("%.1f", go_.rps))
	row("Samples", fmt.Sprintf("%d", cr.n), fmt.Sprintf("%d", go_.n))
}

type winner struct {
	label    string
	crP50    time.Duration
	goP50    time.Duration
	winCryst bool
}

func printSummary(wins []winner) {
	fmt.Printf("\n%s\n", strings.Repeat("═", 72))
	fmt.Printf("  Summary — median latency (p50) per scenario\n")
	fmt.Printf("%s\n", strings.Repeat("═", 72))
	fmt.Printf("\n  %-28s  %12s  %10s  %s\n", "Scenario", "Crystal H3", "Go H3", "Winner")
	fmt.Printf("  %s\n", strings.Repeat("─", 68))

	crWins, goWins := 0, 0
	for _, w := range wins {
		winnerName := "Go H3"
		if w.winCryst {
			winnerName = "Crystal H3"
			crWins++
		} else {
			goWins++
		}
		fmt.Printf("  %-28s  %10s  %8s  %s\n",
			w.label, dur(w.crP50), dur(w.goP50), winnerName)
	}
	total := len(wins)
	fmt.Printf("\n  Wins (by p50): Crystal H3 %d/%d  |  Go H3 %d/%d\n",
		crWins, total, goWins, total)
}

// ── main ─────────────────────────────────────────────────────────────────────

func main() {
	crystalPort := flag.Int("crystal-port", 4433, "Crystal quic.cr server port")
	goPort      := flag.Int("go-port",      4444, "Go quic-go server port (started inline)")
	n           := flag.Int("n",    50, "Requests per scenario")
	c           := flag.Int("c",    5,  "Concurrency")
	warmup      := flag.Int("warmup", 5, "Warmup requests per server")
	flag.Parse()

	// Build scenario bodies
	body1KB := append([]byte(`{"k":"`), append(bytes.Repeat([]byte("v"), 512), []byte(`"}`)...)...)
	body64KB := make([]byte, 65536)
	for i := range body64KB {
		body64KB[i] = 'x'
	}

	scenarios := []scenario{
		{"GET /",              "GET",  "/",                nil},
		{"GET /greet",         "GET",  "/greet?name=Bench", nil},
		{"GET /users/42",      "GET",  "/users/42",        nil},
		{"POST /echo 1KB",     "POST", "/echo",            body1KB},
		{"POST /echo 64KB",    "POST", "/echo",            body64KB},
	}

	// Start inline Go server
	fmt.Printf("Starting inline Go HTTP/3 server on :%d…\n", *goPort)
	goSrv, err := startGoServer(*goPort)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start Go server: %v\n", err)
		os.Exit(1)
	}
	defer goSrv.Close()

	crystalBase := fmt.Sprintf("https://127.0.0.1:%d", *crystalPort)
	goBase      := fmt.Sprintf("https://127.0.0.1:%d", *goPort)

	// Verify Crystal server
	{
		tr := newTransport()
		c2 := &http.Client{Transport: tr}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "GET", crystalBase+"/ping", nil)
		resp, err := c2.Do(req)
		tr.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Crystal server not reachable on :%d: %v\n", *crystalPort, err)
			fmt.Fprintln(os.Stderr, "Start it first: crystal build examples/e2e_server.cr -o /tmp/e2e_server --release && /tmp/e2e_server")
			os.Exit(1)
		}
		resp.Body.Close()
	}

	fmt.Printf("\n%s\n", strings.Repeat("═", 72))
	fmt.Printf("  3-Way HTTP/3 Benchmark: Crystal quic.cr vs Go quic-go\n")
	fmt.Printf("  n=%d  concurrency=%d  warmup=%d\n", *n, *c, *warmup)
	fmt.Printf("%s\n", strings.Repeat("═", 72))

	// Warmup
	fmt.Print("\n  Warming up Crystal… ")
	for i := 0; i < *warmup; i++ {
		doRequest(crystalBase, "GET", "/ping", nil)
	}
	fmt.Print("done  |  Go… ")
	for i := 0; i < *warmup; i++ {
		doRequest(goBase, "GET", "/ping", nil)
	}
	fmt.Println("done")

	var summaryWins []winner

	for _, sc := range scenarios {
		fmt.Printf("\n  Running Crystal: %s… ", sc.label)
		crStats := runScenario(crystalBase, sc, *n, *c)
		fmt.Printf("done  |  Go… ")
		goStats := runScenario(goBase, sc, *n, *c)
		fmt.Printf("done")

		printScenario(sc.label, crStats, goStats)

		summaryWins = append(summaryWins, winner{
			label:    sc.label,
			crP50:    crStats.p50,
			goP50:    goStats.p50,
			winCryst: crStats.p50 <= goStats.p50,
		})
	}

	printSummary(summaryWins)
	fmt.Println()
}
