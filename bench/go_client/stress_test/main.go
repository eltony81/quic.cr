// Heavy stress test: Crystal quic.cr vs Go quic-go
//
// Runs 6 phases:
//   1. Connection Flood  — many simultaneous new QUIC connections
//   2. Sustained RPS     — peak throughput on one shared connection
//   3. Throughput        — 100 KB download stress
//   4. Connection Churn  — timed new-connection-per-request
//   5. Mixed Load        — random small/large/POST mix
//   6. Long-Lived        — stream cleanup correctness (N×10000 reqs)
//
// Usage:
//   go build -o stress_test .
//   /tmp/e2e_server &
//   ./stress_test
//   ./stress_test -duration 60 -conns 500

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// ── TLS / server helpers ──────────────────────────────────────────────────────

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "go-stress-bench"},
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

func startGoServer(port int, payload100k []byte) (*http3.Server, error) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/plain")
		w.Write([]byte("pong")) //nolint:errcheck
	})
	mux.HandleFunc("/100k", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/octet-stream")
		w.Write(payload100k) //nolint:errcheck
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/octet-stream")
		io.Copy(w, r.Body) //nolint:errcheck
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.Write([]byte(`{"message":"Welcome to quic.cr","version":"1.0"}`)) //nolint:errcheck
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
	time.Sleep(300 * time.Millisecond)
	return srv, nil
}

func newTransport() *http3.Transport {
	return &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		QUICConfig:      &quic.Config{},
	}
}

// ── Metrics ───────────────────────────────────────────────────────────────────

type metrics struct {
	mu      sync.Mutex
	lats    []time.Duration
	errors  int64
	total   int64
	bytes_  int64
}

func (m *metrics) record(lat time.Duration, nb int64) {
	m.mu.Lock()
	m.lats = append(m.lats, lat)
	m.bytes_ += nb
	m.mu.Unlock()
	atomic.AddInt64(&m.total, 1)
}

func (m *metrics) fail() {
	atomic.AddInt64(&m.errors, 1)
	atomic.AddInt64(&m.total, 1)
}

func (m *metrics) sorted() []time.Duration {
	m.mu.Lock()
	cp := make([]time.Duration, len(m.lats))
	copy(cp, m.lats)
	m.mu.Unlock()
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	return cp
}

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

func avg(lats []time.Duration) time.Duration {
	if len(lats) == 0 {
		return 0
	}
	var s time.Duration
	for _, l := range lats {
		s += l
	}
	return s / time.Duration(len(lats))
}

func fmtDur(d time.Duration) string {
	if d == 0 {
		return "—"
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%.0fµs", float64(d)/float64(time.Microsecond))
	}
	return fmt.Sprintf("%.2fms", float64(d)/float64(time.Millisecond))
}

// ── Phase result ─────────────────────────────────────────────────────────────

type phaseResult struct {
	name    string
	ok      int64
	total   int64
	errors  int64
	elapsed time.Duration
	lats    []time.Duration // sorted
	bytes_  int64
	// derived
	rps    float64
	mbps   float64
	p50    time.Duration
	p95    time.Duration
	p99    time.Duration
	p999   time.Duration
	maxLat time.Duration
	avgLat time.Duration
}

func finalize(name string, m *metrics, elapsed time.Duration) phaseResult {
	lats := m.sorted()
	ok := atomic.LoadInt64(&m.total) - atomic.LoadInt64(&m.errors)
	var p999 time.Duration
	if len(lats) >= 1000 {
		p999 = pct(lats, 0.999)
	}
	var maxLat time.Duration
	if len(lats) > 0 {
		maxLat = lats[len(lats)-1]
	}
	rps := 0.0
	if elapsed > 0 {
		rps = float64(ok) / elapsed.Seconds()
	}
	mb := 0.0
	if elapsed > 0 {
		m.mu.Lock()
		b := m.bytes_
		m.mu.Unlock()
		mb = float64(b) / elapsed.Seconds() / 1e6
	}
	return phaseResult{
		name:    name,
		ok:      ok,
		total:   atomic.LoadInt64(&m.total),
		errors:  atomic.LoadInt64(&m.errors),
		elapsed: elapsed,
		lats:    lats,
		rps:     rps,
		mbps:    mb,
		p50:     pct(lats, 0.50),
		p95:     pct(lats, 0.95),
		p99:     pct(lats, 0.99),
		p999:    p999,
		maxLat:  maxLat,
		avgLat:  avg(lats),
	}
}

// ── Phase 1: Connection Flood ─────────────────────────────────────────────────

func phaseFlood(base string, conns int) phaseResult {
	m := &metrics{}
	var wg sync.WaitGroup
	start := time.Now()

	// All goroutines start together
	ready := make(chan struct{})
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ready // wait for simultaneous start
			tr := newTransport()
			defer tr.Close()
			c := &http.Client{Transport: tr}
			t0 := time.Now()
			resp, err := c.Get(base + "/ping")
			if err != nil {
				m.fail()
				return
			}
			nb, _ := io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			m.record(time.Since(t0), nb)
		}()
	}
	close(ready)
	wg.Wait()
	return finalize("Connection Flood", m, time.Since(start))
}

// ── Phase 2: Sustained RPS ────────────────────────────────────────────────────

func phaseRPS(base string, conns int, duration time.Duration, tr *http3.Transport) phaseResult {
	m := &metrics{}
	deadline := time.Now().Add(duration)
	var wg sync.WaitGroup
	c := &http.Client{Transport: tr}

	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				t0 := time.Now()
				resp, err := c.Get(base + "/ping")
				if err != nil {
					m.fail()
					continue
				}
				nb, _ := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				m.record(time.Since(t0), nb)
			}
		}()
	}

	t0 := time.Now()
	wg.Wait()
	return finalize("Sustained RPS", m, time.Since(t0))
}

// ── Phase 3: Throughput ───────────────────────────────────────────────────────

func phaseThroughput(base string, conns int, reqsPerConn int) phaseResult {
	m := &metrics{}
	workers := conns / 4
	if workers < 10 {
		workers = 10
	}
	var wg sync.WaitGroup

	t0 := time.Now()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr := newTransport()
			defer tr.Close()
			c := &http.Client{Transport: tr}
			for j := 0; j < reqsPerConn; j++ {
				ts := time.Now()
				resp, err := c.Get(base + "/100k")
				if err != nil {
					m.fail()
					continue
				}
				nb, _ := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				m.record(time.Since(ts), nb)
			}
		}()
	}
	wg.Wait()
	return finalize("Throughput", m, time.Since(t0))
}

// ── Phase 4: Connection Churn ─────────────────────────────────────────────────

func phaseChurn(base string, conns int, duration time.Duration) phaseResult {
	m := &metrics{}
	workers := conns / 2
	if workers < 1 {
		workers = 1
	}
	deadline := time.Now().Add(duration)
	var wg sync.WaitGroup

	t0 := time.Now()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				tr := newTransport()
				c := &http.Client{Transport: tr}
				ts := time.Now()
				resp, err := c.Get(base + "/ping")
				if err != nil {
					tr.Close()
					m.fail()
					continue
				}
				nb, _ := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				tr.Close()
				m.record(time.Since(ts), nb)
			}
		}()
	}
	wg.Wait()
	return finalize("Connection Churn", m, time.Since(t0))
}

// ── Phase 5: Mixed Load ───────────────────────────────────────────────────────

func phaseMixed(base string, conns int, duration time.Duration, body64k []byte, tr *http3.Transport) phaseResult {
	m := &metrics{}
	deadline := time.Now().Add(duration)
	c := &http.Client{Transport: tr}
	var wg sync.WaitGroup

	t0 := time.Now()
	for i := 0; i < conns; i++ {
		wg.Add(1)
		idx := i
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				pick := idx % 10 // deterministic rotation: 0-6=small, 7-8=post, 9=large
				var (
					ts   = time.Now()
					resp *http.Response
					err  error
				)
				switch {
				case pick <= 6: // 70% small GET
					resp, err = c.Get(base + "/ping")
				case pick <= 8: // 20% POST /echo 64KB
					resp, err = c.Post(base+"/echo", "application/octet-stream", bytes.NewReader(body64k))
				default: // 10% large GET
					resp, err = c.Get(base + "/100k")
				}
				idx++ // advance deterministic picker
				if err != nil {
					m.fail()
					continue
				}
				nb, _ := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				m.record(time.Since(ts), nb)
			}
		}()
	}
	wg.Wait()
	return finalize("Mixed Load", m, time.Since(t0))
}

// ── Phase 6: Long-Lived Connections ──────────────────────────────────────────

func phaseLongLived(base string, numConns int, reqsPerConn int) phaseResult {
	m := &metrics{}
	var wg sync.WaitGroup

	t0 := time.Now()
	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr := newTransport()
			defer tr.Close()
			c := &http.Client{Transport: tr}
			for j := 0; j < reqsPerConn; j++ {
				ts := time.Now()
				resp, err := c.Get(base + "/ping")
				if err != nil {
					m.fail()
					continue
				}
				nb, _ := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				m.record(time.Since(ts), nb)
			}
		}()
	}
	wg.Wait()
	return finalize("Long-Lived", m, time.Since(t0))
}

// ── Display helpers ───────────────────────────────────────────────────────────

const (
	bold   = "\033[1m"
	reset  = "\033[0m"
	green  = "\033[32m"
	yellow = "\033[33m"
	red    = "\033[31m"
	cyan   = "\033[36m"
)

func printPhaseHeader(title string, extra string) {
	line := strings.Repeat("━", 66)
	fmt.Printf("\n%s%s%s\n", bold, line, reset)
	if extra != "" {
		fmt.Printf("%s  %s  (%s)%s\n", bold, title, extra, reset)
	} else {
		fmt.Printf("%s  %s%s\n", bold, title, reset)
	}
	fmt.Printf("%s%s%s\n", bold, line, reset)
}

func printPhaseRow(metric, cv, gv string, prefer string) {
	// prefer: "lower" or "higher"
	fmt.Printf("  %-30s  %-18s  %s\n", metric, cv, gv)
}

func colorWinner(v, other float64, higher bool) string {
	if v == 0 && other == 0 {
		return ""
	}
	if higher {
		if v > other {
			return green
		}
		return ""
	}
	if v < other {
		return green
	}
	return ""
}

func printPhaseComparison(cr, go_ phaseResult) {
	header := fmt.Sprintf("%-30s  %-18s  %s", "Metric", "Crystal quic.cr", "Go quic-go")
	fmt.Printf("  %s%s%s\n", bold, header, reset)
	fmt.Printf("  %s\n", strings.Repeat("─", 66))

	okCr := fmt.Sprintf("%d/%d (%.0f%%)", cr.ok, cr.total, 100*float64(cr.ok)/maxf(float64(cr.total), 1))
	okGo := fmt.Sprintf("%d/%d (%.0f%%)", go_.ok, go_.total, 100*float64(go_.ok)/maxf(float64(go_.total), 1))
	fmt.Printf("  %-30s  %-18s  %s\n", "Success rate", okCr, okGo)

	if cr.avgLat > 0 || go_.avgLat > 0 {
		cColor := colorWinner(float64(cr.avgLat), float64(go_.avgLat), false)
		gColor := colorWinner(float64(go_.avgLat), float64(cr.avgLat), false)
		fmt.Printf("  %-30s  %s%-18s%s  %s%s%s\n", "Avg latency",
			cColor, fmtDur(cr.avgLat), reset,
			gColor, fmtDur(go_.avgLat), reset)
		fmt.Printf("  %-30s  %-18s  %s\n", "p50", fmtDur(cr.p50), fmtDur(go_.p50))
		fmt.Printf("  %-30s  %-18s  %s\n", "p95", fmtDur(cr.p95), fmtDur(go_.p95))
		fmt.Printf("  %-30s  %-18s  %s\n", "p99", fmtDur(cr.p99), fmtDur(go_.p99))
		if cr.p999 > 0 || go_.p999 > 0 {
			fmt.Printf("  %-30s  %-18s  %s\n", "p999", fmtDur(cr.p999), fmtDur(go_.p999))
		}
		fmt.Printf("  %-30s  %-18s  %s\n", "max", fmtDur(cr.maxLat), fmtDur(go_.maxLat))
	}

	if cr.rps > 0 || go_.rps > 0 {
		cColor := colorWinner(cr.rps, go_.rps, true)
		gColor := colorWinner(go_.rps, cr.rps, true)
		fmt.Printf("  %-30s  %s%-18s%s  %s%s%s\n", "RPS",
			cColor, fmt.Sprintf("%.0f", cr.rps), reset,
			gColor, fmt.Sprintf("%.0f", go_.rps), reset)
	}

	if cr.mbps > 0 || go_.mbps > 0 {
		cColor := colorWinner(cr.mbps, go_.mbps, true)
		gColor := colorWinner(go_.mbps, cr.mbps, true)
		fmt.Printf("  %-30s  %s%-18s%s  %s%s%s\n", "Throughput (MB/s)",
			cColor, fmt.Sprintf("%.1f", cr.mbps), reset,
			gColor, fmt.Sprintf("%.1f", go_.mbps), reset)
	}

	if cr.rps > 0 && go_.rps > 0 {
		ratio := cr.rps / go_.rps
		winner := "Go"
		pct := (1/ratio - 1) * 100
		if ratio > 1 {
			winner = "Crystal"
			pct = (ratio - 1) * 100
		}
		fmt.Printf("  %-30s  %s+%.0f%% winner%s\n", "→ RPS winner: "+winner, cyan, pct, reset)
	}

	errRate := float64(cr.errors) / maxf(float64(cr.total), 1) * 100
	if errRate > 20 {
		fmt.Printf("  %s⚠ High Crystal error rate: %.0f%%%s\n", yellow, errRate, reset)
	}
	errRate = float64(go_.errors) / maxf(float64(go_.total), 1) * 100
	if errRate > 20 {
		fmt.Printf("  %s⚠ High Go error rate: %.0f%%%s\n", yellow, errRate, reset)
	}
}

func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// ── Summary table ─────────────────────────────────────────────────────────────

type summaryRow struct {
	phase     string
	crMetric  float64 // primary metric
	goMetric  float64
	unit      string
	higher    bool // true if higher is better
}

func printSummary(rows []summaryRow) {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║       HTTP/3 Stress Test: Crystal quic.cr vs Go quic-go         ║")
	fmt.Println("╠═══════════════════════════════╦═══════════════╦═════════════════╣")
	fmt.Printf("║  %-29s║  %-13s║  %-15s║\n", "Phase", "Crystal", "Go")
	fmt.Println("╠═══════════════════════════════╬═══════════════╬═════════════════╣")

	crystalWins := 0
	for _, r := range rows {
		crWins := (r.higher && r.crMetric > r.goMetric) || (!r.higher && r.crMetric < r.goMetric)
		goWins := !crWins && r.crMetric != r.goMetric

		crStr := formatMetric(r.crMetric, r.unit)
		goStr := formatMetric(r.goMetric, r.unit)

		winner := "—"
		if crWins {
			winner = "Crystal ✓"
			crystalWins++
		} else if goWins {
			winner = "Go ✓"
		}

		fmt.Printf("║  %-29s║  %-13s║  %-15s║\n",
			r.phase,
			crStr,
			goStr)
		_ = winner
	}

	fmt.Println("╠═══════════════════════════════╩═══════════════╩═════════════════╣")
	total := len(rows)
	goWins := total - crystalWins
	fmt.Printf("║  Overall: Crystal %d/%d  Go %d/%d%s║\n",
		crystalWins, total, goWins, total,
		strings.Repeat(" ", 66-len(fmt.Sprintf("  Overall: Crystal %d/%d  Go %d/%d", crystalWins, total, goWins, total))-2))
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
}

func formatMetric(v float64, unit string) string {
	switch unit {
	case "rps":
		return fmt.Sprintf("%.0f req/s", v)
	case "mb":
		return fmt.Sprintf("%.1f MB/s", v)
	case "ms":
		return fmt.Sprintf("%.2fms", v)
	case "conn/s":
		return fmt.Sprintf("%.0f conn/s", v)
	default:
		return fmt.Sprintf("%.2f", v)
	}
}

// ── Check if a port is listening ──────────────────────────────────────────────

func portListening(port int) bool {
	conn, err := net.DialTimeout("udp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
	if err == nil {
		conn.Close()
		return true
	}
	// For UDP we check by making a quick HTTP/3 request
	tr := newTransport()
	defer tr.Close()
	c := &http.Client{Transport: tr}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://127.0.0.1:%d/ping", port), nil)
	resp, err := c.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

// ── warmup ────────────────────────────────────────────────────────────────────

func warmup(c *http.Client, base string, n int) {
	for i := 0; i < n; i++ {
		resp, err := c.Get(base + "/ping")
		if err == nil {
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
		}
	}
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	crystalPort := flag.Int("crystal-port", 4433, "Crystal quic.cr server port")
	goPort      := flag.Int("go-port", 4444, "Go quic-go server port")
	duration    := flag.Int("duration", 30, "Seconds per time-bounded phase (2, 4, 5)")
	conns       := flag.Int("conns", 200, "Max concurrent goroutines")
	noCrystal   := flag.Bool("no-crystal", false, "Skip Crystal server")
	noGo        := flag.Bool("no-go", false, "Skip Go server")
	phasesFlag  := flag.String("phases", "all", "Comma-separated phases: flood,rps,throughput,churn,mixed,longlived")
	autoStart   := flag.Bool("auto-start", true, "Auto-start Crystal server if not listening")
	flag.Parse()

	phaseDur := time.Duration(*duration) * time.Second

	activePhases := map[string]bool{}
	if *phasesFlag == "all" {
		for _, p := range []string{"flood", "rps", "throughput", "churn", "mixed", "longlived"} {
			activePhases[p] = true
		}
	} else {
		for _, p := range strings.Split(*phasesFlag, ",") {
			activePhases[strings.TrimSpace(p)] = true
		}
	}

	payload100k := make([]byte, 100*1024)
	for i := range payload100k {
		payload100k[i] = 'x'
	}
	body64k := bytes.Repeat([]byte("y"), 65536)

	crystalBase := fmt.Sprintf("https://127.0.0.1:%d", *crystalPort)
	goBase      := fmt.Sprintf("https://127.0.0.1:%d", *goPort)

	fmt.Printf("\n%s%s HTTP/3 Stress Test: Crystal quic.cr vs Go quic-go %s%s\n",
		bold, cyan, reset, reset)
	fmt.Printf("  conns=%d  duration=%ds per phase  phases=%s\n",
		*conns, *duration, *phasesFlag)
	fmt.Println()

	// ── Start servers ────────────────────────────────────────────────────────

	var crystalCmd *exec.Cmd

	if !*noCrystal {
		if *autoStart && !portListening(*crystalPort) {
			fmt.Printf("  Auto-starting Crystal server (/tmp/e2e_server)…\n")
			crystalCmd = exec.Command("/tmp/e2e_server")
			crystalCmd.Stdout = io.Discard
			crystalCmd.Stderr = io.Discard
			if err := crystalCmd.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ Failed to start Crystal server: %v\n", err)
				fmt.Fprintln(os.Stderr, "    Build with: crystal build examples/e2e_server.cr -o /tmp/e2e_server --release")
				os.Exit(1)
			}
			time.Sleep(2 * time.Second)
		}
		// Probe
		if !portListening(*crystalPort) {
			fmt.Fprintf(os.Stderr, "  ✗ Crystal server not reachable on :%d\n", *crystalPort)
			fmt.Fprintln(os.Stderr, "    Start it: crystal build examples/e2e_server.cr -o /tmp/e2e_server --release && /tmp/e2e_server")
			os.Exit(1)
		}
		fmt.Printf("  ✓ Crystal server  :%d\n", *crystalPort)
	}

	var goSrv *http3.Server
	if !*noGo {
		var err error
		fmt.Printf("  Starting inline Go server…\n")
		goSrv, err = startGoServer(*goPort, payload100k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ Failed to start Go server: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  ✓ Go server       :%d\n", *goPort)
	}

	// ── Shared transports (one per server, reused across phases that allow it) ──

	var crSharedTr, goSharedTr *http3.Transport
	if !*noCrystal {
		crSharedTr = newTransport()
		defer crSharedTr.Close()
		fmt.Print("  Warming up Crystal…")
		warmup(&http.Client{Transport: crSharedTr}, crystalBase, 50)
		fmt.Println(" done")
	}
	if !*noGo {
		goSharedTr = newTransport()
		defer goSharedTr.Close()
		fmt.Print("  Warming up Go…")
		warmup(&http.Client{Transport: goSharedTr}, goBase, 50)
		fmt.Println(" done")
	}

	// ── Run phases ────────────────────────────────────────────────────────────

	type pairResult struct {
		cr, go_ phaseResult
	}
	results := map[string]pairResult{}

	if activePhases["flood"] {
		printPhaseHeader("Phase 1: Connection Flood",
			fmt.Sprintf("%d simultaneous new QUIC connections", *conns))
		var crR, goR phaseResult
		if !*noCrystal {
			fmt.Println("  Testing Crystal quic.cr…")
			crR = phaseFlood(crystalBase, *conns)
		}
		if !*noGo {
			fmt.Println("  Testing Go quic-go…")
			goR = phaseFlood(goBase, *conns)
		}
		fmt.Println()
		printPhaseComparison(crR, goR)
		results["flood"] = pairResult{crR, goR}
	}

	if activePhases["rps"] {
		printPhaseHeader("Phase 2: Sustained RPS",
			fmt.Sprintf("%d concurrent goroutines × %ds", *conns, *duration))
		var crR, goR phaseResult
		if !*noCrystal {
			fmt.Printf("  Testing Crystal quic.cr (%ds)…\n", *duration)
			// New transport to avoid interference from warmup traffic
			crRpsTr := newTransport()
			warmup(&http.Client{Transport: crRpsTr}, crystalBase, 20)
			crR = phaseRPS(crystalBase, *conns, phaseDur, crRpsTr)
			crRpsTr.Close()
		}
		if !*noGo {
			fmt.Printf("  Testing Go quic-go (%ds)…\n", *duration)
			goRpsTr := newTransport()
			warmup(&http.Client{Transport: goRpsTr}, goBase, 20)
			goR = phaseRPS(goBase, *conns, phaseDur, goRpsTr)
			goRpsTr.Close()
		}
		fmt.Println()
		printPhaseComparison(crR, goR)
		results["rps"] = pairResult{crR, goR}
	}

	if activePhases["throughput"] {
		printPhaseHeader("Phase 3: Throughput Stress",
			fmt.Sprintf("%d workers × 10 reqs of GET /100k (100KB each)", *conns/4))
		var crR, goR phaseResult
		if !*noCrystal {
			fmt.Println("  Testing Crystal quic.cr…")
			crR = phaseThroughput(crystalBase, *conns, 10)
		}
		if !*noGo {
			fmt.Println("  Testing Go quic-go…")
			goR = phaseThroughput(goBase, *conns, 10)
		}
		fmt.Println()
		printPhaseComparison(crR, goR)
		results["throughput"] = pairResult{crR, goR}
	}

	if activePhases["churn"] {
		churnDur := phaseDur / 3
		if churnDur < 5*time.Second {
			churnDur = 5 * time.Second
		}
		printPhaseHeader("Phase 4: Connection Churn",
			fmt.Sprintf("%d workers, new connection per req, %ds", *conns/2, int(churnDur.Seconds())))
		var crR, goR phaseResult
		if !*noCrystal {
			fmt.Printf("  Testing Crystal quic.cr (%ds)…\n", int(churnDur.Seconds()))
			crR = phaseChurn(crystalBase, *conns, churnDur)
		}
		if !*noGo {
			fmt.Printf("  Testing Go quic-go (%ds)…\n", int(churnDur.Seconds()))
			goR = phaseChurn(goBase, *conns, churnDur)
		}
		fmt.Println()
		printPhaseComparison(crR, goR)
		results["churn"] = pairResult{crR, goR}
	}

	if activePhases["mixed"] {
		printPhaseHeader("Phase 5: Mixed Load",
			fmt.Sprintf("%d goroutines, 70%% GET /ping · 20%% POST 64KB · 10%% GET /100k, %ds",
				*conns, *duration))
		var crR, goR phaseResult
		if !*noCrystal {
			fmt.Printf("  Testing Crystal quic.cr (%ds)…\n", *duration)
			crMixTr := newTransport()
			warmup(&http.Client{Transport: crMixTr}, crystalBase, 10)
			crR = phaseMixed(crystalBase, *conns, phaseDur, body64k, crMixTr)
			crMixTr.Close()
		}
		if !*noGo {
			fmt.Printf("  Testing Go quic-go (%ds)…\n", *duration)
			goMixTr := newTransport()
			warmup(&http.Client{Transport: goMixTr}, goBase, 10)
			goR = phaseMixed(goBase, *conns, phaseDur, body64k, goMixTr)
			goMixTr.Close()
		}
		fmt.Println()
		printPhaseComparison(crR, goR)
		results["mixed"] = pairResult{crR, goR}
	}

	if activePhases["longlived"] {
		llConns := 10
		llReqs := 10000
		printPhaseHeader("Phase 6: Long-Lived Connections",
			fmt.Sprintf("%d connections × %d sequential GET /ping", llConns, llReqs))
		var crR, goR phaseResult
		if !*noCrystal {
			fmt.Printf("  Testing Crystal quic.cr (%d×%d)…\n", llConns, llReqs)
			crR = phaseLongLived(crystalBase, llConns, llReqs)
		}
		if !*noGo {
			fmt.Printf("  Testing Go quic-go (%d×%d)…\n", llConns, llReqs)
			goR = phaseLongLived(goBase, llConns, llReqs)
		}
		fmt.Println()
		printPhaseComparison(crR, goR)
		results["longlived"] = pairResult{crR, goR}
	}

	// ── Summary ───────────────────────────────────────────────────────────────

	var summaryRows []summaryRow
	phaseOrder := []struct {
		key   string
		label string
		unit  string
		field func(phaseResult) float64
		higher bool
	}{
		{"flood", "1. Connection Flood", "rps", func(r phaseResult) float64 { return r.rps }, true},
		{"rps", "2. Sustained RPS", "rps", func(r phaseResult) float64 { return r.rps }, true},
		{"throughput", "3. Throughput", "mb", func(r phaseResult) float64 { return r.mbps }, true},
		{"churn", "4. Conn Churn", "conn/s", func(r phaseResult) float64 { return r.rps }, true},
		{"mixed", "5. Mixed Load", "rps", func(r phaseResult) float64 { return r.rps }, true},
		{"longlived", "6. Long-Lived", "rps", func(r phaseResult) float64 { return r.rps }, true},
	}

	for _, po := range phaseOrder {
		if pr, ok := results[po.key]; ok {
			summaryRows = append(summaryRows, summaryRow{
				phase:    po.label,
				crMetric: po.field(pr.cr),
				goMetric: po.field(pr.go_),
				unit:     po.unit,
				higher:   po.higher,
			})
		}
	}

	if len(summaryRows) > 0 {
		printSummary(summaryRows)
	}

	// ── Cleanup ───────────────────────────────────────────────────────────────

	if goSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		goSrv.Shutdown(ctx) //nolint:errcheck
	}
	if crystalCmd != nil {
		crystalCmd.Process.Kill() //nolint:errcheck
	}
}
