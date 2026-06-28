// HTTP/3 throughput benchmark: Crystal quic.cr vs Go quic-go
//
// Crystal server must be running first:
//   crystal run examples/e2e_server.cr   (from repo root)
//
// Then run this benchmark:
//   cd bench/go_client/bench_h3
//   go run .
//   go run . -seq-n 1000 -conc-n 5000 -conc-c 100

package main

import (
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
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// ── Self-signed cert for the inline Go server ────────────────────────────────

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "go-quic-bench"},
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

// ── Inline Go HTTP/3 server ──────────────────────────────────────────────────

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

// ── HTTP/3 client transport ──────────────────────────────────────────────────

func newTransport() *http3.Transport {
	return &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		QUICConfig:      &quic.Config{},
	}
}

// ── Sequential latency benchmark ─────────────────────────────────────────────

func runSeq(client *http.Client, url string, n int) (lats []time.Duration, errCount int) {
	lats = make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		t0 := time.Now()
		resp, err := client.Get(url)
		if err != nil {
			errCount++
			continue
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
		lats = append(lats, time.Since(t0))
	}
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	return
}

// ── Concurrent RPS benchmark ─────────────────────────────────────────────────

func runConc(client *http.Client, url string, n, c int) (rps float64, p99 time.Duration, maxLat time.Duration, errCount int) {
	lats := make([]time.Duration, 0, n)
	var mu sync.Mutex
	var errs int32

	sem := make(chan struct{}, c)
	var wg sync.WaitGroup
	t0 := time.Now()

	for i := 0; i < n; i++ {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			ts := time.Now()
			resp, err := client.Get(url)
			if err != nil {
				atomic.AddInt32(&errs, 1)
				return
			}
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
			lat := time.Since(ts)
			mu.Lock()
			lats = append(lats, lat)
			mu.Unlock()
		}()
	}
	wg.Wait()
	elapsed := time.Since(t0)

	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	if len(lats) > 0 {
		p99 = lats[int(float64(len(lats))*0.99)]
		maxLat = lats[len(lats)-1]
	}
	rps = float64(len(lats)) / elapsed.Seconds()
	errCount = int(errs)
	return
}

// ── Throughput benchmark ─────────────────────────────────────────────────────

func runThroughput(client *http.Client, url string, n int) (mbPerSec float64, errCount int) {
	var total int64
	t0 := time.Now()
	for i := 0; i < n; i++ {
		resp, err := client.Get(url)
		if err != nil {
			errCount++
			continue
		}
		nb, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		total += nb
	}
	elapsed := time.Since(t0)
	if elapsed > 0 {
		mbPerSec = float64(total) / elapsed.Seconds() / 1e6
	}
	return
}

// ── Stats ────────────────────────────────────────────────────────────────────

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

// ── Result type ──────────────────────────────────────────────────────────────

type result struct {
	label        string
	seqAvg       time.Duration
	seqP50       time.Duration
	seqP99       time.Duration
	seqMax       time.Duration
	concRPS      float64
	concP99      time.Duration
	concMax      time.Duration
	throughputMB float64
}

func bench(label, base string, seqN, concN, concC, tpN int, tr *http3.Transport) result {
	c := &http.Client{Transport: tr}


	lats, serr := runSeq(c, base+"/ping", seqN)
	if serr > 0 {
		fmt.Fprintf(os.Stderr, "  [%s] seq errors: %d\n", label, serr)
	}

	rps, cp99, cmax, cerr := runConc(c, base+"/ping", concN, concC)
	if cerr > 0 {
		fmt.Fprintf(os.Stderr, "  [%s] conc errors: %d\n", label, cerr)
	}

	mbps, terr := runThroughput(c, base+"/100k", tpN)
	if terr > 0 {
		fmt.Fprintf(os.Stderr, "  [%s] throughput errors: %d\n", label, terr)
	}

	var seqMax time.Duration
	if len(lats) > 0 {
		seqMax = lats[len(lats)-1]
	}

	return result{
		label:        label,
		seqAvg:       avgDur(lats),
		seqP50:       pct(lats, 0.50),
		seqP99:       pct(lats, 0.99),
		seqMax:       seqMax,
		concRPS:      rps,
		concP99:      cp99,
		concMax:      cmax,
		throughputMB: mbps,
	}
}

// ── Report ───────────────────────────────────────────────────────────────────

func printReport(cr, go_ result) {
	d := func(d time.Duration) string { return d.Round(time.Microsecond).String() }
	r := func(v float64) string { return fmt.Sprintf("%.0f req/s", v) }
	m := func(v float64) string { return fmt.Sprintf("%.1f MB/s", v) }

	row := func(metric, cv, gv string) {
		fmt.Printf("  %-26s  %-16s  %s\n", metric, cv, gv)
	}

	fmt.Println()
	fmt.Println("┌────────────────────────────────────────────────────────────────┐")
	fmt.Println("│         HTTP/3 Benchmark: Crystal quic.cr vs Go quic-go        │")
	fmt.Println("├──────────────────────────────┬──────────────────┬──────────────┤")
	fmt.Printf("│  %-28s│  %-16s│  %s\n", "Metric", "Crystal quic.cr", "Go quic-go   │")
	fmt.Println("├──────────────────────────────┼──────────────────┼──────────────┤")
	fmt.Println("│  Sequential latency (GET /ping)                               │")
	row("    avg", d(cr.seqAvg), d(go_.seqAvg))
	row("    p50", d(cr.seqP50), d(go_.seqP50))
	row("    p99", d(cr.seqP99), d(go_.seqP99))
	row("    max", d(cr.seqMax), d(go_.seqMax))
	fmt.Println("│                                                               │")
	fmt.Println("│  Concurrent (GET /ping)                                       │")
	row("    req/s", r(cr.concRPS), r(go_.concRPS))
	row("    p99 latency", d(cr.concP99), d(go_.concP99))
	row("    max latency", d(cr.concMax), d(go_.concMax))
	fmt.Println("│                                                               │")
	fmt.Println("│  Throughput (GET /100k)                                       │")
	row("    MB/s", m(cr.throughputMB), m(go_.throughputMB))
	fmt.Println("├──────────────────────────────────────────────────────────────┤")

	if go_.seqAvg > 0 && cr.seqAvg > 0 {
		latRatio := float64(go_.seqAvg) / float64(cr.seqAvg)
		rpsRatio := cr.concRPS / go_.concRPS
		tpRatio  := cr.throughputMB / go_.throughputMB
		fmt.Printf("  Latency  Crystal/Go:  %.2fx  (>1 = Crystal faster)\n", latRatio)
		fmt.Printf("  RPS      Crystal/Go:  %.2fx  (>1 = Crystal faster)\n", rpsRatio)
		fmt.Printf("  Throughput Crystal/Go: %.2fx  (>1 = Crystal faster)\n", tpRatio)
	}
	fmt.Println("└──────────────────────────────────────────────────────────────┘")
	fmt.Println()
}

// ── main ─────────────────────────────────────────────────────────────────────

func main() {
	crystalPort := flag.Int("crystal-port", 4433, "Crystal quic.cr server port")
	goPort      := flag.Int("go-port", 4444, "Go quic-go server port")
	seqN        := flag.Int("seq-n", 300, "Sequential requests (latency benchmark)")
	concN       := flag.Int("conc-n", 1000, "Total requests (concurrent benchmark)")
	concC       := flag.Int("conc-c", 50, "Concurrency (concurrent benchmark)")
	tpN         := flag.Int("tp-n", 20, "Requests for throughput benchmark (GET /100k)")
	serverMode  := flag.Bool("server", false, "Run Go HTTP/3 server only")
	flag.Parse()

	payload100k := make([]byte, 100*1024)
	for i := range payload100k {
		payload100k[i] = 'x'
	}

	if *serverMode {
		_, err := startGoServer(*goPort, payload100k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to start Go server: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Go HTTP/3 server listening on udp://127.0.0.1:%d\n", *goPort)
		select {}
	}

	crystalBase := fmt.Sprintf("https://127.0.0.1:%d", *crystalPort)
	goBase      := fmt.Sprintf("https://127.0.0.1:%d", *goPort)

	// Check Crystal server is reachable
	{
		tr := newTransport()
		c := &http.Client{Transport: tr}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "GET", crystalBase+"/ping", nil)
		resp, err := c.Do(req)
		tr.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Crystal server not reachable on :%d: %v\n", *crystalPort, err)
			fmt.Fprintln(os.Stderr, "Start it first (from repo root):  crystal run examples/e2e_server.cr")
			os.Exit(1)
		}
		resp.Body.Close()
		fmt.Printf("Crystal server OK on :%d\n", *crystalPort)
	}

	// Check Go server is reachable
	{
		tr := newTransport()
		c := &http.Client{Transport: tr}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "GET", goBase+"/ping", nil)
		resp, err := c.Do(req)
		tr.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Go server not reachable on :%d: %v\n", *goPort, err)
			os.Exit(1)
		}
		resp.Body.Close()
		fmt.Printf("Go server OK on :%d\n", *goPort)
	}

	fmt.Printf("Config: seq=%d  conc=%d/%d workers  tp=%d×100k\n",
		*seqN, *concN, *concC, *tpN)

	fmt.Println("\nBenchmarking Crystal quic.cr…")
	crTr := newTransport()
	defer crTr.Close()
	// Warm up Crystal transport to complete the handshake and OpenSSL init
	cCr := &http.Client{Transport: crTr}
	for i := 0; i < 30; i++ {
		resp, err := cCr.Get(crystalBase + "/ping")
		if err == nil {
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
		}
	}
	crRes := bench("Crystal quic.cr", crystalBase, *seqN, *concN, *concC, *tpN, crTr)

	fmt.Println("Benchmarking Go quic-go…")
	goTr := newTransport()
	defer goTr.Close()
	// Warm up Go transport to complete the handshake
	cGo := &http.Client{Transport: goTr}
	for i := 0; i < 30; i++ {
		resp, err := cGo.Get(goBase + "/ping")
		if err == nil {
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
		}
	}
	goRes := bench("Go quic-go", goBase, *seqN, *concN, *concC, *tpN, goTr)

	printReport(crRes, goRes)
}
