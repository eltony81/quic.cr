package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/quic-go/quic-go/http3"
)

var startTime = time.Now()

func main() {
	port := flag.Int("port", 4434, "UDP port to listen on")
	cert := flag.String("cert", "../../cert.pem", "TLS certificate file")
	key := flag.String("key", "../../key.pem", "TLS private key file")
	flag.Parse()

	// Resolve cert/key relative to the binary location
	certPath := resolveRelativePath(*cert)
	keyPath := resolveRelativePath(*key)

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/html; charset=utf-8")
		w.Header().Set("x-powered-by", "quic-go")
		fmt.Fprintf(w, `<!DOCTYPE html><html><body><h1>Go HTTP/3 Server</h1><p>quic-go benchmark</p></body></html>`)
	})

	mux.HandleFunc("/greet", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			name = "stranger"
		}
		w.Header().Set("content-type", "application/json")
		w.Header().Set("x-powered-by", "quic-go")
		fmt.Fprintf(w, `{"message":"Hello, %s!","server":"quic-go"}`, name)
	})

	mux.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
		id := filepath.Base(r.URL.Path)
		w.Header().Set("content-type", "application/json")
		w.Header().Set("x-powered-by", "quic-go")
		switch r.Method {
		case http.MethodGet:
			fmt.Fprintf(w, `{"user":{"id":"%s","status":"active"}}`, id)
		case http.MethodDelete:
			fmt.Fprintf(w, `{"deleted":true,"id":"%s"}`, id)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var buf [1 << 20]byte // 1 MB max
		n, _ := r.Body.Read(buf[:])
		body := string(buf[:n])
		ct := r.Header.Get("content-type")
		w.Header().Set("x-powered-by", "quic-go")
		if ct == "application/json" {
			w.Header().Set("content-type", "application/json")
			fmt.Fprintf(w, `{"echo":%s,"bytes":%d}`, json.RawMessage(body), n)
		} else {
			w.Header().Set("content-type", "text/plain")
			fmt.Fprintf(w, "Echo: %s", body)
		}
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","uptime_ms":%d,"go_version":"%s","goroutines":%d}`,
			time.Since(startTime).Milliseconds(), runtime.Version(), runtime.NumGoroutine())
	})

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	server := &http3.Server{
		Addr:      fmt.Sprintf("127.0.0.1:%d", *port),
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	log.Printf("🚀 Go HTTP/3 server (quic-go) listening on udp://127.0.0.1:%d", *port)
	if err := server.ListenAndServeTLS(certPath, keyPath); err != nil {
		log.Fatalf("server error: %v\n", err)
	}
}

func resolveRelativePath(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	exe, err := os.Executable()
	if err != nil {
		return p
	}
	return filepath.Join(filepath.Dir(exe), p)
}
