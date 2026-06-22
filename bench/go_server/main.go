package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/quic-go/quic-go/http3"
)

func main() {
	cert := "../../cert.pem"
	key := "../../key.pem"
	if len(os.Args) >= 3 {
		cert = os.Args[1]
		key = os.Args[2]
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/html")
		fmt.Fprintln(w, "<!DOCTYPE html><html><body><h1>quic-go HTTP/3 benchmark server</h1></body></html>")
	})

	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}
		if r.Header.Get("content-type") == "application/json" {
			w.Header().Set("content-type", "application/json")
			fmt.Fprintf(w, `{"echo":%q,"bytes":%d}`, string(body), len(body))
		} else {
			w.Header().Set("content-type", "text/plain")
			fmt.Fprintf(w, "Echo: %s", body)
		}
	})

	mux.HandleFunc("/greet", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			name = "stranger"
		}
		w.Header().Set("content-type", "application/json")
		fmt.Fprintf(w, `{"message":"Hello, %s!","server":"quic-go"}`, name)
	})

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	server := &http3.Server{
		Addr:      "127.0.0.1:4434",
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	fmt.Fprintln(os.Stderr, "🚀 Go HTTP/3 Server (quic-go) listening on udp://127.0.0.1:4434")
	if err := server.ListenAndServeTLS(cert, key); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}
