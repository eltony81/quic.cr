package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func newTransport() *http3.Transport {
	return &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		QUICConfig:      &quic.Config{Versions: []quic.Version{quic.Version1}},
	}
}

func doReq(client *http.Client, method, url string, body string) (int, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var rb io.Reader
	if body != "" {
		rb = bytes.NewBufferString(body)
	}
	req, _ := http.NewRequestWithContext(ctx, method, url, rb)
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

func main() {
	base := "https://127.0.0.1:4433"

	// Suite 5: Concurrent GET x50
	fmt.Println("=== Suite 5: 50 concurrent GET /ping ===")
	{
		tr := newTransport()
		defer tr.Close()
		c := &http.Client{Transport: tr}
		var wg sync.WaitGroup
		pass := 0
		var mu sync.Mutex
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, body, err := doReq(c, "GET", base+"/ping", "")
				mu.Lock()
				if err == nil && body == "pong" {
					pass++
				}
				mu.Unlock()
			}()
		}
		wg.Wait()
		fmt.Printf("Suite 5: %d/50\n", pass)
	}

	fmt.Println("\n=== Suite 6: 20 concurrent POST /echo 4KB ===")
	{
		tr := newTransport()
		defer tr.Close()
		c := &http.Client{Transport: tr}
		body4k := strings.Repeat("a", 4096)
		var wg sync.WaitGroup
		results := make(chan string, 20)
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				start := time.Now()
				_, body, err := doReq(c, "POST", base+"/echo", body4k)
				elapsed := time.Since(start)
				if err != nil {
					results <- fmt.Sprintf("[%02d] FAIL %v: %v", id, elapsed, err)
				} else if strings.Contains(body, "aaa") {
					results <- fmt.Sprintf("[%02d] OK len=%d %v", id, len(body), elapsed)
				} else {
					results <- fmt.Sprintf("[%02d] WRONG len=%d %v", id, len(body), elapsed)
				}
			}(i)
		}
		go func() { wg.Wait(); close(results) }()
		pass := 0
		for msg := range results {
			fmt.Println(msg)
			if len(msg) > 5 && msg[5] == 'O' {
				pass++
			}
		}
		fmt.Printf("Suite 6: %d/20\n", pass)
	}

	time.Sleep(500 * time.Millisecond) // let server log flush
}
