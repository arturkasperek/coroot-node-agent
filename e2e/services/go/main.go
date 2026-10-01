// A tiny HTTP/1.1 + h2c (cleartext HTTP/2) test service for the e2e suite.
// Usage: go-service -addr1 :8081 -addr2 :8082
// addr1 serves plain HTTP/1.1, addr2 serves h2c (HTTP/2 without TLS).
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 1, "name": "alice"}, {"id": 2, "name": "bob"}})
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	// /edge/*: shapes of HTTP/1 traffic at the edge of what the eBPF
	// capture handles (see e2e/loadgen/edge.go).
	mux.HandleFunc("/edge/", edgeHandler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

func edgeHandler(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	switch r.URL.Path {
	case "/edge/chunkedresp":
		f, _ := w.(http.Flusher)
		for i := 0; i < 200; i++ {
			_, _ = fmt.Fprintf(w, "chunk-%d\n", i)
			if f != nil {
				f.Flush()
			}
		}
	case "/edge/bigresp":
		_, _ = w.Write(bytes.Repeat([]byte("x"), 200*1024))
	case "/edge/closedelim":
		// A response with neither Content-Length nor chunking: the body ends
		// when the server closes the connection.
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nclose-delimited body\n")
		_ = buf.Flush()
		_ = conn.Close()
	default:
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
}

func main() {
	addr1 := flag.String("addr1", ":8081", "HTTP/1.1 listen address")
	addr2 := flag.String("addr2", ":8082", "h2c (HTTP/2 cleartext) listen address")
	flag.Parse()

	h := handler()

	go func() {
		log.Printf("go-service: http/1.1 on %s", *addr1)
		log.Fatal(http.ListenAndServe(*addr1, h))
	}()

	h2s := &http2.Server{}
	log.Printf("go-service: h2c on %s", *addr2)
	log.Fatal(http.ListenAndServe(*addr2, h2c.NewHandler(h, h2s)))
}
