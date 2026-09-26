// A tiny HTTP/1.1 + h2c (cleartext HTTP/2) test service for the e2e suite.
// Usage: go-service -addr1 :8081 -addr2 :8082
// addr1 serves plain HTTP/1.1, addr2 serves h2c (HTTP/2 without TLS).
package main

import (
	"encoding/json"
	"flag"
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
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return mux
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
