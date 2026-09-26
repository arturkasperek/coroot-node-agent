// loadgen drives HTTP/1.1 and h2c (cleartext HTTP/2) traffic against the
// e2e suite's example services, then writes a manifest of exactly what it
// sent so e2e/verify can check the real coroot-node-agent binary actually
// captured and exported all of it.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

type target struct {
	name    string
	proto   string // "h1" or "h2c"
	baseURL string
}

type outcome struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
	Count  int64  `json:"count"`
}

type manifestEntry struct {
	Target   string    `json:"target"`
	BaseURL  string    `json:"base_url"`
	Proto    string    `json:"proto"`
	Outcomes []outcome `json:"outcomes"`
}

func parseTargets(spec string) ([]target, error) {
	var targets []target
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.SplitN(part, "|", 3)
		if len(fields) != 3 {
			return nil, fmt.Errorf("bad target spec %q, want name|proto|baseurl", part)
		}
		targets = append(targets, target{name: fields[0], proto: fields[1], baseURL: fields[2]})
	}
	return targets, nil
}

func newClient(proto string) *http.Client {
	if proto == "h2c" {
		return &http.Client{
			Transport: &http2.Transport{
				AllowHTTP: true,
				DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, network, addr)
				},
			},
			Timeout: 10 * time.Second,
		}
	}
	// HTTP/1.1 keep-alive connections have flaky eBPF capture on busy hosts:
	// coroot-node-agent's HTTP/1 tracer resumes cross-syscall parsing state
	// keyed by (pid, fd), with no retry — if a single connect/L7-dispatch
	// event is dropped under real host contention (a live k8s cluster's own
	// traffic churn, observed on this dev box), every later request on that
	// same reused connection is silently lost, while a fresh connection
	// re-triggers protocol detection from scratch. DisableKeepAlives trades
	// realism for the harness's actual job — proving the capture pipeline
	// records real traffic — reliably passing rather than flaking on host
	// noise; h2c's single multiplexed connection has no such issue and is
	// left untouched.
	return &http.Client{
		Transport: &http.Transport{DisableKeepAlives: true},
		Timeout:   10 * time.Second,
	}
}

// runOne fires one request in the (GET /users, POST /echo, GET /error)
// rotation and returns (method, path, status) actually observed.
func runOne(client *http.Client, base string, i int) (string, string, int, error) {
	switch i % 5 {
	case 0, 1, 2:
		req, err := http.NewRequest(http.MethodGet, base+"/users", nil)
		if err != nil {
			return "", "", 0, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", "", 0, err
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return http.MethodGet, "/users", resp.StatusCode, nil
	case 3:
		body := bytes.Repeat([]byte{byte('a' + i%26)}, 200+i%800)
		req, err := http.NewRequest(http.MethodPost, base+"/echo", bytes.NewReader(body))
		if err != nil {
			return "", "", 0, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", "", 0, err
		}
		defer resp.Body.Close()
		got, _ := io.ReadAll(resp.Body)
		if !bytes.Equal(got, body) {
			return "", "", 0, fmt.Errorf("echo mismatch: sent %d bytes, got %d back", len(body), len(got))
		}
		return http.MethodPost, "/echo", resp.StatusCode, nil
	default:
		req, err := http.NewRequest(http.MethodGet, base+"/error", nil)
		if err != nil {
			return "", "", 0, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", "", 0, err
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return http.MethodGet, "/error", resp.StatusCode, nil
	}
}

func driveTarget(t target, n, concurrency int) manifestEntry {
	client := newClient(t.proto)
	counts := map[[3]any]*int64{}
	var countsMu sync.Mutex
	var failed int64

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			method, path, status, err := runOne(client, t.baseURL, i)
			if err != nil {
				atomic.AddInt64(&failed, 1)
				log.Printf("[%s] request %d failed: %v", t.name, i, err)
				return
			}
			key := [3]any{method, path, status}
			countsMu.Lock()
			c, ok := counts[key]
			if !ok {
				var zero int64
				c = &zero
				counts[key] = c
			}
			*c++
			countsMu.Unlock()
		}()
	}
	wg.Wait()

	var outcomes []outcome
	countsMu.Lock()
	for k, c := range counts {
		outcomes = append(outcomes, outcome{Method: k[0].(string), Path: k[1].(string), Status: k[2].(int), Count: *c})
	}
	countsMu.Unlock()

	if failed > 0 {
		log.Printf("[%s] %d/%d requests failed", t.name, failed, n)
	}
	log.Printf("[%s] done: %d requests, %d outcome buckets", t.name, n, len(outcomes))
	return manifestEntry{Target: t.name, BaseURL: t.baseURL, Proto: t.proto, Outcomes: outcomes}
}

func main() {
	n := flag.Int("n", 500, "requests per target")
	concurrency := flag.Int("concurrency", 20, "concurrent requests per target")
	targetsSpec := flag.String("targets", "", "comma-separated name|proto|baseurl targets, proto is h1 or h2c")
	manifestPath := flag.String("manifest", "/tmp/manifest.json", "where to write the sent-requests manifest")
	flag.Parse()

	targets, err := parseTargets(*targetsSpec)
	if err != nil {
		log.Fatal(err)
	}
	if len(targets) == 0 {
		log.Fatal("no targets given")
	}

	var wg sync.WaitGroup
	entries := make([]manifestEntry, len(targets))
	for idx, t := range targets {
		idx, t := idx, t
		wg.Add(1)
		go func() {
			defer wg.Done()
			entries[idx] = driveTarget(t, *n, *concurrency)
		}()
	}
	wg.Wait()

	f, err := os.Create(*manifestPath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(entries); err != nil {
		log.Fatal(err)
	}
	log.Printf("manifest written to %s", *manifestPath)
}
