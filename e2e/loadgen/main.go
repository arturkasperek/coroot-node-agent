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
	"net/http/httptrace"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

type target struct {
	name    string
	proto   string // "h1", "h2c", "h1-keepalive", or "h1-tls"
	baseURL string
}

type outcome struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
	Count  int64  `json:"count"`
	// IDs are the request indices (see runOne's "n" query parameter) that
	// made up Count, so verify can name exactly which requests went missing
	// instead of only how many. Empty for targets whose server can't take a
	// query string (h1-keepalive matches the full URL).
	IDs []int `json:"ids,omitempty"`
	// SrcPorts[i] is the local TCP port request IDs[i] went out on. With it a
	// missing request can be joined to the agent's log of connection-open
	// events, which says whether the agent ever learned the connection
	// existed (see run-agent.sh's portcheck).
	SrcPorts []int `json:"src_ports,omitempty"`
}

type manifestEntry struct {
	// Run tags every request of this loadgen invocation ("r" query
	// parameter), so verify only counts spans this run produced and never
	// warmup or probe traffic that reuses the same routes and indices.
	Run      string    `json:"run,omitempty"`
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
	if proto == "h1-tls" {
		// Fresh TLS connection per request, same reasoning as the plain
		// h1 client below (never reused — keeps this exercising
		// TLS-uprobe attach + protocol detection repeatedly rather than
		// once per test). Self-signed cert (e2e/certs), so skip
		// verification — this harness only cares whether the eBPF
		// SSL_write/SSL_read uprobes see the decrypted plaintext, not
		// about certificate trust.
		return &http.Client{
			Transport: &http.Transport{
				DisableKeepAlives: true,
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: 10 * time.Second,
		}
	}
	if proto == "h1-keepalive" {
		// The deliberate exception to the DisableKeepAlives workaround
		// below: this proto exists specifically to exercise a real,
		// reused HTTP/1.1 connection (see e2e/services/node-keepalive
		// and driveTarget's concurrency override), now that
		// containers/container.go's connection-registration-race fixes
		// (connectionsByPidFdTs, PidFdTs-keyed pending buffers,
		// completed-request buffering) apply equally whether a
		// connection is reused or freshly dialed. Default Transport
		// (nil) keeps Go's normal keep-alive behavior.
		return &http.Client{Timeout: 10 * time.Second}
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

// routeStep describes one request in a target's rotation: either a plain
// GET expecting status, or (echoBody true) a POST /echo-style request
// whose body is generated per-call and must come back unchanged.
type routeStep struct {
	method   string
	path     string
	status   int
	echoBody bool
}

var defaultRoutes = []routeStep{
	{method: http.MethodGet, path: "/users", status: http.StatusOK},
	{method: http.MethodGet, path: "/users", status: http.StatusOK},
	{method: http.MethodGet, path: "/users", status: http.StatusOK},
	{method: http.MethodPost, path: "/echo", status: http.StatusOK, echoBody: true},
	{method: http.MethodGet, path: "/error", status: http.StatusInternalServerError},
}

// keepAliveRoutes rotates across e2e/services/node-keepalive's routes,
// whose response bodies deliberately span a wide size range (see that
// service's ROUTE_SIZES) — a few bytes up to well past both
// HTTP1_CAPTURE_MAX and MAX_PAYLOAD_SIZE in ebpftracer/ebpf/l7/http1.c, all
// multiplexed over the one shared connection driveTarget forces for the
// h1-keepalive proto.
var keepAliveRoutes = []routeStep{
	{method: http.MethodGet, path: "/r/tiny", status: http.StatusOK},
	{method: http.MethodGet, path: "/r/small", status: http.StatusOK},
	{method: http.MethodGet, path: "/r/medium", status: http.StatusOK},
	{method: http.MethodGet, path: "/r/large", status: http.StatusOK},
	{method: http.MethodGet, path: "/r/huge", status: http.StatusOK},
}

func routesFor(proto string) []routeStep {
	if proto == "h1-keepalive" {
		return keepAliveRoutes
	}
	return defaultRoutes
}

// runOne fires one request per step's rotation and returns (method, path,
// status) actually observed.
func runOne(client *http.Client, base string, step routeStep, i int, query string, srcPort *int) (string, string, int, error) {
	// trace records the local port the request's connection was dialed from.
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		if a, ok := info.Conn.LocalAddr().(*net.TCPAddr); ok {
			*srcPort = a.Port
		}
	}}
	if step.echoBody {
		body := bytes.Repeat([]byte{byte('a' + i%26)}, 200+i%800)
		req, err := http.NewRequest(step.method, base+step.path+query, bytes.NewReader(body))
		if err != nil {
			return "", "", 0, err
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
		resp, err := client.Do(req)
		if err != nil {
			return "", "", 0, err
		}
		defer resp.Body.Close()
		got, _ := io.ReadAll(resp.Body)
		if !bytes.Equal(got, body) {
			return "", "", 0, fmt.Errorf("echo mismatch: sent %d bytes, got %d back", len(body), len(got))
		}
		return step.method, step.path, resp.StatusCode, nil
	}
	req, err := http.NewRequest(step.method, base+step.path+query, nil)
	if err != nil {
		return "", "", 0, err
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	resp, err := client.Do(req)
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return step.method, step.path, resp.StatusCode, nil
}

func driveTarget(t target, n, concurrency int) manifestEntry {
	if t.proto == "h1-edge" {
		return driveEdge(t, n, concurrency)
	}
	client := newClient(t.proto)
	routes := routesFor(t.proto)
	counts := map[[3]any]*int64{}
	ids := map[[3]any][]int{}
	ports := map[int]int{} // request id -> local source port
	var countsMu sync.Mutex
	var failed int64

	if t.proto == "h1-keepalive" {
		// The whole point of this proto: every request must land on the
		// same shared connection, not whichever one Go's connection pool
		// hands out under concurrent dispatch.
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			step := routes[i%len(routes)]
			// n = which request, r = which loadgen run: lets verify name the
			// exact requests that never became spans. Not for h1-keepalive,
			// whose server looks the *whole* URL up in a table.
			query := ""
			if t.proto != "h1-keepalive" {
				query = fmt.Sprintf("?n=%d&r=%s", i, runID)
			}
			srcPort := 0
			method, path, status, err := runOne(client, t.baseURL, step, i, query, &srcPort)
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
			if query != "" {
				ids[key] = append(ids[key], i)
				ports[i] = srcPort
			}
			countsMu.Unlock()
		}()
	}
	wg.Wait()

	var outcomes []outcome
	countsMu.Lock()
	for k, c := range counts {
		sort.Ints(ids[k])
		var srcPorts []int
		for _, id := range ids[k] {
			srcPorts = append(srcPorts, ports[id])
		}
		outcomes = append(outcomes, outcome{Method: k[0].(string), Path: k[1].(string), Status: k[2].(int), Count: *c, IDs: ids[k], SrcPorts: srcPorts})
	}
	countsMu.Unlock()

	if failed > 0 {
		log.Printf("[%s] %d/%d requests failed", t.name, failed, n)
	}
	log.Printf("[%s] done: %d requests, %d outcome buckets", t.name, n, len(outcomes))
	return manifestEntry{Run: runID, Target: t.name, BaseURL: t.baseURL, Proto: t.proto, Outcomes: outcomes}
}

// runID tags every request of this process; see manifestEntry.Run.
var runID = fmt.Sprintf("%x", time.Now().UnixNano()&0xffffffff)

func main() {
	n := flag.Int("n", 500, "requests per target")
	concurrency := flag.Int("concurrency", 20, "concurrent requests per target")
	targetsSpec := flag.String("targets", "", "comma-separated name|proto|baseurl targets, proto is h1, h2c, h1-keepalive, or h1-tls")
	manifestPath := flag.String("manifest", "/tmp/manifest.json", "where to write the sent-requests manifest")
	// Keep the process alive after the requests are done. Used by
	// run-agent.sh's TLS-uprobe priming: coroot-node-agent attaches Go TLS
	// uprobes per *executable*, but only once it has seen a live process
	// running it (via that process's EventTypeConnectionOpen, see
	// containers/registry.go). A priming run that exits in milliseconds is
	// already gone by the time the agent's event loop reaches its
	// connect event, so /proc/<pid> is unreadable, no container resolves,
	// and no uprobe is ever attached — the attach then lands mid-way
	// through the real measured load instead, losing whatever ran first.
	hold := flag.Duration("hold", 0, "stay alive this long after finishing (keeps the process visible to an eBPF agent)")
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
	if *hold > 0 {
		time.Sleep(*hold)
	}
}
