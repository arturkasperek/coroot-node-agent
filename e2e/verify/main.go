// verify checks that everything e2e/loadgen sent (see its manifest) shows
// up as OTLP spans in the mock backend — i.e. that the real
// coroot-node-agent binary's eBPF capture -> containers dispatch ->
// OTLP export pipeline worked end-to-end for every example service.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

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

type recordedSpan struct {
	Name       string            `json:"name"`
	Attributes map[string]string `json:"attributes"`
}

func fetchSpans(backend string) ([]recordedSpan, error) {
	resp, err := http.Get(strings.TrimRight(backend, "/") + "/api/spans")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var spans []recordedSpan
	if err := json.NewDecoder(resp.Body).Decode(&spans); err != nil {
		return nil, err
	}
	return spans, nil
}

// hostPort resolves the target's hostname to the IP address the agent's
// eBPF capture actually sees on the wire (it records the raw socket
// destination, never the DNS name that was dialed), so matching against
// spans has to key off ip:port, not host:port.
func hostPort(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	port := u.Port()
	if net.ParseIP(host) == nil {
		ips, err := net.LookupHost(host)
		if err != nil || len(ips) == 0 {
			return "", fmt.Errorf("resolving %q: %v", host, err)
		}
		host = ips[0]
	}
	return net.JoinHostPort(host, port), nil
}

func main() {
	backend := flag.String("backend", "http://127.0.0.1:4318", "mock backend base URL")
	manifestPath := flag.String("manifest", "/tmp/manifest.json", "manifest written by loadgen")
	minRatio := flag.Float64("min-ratio", 0.95, "minimum fraction of sent requests that must show up as recorded spans, per h2c target")
	// coroot-node-agent's HTTP/1 tracer correlates L7 payload events to a
	// tracked connection by (pid, fd, timestamp). On a genuinely busy host
	// (this suite has been run against a live k8s cluster sharing the
	// box), (pid, fd) gets reused across connections faster than the two
	// independent ring-buffer readers (tcp-connect-events and l7-events —
	// see runTcpConnectEventsReader/runL7EventsReader in
	// ebpftracer/tracer.go) are guaranteed to stay in order, so a late
	// event for an older connection can arrive after a newer one has
	// already reused its fd. containers/container.go's onL7Request and
	// onConnectionOpen now keep a secondary index (connectionsByPidFdTs)
	// so a late event can still find its exact, superseded connection
	// instead of being compared against — and rejected by — the new one,
	// plus a pendingHttp1Parsers buffer (mirroring HTTP2's
	// pendingHttp2Parsers) for events that arrive before their connection
	// is registered at all, and pendingHttp1Parsers is itself keyed by
	// the full (pid, fd, timestamp) rather than just (pid, fd) so several
	// concurrently-pending connections on a fast-recycled fd don't
	// clobber each other's buffered parsing state. A request/response
	// pair that completes entirely before its connection registers is no
	// longer discarded either: it's queued (pendingHttp1CompletedRequest)
	// and emitted retroactively once the connection is found, bounded by
	// pendingHttp1RequestMaxAge (2s) since Trace.createSpan stamps a
	// span's absolute time from time.Now() at emission, not a kernel
	// timestamp — recovering an arbitrarily stale request would mean an
	// arbitrarily skewed span. Together these brought measured ratios
	// from ~0.60-0.83 up to a consistent 1.00 on this host, matching
	// h2c's own ~1.00 (its single multiplexed connection never reuses
	// its fd, so none of this ever applied to it). Kept a hair under
	// h2c's bar rather than raising it to the exact same value — both
	// are still host-noise-sensitive, and 1.00 leaves zero slack for any
	// one request genuinely lost to real ring-buffer pressure.
	minRatioH1 := flag.Float64("min-ratio-h1", 0.95, "minimum fraction of sent requests that must show up as recorded spans, per h1 target (see comment: lower than h2c because of real host-noise-driven capture loss in the HTTP/1 tracer)")
	waitFor := flag.Duration("wait", 20*time.Second, "how long to wait/poll for spans to arrive before giving up")
	flag.Parse()

	data, err := os.ReadFile(*manifestPath)
	if err != nil {
		log.Fatalf("reading manifest: %v", err)
	}
	var manifest []manifestEntry
	if err := json.Unmarshal(data, &manifest); err != nil {
		log.Fatalf("parsing manifest: %v", err)
	}

	deadline := time.Now().Add(*waitFor)
	var spans []recordedSpan
	for {
		spans, err = fetchSpans(*backend)
		if err != nil {
			log.Fatalf("fetching spans: %v", err)
		}
		if len(spans) > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	log.Printf("fetched %d recorded spans from mock backend", len(spans))

	ok := true
	for _, entry := range manifest {
		hp, err := hostPort(entry.BaseURL)
		if err != nil {
			log.Printf("[%s] bad base url %q: %v", entry.Target, entry.BaseURL, err)
			ok = false
			continue
		}

		// counts[method|path|status] = how many spans matched this bucket
		matched := map[string]int64{}
		for _, sp := range spans {
			u := sp.Attributes["http.url"]
			if !strings.Contains(u, hp) {
				continue
			}
			status := sp.Attributes["http.status_code"]
			var path string
			if idx := strings.Index(u, hp); idx >= 0 {
				rest := u[idx+len(hp):]
				if i := strings.Index(rest, "?"); i >= 0 {
					rest = rest[:i]
				}
				path = rest
			}
			key := sp.Name + "|" + path + "|" + status
			matched[key]++
		}

		var wantTotal, gotTotal int64
		for _, oc := range entry.Outcomes {
			key := oc.Method + "|" + oc.Path + "|" + strconv.Itoa(oc.Status)
			wantTotal += oc.Count
			gotTotal += matched[key]
		}
		ratio := 0.0
		if wantTotal > 0 {
			ratio = float64(gotTotal) / float64(wantTotal)
		}
		threshold := *minRatio
		if entry.Proto == "h1" || entry.Proto == "h1-keepalive" || entry.Proto == "h1-tls" {
			threshold = *minRatioH1
		}
		status := "OK"
		if wantTotal == 0 || ratio < threshold {
			status = "FAIL"
			ok = false
		}
		fmt.Printf("%-6s target=%-14s proto=%-4s sent=%-5d recorded=%-5d ratio=%.2f\n",
			status, entry.Target, entry.Proto, wantTotal, gotTotal, ratio)
		if status == "FAIL" {
			for _, oc := range entry.Outcomes {
				key := oc.Method + "|" + oc.Path + "|" + strconv.Itoa(oc.Status)
				fmt.Printf("         %-6s %-6s -> %d sent, %d recorded\n", oc.Method, oc.Path, oc.Count, matched[key])
			}
		}
	}

	if !ok {
		fmt.Println("FAIL: not everything sent was recorded — see above")
		os.Exit(1)
	}
	fmt.Println("PASS: all targets recorded within tolerance")
}
