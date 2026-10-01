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
	IDs    []int  `json:"ids,omitempty"`
}

type manifestEntry struct {
	Run      string    `json:"run,omitempty"`
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
	// Every request sent must show up as a recorded span: 1.0, for every
	// protocol. Measured on a quiet host and under k3s load alike, a healthy
	// agent records all of them — so anything below is a real capture problem,
	// not noise. The per-route breakdown printed for any shortfall says where
	// it is, and node_l7_event_queue_depth, node_l7_tls_attach_seconds_total
	// and node_l7_dropped_unknown_container_total (dumped by run-agent.sh) say
	// whether the agent's event loop was starved.
	minRatio := flag.Float64("min-ratio", 1.0, "minimum fraction of sent requests that must show up as recorded spans, for every target")
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
		// matchedIDs[bucket][n] = request n of THIS loadgen run has a span.
		// Spans from other traffic (warmup, probes) carry another r= or none,
		// so they can neither be counted nor mask a missing request.
		matchedIDs := map[string]map[int]bool{}
		examples := map[string]string{}
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
			if _, ok := examples[key]; !ok {
				examples[key] = u
			}
			if q, err := url.Parse(u); err == nil && entry.Run != "" && q.Query().Get("r") == entry.Run {
				if n, err := strconv.Atoi(q.Query().Get("n")); err == nil {
					if matchedIDs[key] == nil {
						matchedIDs[key] = map[int]bool{}
					}
					matchedIDs[key][n] = true
				}
			}
		}

		// Spans for this destination that fit none of the sent buckets (a
		// request the agent saw but mis-parsed, e.g. an unknown path). They
		// never count toward the ratio; they are printed so a shortfall can be
		// told apart from a request the agent never saw at all.
		wanted := map[string]bool{}
		for _, oc := range entry.Outcomes {
			wanted[oc.Method+"|"+oc.Path+"|"+strconv.Itoa(oc.Status)] = true
		}
		for key, n := range matched {
			if !wanted[key] {
				log.Printf("[%s] unexpected spans: %s x%d e.g. %s", entry.Target, key, n, examples[key])
			}
		}

		var wantTotal, gotTotal int64
		for _, oc := range entry.Outcomes {
			key := oc.Method + "|" + oc.Path + "|" + strconv.Itoa(oc.Status)
			wantTotal += oc.Count
			// Capped at what was sent: with a bar of exactly 1.0, extra
			// spans in one (method, path, status) bucket must not be able
			// to make up for missing ones in another.
			got := matched[key]
			if len(oc.IDs) > 0 {
				got = 0
				for _, id := range oc.IDs {
					if matchedIDs[key][id] {
						got++
					}
				}
			}
			if got > oc.Count {
				got = oc.Count
			}
			gotTotal += got
		}
		ratio := 0.0
		if wantTotal > 0 {
			ratio = float64(gotTotal) / float64(wantTotal)
		}
		threshold := *minRatio
		status := "OK"
		if wantTotal == 0 || ratio < threshold {
			status = "FAIL"
			ok = false
		}
		fmt.Printf("%-6s target=%-14s proto=%-4s sent=%-5d recorded=%-5d ratio=%.2f\n",
			status, entry.Target, entry.Proto, wantTotal, gotTotal, ratio)
		// Print the per-route breakdown for any shortfall: which routes lose
		// requests is the single most diagnostic fact about a partial
		// capture (loss concentrated on the one route with a request body
		// points somewhere completely different than loss spread evenly).
		if status == "FAIL" || gotTotal < wantTotal {
			for _, oc := range entry.Outcomes {
				key := oc.Method + "|" + oc.Path + "|" + strconv.Itoa(oc.Status)
				line := fmt.Sprintf("         %-6s %-6s -> %d sent, %d recorded", oc.Method, oc.Path, oc.Count, matched[key])
				var missing []int
				for _, id := range oc.IDs {
					if !matchedIDs[key][id] {
						missing = append(missing, id)
					}
				}
				if len(missing) > 0 {
					line += fmt.Sprintf("   MISSING n=%v", missing)
				}
				fmt.Println(line)
			}
		}
	}

	if !ok {
		fmt.Println("FAIL: not everything sent was recorded — see above")
		os.Exit(1)
	}
	fmt.Println("PASS: all targets recorded within tolerance")
}
