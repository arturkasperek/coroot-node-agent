// mockbackend is a minimal stand-in for the Coroot collector: it accepts
// OTLP/HTTP trace exports (the same wire format tracing.Init sends real
// traces with — see tracing/tracing.go), keeps every received span in
// memory, and exposes them over a small JSON query API so the e2e verifier
// can check what the real coroot-node-agent binary actually captured and
// exported end-to-end.
package main

import (
	"compress/gzip"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"

	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/proto"
)

type RecordedSpan struct {
	Name       string            `json:"name"`
	Attributes map[string]string `json:"attributes"`
}

var (
	mu    sync.Mutex
	spans []RecordedSpan
)

func attrString(v *commonpb.AnyValue) string {
	if v == nil {
		return ""
	}
	switch x := v.Value.(type) {
	case *commonpb.AnyValue_StringValue:
		return x.StringValue
	case *commonpb.AnyValue_IntValue:
		return strconv.FormatInt(x.IntValue, 10)
	case *commonpb.AnyValue_BoolValue:
		return strconv.FormatBool(x.BoolValue)
	case *commonpb.AnyValue_DoubleValue:
		return strconv.FormatFloat(x.DoubleValue, 'f', -1, 64)
	}
	return ""
}

func readBody(r *http.Request) ([]byte, error) {
	body := r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(body)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		return io.ReadAll(gz)
	}
	return io.ReadAll(body)
}

func handleTraces(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req collectortracepb.ExportTraceServiceRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var received []RecordedSpan
	for _, rs := range req.ResourceSpans {
		for _, ss := range rs.ScopeSpans {
			for _, sp := range ss.Spans {
				rec := RecordedSpan{Name: sp.Name, Attributes: map[string]string{}}
				for _, kv := range sp.Attributes {
					rec.Attributes[kv.Key] = attrString(kv.Value)
				}
				received = append(received, rec)
			}
		}
	}
	mu.Lock()
	spans = append(spans, received...)
	mu.Unlock()

	resp := &collectortracepb.ExportTraceServiceResponse{}
	out, err := proto.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

// handleDrain accepts (and drops) OTLP metrics/logs/profiles exports so the
// real agent doesn't log export errors for channels this harness doesn't
// care about verifying.
func handleDrain(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	w.WriteHeader(http.StatusOK)
}

func handleSpans(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	out := make([]RecordedSpan, len(spans))
	copy(out, spans)
	mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func handleReset(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	spans = nil
	mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func main() {
	addr := flag.String("addr", ":4318", "listen address")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/traces", handleTraces)
	mux.HandleFunc("/v1/metrics", handleDrain)
	mux.HandleFunc("/v1/logs", handleDrain)
	mux.HandleFunc("/v1/profiles", handleDrain)
	mux.HandleFunc("/api/spans", handleSpans)
	mux.HandleFunc("/api/reset", handleReset)

	log.Printf("mockbackend: listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
