package tracing

import (
	"testing"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"inet.af/netaddr"
)

func testTrace(t *testing.T) (*Trace, *tracetest.InMemoryExporter) {
	t.Helper()
	old := samplingRate
	samplingRate = 1.0
	t.Cleanup(func() { samplingRate = old })
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	tr := &Tracer{otel: tp.Tracer("test")}
	return tr.NewTrace(common.HostPortFromIPPort(netaddr.MustParseIPPort("10.0.0.1:8080"))), exp
}

func attrMap(kvs []attribute.KeyValue) map[string]attribute.Value {
	m := map[string]attribute.Value{}
	for _, kv := range kvs {
		m[string(kv.Key)] = kv.Value
	}
	return m
}

func TestHttpRequestSpanWithBodies(t *testing.T) {
	tr, exp := testTrace(t)
	tr.HttpRequest("POST", "/orders", l7.Status(201), 3*time.Millisecond,
		&HttpBodies{Request: `{"a":1}`, Response: `{"id":"ab"}`, RequestSize: 7, ResponseSize: 11}, time.Time{})
	spans := exp.GetSpans()
	require.Len(t, spans, 1)
	a := attrMap(spans[0].Attributes)
	require.Equal(t, `{"a":1}`, a["http.request.body"].AsString())
	require.Equal(t, `{"id":"ab"}`, a["http.response.body"].AsString())
	require.Equal(t, int64(7), a["http.request.body.size"].AsInt64())
	require.Equal(t, int64(11), a["http.response.body.size"].AsInt64())
}

func TestHttpRequestSpanWithoutBodiesIsUnchanged(t *testing.T) {
	tr, exp := testTrace(t)
	tr.HttpRequest("GET", "/users", l7.Status(200), time.Millisecond, nil, time.Time{})
	tr.HttpRequest("GET", "/users", l7.Status(200), time.Millisecond, &HttpBodies{RequestSize: -1, ResponseSize: -1}, time.Time{})
	spans := exp.GetSpans()
	require.Len(t, spans, 2)
	for _, s := range spans {
		require.ElementsMatch(t, []string{"http.url", "http.method", "http.status_code", "net.peer.name", "net.peer.port"}, keys(attrMap(s.Attributes)))
	}
}

func keys(m map[string]attribute.Value) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestHttp2RequestSpanWithBodies(t *testing.T) {
	tr, exp := testTrace(t)
	tr.Http2Request("POST", "/orders", "http", l7.Status(200), -1, time.Millisecond,
		&HttpBodies{Request: "req", Response: "resp", RequestSize: -1, ResponseSize: 4}, time.Time{})
	spans := exp.GetSpans()
	require.Len(t, spans, 1)
	a := attrMap(spans[0].Attributes)
	require.Equal(t, "req", a["http.request.body"].AsString())
	require.Equal(t, "resp", a["http.response.body"].AsString())
	require.NotContains(t, a, "http.request.body.size", "an unknown size is not reported")
	require.Equal(t, int64(4), a["http.response.body.size"].AsInt64())
}

func TestSpanUsesGivenEndTime(t *testing.T) {
	tr, exp := testTrace(t)
	at := time.Now().Add(-300 * time.Millisecond)
	tr.HttpRequest("GET", "/x", l7.Status(200), 50*time.Millisecond, nil, at)
	s := exp.GetSpans()[0]
	require.WithinDuration(t, at, s.EndTime, time.Millisecond)
	require.WithinDuration(t, at.Add(-50*time.Millisecond), s.StartTime, time.Millisecond)

	tr.Http2Request("GET", "/x", "http", l7.Status(200), -1, 50*time.Millisecond, nil, at)
	s = exp.GetSpans()[1]
	require.WithinDuration(t, at, s.EndTime, time.Millisecond)
}
