package tracing

import (
	"testing"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
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
	return tr.NewTrace(common.HostPortFromIPPort(netaddr.MustParseIPPort("10.0.0.1:8080")), netaddr.IPPort{}), exp
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
		&HttpBodies{Request: `{"a":1}`, Response: `{"id":"ab"}`, RequestSize: 7, ResponseSize: 11}, time.Time{}, 0)
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
	tr.HttpRequest("GET", "/users", l7.Status(200), time.Millisecond, nil, time.Time{}, 0)
	tr.HttpRequest("GET", "/users", l7.Status(200), time.Millisecond, &HttpBodies{RequestSize: -1, ResponseSize: -1}, time.Time{}, 0)
	spans := exp.GetSpans()
	require.Len(t, spans, 2)
	for _, s := range spans {
		require.ElementsMatch(t, []string{
			"http.url", "http.target", "url.path", "http.scheme", "server.address", "server.port",
			"http.method", "http.status_code", "net.peer.name", "net.peer.port",
		}, keys(attrMap(s.Attributes)))
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
		&HttpBodies{Request: "req", Response: "resp", RequestSize: -1, ResponseSize: 4}, time.Time{}, 0)
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
	tr.HttpRequest("GET", "/x", l7.Status(200), 50*time.Millisecond, nil, at, 0)
	s := exp.GetSpans()[0]
	require.WithinDuration(t, at, s.EndTime, time.Millisecond)
	require.WithinDuration(t, at.Add(-50*time.Millisecond), s.StartTime, time.Millisecond)

	tr.Http2Request("GET", "/x", "http", l7.Status(200), -1, 50*time.Millisecond, nil, at, 0)
	s = exp.GetSpans()[1]
	require.WithinDuration(t, at, s.EndTime, time.Millisecond)
}

func TestContainerResourceAttributes(t *testing.T) {
	attributes := attrMap(containerResourceAttributes("/k8s/coroot-dev/demo-traffic-75b97975f8-4c8kf/traffic"))
	require.Equal(t, "/k8s/coroot-dev/demo-traffic", attributes["service.name"].AsString())
	require.Equal(t, "/k8s/coroot-dev/demo-traffic-75b97975f8-4c8kf/traffic", attributes["container.id"].AsString())
	require.Equal(t, "coroot-dev", attributes["k8s.namespace.name"].AsString())
	require.Equal(t, "demo-traffic-75b97975f8-4c8kf", attributes["k8s.pod.name"].AsString())
	require.Equal(t, "traffic", attributes["k8s.container.name"].AsString())
	require.NotContains(t, attributes, "k8s.cronjob.name")

	attributes = attrMap(containerResourceAttributes("/k8s-cronjob/default/hello/xz"))
	require.Equal(t, "default", attributes["k8s.namespace.name"].AsString())
	require.Equal(t, "hello", attributes["k8s.cronjob.name"].AsString())
	require.Equal(t, "xz", attributes["k8s.container.name"].AsString())
	require.NotContains(t, attributes, "k8s.pod.name")

	attributes = attrMap(containerResourceAttributes("/system.slice/k3s.service"))
	require.ElementsMatch(t, []string{"service.name", "container.id"}, keys(attributes))
}

// The attributes an instrumented HTTP server sets for the request, so that a
// span of the agent and a span of the application describe it the same way.
func TestHttpRequestSpanAddressAttributes(t *testing.T) {
	tr, exp := testTrace(t)
	tr.HttpRequest("GET", "/products/42?ref=home", l7.Status(404), time.Millisecond, nil, time.Time{}, 0)
	tr.Http2Request("POST", "/orders", "https", l7.Status(200), -1, time.Millisecond, nil, time.Time{}, 0)
	spans := exp.GetSpans()
	require.Len(t, spans, 2)

	http1 := attrMap(spans[0].Attributes)
	require.Equal(t, "http://10.0.0.1:8080/products/42?ref=home", http1["http.url"].AsString())
	require.Equal(t, "/products/42?ref=home", http1["http.target"].AsString())
	require.Equal(t, "/products/42", http1["url.path"].AsString())
	require.Equal(t, "http", http1["http.scheme"].AsString())
	require.Equal(t, "10.0.0.1", http1["server.address"].AsString())
	require.Equal(t, int64(8080), http1["server.port"].AsInt64())

	http2 := attrMap(spans[1].Attributes)
	require.Equal(t, "https://10.0.0.1:8080/orders", http2["http.url"].AsString())
	require.Equal(t, "/orders", http2["http.target"].AsString())
	require.Equal(t, "/orders", http2["url.path"].AsString())
	require.Equal(t, "https", http2["http.scheme"].AsString())
}

// A span of an HTTP call is an error when the server failed (5xx) or the gRPC
// call did not succeed, the way Coroot counts failed requests in its SLIs and
// an instrumented server marks its spans; a 4xx is the client's mistake.
func TestHttpRequestSpanStatus(t *testing.T) {
	for _, status := range []int{200, 301, 400, 401, 404, 499, 500, 503} {
		tr, exp := testTrace(t)
		tr.HttpRequest("GET", "/x", l7.Status(status), time.Millisecond, nil, time.Time{}, 0)
		tr.Http2Request("GET", "/x", "http", l7.Status(status), -1, time.Millisecond, nil, time.Time{}, 0)
		spans := exp.GetSpans()
		require.Len(t, spans, 2)
		expected := codes.Unset
		if status >= 500 {
			expected = codes.Error
		}
		require.Equal(t, expected, spans[0].Status.Code, "HTTP/1 %d", status)
		require.Equal(t, expected, spans[1].Status.Code, "HTTP/2 %d", status)
	}

	tr, exp := testTrace(t)
	tr.Http2Request("POST", "/pkg.Service/Method", "http", l7.Status(200), l7.Status(14), time.Millisecond, nil, time.Time{}, 0) // grpc:UNAVAILABLE
	tr.Http2Request("POST", "/pkg.Service/Method", "http", l7.Status(200), l7.Status(0), time.Millisecond, nil, time.Time{}, 0)  // grpc:OK
	spans := exp.GetSpans()
	require.Equal(t, codes.Error, spans[0].Status.Code)
	require.Equal(t, codes.Unset, spans[1].Status.Code)
}

// The client and the server of a request name it the same, and only it.
func TestRequestKey(t *testing.T) {
	client := netaddr.MustParseIPPort("10.42.0.150:51234")
	server := netaddr.MustParseIPPort("10.42.0.140:3000")
	key := RequestKey(client, server, 3, "GET", "/products/42")
	mappedClient := netaddr.IPPortFrom(netaddr.IPv6Raw(client.IP().Unmap().As16()), client.Port())
	require.Equal(t, key, RequestKey(mappedClient, server, 3, "GET", "/products/42"), "an IPv4-mapped address is the same address")
	for _, other := range []uint64{
		RequestKey(client, server, 4, "GET", "/products/42"),                                       // the next request
		RequestKey(netaddr.MustParseIPPort("10.42.0.150:51235"), server, 3, "GET", "/products/42"), // another connection
		RequestKey(client, server, 3, "POST", "/products/42"),
		RequestKey(client, server, 3, "GET", "/products/43"),
	} {
		require.NotEqual(t, key, other)
	}
}

func TestServerSpan(t *testing.T) {
	tr, exp := testTrace(t)
	server := tr.tracer.NewServerTrace(netaddr.MustParseIPPort("10.42.0.140:3000"), netaddr.MustParseIPPort("10.42.0.150:51234"))
	server.HttpRequest("GET", "/products/42?ref=home", l7.Status(404), 2*time.Millisecond,
		&HttpBodies{Response: "not found", RequestSize: -1, ResponseSize: 9}, time.Time{}, 0xabc)
	server.HttpRequest("GET", "/api/error", l7.Status(500), time.Millisecond, nil, time.Time{}, 0)
	spans := exp.GetSpans()
	require.Len(t, spans, 2)

	require.Equal(t, trace.SpanKindServer, spans[0].SpanKind)
	require.Equal(t, codes.Unset, spans[0].Status.Code, "a 4xx is the client's mistake")
	a := attrMap(spans[0].Attributes)
	require.Equal(t, "GET", a["http.method"].AsString())
	require.Equal(t, int64(404), a["http.status_code"].AsInt64())
	require.Equal(t, "/products/42?ref=home", a["http.target"].AsString())
	require.Equal(t, "/products/42", a["url.path"].AsString())
	require.Equal(t, "10.42.0.140", a["server.address"].AsString())
	require.Equal(t, int64(3000), a["server.port"].AsInt64())
	require.Equal(t, "10.42.0.150", a["client.address"].AsString())
	require.Equal(t, int64(51234), a["client.port"].AsInt64())
	require.Equal(t, "not found", a["http.response.body"].AsString())
	require.Equal(t, "0000000000000abc", a[RequestKeyAttribute].AsString())
	require.NotContains(t, a, "net.peer.name", "the peer of a server span is its client")

	require.Equal(t, codes.Error, spans[1].Status.Code)
	require.NotContains(t, attrMap(spans[1].Attributes), RequestKeyAttribute, "no key when the number is not known")
}

func TestClientSpanCarriesItsRequestKey(t *testing.T) {
	tr, exp := testTrace(t)
	tr.HttpRequest("GET", "/x", l7.Status(200), time.Millisecond, nil, time.Time{}, 0x1f)
	require.Equal(t, "000000000000001f", attrMap(exp.GetSpans()[0].Attributes)[RequestKeyAttribute].AsString())
}

// A client span tells the address it was sent from, so that Coroot knows a
// client the world does not know yet (a pod started a moment ago) by its IP.
func TestClientSpanCarriesItsLocalAddress(t *testing.T) {
	_, exp := testTrace(t)
	tracer := &Tracer{otel: sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp)).Tracer("test")}
	trace := tracer.NewTrace(common.HostPortFromIPPort(netaddr.MustParseIPPort("10.42.0.140:3000")), netaddr.MustParseIPPort("10.42.0.150:41234"))
	trace.HttpRequest("GET", "/x", l7.Status(200), time.Millisecond, nil, time.Time{}, 0)
	a := attrMap(exp.GetSpans()[0].Attributes)
	require.Equal(t, "10.42.0.150", a["network.local.address"].AsString())
	require.Equal(t, int64(41234), a["network.local.port"].AsInt64())
}

// The server side of the other protocols: the same spans as at the client,
// of the server's kind and with the two ends instead of the peer.
func TestServerSpansOfOtherProtocols(t *testing.T) {
	tr, exp := testTrace(t)
	server := tr.tracer.NewServerTrace(netaddr.MustParseIPPort("10.42.0.20:5432"), netaddr.MustParseIPPort("10.42.0.150:40000"))
	server.PostgresQuery("SELECT 1", false, time.Millisecond)
	server.Http2Request("POST", "/pkg.Service/Method", "http", l7.Status(200), l7.Status(0), time.Millisecond, nil, time.Time{}, 7)
	spans := exp.GetSpans()
	require.Len(t, spans, 2)
	for _, span := range spans {
		require.Equal(t, trace.SpanKindServer, span.SpanKind)
		a := attrMap(span.Attributes)
		require.Equal(t, "10.42.0.20", a["server.address"].AsString())
		require.Equal(t, "10.42.0.150", a["client.address"].AsString())
		require.NotContains(t, a, "net.peer.name")
		require.NotContains(t, a, "http.url", "a server does not know the URL its client used")
	}
	require.Equal(t, "postgresql", attrMap(spans[0].Attributes)["db.system"].AsString())
	require.Equal(t, "0000000000000007", attrMap(spans[1].Attributes)[RequestKeyAttribute].AsString())
}
