package tracing

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/coroot/coroot-node-agent/api"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/coroot/coroot-node-agent/flags"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.18.0"
	"go.opentelemetry.io/otel/trace"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

const (
	MemcacheDBItemKeyName attribute.Key = "db.memcached.item"
)

// Span accounting. spansCreated counts spans handed to the SDK (End called);
// spansExported/spansExportFailed count what the OTLP exporter actually sent
// or failed to send. The SDK's BatchSpanProcessor silently drops a span when
// its queue is full (it only logs that at debug level), so created minus
// (exported + failed), once the pipeline has drained, is exactly the number
// of spans lost between the agent's parser and the collector.
var (
	spansCreated      atomic.Uint64
	spansExported     atomic.Uint64
	spansExportFailed atomic.Uint64
)

// Stats returns the span counters described above.
func Stats() (created, exported, failed uint64) {
	return spansCreated.Load(), spansExported.Load(), spansExportFailed.Load()
}

// QueueStats returns the estimated bytes of the spans waiting for the exporter and the
// number of spans dropped because the queue was full (see queueBudget).
func QueueStats() (bytes int64, dropped uint64) {
	if budget == nil {
		return 0, 0
	}
	return budget.bytes.Load(), budget.dropped.Load()
}

var (
	batcher             sdktrace.TracerProviderOption
	budget              *queueBudget
	commonResourceAttrs []attribute.KeyValue
	agentVersion        string
	initialized         bool
	samplingRate        float64
)

func Init(machineId, hostname, version string) {
	endpointUrl := *flags.TracesEndpoint
	if endpointUrl == nil {
		klog.Infoln("no OpenTelemetry traces collector endpoint configured")
		return
	}

	samplingRate = *flags.TracesSampling
	if samplingRate < 0.0 || samplingRate > 1.0 {
		klog.Warningf("invalid traces-sampling value %f, must be between 0.0 and 1.0, using default 1.0", samplingRate)
		samplingRate = 1.0
	}
	if samplingRate < 1.0 {
		klog.Infof("trace sampling rate set to %f", samplingRate)
	}
	klog.Infoln("OpenTelemetry traces collector endpoint:", endpointUrl.String())
	path := endpointUrl.Path
	if path == "" {
		path = "/"
	}
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(endpointUrl.Host),
		otlptracehttp.WithURLPath(path),
		otlptracehttp.WithHeaders(api.AuthHeaders(*flags.ApiKey)),
		otlptracehttp.WithTLSClientConfig(api.TlsConfig(*flags.CAFile, *flags.InsecureSkipVerify)),
	}
	if endpointUrl.Scheme != "https" {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	client := otlptracehttp.NewClient(opts...)
	exporter, err := otlptrace.New(context.Background(), client)
	if err != nil {
		klog.Exitln(err)
	}

	// Every request between two containers with agents makes two spans (the
	// client's and the server's), and spans that carry bodies are several times
	// larger, so a burst of calls overflows the default queue (2048 spans). A
	// deeper queue absorbs the burst; what bounds its memory is
	// --traces-queue-max-bytes.
	const maxSpans = 16384
	budget = newQueueBudget(int64(*flags.TracesQueueMaxBytes), maxSpans)
	batcher = sdktrace.WithSpanProcessor(newBatcher(exporter, budget))
	commonResourceAttrs = []attribute.KeyValue{semconv.HostName(hostname), semconv.HostID(machineId)}
	agentVersion = version
	initialized = true
}

type Tracer struct {
	otel trace.Tracer
}

func shouldSample() bool {
	if samplingRate >= 1.0 {
		return true
	}
	if samplingRate <= 0.0 {
		return false
	}

	return rand.Float64() < samplingRate
}

func GetContainerTracer(containerId string) *Tracer {
	if !initialized {
		return &Tracer{otel: nil}
	}
	provider := sdktrace.NewTracerProvider(
		batcher,
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			append(commonResourceAttrs, containerResourceAttributes(containerId)...)...,
		)),
	)
	return &Tracer{otel: provider.Tracer("coroot-node-agent", trace.WithInstrumentationVersion(agentVersion))}
}

// containerResourceAttributes describe the container whose calls the spans
// are: its service and id, and for a container of a Kubernetes pod its
// namespace, pod (or cron job) and name, as an instrumented application
// running there reports them.
func containerResourceAttributes(containerId string) []attribute.KeyValue {
	attributes := []attribute.KeyValue{
		semconv.ServiceName(common.ContainerIdToOtelServiceName(containerId)),
		semconv.ContainerID(containerId),
	}
	container, ok := common.KubernetesContainerOf(containerId)
	if !ok {
		return attributes
	}
	attributes = append(attributes, semconv.K8SNamespaceName(container.Namespace), semconv.K8SContainerName(container.Container))
	if container.Pod != "" {
		attributes = append(attributes, semconv.K8SPodName(container.Pod))
	}
	if container.CronJob != "" {
		attributes = append(attributes, semconv.K8SCronJobName(container.CronJob))
	}
	return attributes
}

// NewTrace records the client side of the calls a container makes to
// destination.
// NewTrace records the client side of the requests of a connection to
// destination; client is its local end (zero when not known), by which Coroot
// knows a client pod before its world does.
func (t *Tracer) NewTrace(destination common.HostPort, client netaddr.IPPort) *Trace {
	attrs := []attribute.KeyValue{
		semconv.NetPeerName(destination.Host()),
		semconv.NetPeerPort(int(destination.Port())),
	}
	if client.IsValid() {
		attrs = append(attrs, attribute.String("network.local.address", client.IP().Unmap().String()), attribute.Int("network.local.port", int(client.Port())))
	}
	return &Trace{tracer: t, kind: trace.SpanKindClient, destination: destination, commonAttrs: attrs}
}

// NewServerTrace records the server side of the requests of a connection a
// container accepted: server is its local end, client the remote one (zero
// when the agent did not see the connection open).
func (t *Tracer) NewServerTrace(server, client netaddr.IPPort) *Trace {
	var attrs []attribute.KeyValue
	if server.IsValid() {
		attrs = append(attrs, attribute.String("server.address", server.IP().Unmap().String()), attribute.Int("server.port", int(server.Port())))
	}
	if client.IsValid() {
		attrs = append(attrs, attribute.String("client.address", client.IP().Unmap().String()), attribute.Int("client.port", int(client.Port())))
	}
	return &Trace{tracer: t, kind: trace.SpanKindServer, commonAttrs: attrs}
}

// Trace makes the spans of one side of the requests of a connection: the
// client side (SpanKindClient, to destination) or the server side.
type Trace struct {
	tracer      *Tracer
	kind        trace.SpanKind
	destination common.HostPort
	commonAttrs []attribute.KeyValue
}

// HttpBodies are the bodies of an HTTP call as captured by the eBPF side. A
// size is the real size when the message declared one, -1 when it did not; an
// empty body is not put on the span.
type HttpBodies struct {
	Request      string
	Response     string
	RequestSize  int64
	ResponseSize int64
}

func (b *HttpBodies) attrs() []attribute.KeyValue {
	if b == nil {
		return nil
	}
	var res []attribute.KeyValue
	if b.Request != "" {
		res = append(res, attribute.String("http.request.body", b.Request))
	}
	if b.Response != "" {
		res = append(res, attribute.String("http.response.body", b.Response))
	}
	if b.RequestSize >= 0 && b.Request != "" {
		res = append(res, attribute.Int64("http.request.body.size", b.RequestSize))
	}
	if b.ResponseSize >= 0 && b.Response != "" {
		res = append(res, attribute.Int64("http.response.body.size", b.ResponseSize))
	}
	return res
}

// createSpan makes a span that ended now.
func (t *Trace) createSpan(name string, duration time.Duration, error bool, attrs ...attribute.KeyValue) {
	t.createSpanAt(time.Time{}, name, duration, error, attrs...)
}

// createSpanAt makes a span of the trace's side that ended at `at` (now when
// zero): a span whose body was awaited is created later than the call ended.
func (t *Trace) createSpanAt(at time.Time, name string, duration time.Duration, error bool, attrs ...attribute.KeyValue) {
	t.tracer.createSpanAt(t.kind, at, name, duration, error, append(attrs, t.commonAttrs...)...)
}

// createSpanAt makes a span of the given kind that ended at `at` (now when zero).
func (t *Tracer) createSpanAt(kind trace.SpanKind, at time.Time, name string, duration time.Duration, error bool, attrs ...attribute.KeyValue) {
	if t.otel == nil {
		return
	}
	end := at
	if end.IsZero() {
		end = time.Now()
	}

	if !shouldSample() {
		return
	}

	start := end.Add(-duration)
	_, span := t.otel.Start(nil, name, trace.WithTimestamp(start), trace.WithSpanKind(kind))
	span.SetAttributes(attrs...)
	if error {
		span.SetStatus(codes.Error, "")
	}
	span.End(trace.WithTimestamp(end))
	spansCreated.Add(1)
}

// RequestKeyAttribute carries RequestKey on a span, as 16 hex digits.
const RequestKeyAttribute = "coroot.request.key"

// RequestKey names a request so that its client and its server, each recording
// it on its own node, name it the same: the two ends of the connection, the
// number of the request on it (counted by both from the connection's open, one
// request at a time), its method and its path. A 4-tuple is not used again for
// a minute after its connection closes (TIME_WAIT), so a key looked up within a
// few seconds of its request is the key of that request.
func RequestKey(client, server netaddr.IPPort, number uint64, method, path string) uint64 {
	h := xxhash.New()
	var buf [8]byte
	for _, end := range []netaddr.IPPort{client, server} {
		ip := end.IP().Unmap().As16()
		_, _ = h.Write(ip[:])
		binary.LittleEndian.PutUint16(buf[:2], end.Port())
		_, _ = h.Write(buf[:2])
	}
	binary.LittleEndian.PutUint64(buf[:], number)
	_, _ = h.Write(buf[:])
	_, _ = h.WriteString(method)
	_, _ = h.Write([]byte{0})
	_, _ = h.WriteString(path)
	return h.Sum64()
}

func requestKeyAttributes(requestKey uint64) []attribute.KeyValue {
	if requestKey == 0 {
		return nil
	}
	return []attribute.KeyValue{attribute.String(RequestKeyAttribute, fmt.Sprintf("%016x", requestKey))}
}

// httpAddressAttributes describe the address of an HTTP call the way an
// instrumented server describes the request: the whole URL, the target (path
// and query), the path, the scheme, and the server. path is the request
// target as sent, with its query.
func (t *Trace) httpAddressAttributes(scheme, path string) []attribute.KeyValue {
	urlPath, _, _ := strings.Cut(path, "?")
	if t.kind == trace.SpanKindServer {
		// the server's and the client's addresses are common attributes
		return []attribute.KeyValue{semconv.HTTPTarget(path), attribute.String("url.path", urlPath), semconv.HTTPScheme(scheme)}
	}
	return []attribute.KeyValue{
		semconv.HTTPURL(fmt.Sprintf("%s://%s%s", scheme, t.destination.String(), path)),
		semconv.HTTPTarget(path),
		attribute.String("url.path", urlPath),
		semconv.HTTPScheme(scheme),
		attribute.String("server.address", t.destination.Host()),
		attribute.Int("server.port", int(t.destination.Port())),
	}
}

// HttpRequest records an outbound HTTP/1 call. bodies may be nil; at is when
// the call ended (zero for now); requestKey is RequestKey, 0 when the number of
// the request on its connection is not known.
func (t *Trace) HttpRequest(method, path string, status l7.Status, duration time.Duration, bodies *HttpBodies, at time.Time, requestKey uint64) {
	if t == nil || method == "" {
		return
	}
	attrs := append(t.httpAddressAttributes("http", path),
		semconv.HTTPMethod(method),
		semconv.HTTPStatusCode(int(status)),
	)
	attrs = append(attrs, bodies.attrs()...)
	t.createSpanAt(at, method, duration, status.HttpServerError(), append(attrs, requestKeyAttributes(requestKey)...)...)
}

// Http2Request records an HTTP/2 (or gRPC) call. requestKey is RequestKey with
// the stream id as the number, 0 when the connection's ends are not known.
func (t *Trace) Http2Request(method, path, scheme string, status, grpcStatus l7.Status, duration time.Duration, bodies *HttpBodies, at time.Time, requestKey uint64) {
	if t == nil {
		return
	}
	if method == "" {
		method = "unknown"
	}
	if path == "" {
		path = "/unknown"
	}
	if scheme == "" {
		scheme = "unknown"
	}

	attrs := append(t.httpAddressAttributes(scheme, path),
		semconv.HTTPMethod(method),
		semconv.HTTPStatusCode(int(status)),
	)
	if grpcStatus >= 0 {
		attrs = append(attrs, semconv.RPCGRPCStatusCodeKey.Int(int(grpcStatus)))
	}
	attrs = append(attrs, bodies.attrs()...)
	t.createSpanAt(at, method, duration, status.HttpServerError() || grpcStatus > 0, append(attrs, requestKeyAttributes(requestKey)...)...)
}

func (t *Trace) PostgresQuery(query string, error bool, duration time.Duration) {
	if t == nil || query == "" {
		return
	}
	t.createSpan("query", duration, error,
		semconv.DBSystemPostgreSQL,
		semconv.DBStatement(query),
	)
}

func (t *Trace) MysqlQuery(query string, error bool, duration time.Duration) {
	if t == nil || query == "" {
		return
	}
	t.createSpan("query", duration, error,
		semconv.DBSystemMySQL,
		semconv.DBStatement(query),
	)
}

func (t *Trace) MongoQuery(query string, error bool, duration time.Duration) {
	if t == nil || query == "" {
		return
	}
	t.createSpan("query", duration, error,
		semconv.DBSystemMongoDB,
		semconv.DBStatement(query),
	)
}

func (t *Trace) MemcachedQuery(cmd string, items []string, error bool, duration time.Duration) {
	if t == nil || cmd == "" {
		return
	}
	attrs := []attribute.KeyValue{
		semconv.DBSystemMemcached,
		semconv.DBOperation(cmd),
	}
	if len(items) == 1 {
		attrs = append(attrs, MemcacheDBItemKeyName.String(items[0]))
	} else if len(items) > 1 {
		attrs = append(attrs, MemcacheDBItemKeyName.StringSlice(items))
	}
	t.createSpan(cmd, duration, error, attrs...)
}

func (t *Trace) RedisQuery(cmd, args string, error bool, duration time.Duration) {
	if t == nil || cmd == "" {
		return
	}
	statement := cmd
	if args != "" {
		statement += " " + args
	}
	t.createSpan(cmd, duration, error,
		semconv.DBSystemRedis,
		semconv.DBOperation(cmd),
		semconv.DBStatement(statement),
	)
}

func (t *Trace) ClickhouseQuery(query string, error bool, duration time.Duration) {
	if t == nil {
		return
	}
	t.createSpan("query", duration, error,
		semconv.DBSystemClickhouse,
		semconv.DBStatement(query),
	)
}

func (t *Trace) ZookeeperRequest(op string, args string, status l7.Status, duration time.Duration) {
	if t == nil {
		return
	}
	if op == "" {
		return
	}
	statement := op
	if args != "" {
		statement += " " + args
	}
	t.createSpan(op, duration, status.Zookeeper() != "ok",
		semconv.DBSystemKey.String("zookeeper"),
		semconv.DBOperation(op),
		semconv.DBStatementKey.String(statement),
		attribute.Key("zookeeper.status_code").Int(int(status)),
	)
}
