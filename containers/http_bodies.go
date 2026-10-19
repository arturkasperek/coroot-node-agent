package containers

import (
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/tracing"
)

// How often parsers that hold messages back for their bodies are asked to
// release the ones that have waited long enough (--http-body-wait).
const httpBodyFlushInterval = 250 * time.Millisecond

// bodyFlushMaxQueue: held messages are released after a quiet period measured
// when events are processed. If the event queue holds more than this the
// process is behind, the quiet period says nothing, and releasing would cut
// bodies that are already queued.
const bodyFlushMaxQueue = 16

func httpBodyOptions() l7.BodyOptions {
	opts := l7.DefaultBodyOptions()
	opts.Enabled = *flags.HttpBodyCapture
	if n := *flags.HttpBodyMaxBytes; n > 0 {
		opts.MaxBytes = n
	}
	if len(*flags.HttpBodyContentTypes) > 0 {
		opts.ContentTypes = *flags.HttpBodyContentTypes
	}
	if w := *flags.HttpBodyWait; w > 0 {
		opts.Wait = w
	}
	return opts
}

// newHttp1Parser and newHttp2Parser create the parsers of outbound
// connections: with --http-body-capture they keep bodies, otherwise they are
// exactly the plain parsers. Inbound parsers never keep bodies.
func newHttp1Parser() *l7.Http1Parser {
	if *flags.HttpBodyCapture {
		return l7.NewHttp1ParserWithBodies(httpBodyOptions())
	}
	return l7.NewHttp1Parser()
}

func newHttp2Parser() *l7.Http2Parser {
	if *flags.HttpBodyCapture {
		return l7.NewHttp2ParserWithBodies(httpBodyOptions())
	}
	return l7.NewHttp2Parser()
}

func http1Bodies(req l7.Http1Request) *tracing.HttpBodies {
	if req.RequestBody == "" && req.ResponseBody == "" {
		return nil
	}
	return &tracing.HttpBodies{Request: req.RequestBody, Response: req.ResponseBody, RequestSize: req.RequestBodySize, ResponseSize: req.ResponseBodySize}
}

func http2Bodies(req l7.Http2Request) *tracing.HttpBodies {
	if req.RequestBody == "" && req.ResponseBody == "" {
		return nil
	}
	return &tracing.HttpBodies{Request: req.RequestBody, Response: req.ResponseBody, RequestSize: req.RequestBodySize, ResponseSize: req.ResponseBodySize}
}

// noteBodyHolder remembers a connection whose parser holds messages back, so
// flushHttpBodies visits only those. Called with c.lock held.
func (c *Container) noteBodyHolder(conn *ActiveConnection) {
	if conn.http1Parser == nil && conn.http2Parser == nil {
		return
	}
	if (conn.http1Parser != nil && conn.http1Parser.Held() > 0) || (conn.http2Parser != nil && conn.http2Parser.Held() > 0) {
		if c.bodyHolders == nil {
			c.bodyHolders = map[*ActiveConnection]struct{}{}
		}
		c.bodyHolders[conn] = struct{}{}
	}
}

func (c *Container) traceFor(conn *ActiveConnection) *tracing.Trace {
	if c.ebpfTracesDisabled() {
		return nil
	}
	return c.tracer.NewTrace(conn.DestinationKey.ActualDestinationIfKnown(), conn.key.src)
}

// flushHttpBodies creates the spans of the messages that were held back for
// their bodies and have waited long enough.
func (c *Container) flushHttpBodies(now time.Time) {
	c.lock.Lock()
	defer c.lock.Unlock()
	for conn := range c.bodyHolders {
		if !c.flushConnectionBodies(conn, now) {
			delete(c.bodyHolders, conn)
		}
	}
	for _, p := range c.processes {
		for fd, state := range p.inboundHttp1Parsers {
			if state.parser.Held() > 0 {
				c.observeInboundHttp1(p, fd, state, state.parser.Flush(now))
			}
		}
		for fd, state := range p.inboundHttp2Parsers {
			if state.parser.Held() > 0 {
				c.observeInboundHttp2(p, fd, state, state.parser.Flush(now))
			}
		}
	}
}

// flushConnectionBodies creates the spans of the messages of one connection that
// have waited long enough for their bodies, and says whether it still holds any.
// Called with c.lock held.
func (c *Container) flushConnectionBodies(conn *ActiveConnection, now time.Time) (held bool) {
	if conn.http1Parser != nil {
		if reqs := conn.http1Parser.Flush(now); len(reqs) > 0 {
			stats := c.l7Stats.get(l7.ProtocolHTTP, conn.DestinationKey)
			trace := c.traceFor(conn)
			for _, req := range reqs {
				c.observeOutboundHttp1(conn, stats, trace, req)
			}
		}
	}
	if conn.http2Parser != nil {
		if reqs := conn.http2Parser.Flush(now); len(reqs) > 0 {
			stats := c.l7Stats.get(l7.ProtocolHTTP2, conn.DestinationKey)
			trace := c.traceFor(conn)
			for _, req := range reqs {
				c.observeHttp2(stats, trace, req, outboundHttp2RequestKey(conn, req))
			}
		}
	}
	return (conn.http1Parser != nil && conn.http1Parser.Held() > 0) || (conn.http2Parser != nil && conn.http2Parser.Held() > 0)
}

// observeHttp1 and observeHttp2 count a finished call and create its span; the
// live path, the replay of events that arrived before their connection was
// registered and flushHttpBodies all end here.
// observeOutboundHttp1 numbers a request of an outbound connection, in the
// order the parser hands the requests over (a request held for its body
// comes later, but still before the requests after it), and observes it.
func (c *Container) observeOutboundHttp1(conn *ActiveConnection, stats *L7Metrics, trace *tracing.Trace, req l7.Http1Request) {
	conn.http1Requests++
	c.observeHttp1(stats, trace, req, outboundRequestKey(conn, req))
}

func (c *Container) observeHttp1(stats *L7Metrics, trace *tracing.Trace, req l7.Http1Request, requestKey uint64) {
	c.registry.http1RequestsParsed.Add(1)
	if common.HttpFilter.ShouldBeSkipped(req.Path) {
		return
	}
	stats.observe(req.Status.Http(), "", req.Duration)
	trace.HttpRequest(req.Method, req.Path, req.Status, req.Duration, http1Bodies(req), req.At, requestKey)
}

func (c *Container) observeHttp2(stats *L7Metrics, trace *tracing.Trace, req l7.Http2Request, requestKey uint64) {
	c.registry.http2RequestsParsed.Add(1)
	if common.HttpFilter.ShouldBeSkipped(req.Path) {
		return
	}
	status := req.Status.Http()
	if req.GrpcStatus >= 0 {
		status = req.GrpcStatus.GRPC()
	}
	stats.observe(status, "", req.Duration)
	trace.Http2Request(req.Method, req.Path, req.Scheme, req.Status, req.GrpcStatus, req.Duration, http2Bodies(req), req.At, requestKey)
}
