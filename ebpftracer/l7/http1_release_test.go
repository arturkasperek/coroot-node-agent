package l7

import (
	"bytes"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The parser keeps pointers to the last request and the current response after their span
// is made: their bodies must not stay with them. Under connection churn a parser per
// connection held ~1 KB per body for every finished exchange (590 MB in a load test).
func requireBodiesReleased(t *testing.T, p *Http1Parser) {
	t.Helper()
	if p.lastReq != nil {
		assertReleased(t, p.lastReq.body, "request body of a finished exchange")
	}
	if p.curResp != nil && p.curResp.released {
		assertReleased(t, p.curResp.body, "response body of a finished exchange")
		assertReleased(t, p.curResp.req.body, "request body of a finished exchange")
	}
}

func assertReleased(t *testing.T, c *bodyCollector, what string) {
	t.Helper()
	assert.True(t, c.buf == nil, "%s still holds %d bytes", what, len(c.buf))
}

func TestHttp1BodiesAreReleasedWithTheirSpan(t *testing.T) {
	t.Run("content-length", func(t *testing.T) {
		p := newBodyParser(4096)
		p.Parse(MethodHttpClientHeaders, []byte("POST /a HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n"), 1)
		p.Parse(MethodHttpClientData, []byte(`{"a":1}`), 2)
		p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n"), 3)
		got := p.Parse(MethodHttpServerData, []byte(`{"b":2}`), 4)
		require.Len(t, got, 1)
		require.Equal(t, `{"a":1}`, got[0].RequestBody, "the span has its own copy of the bodies")
		require.Equal(t, `{"b":2}`, got[0].ResponseBody)
		requireBodiesReleased(t, p)
	})
	t.Run("a response without a body", func(t *testing.T) {
		p := newBodyParser(4096)
		p.Parse(MethodHttpClientHeaders, []byte("POST /a HTTP/1.1\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n"), 1)
		p.Parse(MethodHttpClientData, []byte("hello"), 2)
		got := p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 204 No Content\r\n\r\n"), 3)
		require.Len(t, got, 1)
		require.Equal(t, "hello", got[0].RequestBody)
		requireBodiesReleased(t, p)
	})
	t.Run("chunked, released by Flush", func(t *testing.T) {
		p := newBodyParser(4096)
		t0 := time.Now()
		p.ParseAt(MethodHttpClientHeaders, []byte("GET /s HTTP/1.1\r\n\r\n"), 1, t0)
		p.ParseAt(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n"), 2, t0)
		p.ParseAt(MethodHttpServerData, []byte("part"), 3, t0)
		got := p.Flush(t0.Add(time.Second))
		require.Len(t, got, 1)
		require.Equal(t, "part", got[0].ResponseBody)
		requireBodiesReleased(t, p)
	})
	t.Run("chunked, released by the next request", func(t *testing.T) {
		p := newBodyParser(4096)
		p.Parse(MethodHttpClientHeaders, []byte("GET /a HTTP/1.1\r\n\r\n"), 1)
		p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n"), 2)
		p.Parse(MethodHttpServerData, []byte("part"), 3)
		got := p.Parse(MethodHttpClientHeaders, []byte("GET /b HTTP/1.1\r\n\r\n"), 4)
		require.Len(t, got, 1)
		require.Equal(t, "part", got[0].ResponseBody)
		// lastReq is /b now and its body is still being collected; /a's response is released
		require.True(t, p.curResp.released)
		assertReleased(t, p.curResp.body, "response body of /a")
		assertReleased(t, p.curResp.req.body, "request body of /a")
	})
}

// A server can answer before the client has sent all of its body (a 413, a 401): the rest
// of the request body arrives after the span is made. It must not panic, and it must not
// change what was reported or what the next exchange reports.
func TestHttp1RequestDataAfterItsSpanIsIgnored(t *testing.T) {
	p := newBodyParser(4096)
	p.Parse(MethodHttpClientHeaders, []byte("POST /upload HTTP/1.1\r\nContent-Type: text/plain\r\nContent-Length: 10000\r\n\r\n"), 1)
	p.Parse(MethodHttpClientData, []byte("first"), 2)
	got := p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n"), 3)
	require.Len(t, got, 1)
	require.Equal(t, "first", got[0].RequestBody)

	require.NotPanics(t, func() {
		require.Empty(t, p.Parse(MethodHttpClientData, bytes.Repeat([]byte("x"), 2048), 4))
	})
	requireBodiesReleased(t, p)

	p.Parse(MethodHttpClientHeaders, []byte("POST /next HTTP/1.1\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\n"), 5)
	p.Parse(MethodHttpClientData, []byte("next"), 6)
	got = p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 7)
	require.Len(t, got, 1)
	require.Equal(t, "/next", got[0].Path)
	require.Equal(t, "next", got[0].RequestBody, "the next request collects its own body")
}

// Pipelining: when the span of the first request is made, the second one may still be
// receiving its body. Only the finished exchange gives its buffers back.
func TestHttp1PipelinedRequestKeepsItsBodyAfterAnEarlierSpan(t *testing.T) {
	p := newBodyParser(4096)
	p.Parse(MethodHttpClientHeaders, []byte("POST /one HTTP/1.1\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\n"), 1)
	p.Parse(MethodHttpClientData, []byte("aaa"), 2)
	p.Parse(MethodHttpClientHeaders, []byte("POST /two HTTP/1.1\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\n"), 3)
	p.Parse(MethodHttpClientData, []byte("bbb"), 4)
	r1 := p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 5)
	require.Len(t, r1, 1)
	require.Equal(t, "aaa", r1[0].RequestBody)

	p.Parse(MethodHttpClientData, []byte("ccc"), 6) // the rest of /two, after the span of /one
	r2 := p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 7)
	require.Len(t, r2, 1)
	require.Equal(t, "/two", r2[0].Path)
	require.Equal(t, "bbbccc", r2[0].RequestBody)
}

// What the agent keeps per connection, measured: a parser with one finished exchange whose
// request and response bodies were 1 KB each must not hold on to them.
func TestHttp1ParserDoesNotKeepBodiesOfFinishedExchanges(t *testing.T) {
	const parsers = 2000
	body := bytes.Repeat([]byte("a"), 1024)
	run := func() []*Http1Parser {
		ps := make([]*Http1Parser, parsers)
		for i := range ps {
			p := newBodyParser(4096)
			p.Parse(MethodHttpClientHeaders, []byte("POST /a HTTP/1.1\r\nContent-Type: text/plain\r\nContent-Length: 1024\r\n\r\n"), 1)
			p.Parse(MethodHttpClientData, body, 2)
			p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 1024\r\n\r\n"), 3)
			if got := p.Parse(MethodHttpServerData, body, 4); len(got) != 1 {
				t.Fatalf("exchange %d not finished", i)
			}
			ps[i] = p
		}
		return ps
	}
	heap := func() uint64 {
		runtime.GC()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		return ms.HeapAlloc
	}
	before := heap()
	ps := run()
	after := heap()
	perParser := float64(after-before) / parsers
	t.Logf("%.0f bytes kept per parser with one finished exchange", perParser)
	assert.Less(t, perParser, float64(len(body)), "less than one of its two 1 KB bodies")
	runtime.KeepAlive(ps)
}
