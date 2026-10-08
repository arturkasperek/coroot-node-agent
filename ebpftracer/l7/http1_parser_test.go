package l7

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHttp1ParserBasic(t *testing.T) {
	p := NewHttp1Parser()
	require.Empty(t, p.Parse(MethodHttpClientHeaders, []byte("GET /users HTTP/1.1\r\nHost: x\r\n\r\n"), 1))
	got := p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n"), 5)
	require.Len(t, got, 1)
	require.Equal(t, "GET", got[0].Method)
	require.Equal(t, "/users", got[0].Path)
	require.Equal(t, Status(200), got[0].Status)
	require.Equal(t, int64(4), int64(got[0].Duration))
}

func TestHttp1ParserHeadersSplitAcrossChunks(t *testing.T) {
	p := NewHttp1Parser()
	req := []byte("GET /users HTTP/1.1\r\nHost: x\r\n\r\n")
	split := len(req) / 2
	require.Empty(t, p.Parse(MethodHttpClientHeaders, req[:split], 1))
	require.Empty(t, p.Parse(MethodHttpClientHeaders, req[split:], 1))

	resp := []byte("HTTP/1.1 404 Not Found\r\n\r\n")
	rsplit := len(resp) / 2
	require.Empty(t, p.Parse(MethodHttpServerHeaders, resp[:rsplit], 1))
	got := p.Parse(MethodHttpServerHeaders, resp[rsplit:], 1)
	require.Len(t, got, 1)
	require.Equal(t, "GET", got[0].Method)
	require.Equal(t, "/users", got[0].Path)
	require.Equal(t, Status(404), got[0].Status)
}

// TestHttp1ParserPipelinedRequests checks FIFO request/response matching: a
// second request's headers arriving with no DATA chunk in between (a
// body-less GET, matching real http1.c behavior — see http1_capture_data)
// must not get appended onto the first request's already-finished headers.
func TestHttp1ParserPipelinedRequests(t *testing.T) {
	p := NewHttp1Parser()
	require.Empty(t, p.Parse(MethodHttpClientHeaders, []byte("GET /one HTTP/1.1\r\nHost: x\r\n\r\n"), 1))
	require.Empty(t, p.Parse(MethodHttpClientHeaders, []byte("GET /two HTTP/1.1\r\nHost: x\r\n\r\n"), 2))

	got := p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\n\r\n"), 3)
	require.Len(t, got, 1)
	require.Equal(t, "/one", got[0].Path)

	got = p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 201 Created\r\n\r\n"), 4)
	require.Len(t, got, 1)
	require.Equal(t, "/two", got[0].Path)
	require.Equal(t, Status(201), got[0].Status)
}

// TestHttp1ParserHeadersOverCapForceCompletes mirrors http1.c's own
// HTTP1_CAPTURE_MAX truncation: once http1CaptureMax bytes have arrived
// with no "\r\n\r\n" (headers longer than the kernel-side cap), the parser
// must stop waiting for a terminator that will never show up in the
// captured bytes, using the request line (always near the start) instead.
func TestHttp1ParserHeadersOverCapForceCompletes(t *testing.T) {
	p := NewHttp1Parser()
	head := []byte("GET /users HTTP/1.1\r\nHost: x\r\nX-Pad: ")
	buf := append(head, bytes.Repeat([]byte{'a'}, http1CaptureMax-len(head))...)
	require.Equal(t, http1CaptureMax, len(buf))
	require.Empty(t, p.Parse(MethodHttpClientHeaders, buf, 1))

	got := p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\n\r\n"), 2)
	require.Len(t, got, 1)
	require.Equal(t, "GET", got[0].Method)
	require.Equal(t, "/users", got[0].Path)
}

func TestHttp1ParserNoPendingRequestIsIgnored(t *testing.T) {
	p := NewHttp1Parser()
	// A response with no matching request (e.g. we attached mid-stream)
	// must not panic or emit a bogus Http1Request.
	require.Empty(t, p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\n\r\n"), 1))
}

// The end of a chunked body leaves an empty line that the kernel side used to
// report as a header event of its own. It must not poison the next response on
// the same connection.
func TestHttp1ParserEmptyLineAfterChunkedResponse(t *testing.T) {
	p := NewHttp1Parser()
	for i := 0; i < 3; i++ {
		require.Empty(t, p.Parse(MethodHttpClientHeaders, []byte("POST /echo HTTP/1.1\r\nHost: x\r\n\r\n"), uint64(10*i+1)))
		got := p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"), uint64(10*i+5))
		require.Len(t, got, 1, "exchange %d", i)
		require.Equal(t, "/echo", got[0].Path)
		require.Empty(t, p.Parse(MethodHttpServerHeaders, []byte("\r\n"), uint64(10*i+6)))
	}
	// An empty line before a request is ignored the same way.
	require.Empty(t, p.Parse(MethodHttpClientHeaders, []byte("\r\n"), 100))
	require.Empty(t, p.Parse(MethodHttpClientHeaders, []byte("GET /next HTTP/1.1\r\n\r\n"), 101))
	got := p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 204 No Content\r\n\r\n"), 105)
	require.Len(t, got, 1)
	require.Equal(t, "/next", got[0].Path)
}

func newBodyParser(max int) *Http1Parser {
	opts := DefaultBodyOptions()
	opts.Enabled = true
	opts.MaxBytes = max
	return NewHttp1ParserWithBodies(opts)
}

func TestHttp1BodiesContentLength(t *testing.T) {
	p := newBodyParser(4096)
	p.Parse(MethodHttpClientHeaders, []byte("POST /orders HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n"), 1)
	p.Parse(MethodHttpClientData, []byte(`{"a":1}`), 2)
	require.Empty(t, p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n"), 5))
	got := p.Parse(MethodHttpServerData, []byte(`{"id":"ab"}`), 6)
	require.Len(t, got, 1)
	require.Equal(t, "/orders", got[0].Path)
	require.Equal(t, Status(201), got[0].Status)
	require.Equal(t, `{"a":1}`, got[0].RequestBody)
	require.Equal(t, `{"id":"ab"}`, got[0].ResponseBody)
	require.Equal(t, int64(7), got[0].RequestBodySize)
	require.Equal(t, int64(11), got[0].ResponseBodySize)
	require.Equal(t, 4*time.Nanosecond, got[0].Duration, "duration is still request headers to response headers")
	require.False(t, got[0].At.IsZero())
}

func TestHttp1NoBodyCompletesOnHeaders(t *testing.T) {
	p := newBodyParser(4096)
	p.Parse(MethodHttpClientHeaders, []byte("GET /users HTTP/1.1\r\nHost: x\r\n\r\n"), 1)
	got := p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 204 No Content\r\n\r\n"), 2)
	require.Len(t, got, 1)
	require.Empty(t, got[0].RequestBody)
	require.Empty(t, got[0].ResponseBody)

	// HEAD: a Content-Length without a body
	p.Parse(MethodHttpClientHeaders, []byte("HEAD /users HTTP/1.1\r\nHost: x\r\n\r\n"), 3)
	got = p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n"), 4)
	require.Len(t, got, 1)
	require.Empty(t, got[0].ResponseBody)

	// Content-Length: 0
	p.Parse(MethodHttpClientHeaders, []byte("GET /empty HTTP/1.1\r\nHost: x\r\n\r\n"), 5)
	got = p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 6)
	require.Len(t, got, 1)
	require.Equal(t, "/empty", got[0].Path)
}

func TestHttp1ChunkedWaitsForFlush(t *testing.T) {
	p := newBodyParser(4096)
	t0 := time.Now()
	p.ParseAt(MethodHttpClientHeaders, []byte("GET /stream HTTP/1.1\r\nHost: x\r\n\r\n"), 1, t0)
	require.Empty(t, p.ParseAt(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n"), 2, t0))
	require.Empty(t, p.ParseAt(MethodHttpServerData, []byte("hello "), 3, t0.Add(10*time.Millisecond)))
	require.Empty(t, p.ParseAt(MethodHttpServerData, []byte("world"), 4, t0.Add(20*time.Millisecond)))
	require.Equal(t, 1, p.Held())

	require.Empty(t, p.Flush(t0.Add(100*time.Millisecond)), "still within the wait after the last data")
	got := p.Flush(t0.Add(300 * time.Millisecond))
	require.Len(t, got, 1)
	require.Equal(t, "hello world", got[0].ResponseBody)
	require.Equal(t, int64(-1), got[0].ResponseBodySize)
	require.Equal(t, 0, p.Held())
	require.WithinDuration(t, t0, got[0].At, time.Millisecond, "the span keeps the time of the response headers")
}

func TestHttp1ChunkedReleasedByNextRequest(t *testing.T) {
	p := newBodyParser(4096)
	p.Parse(MethodHttpClientHeaders, []byte("GET /a HTTP/1.1\r\nHost: x\r\n\r\n"), 1)
	p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"), 2)
	p.Parse(MethodHttpServerData, []byte(`{"k":1}`), 3)
	// a keep-alive connection that moved on: the next request ends the previous response
	got := p.Parse(MethodHttpClientHeaders, []byte("GET /b HTTP/1.1\r\nHost: x\r\n\r\n"), 4)
	require.Len(t, got, 1)
	require.Equal(t, "/a", got[0].Path)
	require.Equal(t, `{"k":1}`, got[0].ResponseBody)
}

func TestHttp1ChunkedReleasedByNextResponse(t *testing.T) {
	p := newBodyParser(4096)
	// pipelined: the second request is already sent when the first response is still streaming
	p.Parse(MethodHttpClientHeaders, []byte("GET /a HTTP/1.1\r\nHost: x\r\n\r\n"), 1)
	p.Parse(MethodHttpClientHeaders, []byte("GET /b HTTP/1.1\r\nHost: x\r\n\r\n"), 2)
	p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"), 3)
	p.Parse(MethodHttpServerData, []byte("first"), 4)
	got := p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 5)
	require.Len(t, got, 2)
	require.Equal(t, "/a", got[0].Path)
	require.Equal(t, "first", got[0].ResponseBody)
	require.Equal(t, "/b", got[1].Path)
}

func TestHttp1BodyTruncatedAtMax(t *testing.T) {
	p := newBodyParser(100)
	p.Parse(MethodHttpClientHeaders, []byte("POST /big HTTP/1.1\r\nHost: x\r\nContent-Length: 5000\r\nContent-Type: text/plain\r\n\r\n"), 1)
	p.Parse(MethodHttpClientData, bytes.Repeat([]byte("a"), 1024), 2)
	p.Parse(MethodHttpClientData, bytes.Repeat([]byte("a"), 1024), 3)
	p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nContent-Length: 5000\r\nContent-Type: text/plain\r\n\r\n"), 4)
	got := p.Parse(MethodHttpServerData, bytes.Repeat([]byte("b"), 1024), 5)
	require.Len(t, got, 1, "the response is complete once max bytes are in, the kernel sends no more")
	require.Equal(t, strings.Repeat("a", 100), got[0].RequestBody)
	require.Equal(t, strings.Repeat("b", 100), got[0].ResponseBody)
	require.Equal(t, int64(5000), got[0].RequestBodySize)
	require.Equal(t, int64(5000), got[0].ResponseBodySize)
}

func TestHttp1BodyDataSplitAcrossEvents(t *testing.T) {
	p := newBodyParser(4096)
	p.Parse(MethodHttpClientHeaders, []byte("POST /x HTTP/1.1\r\nContent-Length: 3000\r\n\r\n"), 1)
	body := strings.Repeat("0123456789", 300)
	for i := 0; i < 3; i++ {
		p.Parse(MethodHttpClientData, []byte(body[i*1000:(i+1)*1000]), uint64(2+i))
	}
	got := p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 9)
	require.Len(t, got, 1)
	require.Equal(t, body, got[0].RequestBody)
	require.Equal(t, int64(3000), got[0].RequestBodySize)
}

func TestHttp1GzipAndBinaryAreSkipped(t *testing.T) {
	p := newBodyParser(4096)
	p.Parse(MethodHttpClientHeaders, []byte("POST /x HTTP/1.1\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\n\r\n"), 1)
	p.Parse(MethodHttpClientData, []byte("\x1f\x8b\x08\x00"), 2)
	p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 4\r\n\r\n"), 3)
	got := p.Parse(MethodHttpServerData, []byte("\x89PNG"), 4)
	require.Len(t, got, 1, "the span is still produced")
	require.Equal(t, "/x", got[0].Path)
	require.Empty(t, got[0].RequestBody)
	require.Empty(t, got[0].ResponseBody)
}

func TestHttp1PipelinedBodiesStayWithTheirRequests(t *testing.T) {
	p := newBodyParser(4096)
	p.Parse(MethodHttpClientHeaders, []byte("POST /one HTTP/1.1\r\nContent-Length: 3\r\n\r\n"), 1)
	p.Parse(MethodHttpClientData, []byte("aaa"), 2)
	p.Parse(MethodHttpClientHeaders, []byte("POST /two HTTP/1.1\r\nContent-Length: 3\r\n\r\n"), 3)
	p.Parse(MethodHttpClientData, []byte("bbb"), 4)
	p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n"), 5)
	r1 := p.Parse(MethodHttpServerData, []byte("1"), 6)
	p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n"), 7)
	r2 := p.Parse(MethodHttpServerData, []byte("2"), 8)
	require.Len(t, r1, 1)
	require.Len(t, r2, 1)
	require.Equal(t, "aaa", r1[0].RequestBody)
	require.Equal(t, "1", r1[0].ResponseBody)
	require.Equal(t, "bbb", r2[0].RequestBody)
	require.Equal(t, "2", r2[0].ResponseBody)
}

func TestHttp1DataWithoutMessageIsDropped(t *testing.T) {
	p := newBodyParser(4096)
	require.Empty(t, p.Parse(MethodHttpClientData, []byte("orphan"), 1))
	require.Empty(t, p.Parse(MethodHttpServerData, []byte("orphan"), 2))
	p.Parse(MethodHttpClientHeaders, []byte("GET /x HTTP/1.1\r\n\r\n"), 3)
	got := p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 4)
	require.Len(t, got, 1)
	require.Empty(t, got[0].RequestBody)
}

func TestHttp1HeldQueueIsBounded(t *testing.T) {
	p := newBodyParser(4096)
	var released int
	for i := 0; i < 70; i++ {
		p.Parse(MethodHttpClientHeaders, []byte("GET /s HTTP/1.1\r\n\r\n"), uint64(2*i+1))
		released += len(p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"), uint64(2*i+2)))
		// every response is chunked and never finishes, the next request releases it
	}
	require.LessOrEqual(t, p.Held(), 64)
	_ = released
}

func TestHttp1DisabledIsUnchanged(t *testing.T) {
	p := NewHttp1Parser()
	p.Parse(MethodHttpClientHeaders, []byte("POST /x HTTP/1.1\r\nContent-Length: 3\r\n\r\n"), 1)
	p.Parse(MethodHttpClientData, []byte("abc"), 2)
	got := p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n"), 3)
	require.Len(t, got, 1, "completes on the response headers, as before")
	require.Empty(t, got[0].RequestBody)
	require.Empty(t, got[0].ResponseBody)
	require.True(t, got[0].At.IsZero())
	require.Equal(t, 0, p.Held())
	require.Empty(t, p.Flush(time.Now().Add(time.Hour)))
}
