package l7

import (
	"bytes"
	"testing"

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
