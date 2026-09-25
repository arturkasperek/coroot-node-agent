package l7

import (
	"bytes"
	"strconv"
	"strings"
	"time"
)

type Http1Request struct {
	Method   string
	Path     string
	Status   Status
	Duration time.Duration
}

type http1PendingRequest struct {
	method     string
	path       string
	kernelTime uint64
}

var http1HeaderEnd = []byte("\r\n\r\n")

// http1CaptureMax mirrors HTTP1_CAPTURE_MAX in ebpf/l7/http1.c: once a
// header block this large has arrived without a "\r\n\r\n" terminator, the
// kernel side has already given up capturing more of it (headers longer
// than this are truncated there, not appended to further), so this side
// must also stop waiting for a terminator that will never come — or a
// later, unrelated request's header bytes would land in this stuck buffer
// forever.
const http1CaptureMax = 4096

// Http1Parser reassembles HTTP/1.x request/response headers captured as
// METHOD_HTTP_CLIENT_HEADERS/METHOD_HTTP_SERVER_HEADERS chunks (see
// ebpf/l7/http1.c) into Http1Request values, one per completed
// request/response pair. Unlike HTTP2, HTTP/1 has no stream id, so
// requests and responses on the same connection are matched strictly in
// arrival order (RFC 7230 requires a server to send responses in the same
// order it received their requests, pipelined or not).
//
// A single METHOD_HTTP_CLIENT_HEADERS (or _SERVER_HEADERS) payload never
// straddles two different requests' header blocks — http1.c always flushes
// the tail of one run (ending in "\r\n\r\n" if the terminator was found
// within the capture cap) as its own event before a fresh run's bytes are
// captured — so accumulating chunks until the running buffer ends in
// "\r\n\r\n" correctly reconstructs each header block regardless of how
// many chunks (or ring events) it was split across, including a body-less
// request immediately followed by the next request's headers with no DATA
// event in between.
type Http1Parser struct {
	clientBuf      []byte
	clientBufStart uint64
	serverBuf      []byte
	pending        []http1PendingRequest
}

func NewHttp1Parser() *Http1Parser {
	return &Http1Parser{}
}

func (p *Http1Parser) Parse(method Method, payload []byte, kernelTime uint64) []Http1Request {
	switch method {
	case MethodHttpClientHeaders:
		if len(p.clientBuf) == 0 {
			p.clientBufStart = kernelTime
		}
		p.clientBuf = append(p.clientBuf, payload...)
		if bytes.HasSuffix(p.clientBuf, http1HeaderEnd) || len(p.clientBuf) >= http1CaptureMax {
			if m, path, ok := parseHttp1RequestLine(p.clientBuf); ok {
				p.pending = append(p.pending, http1PendingRequest{method: m, path: path, kernelTime: p.clientBufStart})
			}
			p.clientBuf = nil
		}
	case MethodHttpServerHeaders:
		p.serverBuf = append(p.serverBuf, payload...)
		if bytes.HasSuffix(p.serverBuf, http1HeaderEnd) || len(p.serverBuf) >= http1CaptureMax {
			status, ok := parseHttp1StatusLine(p.serverBuf)
			p.serverBuf = nil
			if ok && len(p.pending) > 0 {
				req := p.pending[0]
				p.pending = p.pending[1:]
				return []Http1Request{{
					Method:   req.method,
					Path:     req.path,
					Status:   status,
					Duration: time.Duration(kernelTime - req.kernelTime),
				}}
			}
		}
	}
	return nil
}

func parseHttp1RequestLine(buf []byte) (method, path string, ok bool) {
	line := buf
	if i := bytes.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	line = bytes.TrimSuffix(line, []byte("\r"))
	m, rest, found := bytes.Cut(line, []byte(" "))
	if !found || !isHttpMethod(string(m)) {
		return "", "", false
	}
	uri, _, found := bytes.Cut(rest, []byte(" "))
	if !found {
		uri = rest
	}
	return string(m), string(uri), true
}

func parseHttp1StatusLine(buf []byte) (Status, bool) {
	line := buf
	if i := bytes.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	line = bytes.TrimSuffix(line, []byte("\r"))
	parts := strings.SplitN(string(line), " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return StatusUnknown, false
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return StatusUnknown, false
	}
	return Status(code), true
}
