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

	// Set only by a parser created with NewHttp1ParserWithBodies. A size is the
	// real size when the message declared one, -1 when it did not; a body is
	// empty when none was captured or it was skipped (see BodyOptions.Decide).
	RequestBody      string
	ResponseBody     string
	RequestBodySize  int64
	ResponseBodySize int64
	// At is when the response headers were seen, the end of the call; the pair
	// can be released later than that while the response body is awaited.
	At time.Time
}

type http1PendingRequest struct {
	method     string
	path       string
	kernelTime uint64

	// body mode only
	hdr  http1Headers
	body *bodyCollector
}

// http1Headers are the few header values that decide whether and how a body is
// kept.
type http1Headers struct {
	contentLength   int64 // -1 when absent
	chunked         bool
	contentType     string
	contentEncoding string
}

func parseHttp1Headers(block []byte) http1Headers {
	h := http1Headers{contentLength: -1}
	lines := bytes.Split(block, []byte("\n"))
	for i, line := range lines {
		if i == 0 {
			continue
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		v := strings.TrimSpace(string(value))
		switch strings.ToLower(strings.TrimSpace(string(name))) {
		case "content-length":
			h.contentLength = parseContentLength(v)
		case "transfer-encoding":
			if strings.Contains(strings.ToLower(v), "chunked") {
				h.chunked = true
			}
		case "content-type":
			h.contentType = v
		case "content-encoding":
			h.contentEncoding = v
		}
	}
	return h
}

// http1Exchange is a request matched with its response headers, waiting for the
// response body to be complete.
type http1Exchange struct {
	req       *http1PendingRequest
	status    Status
	hdr       http1Headers
	body      *bodyCollector
	duration  time.Duration
	at        time.Time
	lastEvent time.Time
	noBody    bool
	complete  bool
	released  bool
}

const (
	// maxHttp1Pending bounds the requests and the responses a parser holds.
	maxHttp1Pending = 64
	// http1HoldMax bounds how long a response with an unknown end is held even
	// while data keeps arriving (a long-lived stream).
	http1HoldMax = 5 * time.Second
)

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
	pending        []*http1PendingRequest

	opts BodyOptions
	// body mode only: the newest request (client data belongs to it), the
	// responses whose body is still awaited, and the newest of them (server data
	// belongs to it)
	lastReq *http1PendingRequest
	held    []*http1Exchange
	curResp *http1Exchange
}

func NewHttp1Parser() *Http1Parser {
	return &Http1Parser{}
}

// NewHttp1ParserWithBodies is NewHttp1Parser that also keeps request and
// response bodies, and so holds a pair back until its response body is known to
// be complete (see Flush). With opts.Enabled false it is NewHttp1Parser.
func NewHttp1ParserWithBodies(opts BodyOptions) *Http1Parser {
	if opts.MaxBytes <= 0 || opts.MaxBytes > KernelBodyCaptureMax {
		opts.MaxBytes = KernelBodyCaptureMax
	}
	return &Http1Parser{opts: opts}
}

// Held is the number of responses waiting for their body.
func (p *Http1Parser) Held() int { return len(p.held) }

// trimLeadingCRLF drops empty lines before the start line of a header block.
// RFC 7230 3.5 has a recipient ignore at least one empty line before a
// request line, and the end of a chunked body leaves one behind: the "\r\n"
// that closes an empty trailer section.
func trimLeadingCRLF(b []byte) []byte {
	for len(b) >= 2 && b[0] == '\r' && b[1] == '\n' {
		b = b[2:]
	}
	return b
}

func (p *Http1Parser) Parse(method Method, payload []byte, kernelTime uint64) []Http1Request {
	return p.ParseAt(method, payload, kernelTime, time.Now())
}

// ParseAt is Parse with the wall-clock time of the event, which only matters
// when bodies are kept.
func (p *Http1Parser) ParseAt(method Method, payload []byte, kernelTime uint64, now time.Time) []Http1Request {
	switch method {
	case MethodHttpClientHeaders:
		if len(p.clientBuf) == 0 {
			payload = trimLeadingCRLF(payload)
			if len(payload) == 0 {
				return nil
			}
			p.clientBufStart = kernelTime
		}
		p.clientBuf = append(p.clientBuf, payload...)
		if bytes.HasSuffix(p.clientBuf, http1HeaderEnd) || len(p.clientBuf) >= http1CaptureMax {
			var released []Http1Request
			if m, path, ok := parseHttp1RequestLine(p.clientBuf); ok {
				req := &http1PendingRequest{method: m, path: path, kernelTime: p.clientBufStart}
				if p.opts.Enabled {
					// A request while nothing else is pipelined means the
					// connection moved on: the previous response ended.
					if len(p.pending) == 0 {
						released = p.releaseAll(now)
					}
					req.hdr = parseHttp1Headers(p.clientBuf)
					req.body = newBodyCollector(p.opts.MaxBytes)
					p.lastReq = req
				}
				p.pending = append(p.pending, req)
				if p.opts.Enabled && len(p.pending) > maxHttp1Pending {
					p.pending = p.pending[1:]
					BodyStats.DroppedQueueFull.Add(1)
				}
			}
			p.clientBuf = nil
			return released
		}
	case MethodHttpClientData:
		if p.opts.Enabled {
			if p.lastReq != nil {
				p.lastReq.body.Add(payload)
			} else {
				BodyStats.DroppedNoMessage.Add(1)
			}
		}
	case MethodHttpServerHeaders:
		if len(p.serverBuf) == 0 {
			payload = trimLeadingCRLF(payload)
			if len(payload) == 0 {
				return nil
			}
		}
		p.serverBuf = append(p.serverBuf, payload...)
		if bytes.HasSuffix(p.serverBuf, http1HeaderEnd) || len(p.serverBuf) >= http1CaptureMax {
			status, ok := parseHttp1StatusLine(p.serverBuf)
			block := p.serverBuf
			p.serverBuf = nil
			if !p.opts.Enabled {
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
				return nil
			}
			// A new response ends the previous one, whose body had no end marker.
			released := p.releaseAll(now)
			p.curResp = nil
			if !ok || len(p.pending) == 0 {
				return released
			}
			req := p.pending[0]
			p.pending = p.pending[1:]
			ex := &http1Exchange{
				req:       req,
				status:    status,
				hdr:       parseHttp1Headers(block),
				body:      newBodyCollector(p.opts.MaxBytes),
				duration:  time.Duration(kernelTime - req.kernelTime),
				at:        now,
				lastEvent: now,
			}
			ex.noBody = req.method == "HEAD" || status < 200 || status == 204 || status == 304 || ex.hdr.contentLength == 0
			p.curResp = ex
			if ex.noBody {
				return append(released, p.finish(ex))
			}
			p.held = append(p.held, ex)
			if len(p.held) > maxHttp1Pending {
				oldest := p.held[0]
				BodyStats.DroppedQueueFull.Add(1)
				released = append(released, p.finish(oldest))
			}
			return released
		}
	case MethodHttpServerData:
		if p.opts.Enabled {
			ex := p.curResp
			if ex == nil || ex.released {
				BodyStats.DroppedNoMessage.Add(1)
				return nil
			}
			ex.body.Add(payload)
			ex.lastEvent = now
			if !ex.hdr.chunked && ex.hdr.contentLength > 0 &&
				(int64(ex.body.Len()) >= ex.hdr.contentLength || ex.body.Full()) {
				return []Http1Request{p.finish(ex)}
			}
		}
	}
	return nil
}

// Flush releases the responses that have waited for their body long enough: no
// data for the configured wait, or held for too long overall. A parser without
// bodies never holds anything.
func (p *Http1Parser) Flush(now time.Time) []Http1Request {
	var out []Http1Request
	for _, ex := range append([]*http1Exchange(nil), p.held...) {
		if now.Sub(ex.lastEvent) >= p.opts.Wait || now.Sub(ex.at) >= http1HoldMax {
			out = append(out, p.finish(ex))
		}
	}
	return out
}

func (p *Http1Parser) releaseAll(now time.Time) []Http1Request {
	if len(p.held) == 0 {
		return nil
	}
	var out []Http1Request
	for _, ex := range append([]*http1Exchange(nil), p.held...) {
		out = append(out, p.finish(ex))
	}
	return out
}

// finish takes an exchange out of the held list and builds its result.
func (p *Http1Parser) finish(ex *http1Exchange) Http1Request {
	ex.released = true
	for i, h := range p.held {
		if h == ex {
			p.held = append(p.held[:i], p.held[i+1:]...)
			break
		}
	}
	reqSize := ex.req.hdr.contentLength
	respSize := ex.hdr.contentLength
	if ex.hdr.chunked {
		respSize = -1
	}
	if ex.req.hdr.chunked {
		reqSize = -1
	}
	reqBody, reqSize := p.opts.finishBody(ex.req.body, ex.req.hdr.contentType, ex.req.hdr.contentEncoding, reqSize)
	respBody := ""
	if !ex.noBody {
		respBody, respSize = p.opts.finishBody(ex.body, ex.hdr.contentType, ex.hdr.contentEncoding, respSize)
	}
	return Http1Request{
		Method:           ex.req.method,
		Path:             ex.req.path,
		Status:           ex.status,
		Duration:         ex.duration,
		RequestBody:      reqBody,
		ResponseBody:     respBody,
		RequestBodySize:  reqSize,
		ResponseBodySize: respSize,
		At:               ex.at,
	}
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
