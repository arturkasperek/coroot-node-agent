package l7

import (
	"encoding/binary"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	http2FrameHeaderLength = 9
	http2DecoderGcInterval = uint64(10 * time.Minute)
	// A ring message is at most 1KB. A frame whose declared length is within
	// that bound can arrive split across several messages.
	http2ReassemblyMax = 1024
)

type Http2FrameHeader struct {
	Type     http2.FrameType
	Flags    http2.Flags
	Length   int
	StreamId uint32
}

type Http2Request struct {
	Method     string
	Path       string
	Scheme     string
	Status     Status
	GrpcStatus Status
	Duration   time.Duration

	// Set only by a parser created with NewHttp2ParserWithBodies; see Http1Request.
	RequestBody      string
	ResponseBody     string
	RequestBodySize  int64
	ResponseBodySize int64
	At               time.Time

	kernelTime uint64
	streamId   uint32
}

// StreamId is the HTTP/2 stream the request was sent on.
func (r *Http2Request) StreamId() uint32 { return r.streamId }

// http2BodyHeaders are the header values that decide whether a body is kept.
type http2BodyHeaders struct {
	contentType     string
	contentEncoding string
	contentLength   int64 // -1 when absent
}

// http2Stream is the state of one request/response pair in flight.
type http2Stream struct {
	Http2Request

	// body mode only
	reqHdr, respHdr         http2BodyHeaders
	reqBody, respBody       *bodyCollector
	reqSkipped, respSkipped bool
	haveResp                bool
	respEnded               bool
	lastEvent               time.Time
}

// http2DataState is a DATA frame whose body is still arriving: the kernel cuts
// a frame at the end of a write and sends the rest as raw continuation bytes.
type http2DataState struct {
	stream    *http2Stream
	remaining int
	padded    bool
	endStream bool
}

// http2HoldMax bounds how long a response that has not ended is held.
const http2HoldMax = 5 * time.Second

type http2PartialFrame struct {
	header Http2FrameHeader
	body   []byte
}

type Http2Parser struct {
	clientDecoder  *hpack.Decoder
	serverDecoder  *hpack.Decoder
	activeRequests map[uint32]*http2Stream
	lastGcTime     uint64
	clientPartial  *http2PartialFrame
	serverPartial  *http2PartialFrame
	clientHeader   []byte
	serverHeader   []byte

	opts       BodyOptions
	held       map[uint32]*http2Stream
	clientData *http2DataState
	serverData *http2DataState
}

func NewHttp2Parser() *Http2Parser {
	return &Http2Parser{
		clientDecoder:  hpack.NewDecoder(4096, nil),
		serverDecoder:  hpack.NewDecoder(4096, nil),
		activeRequests: map[uint32]*http2Stream{},
	}
}

// NewHttp2ParserWithBodies is NewHttp2Parser that also keeps request and
// response bodies (DATA frames), and so returns a request when its response
// stream ends rather than on the response headers. With opts.Enabled false it
// is NewHttp2Parser.
func NewHttp2ParserWithBodies(opts BodyOptions) *Http2Parser {
	if opts.MaxBytes <= 0 || opts.MaxBytes > KernelBodyCaptureMax {
		opts.MaxBytes = KernelBodyCaptureMax
	}
	p := NewHttp2Parser()
	p.opts = opts
	p.held = map[uint32]*http2Stream{}
	return p
}

// Held is the number of responses waiting for their stream to end.
func (p *Http2Parser) Held() int { return len(p.held) }

func (p *Http2Parser) Parse(method Method, payload []byte, kernelTime uint64) []Http2Request {
	return p.ParseAt(method, payload, kernelTime, time.Now())
}

// ParseAt is Parse with the wall-clock time of the event, which only matters
// when bodies are kept.
func (p *Http2Parser) ParseAt(method Method, payload []byte, kernelTime uint64, now time.Time) []Http2Request {
	if method == MethodHttp2ClientFrames {
		l := len(http2.ClientPreface)
		if len(payload) >= l && string(payload[:l]) == http2.ClientPreface {
			payload = payload[l:]
		}
	}
	if len(payload) == 0 {
		return nil
	}

	var decoder *hpack.Decoder
	var partial **http2PartialFrame
	var header *[]byte
	var data **http2DataState
	touched := map[uint32]struct{}{}
	statuses := map[uint32]Status{}
	grpcStatuses := map[uint32]Status{}

	switch method {
	case MethodHttp2ClientFrames:
		decoder = p.clientDecoder
		partial = &p.clientPartial
		header = &p.clientHeader
		data = &p.clientData
	case MethodHttp2ServerFrames:
		decoder = p.serverDecoder
		partial = &p.serverPartial
		header = &p.serverHeader
		data = &p.serverData
	default:
		return nil
	}
	defer decoder.Close()

	rest := payload
	if *data != nil {
		// the rest of a DATA frame whose first part ended the previous event
		d := *data
		n := d.remaining
		if n > len(rest) {
			n = len(rest)
		}
		p.appendData(method, d, rest[:n], now)
		d.remaining -= n
		rest = rest[n:]
		if d.remaining == 0 {
			p.finishData(method, d, touched)
			*data = nil
		}
	}
	if *partial == nil && len(*header) > 0 {
		rest = append(append([]byte{}, *header...), rest...)
		*header = nil
	}
	if *partial != nil {
		need := (*partial).header.Length - len((*partial).body)
		if need > len(rest) {
			(*partial).body = append((*partial).body, rest...)
			return nil
		}
		body := append((*partial).body, rest[:need]...)
		h := (*partial).header
		rest = rest[need:]
		*partial = nil
		p.handleHeaders(method, decoder, h, body, kernelTime, statuses, grpcStatuses, touched)
	}

	for {
		if len(rest) < http2FrameHeaderLength {
			if len(rest) > 0 {
				*header = append([]byte(nil), rest...)
			}
			break
		}
		h := Http2FrameHeader{
			Length:   int(binary.BigEndian.Uint32(rest) >> 8),
			Type:     http2.FrameType(rest[3]),
			Flags:    http2.Flags(rest[4]),
			StreamId: binary.BigEndian.Uint32(rest[5:]) & (1<<31 - 1),
		}
		if p.opts.Enabled && h.Type == http2.FrameData {
			// Streamed rather than reassembled: a body can be far larger than a
			// ring message, and only the bytes are wanted, not the whole frame.
			avail := len(rest) - http2FrameHeaderLength
			n := h.Length
			if n > avail {
				n = avail
			}
			d := &http2DataState{
				stream:    p.activeRequests[h.StreamId],
				remaining: h.Length - n,
				padded:    h.Flags.Has(http2.FlagDataPadded),
				endStream: h.Flags.Has(http2.FlagDataEndStream),
			}
			p.appendData(method, d, rest[http2FrameHeaderLength:http2FrameHeaderLength+n], now)
			rest = rest[http2FrameHeaderLength+n:]
			if d.remaining > 0 {
				*data = d
				break
			}
			p.finishData(method, d, touched)
			continue
		}
		if h.Length < 0 || len(rest)-http2FrameHeaderLength < h.Length {
			if h.Length >= 0 && h.Length <= http2ReassemblyMax {
				body := append([]byte(nil), rest[http2FrameHeaderLength:]...)
				*partial = &http2PartialFrame{header: h, body: body}
			}
			break
		}
		body := rest[http2FrameHeaderLength : http2FrameHeaderLength+h.Length]
		rest = rest[http2FrameHeaderLength+h.Length:]
		if h.Type != http2.FrameHeaders {
			continue
		}
		p.handleHeaders(method, decoder, h, body, kernelTime, statuses, grpcStatuses, touched)
	}
	var res []Http2Request
	if p.opts.Enabled {
		res = p.completeStreams(kernelTime, now, statuses, grpcStatuses, touched)
		p.gc(kernelTime)
		return res
	}
	for streamId, status := range statuses {
		r := p.activeRequests[streamId]
		if r == nil {
			continue
		}
		r.Status = status
		grpcStatus, ok := grpcStatuses[streamId]
		if ok {
			r.GrpcStatus = grpcStatus
		} else {
			r.GrpcStatus = -1
		}
		r.Duration = time.Duration(kernelTime - r.kernelTime)
		res = append(res, r.Http2Request)
		delete(p.activeRequests, streamId)
	}

	p.gc(kernelTime)

	return res
}

func (p *Http2Parser) gc(kernelTime uint64) {
	if kernelTime-p.lastGcTime > http2DecoderGcInterval {
		if p.lastGcTime > 0 {
			for streamId, r := range p.activeRequests {
				if kernelTime-r.kernelTime > http2DecoderGcInterval {
					delete(p.activeRequests, streamId)
					delete(p.held, streamId)
				}
			}
		}
		p.lastGcTime = kernelTime
	}
}

// handleHeaders decodes a HEADERS frame and, with bodies on, notes that the
// response stream ended when the frame carries END_STREAM.
func (p *Http2Parser) handleHeaders(method Method, decoder *hpack.Decoder, h Http2FrameHeader, body []byte, kernelTime uint64, statuses, grpcStatuses map[uint32]Status, touched map[uint32]struct{}) {
	p.decodeHeaders(method, decoder, h, body, kernelTime, statuses, grpcStatuses)
	if p.opts.Enabled && method == MethodHttp2ServerFrames && h.Type == http2.FrameHeaders && h.Flags.Has(http2.FlagHeadersEndStream) {
		if st := p.activeRequests[h.StreamId]; st != nil {
			st.respEnded = true
			touched[h.StreamId] = struct{}{}
		}
	}
}

func (p *Http2Parser) appendData(method Method, d *http2DataState, b []byte, now time.Time) {
	st := d.stream
	if st == nil || len(b) == 0 && !d.padded {
		if st == nil {
			BodyStats.DroppedNoMessage.Add(1)
		}
		return
	}
	switch method {
	case MethodHttp2ClientFrames:
		if d.padded {
			st.reqSkipped = true
		} else {
			st.reqBody.Add(b)
		}
	case MethodHttp2ServerFrames:
		st.lastEvent = now
		if d.padded {
			st.respSkipped = true
		} else {
			st.respBody.Add(b)
		}
	}
}

func (p *Http2Parser) finishData(method Method, d *http2DataState, touched map[uint32]struct{}) {
	if d.stream == nil || !d.endStream || method != MethodHttp2ServerFrames {
		return
	}
	d.stream.respEnded = true
	touched[d.stream.StreamId()] = struct{}{}
}

// completeStreams is the end of a Parse call with bodies on: it records the
// final response of the streams that received one, and returns the requests
// whose response stream has ended.
func (p *Http2Parser) completeStreams(kernelTime uint64, now time.Time, statuses, grpcStatuses map[uint32]Status, touched map[uint32]struct{}) []Http2Request {
	for streamId, status := range statuses {
		r := p.activeRequests[streamId]
		if r == nil {
			continue
		}
		if r.haveResp {
			// trailers after the final response
			if g, ok := grpcStatuses[streamId]; ok {
				r.GrpcStatus = g
			}
			continue
		}
		if status >= 100 && status < 200 {
			continue // 100-continue and the like are not the answer
		}
		r.haveResp = true
		r.Status = status
		if g, ok := grpcStatuses[streamId]; ok {
			r.GrpcStatus = g
		} else {
			r.GrpcStatus = -1
		}
		r.Duration = time.Duration(kernelTime - r.kernelTime)
		r.At = now
		r.lastEvent = now
		p.held[streamId] = r
		touched[streamId] = struct{}{}
	}
	var res []Http2Request
	for streamId := range touched {
		if r := p.activeRequests[streamId]; r != nil && r.haveResp && r.respEnded {
			res = append(res, p.finishStream(streamId, r))
		}
	}
	return res
}

// Flush returns the responses whose stream has not ended but has been quiet for
// the configured wait (or held too long): they are released with the body seen
// so far. A parser without bodies never holds anything.
func (p *Http2Parser) Flush(now time.Time) []Http2Request {
	var res []Http2Request
	for streamId, r := range p.held {
		if p.serverData != nil && p.serverData.stream == r {
			continue // the rest of one of its DATA frames is still due
		}
		if now.Sub(r.lastEvent) >= p.opts.Wait || now.Sub(r.At) >= http2HoldMax {
			res = append(res, p.finishStream(streamId, r))
		}
	}
	return res
}

func (p *Http2Parser) finishStream(streamId uint32, r *http2Stream) Http2Request {
	delete(p.activeRequests, streamId)
	delete(p.held, streamId)
	out := r.Http2Request
	if !r.reqSkipped {
		out.RequestBody, out.RequestBodySize = p.opts.finishBody(r.reqBody, r.reqHdr.contentType, r.reqHdr.contentEncoding, r.reqHdr.contentLength)
	} else {
		out.RequestBodySize = r.reqHdr.contentLength
	}
	if !r.respSkipped {
		out.ResponseBody, out.ResponseBodySize = p.opts.finishBody(r.respBody, r.respHdr.contentType, r.respHdr.contentEncoding, r.respHdr.contentLength)
	} else {
		out.ResponseBodySize = r.respHdr.contentLength
	}
	return out
}

func (p *Http2Parser) decodeHeaders(method Method, decoder *hpack.Decoder, h Http2FrameHeader, body []byte, kernelTime uint64, statuses, grpcStatuses map[uint32]Status) {
	if h.Type != http2.FrameHeaders {
		return
	}
	switch method {
	case MethodHttp2ClientFrames:
		req := p.activeRequests[h.StreamId]
		if req == nil {
			req = p.newStream(h.StreamId, kernelTime)
			p.activeRequests[h.StreamId] = req
		}
		decoder.SetEmitFunc(func(hf hpack.HeaderField) {
			if p.opts.Enabled {
				recordBodyHeader(&req.reqHdr, hf)
			}
			switch hf.Name {
			case ":method":
				if req.Method == "" && isHttpMethod(hf.Value) {
					req.Method = hf.Value
				}
			case ":path":
				if req.Path == "" && isHttpPath(hf.Value) {
					req.Path = hf.Value
				}
			case ":scheme":
				if req.Scheme == "" && isHttpScheme(hf.Value) {
					req.Scheme = hf.Value
				}
			}
		})
	case MethodHttp2ServerFrames:
		if _, ok := statuses[h.StreamId]; !ok {
			statuses[h.StreamId] = 0
		}
		st := p.activeRequests[h.StreamId]
		decoder.SetEmitFunc(func(hf hpack.HeaderField) {
			if p.opts.Enabled && st != nil && !st.haveResp {
				recordBodyHeader(&st.respHdr, hf)
			}
			switch hf.Name {
			case ":status":
				s, _ := strconv.Atoi(hf.Value)
				statuses[h.StreamId] = Status(s)
			case "grpc-status":
				s, _ := strconv.Atoi(hf.Value)
				grpcStatuses[h.StreamId] = Status(s)
			}
		})
	default:
		return
	}
	_, _ = decoder.Write(body)
}

func (p *Http2Parser) newStream(streamId uint32, kernelTime uint64) *http2Stream {
	st := &http2Stream{Http2Request: Http2Request{kernelTime: kernelTime}}
	st.streamId = streamId
	if p.opts.Enabled {
		st.reqHdr.contentLength = -1
		st.respHdr.contentLength = -1
		st.reqBody = newBodyCollector(p.opts.MaxBytes)
		st.respBody = newBodyCollector(p.opts.MaxBytes)
	}
	return st
}

func recordBodyHeader(h *http2BodyHeaders, hf hpack.HeaderField) {
	switch hf.Name {
	case "content-type":
		if h.contentType == "" {
			h.contentType = hf.Value
		}
	case "content-encoding":
		if h.contentEncoding == "" {
			h.contentEncoding = hf.Value
		}
	case "content-length":
		h.contentLength = parseContentLength(hf.Value)
	}
}

func isHttpMethod(s string) bool {
	switch s {
	case http.MethodGet,
		http.MethodHead,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodConnect,
		http.MethodOptions,
		http.MethodTrace:
		return true
	}
	return false
}

func isHttpPath(s string) bool {
	return strings.HasPrefix(s, "/") || s == "*"
}

func isHttpScheme(s string) bool {
	return s == "http" || s == "https"
}
