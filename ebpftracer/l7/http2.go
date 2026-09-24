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

	kernelTime uint64
}

type http2PartialFrame struct {
	header Http2FrameHeader
	body   []byte
}

type Http2Parser struct {
	clientDecoder  *hpack.Decoder
	serverDecoder  *hpack.Decoder
	activeRequests map[uint32]*Http2Request
	lastGcTime     uint64
	clientPartial  *http2PartialFrame
	serverPartial  *http2PartialFrame
	clientHeader   []byte
	serverHeader   []byte
}

func NewHttp2Parser() *Http2Parser {
	return &Http2Parser{
		clientDecoder:  hpack.NewDecoder(4096, nil),
		serverDecoder:  hpack.NewDecoder(4096, nil),
		activeRequests: map[uint32]*Http2Request{},
	}
}

func (p *Http2Parser) Parse(method Method, payload []byte, kernelTime uint64) []Http2Request {
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
	statuses := map[uint32]Status{}
	grpcStatuses := map[uint32]Status{}

	switch method {
	case MethodHttp2ClientFrames:
		decoder = p.clientDecoder
		partial = &p.clientPartial
		header = &p.clientHeader
	case MethodHttp2ServerFrames:
		decoder = p.serverDecoder
		partial = &p.serverPartial
		header = &p.serverHeader
	default:
		return nil
	}
	defer decoder.Close()

	rest := payload
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
		p.decodeHeaders(method, decoder, h, body, kernelTime, statuses, grpcStatuses)
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
		p.decodeHeaders(method, decoder, h, body, kernelTime, statuses, grpcStatuses)
	}
	var res []Http2Request
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
		res = append(res, *r)
		delete(p.activeRequests, streamId)
	}

	// GC
	if kernelTime-p.lastGcTime > http2DecoderGcInterval {
		if p.lastGcTime > 0 {
			for streamId, r := range p.activeRequests {
				if kernelTime-r.kernelTime > http2DecoderGcInterval {
					delete(p.activeRequests, streamId)
				}
			}
		}
		p.lastGcTime = kernelTime
	}

	return res
}

func (p *Http2Parser) decodeHeaders(method Method, decoder *hpack.Decoder, h Http2FrameHeader, body []byte, kernelTime uint64, statuses, grpcStatuses map[uint32]Status) {
	if h.Type != http2.FrameHeaders {
		return
	}
	switch method {
	case MethodHttp2ClientFrames:
		req := p.activeRequests[h.StreamId]
		if req == nil {
			req = &Http2Request{kernelTime: kernelTime}
			p.activeRequests[h.StreamId] = req
		}
		decoder.SetEmitFunc(func(hf hpack.HeaderField) {
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
		decoder.SetEmitFunc(func(hf hpack.HeaderField) {
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
