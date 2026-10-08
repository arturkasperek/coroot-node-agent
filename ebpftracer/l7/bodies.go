package l7

import (
	"path"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// KernelBodyCaptureMax is how much of one HTTP/1 message body, or one HTTP/2
// stream direction, the eBPF side ever sends (HTTP1_CAPTURE_MAX and
// HTTP2_STREAM_CAPTURE_MAX); asking for more is pointless.
const KernelBodyCaptureMax = 4096

// BodyOptions controls whether, and how much of, the HTTP bodies seen by the
// eBPF side are kept next to the request/response headers. The zero value
// (and a parser created without options) keeps none, which is the behaviour
// before body capture existed.
type BodyOptions struct {
	Enabled      bool
	MaxBytes     int
	ContentTypes []string
	// Wait is how long a message whose end cannot be told (a chunked HTTP/1
	// body, an HTTP/2 stream that never ends) is held for more body before
	// it is released with what was captured.
	Wait time.Duration
}

var defaultBodyContentTypes = []string{
	"application/json",
	"application/*+json",
	"application/xml",
	"application/*+xml",
	"text/*",
	"application/x-www-form-urlencoded",
	"application/graphql",
}

// DefaultBodyOptions are the defaults of the --http-body-* flags, with capture
// itself still disabled.
func DefaultBodyOptions() BodyOptions {
	return BodyOptions{
		MaxBytes:     KernelBodyCaptureMax,
		ContentTypes: append([]string(nil), defaultBodyContentTypes...),
		Wait:         200 * time.Millisecond,
	}
}

// Why a body was not kept; see BodyDecision.
type BodyDecision int

const (
	BodyKeep BodyDecision = iota
	BodySkipContentType
	BodySkipEncoding
	BodySkipBinary
)

// Decide says whether a body with these headers and bytes may be attached to a
// span, and if not, why.
func (o BodyOptions) Decide(contentType, contentEncoding string, sample []byte) BodyDecision {
	if enc := strings.ToLower(strings.TrimSpace(contentEncoding)); enc != "" && enc != "identity" {
		return BodySkipEncoding
	}
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if ct == "" {
		// No declared type: keep it only if it looks like text.
		if !looksLikeText(sample) {
			return BodySkipBinary
		}
		return BodyKeep
	}
	if strings.HasPrefix(ct, "application/grpc") {
		return BodySkipContentType
	}
	for _, pattern := range o.ContentTypes {
		if ok, _ := path.Match(strings.ToLower(pattern), ct); ok {
			return BodyKeep
		}
	}
	return BodySkipContentType
}

// Allowed is Decide reduced to a yes/no.
func (o BodyOptions) Allowed(contentType, contentEncoding string, sample []byte) bool {
	return o.Decide(contentType, contentEncoding, sample) == BodyKeep
}

func looksLikeText(b []byte) bool {
	b = trimIncompleteRune(b)
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c == 0 {
			return false
		}
	}
	return utf8.Valid(b)
}

func trimIncompleteRune(b []byte) []byte {
	for i := len(b) - 1; i >= 0 && i >= len(b)-utf8.UTFMax; i-- {
		if utf8.RuneStart(b[i]) {
			if !utf8.FullRune(b[i:]) {
				return b[:i]
			}
			break
		}
	}
	return b
}

// cutUTF8 returns at most max bytes of b, never ending in the middle of a
// UTF-8 sequence. A sequence that is incomplete at the end is dropped even when
// nothing had to be cut: it can only come from a truncated capture.
func cutUTF8(b []byte, max int) []byte {
	if len(b) > max {
		b = b[:max]
	}
	return trimIncompleteRune(b)
}

// bodyCollector gathers up to max bytes of a body.
type bodyCollector struct {
	max int
	buf []byte
}

func newBodyCollector(max int) *bodyCollector {
	return &bodyCollector{max: max}
}

func (c *bodyCollector) Add(b []byte) {
	if room := c.max - len(c.buf); room > 0 {
		if len(b) > room {
			b = b[:room]
		}
		c.buf = append(c.buf, b...)
	}
}

func (c *bodyCollector) Bytes() []byte { return c.buf }
func (c *bodyCollector) Len() int      { return len(c.buf) }
func (c *bodyCollector) Full() bool    { return len(c.buf) >= c.max }

// parseContentLength returns the value of a Content-Length header, or -1 when it
// is absent or not a non-negative integer.
func parseContentLength(v string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n < 0 {
		return -1
	}
	return n
}

// BodyStats counts what happened to bodies; the containers package exports it
// as node_l7_http_bodies_total{result}.
var BodyStats struct {
	Captured           atomic.Uint64
	Truncated          atomic.Uint64
	SkippedContentType atomic.Uint64
	SkippedEncoding    atomic.Uint64
	SkippedBinary      atomic.Uint64
	DroppedNoMessage   atomic.Uint64
	DroppedQueueFull   atomic.Uint64
}

func (o BodyOptions) count(d BodyDecision) {
	switch d {
	case BodySkipContentType:
		BodyStats.SkippedContentType.Add(1)
	case BodySkipEncoding:
		BodyStats.SkippedEncoding.Add(1)
	case BodySkipBinary:
		BodyStats.SkippedBinary.Add(1)
	}
}

// finishBody turns a collected body into the string put on a span. size is the
// real size when known (-1 otherwise). An empty result means "no attribute".
func (o BodyOptions) finishBody(c *bodyCollector, contentType, contentEncoding string, size int64) (string, int64) {
	if c == nil || c.Len() == 0 {
		return "", size
	}
	b := cutUTF8(c.Bytes(), o.MaxBytes)
	if d := o.Decide(contentType, contentEncoding, b); d != BodyKeep {
		o.count(d)
		return "", size
	}
	if len(b) == 0 {
		return "", size
	}
	BodyStats.Captured.Add(1)
	if size > int64(len(b)) {
		BodyStats.Truncated.Add(1)
	}
	return string(b), size
}
