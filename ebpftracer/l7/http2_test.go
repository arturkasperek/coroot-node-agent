package l7

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestHttp2ParserGetUsers(t *testing.T) {
	var client bytes.Buffer
	client.WriteString(http2.ClientPreface)
	cfr := http2.NewFramer(&client, nil)
	require.NoError(t, cfr.WriteSettings())
	var reqHdr bytes.Buffer
	enc := hpack.NewEncoder(&reqHdr)
	for _, hf := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/users"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: "127.0.0.1:1"},
	} {
		require.NoError(t, enc.WriteField(hf))
	}
	require.NoError(t, cfr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: reqHdr.Bytes(),
		EndStream:     true,
		EndHeaders:    true,
	}))

	var server bytes.Buffer
	sfr := http2.NewFramer(&server, nil)
	require.NoError(t, sfr.WriteSettings())
	var respHdr bytes.Buffer
	senc := hpack.NewEncoder(&respHdr)
	require.NoError(t, senc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"}))
	require.NoError(t, sfr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: respHdr.Bytes(),
		EndStream:     true,
		EndHeaders:    true,
	}))

	p := NewHttp2Parser()
	require.Empty(t, p.Parse(MethodHttp2ClientFrames, client.Bytes()[:len(http2.ClientPreface)], 1))
	require.Empty(t, p.Parse(MethodHttp2ClientFrames, client.Bytes()[len(http2.ClientPreface):], 1))
	got := p.Parse(MethodHttp2ServerFrames, server.Bytes(), 2)
	require.Len(t, got, 1)
	require.Equal(t, "GET", got[0].Method)
	require.Equal(t, "/users", got[0].Path)
	require.Equal(t, Status(http.StatusOK), got[0].Status)
}

func encodeHeadersFrame(t *testing.T, streamID uint32, fields []hpack.HeaderField) []byte {
	t.Helper()
	var hdr bytes.Buffer
	enc := hpack.NewEncoder(&hdr)
	for _, hf := range fields {
		require.NoError(t, enc.WriteField(hf))
	}
	var buf bytes.Buffer
	fr := http2.NewFramer(&buf, nil)
	require.NoError(t, fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: hdr.Bytes(),
		EndStream:     true,
		EndHeaders:    true,
	}))
	return buf.Bytes()
}

func TestHttp2ParserSkipsInvalidHpackAndParsesNextFrame(t *testing.T) {
	// A HEADERS frame whose HPACK body is an invalid index 0, followed by a
	// well-formed GET. The parser must advance past the bad frame instead of
	// treating its body as the next frame header.
	invalid := []byte{
		0x00, 0x00, 0x01, // length 1
		0x01,                   // HEADERS
		0x05,                   // END_STREAM | END_HEADERS
		0x00, 0x00, 0x00, 0x03, // stream 3
		0x80, // invalid HPACK index 0
	}
	valid := encodeHeadersFrame(t, 1, []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/users"},
		{Name: ":scheme", Value: "http"},
	})

	p := NewHttp2Parser()
	require.Empty(t, p.Parse(MethodHttp2ClientFrames, append(invalid, valid...), 1))

	var server bytes.Buffer
	sfr := http2.NewFramer(&server, nil)
	var respHdr bytes.Buffer
	senc := hpack.NewEncoder(&respHdr)
	require.NoError(t, senc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"}))
	require.NoError(t, sfr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: respHdr.Bytes(),
		EndStream:     true,
		EndHeaders:    true,
	}))
	got := p.Parse(MethodHttp2ServerFrames, server.Bytes(), 2)
	require.Len(t, got, 1)
	require.Equal(t, "GET", got[0].Method)
	require.Equal(t, "/users", got[0].Path)
}

func TestHttp2ParserIncompleteHeadersDoesNotCreateRequest(t *testing.T) {
	complete := encodeHeadersFrame(t, 1, []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":path", Value: "/submit"},
		{Name: ":scheme", Value: "http"},
	})
	require.Greater(t, len(complete), http2FrameHeaderLength+1)

	p := NewHttp2Parser()
	require.Empty(t, p.Parse(MethodHttp2ClientFrames, complete[:http2FrameHeaderLength+1], 1))
	require.Empty(t, p.activeRequests)
}

func TestHttp2ParserHeadersSplitAcrossReads(t *testing.T) {
	frame := encodeHeadersFrame(t, 1, []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":path", Value: "/submit"},
		{Name: ":scheme", Value: "http"},
	})
	require.Greater(t, len(frame), http2FrameHeaderLength+4)

	p := NewHttp2Parser()
	cut := http2FrameHeaderLength + 1
	require.Empty(t, p.Parse(MethodHttp2ClientFrames, frame[:cut], 1))
	require.Empty(t, p.activeRequests)
	require.Empty(t, p.Parse(MethodHttp2ClientFrames, frame[cut:cut+2], 2))
	require.Empty(t, p.activeRequests)
	require.Empty(t, p.Parse(MethodHttp2ClientFrames, frame[cut+2:], 3))

	req := p.activeRequests[1]
	require.NotNil(t, req)
	require.Equal(t, "POST", req.Method)
	require.Equal(t, "/submit", req.Path)
	require.Equal(t, "http", req.Scheme)
}

func TestHttp2ParserPartialHeadersThenNextFrame(t *testing.T) {
	first := encodeHeadersFrame(t, 1, []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":path", Value: "/submit"},
		{Name: ":scheme", Value: "http"},
	})
	second := encodeHeadersFrame(t, 3, []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/users"},
		{Name: ":scheme", Value: "https"},
	})
	cut := http2FrameHeaderLength + 1

	p := NewHttp2Parser()
	require.Empty(t, p.Parse(MethodHttp2ClientFrames, first[:cut], 1))
	require.Empty(t, p.Parse(MethodHttp2ClientFrames, append(append([]byte{}, first[cut:]...), second...), 2))

	submit := p.activeRequests[1]
	require.NotNil(t, submit)
	require.Equal(t, "POST", submit.Method)
	require.Equal(t, "/submit", submit.Path)
	users := p.activeRequests[3]
	require.NotNil(t, users)
	require.Equal(t, "GET", users.Method)
	require.Equal(t, "/users", users.Path)
	require.Equal(t, "https", users.Scheme)
}

func TestHttp2ParserHeadersOneByteAtATime(t *testing.T) {
	frame := encodeHeadersFrame(t, 5, []hpack.HeaderField{
		{Name: ":method", Value: "PUT"},
		{Name: ":path", Value: "/items"},
		{Name: ":scheme", Value: "http"},
	})

	p := NewHttp2Parser()
	for i, b := range frame {
		p.Parse(MethodHttp2ClientFrames, []byte{b}, uint64(i+1))
	}
	req := p.activeRequests[5]
	require.NotNil(t, req)
	require.Equal(t, "PUT", req.Method)
	require.Equal(t, "/items", req.Path)
}

// h2Conn builds both directions of one HTTP/2 connection with the real framer.
type h2Conn struct {
	t          *testing.T
	client     bytes.Buffer
	server     bytes.Buffer
	cfr, sfr   *http2.Framer
	cenc, senc *hpack.Encoder
	chdr, shdr bytes.Buffer
}

func newH2Conn(t *testing.T) *h2Conn {
	c := &h2Conn{t: t}
	c.cfr = http2.NewFramer(&c.client, nil)
	c.sfr = http2.NewFramer(&c.server, nil)
	c.cenc = hpack.NewEncoder(&c.chdr)
	c.senc = hpack.NewEncoder(&c.shdr)
	return c
}

func (c *h2Conn) reqHeaders(stream uint32, endStream bool, fields ...hpack.HeaderField) []byte {
	c.chdr.Reset()
	for _, f := range fields {
		require.NoError(c.t, c.cenc.WriteField(f))
	}
	c.client.Reset()
	require.NoError(c.t, c.cfr.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: c.chdr.Bytes(), EndStream: endStream, EndHeaders: true}))
	return append([]byte(nil), c.client.Bytes()...)
}

func (c *h2Conn) respHeaders(stream uint32, endStream bool, fields ...hpack.HeaderField) []byte {
	c.shdr.Reset()
	for _, f := range fields {
		require.NoError(c.t, c.senc.WriteField(f))
	}
	c.server.Reset()
	require.NoError(c.t, c.sfr.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: c.shdr.Bytes(), EndStream: endStream, EndHeaders: true}))
	return append([]byte(nil), c.server.Bytes()...)
}

func (c *h2Conn) clientData(stream uint32, endStream bool, data []byte) []byte {
	c.client.Reset()
	require.NoError(c.t, c.cfr.WriteData(stream, endStream, data))
	return append([]byte(nil), c.client.Bytes()...)
}

func (c *h2Conn) serverData(stream uint32, endStream bool, data []byte) []byte {
	c.server.Reset()
	require.NoError(c.t, c.sfr.WriteData(stream, endStream, data))
	return append([]byte(nil), c.server.Bytes()...)
}

func newH2BodyParser(max int) *Http2Parser {
	opts := DefaultBodyOptions()
	opts.Enabled = true
	opts.MaxBytes = max
	return NewHttp2ParserWithBodies(opts)
}

var h2post = []hpack.HeaderField{
	{Name: ":method", Value: "POST"}, {Name: ":path", Value: "/orders"}, {Name: ":scheme", Value: "http"},
	{Name: "content-type", Value: "application/json"},
}

func TestHttp2BodiesRequestAndResponse(t *testing.T) {
	c := newH2Conn(t)
	p := newH2BodyParser(4096)
	require.Empty(t, p.Parse(MethodHttp2ClientFrames, c.reqHeaders(1, false, h2post...), 1))
	require.Empty(t, p.Parse(MethodHttp2ClientFrames, c.clientData(1, true, []byte(`{"a":1}`)), 2))
	require.Empty(t, p.Parse(MethodHttp2ServerFrames, c.respHeaders(1, false,
		hpack.HeaderField{Name: ":status", Value: "201"}, hpack.HeaderField{Name: "content-type", Value: "application/json"}), 5))
	got := p.Parse(MethodHttp2ServerFrames, c.serverData(1, true, []byte(`{"id":"ab"}`)), 6)
	require.Len(t, got, 1)
	require.Equal(t, "POST", got[0].Method)
	require.Equal(t, "/orders", got[0].Path)
	require.Equal(t, Status(201), got[0].Status)
	require.Equal(t, `{"a":1}`, got[0].RequestBody)
	require.Equal(t, `{"id":"ab"}`, got[0].ResponseBody)
	require.Equal(t, 4*time.Nanosecond, got[0].Duration, "request headers to response headers")
	require.Equal(t, 0, p.Held())
}

func TestHttp2NoBodyResponse(t *testing.T) {
	c := newH2Conn(t)
	p := newH2BodyParser(4096)
	p.Parse(MethodHttp2ClientFrames, c.reqHeaders(1, true,
		hpack.HeaderField{Name: ":method", Value: "GET"}, hpack.HeaderField{Name: ":path", Value: "/users"}, hpack.HeaderField{Name: ":scheme", Value: "http"}), 1)
	got := p.Parse(MethodHttp2ServerFrames, c.respHeaders(1, true, hpack.HeaderField{Name: ":status", Value: "204"}), 2)
	require.Len(t, got, 1)
	require.Empty(t, got[0].RequestBody)
	require.Empty(t, got[0].ResponseBody)
}

func TestHttp2DataSplitAcrossEvents(t *testing.T) {
	c := newH2Conn(t)
	p := newH2BodyParser(4096)
	p.Parse(MethodHttp2ClientFrames, c.reqHeaders(1, true, h2post...), 1)
	p.Parse(MethodHttp2ServerFrames, c.respHeaders(1, false,
		hpack.HeaderField{Name: ":status", Value: "200"}, hpack.HeaderField{Name: "content-type", Value: "text/plain"}), 2)
	body := strings.Repeat("0123456789", 300)
	frame := c.serverData(1, true, []byte(body)) // header + 3000 bytes
	// the kernel sends the header with the first part, then raw continuations
	require.Empty(t, p.Parse(MethodHttp2ServerFrames, frame[:9+1000], 3))
	require.Empty(t, p.Parse(MethodHttp2ServerFrames, frame[9+1000:9+2000], 4))
	got := p.Parse(MethodHttp2ServerFrames, frame[9+2000:], 5)
	require.Len(t, got, 1)
	require.Equal(t, body, got[0].ResponseBody)
}

func TestHttp2DataFrameHeaderSplit(t *testing.T) {
	c := newH2Conn(t)
	p := newH2BodyParser(4096)
	p.Parse(MethodHttp2ClientFrames, c.reqHeaders(1, true, h2post...), 1)
	p.Parse(MethodHttp2ServerFrames, c.respHeaders(1, false, hpack.HeaderField{Name: ":status", Value: "200"}), 2)
	frame := c.serverData(1, true, []byte("hello"))
	require.Empty(t, p.Parse(MethodHttp2ServerFrames, frame[:4], 3))
	got := p.Parse(MethodHttp2ServerFrames, frame[4:], 4)
	require.Len(t, got, 1)
	require.Equal(t, "hello", got[0].ResponseBody)
}

func TestHttp2BodyCappedAndEndsStream(t *testing.T) {
	c := newH2Conn(t)
	p := newH2BodyParser(100)
	p.Parse(MethodHttp2ClientFrames, c.reqHeaders(1, false, append(h2post, hpack.HeaderField{Name: "content-length", Value: "10240"})...), 1)
	for i := 0; i < 3; i++ {
		p.Parse(MethodHttp2ClientFrames, c.clientData(1, false, bytes.Repeat([]byte("a"), 4000)), 2)
	}
	p.Parse(MethodHttp2ClientFrames, c.clientData(1, true, bytes.Repeat([]byte("a"), 2240)), 2)
	p.Parse(MethodHttp2ServerFrames, c.respHeaders(1, false, hpack.HeaderField{Name: ":status", Value: "200"}, hpack.HeaderField{Name: "content-type", Value: "text/plain"}), 3)
	got := p.Parse(MethodHttp2ServerFrames, c.serverData(1, true, bytes.Repeat([]byte("b"), 4000)), 4)
	require.Len(t, got, 1)
	require.Equal(t, strings.Repeat("a", 100), got[0].RequestBody)
	require.Equal(t, int64(10240), got[0].RequestBodySize)
	require.Equal(t, strings.Repeat("b", 100), got[0].ResponseBody)
	require.Equal(t, int64(-1), got[0].ResponseBodySize)
}

func TestHttp2GrpcAndGzipSkipped(t *testing.T) {
	c := newH2Conn(t)
	p := newH2BodyParser(4096)
	p.Parse(MethodHttp2ClientFrames, c.reqHeaders(1, false,
		hpack.HeaderField{Name: ":method", Value: "POST"}, hpack.HeaderField{Name: ":path", Value: "/pkg.Svc/Call"}, hpack.HeaderField{Name: ":scheme", Value: "http"},
		hpack.HeaderField{Name: "content-type", Value: "application/grpc"}), 1)
	p.Parse(MethodHttp2ClientFrames, c.clientData(1, true, []byte("\x00\x00\x00\x00\x02\x08\x01")), 2)
	p.Parse(MethodHttp2ServerFrames, c.respHeaders(1, false,
		hpack.HeaderField{Name: ":status", Value: "200"}, hpack.HeaderField{Name: "content-type", Value: "text/plain"}, hpack.HeaderField{Name: "content-encoding", Value: "gzip"}), 3)
	got := p.Parse(MethodHttp2ServerFrames, c.serverData(1, true, []byte("\x1f\x8b\x08")), 4)
	require.Len(t, got, 1, "the span is still produced")
	require.Equal(t, "/pkg.Svc/Call", got[0].Path)
	require.Empty(t, got[0].RequestBody)
	require.Empty(t, got[0].ResponseBody)
}

func TestHttp2InterleavedStreams(t *testing.T) {
	c := newH2Conn(t)
	p := newH2BodyParser(4096)
	p.Parse(MethodHttp2ClientFrames, c.reqHeaders(1, false, h2post...), 1)
	p.Parse(MethodHttp2ClientFrames, c.reqHeaders(3, false, h2post...), 2)
	p.Parse(MethodHttp2ClientFrames, append(c.clientData(1, false, []byte("one-")), c.clientData(3, false, []byte("three-"))...), 3)
	p.Parse(MethodHttp2ClientFrames, append(c.clientData(3, true, []byte("end3")), c.clientData(1, true, []byte("end1"))...), 4)
	ok := []hpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "content-type", Value: "text/plain"}}
	p.Parse(MethodHttp2ServerFrames, c.respHeaders(1, false, ok...), 5)
	p.Parse(MethodHttp2ServerFrames, c.respHeaders(3, false, ok...), 6)
	got := p.Parse(MethodHttp2ServerFrames, append(c.serverData(3, true, []byte("R3")), c.serverData(1, true, []byte("R1"))...), 7)
	require.Len(t, got, 2)
	by := map[string]Http2Request{}
	for _, r := range got {
		by[r.RequestBody] = r
	}
	require.Equal(t, "R1", by["one-end1"].ResponseBody)
	require.Equal(t, "R3", by["three-end3"].ResponseBody)
}

func TestHttp2PaddedDataSkipped(t *testing.T) {
	c := newH2Conn(t)
	p := newH2BodyParser(4096)
	p.Parse(MethodHttp2ClientFrames, c.reqHeaders(1, false, h2post...), 1)
	c.client.Reset()
	require.NoError(t, c.cfr.WriteDataPadded(1, true, []byte("secret"), []byte{0, 0, 0}))
	p.Parse(MethodHttp2ClientFrames, append([]byte(nil), c.client.Bytes()...), 2)
	p.Parse(MethodHttp2ServerFrames, c.respHeaders(1, true, hpack.HeaderField{Name: ":status", Value: "200"}), 3)
	// the next stream still parses: the padded frame was consumed whole
	got := p.Parse(MethodHttp2ClientFrames, c.reqHeaders(3, true, h2post...), 4)
	require.Empty(t, got)
	require.NotNil(t, p.activeRequests[3])
}

func TestHttp2FlushReleasesStreamThatNeverEnds(t *testing.T) {
	c := newH2Conn(t)
	p := newH2BodyParser(4096)
	t0 := time.Now()
	p.ParseAt(MethodHttp2ClientFrames, c.reqHeaders(1, true, h2post...), 1, t0)
	p.ParseAt(MethodHttp2ServerFrames, c.respHeaders(1, false, hpack.HeaderField{Name: ":status", Value: "200"}, hpack.HeaderField{Name: "content-type", Value: "text/plain"}), 2, t0)
	require.Empty(t, p.ParseAt(MethodHttp2ServerFrames, c.serverData(1, false, []byte("partial")), 3, t0.Add(10*time.Millisecond)))
	require.Equal(t, 1, p.Held())
	require.Empty(t, p.Flush(t0.Add(100*time.Millisecond)))
	got := p.Flush(t0.Add(400 * time.Millisecond))
	require.Len(t, got, 1)
	require.Equal(t, "partial", got[0].ResponseBody)
	require.Equal(t, 0, p.Held())
}

func TestHttp2InformationalResponseIsNotTheAnswer(t *testing.T) {
	c := newH2Conn(t)
	p := newH2BodyParser(4096)
	p.Parse(MethodHttp2ClientFrames, c.reqHeaders(1, false, h2post...), 1)
	require.Empty(t, p.Parse(MethodHttp2ServerFrames, c.respHeaders(1, false, hpack.HeaderField{Name: ":status", Value: "100"}), 2))
	p.Parse(MethodHttp2ClientFrames, c.clientData(1, true, []byte("body")), 3)
	p.Parse(MethodHttp2ServerFrames, c.respHeaders(1, false, hpack.HeaderField{Name: ":status", Value: "200"}, hpack.HeaderField{Name: "content-type", Value: "text/plain"}), 4)
	got := p.Parse(MethodHttp2ServerFrames, c.serverData(1, true, []byte("ok")), 5)
	require.Len(t, got, 1)
	require.Equal(t, Status(200), got[0].Status)
	require.Equal(t, "body", got[0].RequestBody)
	require.Equal(t, "ok", got[0].ResponseBody)
}

func TestHttp2DisabledIsUnchanged(t *testing.T) {
	c := newH2Conn(t)
	p := NewHttp2Parser()
	p.Parse(MethodHttp2ClientFrames, c.reqHeaders(1, false, h2post...), 1)
	p.Parse(MethodHttp2ClientFrames, c.clientData(1, true, []byte("body")), 2)
	got := p.Parse(MethodHttp2ServerFrames, c.respHeaders(1, false, hpack.HeaderField{Name: ":status", Value: "200"}), 3)
	require.Len(t, got, 1, "returned on the response headers, as before")
	require.Empty(t, got[0].RequestBody)
	require.True(t, got[0].At.IsZero())
	require.Equal(t, 0, p.Held())
	require.Empty(t, p.Flush(time.Now().Add(time.Hour)))
}

func TestHttp2FlushWaitsForTheRestOfADataFrame(t *testing.T) {
	c := newH2Conn(t)
	p := newH2BodyParser(4096)
	t0 := time.Now()
	p.ParseAt(MethodHttp2ClientFrames, c.reqHeaders(1, true, h2post...), 1, t0)
	p.ParseAt(MethodHttp2ServerFrames, c.respHeaders(1, false, hpack.HeaderField{Name: ":status", Value: "200"}, hpack.HeaderField{Name: "content-type", Value: "text/plain"}), 2, t0)
	frame := c.serverData(1, true, []byte(strings.Repeat("x", 400)))
	p.ParseAt(MethodHttp2ServerFrames, frame[:9+100], 3, t0)
	require.Empty(t, p.Flush(t0.Add(time.Second)), "the continuation of the DATA frame has not been processed yet")
	got := p.ParseAt(MethodHttp2ServerFrames, frame[9+100:], 4, t0.Add(time.Second))
	require.Len(t, got, 1)
	require.Equal(t, strings.Repeat("x", 400), got[0].ResponseBody)
}
