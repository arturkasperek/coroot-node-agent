package l7

import (
	"bytes"
	"net/http"
	"testing"

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
