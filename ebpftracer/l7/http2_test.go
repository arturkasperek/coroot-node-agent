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
