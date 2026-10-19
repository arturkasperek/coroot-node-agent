//go:build linux && amd64

package ebpftracer

import (
	"bytes"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/stretchr/testify/require"
	"inet.af/netaddr"
)

// http2InboundPayload sends an HTTP/2 request with a body from 127.0.0.1 to a
// server of this process, and returns what the server side of the agent
// captured of it: the frames it read, as one stream of bytes.
func http2InboundPayload(t *testing.T, getEvent func() *Event, headerMarker, bodyMarker byte) []byte {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	client, err := net.Dial("tcp4", ln.Addr().String())
	require.NoError(t, err)
	defer client.Close()
	server, err := ln.Accept()
	require.NoError(t, err)
	defer server.Close()
	watchConn(t, server)

	request := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	request = append(request, 0, 0, 0, 4, 0, 0, 0, 0, 0) // SETTINGS
	request = append(request, http2HeadersRaw(bytes.Repeat([]byte{headerMarker}, 24), 1)...)
	request = append(request, http2DataFrame(bytes.Repeat([]byte{bodyMarker}, 600), 1, true)...)
	_, err = client.Write(request)
	require.NoError(t, err)
	_, err = io.ReadFull(server, make([]byte, len(request)))
	require.NoError(t, err)

	var got []byte
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		e := getEvent()
		if e == nil || e.Pid != uint32(os.Getpid()) || e.Type != EventTypeL7Request || e.L7Request == nil {
			continue
		}
		if e.L7Request.Protocol != l7.ProtocolHTTP2 || !e.L7Request.IsInbound {
			continue
		}
		got = append(got, e.L7Request.Payload...)
		if bytes.Contains(got, []byte{0, 0x1, 0, 0, 0, 1}) || bytes.Count(got, []byte{bodyMarker}) >= 600 {
			// the DATA frame of stream 1 with END_STREAM (type 0, flags 1), or its body
			time.Sleep(200 * time.Millisecond)
			for e := getEvent(); e != nil; e = getEvent() {
				if e.Pid == uint32(os.Getpid()) && e.Type == EventTypeL7Request && e.L7Request != nil && e.L7Request.IsInbound {
					got = append(got, e.L7Request.Payload...)
				}
			}
			return got
		}
	}
	return got
}

// A connection accepted from a traced client (its agent captures the bodies
// of its requests) is captured without the bodies of its HTTP/2 DATA frames:
// each DATA frame is its header only, with length 0, so that its END_STREAM
// still ends the stream. Its HEADERS are captured as from any client.
func TestHttp2SkipsTheBodiesOfATracedClient(t *testing.T) {
	skipIfNotVM(t)
	getEvent, stop := runTracer(t)
	defer stop()

	require.NoError(t, sharedTr.SetTracedClients(map[netaddr.IP]bool{netaddr.MustParseIP("127.0.0.1"): true}))
	got := http2InboundPayload(t, getEvent, 0xcd, 0xab)
	require.NoError(t, sharedTr.SetTracedClients(map[netaddr.IP]bool{}))

	require.Equal(t, 24, bytes.Count(got, []byte{0xcd}), "the request headers")
	require.Zero(t, bytes.Count(got, []byte{0xab}), "no byte of the body")
	require.True(t, bytes.Contains(got, []byte{0, 0, 0, 0, 0x1, 0, 0, 0, 1}), "the DATA frame header of stream 1, length 0, END_STREAM")

	// a client not traced: its bodies are captured
	got = http2InboundPayload(t, getEvent, 0xce, 0xac)
	require.Equal(t, 24, bytes.Count(got, []byte{0xce}))
	require.Equal(t, 600, bytes.Count(got, []byte{0xac}), "the whole body")
}
