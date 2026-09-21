package l7

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	http2SniffMaxFrames    = 8
	http2MaxFrameLen       = 1 << 22
	http2FrameHeaderLen    = 9
	http2FrameData         = 0x0
	http2FrameHeaders      = 0x1
	http2FramePriority     = 0x2
	http2FrameRSTStream    = 0x3
	http2FrameSettings     = 0x4
	http2FramePushPromise  = 0x5
	http2FramePing         = 0x6
	http2FrameGoAway       = 0x7
	http2FrameWindow       = 0x8
	http2FrameContinuation = 0x9
	http2FlagEndStream     = 0x1
	http2FlagEndHeaders    = 0x4
	http2FlagPadded        = 0x8
	http2FlagPriority      = 0x20
)

type http2SniffHeader struct {
	Length   uint32
	Type     uint8
	Flags    uint8
	StreamID uint32
}

// detectHTTP2 mirrors eBPF is_http2: preface, SETTINGS on stream 0, or a
// buffer that tiles into HTTP/2 frames and contains HEADERS.
func detectHTTP2(buf []byte) bool {
	if isHTTP2Preface(buf) {
		return true
	}
	if isHTTP2Settings(buf) {
		return true
	}
	return looksLikeHTTP2Frames(buf)
}

func isHTTP2Preface(buf []byte) bool {
	p := http2.ClientPreface
	return len(buf) >= len(p) && string(buf[:len(p)]) == p
}

func isHTTP2Settings(buf []byte) bool {
	fr, ok := parseHTTP2SniffHeader(buf)
	if !ok {
		return false
	}
	if fr.Type != http2FrameSettings || fr.StreamID != 0 || fr.Length%6 != 0 {
		return false
	}
	return http2FrameHeaderLen+int(fr.Length) <= len(buf)
}

func looksLikeHTTP2Frames(buf []byte) bool {
	if len(buf) < http2FrameHeaderLen {
		return false
	}
	pos := 0
	sawHeaders := false
	openHeaders := false
	for i := 0; i < http2SniffMaxFrames && pos < len(buf); i++ {
		if pos+http2FrameHeaderLen > len(buf) {
			return false
		}
		fr, ok := parseHTTP2SniffHeader(buf[pos:])
		if !ok || !http2FramePlausible(fr) {
			return false
		}
		if fr.Type == http2FrameHeaders {
			if fr.StreamID == 0 || fr.StreamID%2 == 0 {
				return false
			}
			if openHeaders {
				return false
			}
			sawHeaders = true
			openHeaders = fr.Flags&http2FlagEndHeaders == 0
		} else if fr.Type == http2FrameContinuation {
			if !openHeaders {
				return false
			}
			openHeaders = fr.Flags&http2FlagEndHeaders == 0
		} else if openHeaders {
			return false
		}
		next := pos + http2FrameHeaderLen + int(fr.Length)
		if next > len(buf) {
			return false
		}
		pos = next
	}
	return sawHeaders && !openHeaders && pos == len(buf)
}

func parseHTTP2SniffHeader(buf []byte) (http2SniffHeader, bool) {
	if len(buf) < http2FrameHeaderLen {
		return http2SniffHeader{}, false
	}
	if buf[5]&0x80 != 0 {
		return http2SniffHeader{}, false
	}
	return http2SniffHeader{
		Length:   uint32(buf[0])<<16 | uint32(buf[1])<<8 | uint32(buf[2]),
		Type:     buf[3],
		Flags:    buf[4],
		StreamID: uint32(buf[5])<<24 | uint32(buf[6])<<16 | uint32(buf[7])<<8 | uint32(buf[8]),
	}, true
}

func http2FlagsMask(t uint8) uint8 {
	switch t {
	case http2FrameData:
		return http2FlagEndStream | http2FlagPadded
	case http2FrameHeaders:
		return http2FlagEndStream | http2FlagEndHeaders | http2FlagPadded | http2FlagPriority
	case http2FrameSettings, http2FramePing:
		return 0x1
	case http2FramePushPromise:
		return http2FlagEndHeaders | http2FlagPadded
	case http2FrameContinuation:
		return http2FlagEndHeaders
	default:
		return 0
	}
}

func http2FramePlausible(fr http2SniffHeader) bool {
	if fr.Type > http2FrameContinuation {
		return false
	}
	if fr.Flags&^http2FlagsMask(fr.Type) != 0 {
		return false
	}
	if fr.Length > http2MaxFrameLen {
		return false
	}
	switch fr.Type {
	case http2FrameData:
		if fr.StreamID == 0 {
			return false
		}
		return fr.Length > 0 || fr.Flags&http2FlagEndStream != 0
	case http2FrameHeaders, http2FramePushPromise, http2FrameContinuation:
		return fr.StreamID != 0 && fr.Length > 0
	case http2FramePriority:
		return fr.StreamID != 0 && fr.Length == 5
	case http2FrameRSTStream:
		return fr.StreamID != 0 && fr.Length == 4
	case http2FrameSettings:
		if fr.Flags&0x1 != 0 {
			return fr.StreamID == 0 && fr.Length == 0
		}
		return fr.StreamID == 0 && fr.Length%6 == 0
	case http2FramePing:
		return fr.StreamID == 0 && fr.Length == 8
	case http2FrameGoAway:
		return fr.StreamID == 0 && fr.Length >= 8
	case http2FrameWindow:
		return fr.Length == 4
	}
	return false
}

func appendHTTP2Frame(dst []byte, length uint32, typ, flags uint8, streamID uint32) []byte {
	var hdr [9]byte
	hdr[0] = byte(length >> 16)
	hdr[1] = byte(length >> 8)
	hdr[2] = byte(length)
	hdr[3] = typ
	hdr[4] = flags
	binary.BigEndian.PutUint32(hdr[5:], streamID)
	dst = append(dst, hdr[:]...)
	if length > 0 {
		dst = append(dst, make([]byte, length)...)
	}
	return dst
}

func TestDetectHTTP2Preface(t *testing.T) {
	require.True(t, detectHTTP2([]byte(http2.ClientPreface)))
	require.True(t, detectHTTP2(append([]byte(http2.ClientPreface), 0, 0, 0)))
}

func TestDetectHTTP2Settings(t *testing.T) {
	buf := appendHTTP2Frame(nil, 0, byte(http2.FrameSettings), 0, 0)
	require.True(t, detectHTTP2(buf), "empty SETTINGS on stream 0")

	buf = appendHTTP2Frame(nil, 6, byte(http2.FrameSettings), 0, 0)
	require.True(t, detectHTTP2(buf), "one SETTINGS entry")

	buf = appendHTTP2Frame(nil, 0, byte(http2.FrameSettings), uint8(http2.FlagSettingsAck), 0)
	require.True(t, detectHTTP2(buf), "SETTINGS ACK")
}

func TestDetectHTTP2HeadersTiling(t *testing.T) {
	buf := encodeHeadersFrame(t, 1, []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/users"},
	})
	require.True(t, detectHTTP2(buf), "HEADERS on stream 1")

	dataThenHeaders := appendHTTP2Frame(nil, 5, byte(http2.FrameData), uint8(http2.FlagDataEndStream), 1)
	dataThenHeaders = append(dataThenHeaders, buf...)
	require.True(t, detectHTTP2(dataThenHeaders), "DATA then HEADERS tiles")
}

func TestDetectHTTP2TilesEightFrames(t *testing.T) {
	headers := encodeHeadersFrame(t, 1, []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/users"},
	})
	var buf []byte
	for i := 0; i < http2SniffMaxFrames-1; i++ {
		buf = appendHTTP2Frame(buf, 1, byte(http2.FrameData), 0, 1)
	}
	buf = append(buf, headers...)
	require.True(t, detectHTTP2(buf), "7 DATA + HEADERS fits the sniff window")

	var tooMany []byte
	for i := 0; i < http2SniffMaxFrames; i++ {
		tooMany = appendHTTP2Frame(tooMany, 1, byte(http2.FrameData), 0, 1)
	}
	tooMany = append(tooMany, headers...)
	require.False(t, detectHTTP2(tooMany), "9th frame is past the sniff window")
}

func TestDetectHTTP2ContinuationTiling(t *testing.T) {
	buf := appendHTTP2Frame(nil, 8, byte(http2.FrameHeaders), 0, 1)
	buf = appendHTTP2Frame(buf, 8, byte(http2.FrameContinuation), uint8(http2.FlagHeadersEndHeaders), 1)
	require.True(t, detectHTTP2(buf), "HEADERS + CONTINUATION tiles")
}

func TestDetectHTTP2RejectsDataOnly(t *testing.T) {
	buf := appendHTTP2Frame(nil, 32, byte(http2.FrameData), 0, 1)
	require.False(t, detectHTTP2(buf), "DATA-only must not latch (mid-attach / after OOM)")
}

func TestDetectHTTP2RejectsIncompleteFrame(t *testing.T) {
	buf := appendHTTP2Frame(nil, 20, byte(http2.FrameHeaders), uint8(http2.FlagHeadersEndHeaders), 1)
	require.False(t, detectHTTP2(buf[:len(buf)-1]), "truncated tiling")
	require.False(t, detectHTTP2(append(buf, 0x00)), "extra trailing byte")
}

func TestDetectHTTP2RejectsEvenStreamHeaders(t *testing.T) {
	buf := appendHTTP2Frame(nil, 20, byte(http2.FrameHeaders), uint8(http2.FlagHeadersEndHeaders), 2)
	require.False(t, detectHTTP2(buf), "server-initiated HEADERS are not a client request sniff")
}

func TestDetectHTTP2RejectsSettingsOnStream(t *testing.T) {
	buf := appendHTTP2Frame(nil, 6, byte(http2.FrameSettings), 0, 1)
	require.False(t, detectHTTP2(buf))
}

func TestDetectHTTP2RejectsPingOnStream(t *testing.T) {
	buf := appendHTTP2Frame(nil, 8, byte(http2.FramePing), 0, 7)
	buf = append(buf, encodeHeadersFrame(t, 1, []hpack.HeaderField{{Name: ":method", Value: "GET"}})...)
	require.False(t, detectHTTP2(buf))
}

func TestDetectHTTP2RejectsMysqlShaped(t *testing.T) {
	const payload = 60
	buf := make([]byte, 4+payload)
	buf[0] = payload // 3-byte LE length, seq=1 looks like HEADERS type
	buf[3] = 1
	require.False(t, detectHTTP2(buf))
}

func TestDetectHTTP2RejectsShort(t *testing.T) {
	require.False(t, detectHTTP2(nil))
	require.False(t, detectHTTP2([]byte("PRI * HTTP/2")))
	require.False(t, detectHTTP2([]byte{0, 0, 0, 4}))
}
