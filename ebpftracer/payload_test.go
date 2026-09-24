package ebpftracer

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/stretchr/testify/require"
)

func TestCopiedPayloadTruncatedTakesFullBuffer(t *testing.T) {
	payload := bytes.Repeat([]byte{'a'}, MaxPayloadSize)
	payload[MaxPayloadSize-1] = 0xff

	got := copiedPayload(payload, 4096)
	require.Equal(t, payload, got)
}

func TestCopiedPayloadExact1024IsComplete(t *testing.T) {
	payload := bytes.Repeat([]byte{'b'}, MaxPayloadSize)

	got := copiedPayload(payload, uint64(MaxPayloadSize))
	require.Equal(t, payload, got)
	require.False(t, payloadTruncated(uint64(MaxPayloadSize), len(got)))
}

func TestCopiedPayloadUntruncated(t *testing.T) {
	payload := bytes.Repeat([]byte{'c'}, MaxPayloadSize)

	got := copiedPayload(payload, 100)
	require.Equal(t, payload[:100], got)
}

func TestCopiedPayloadEmpty(t *testing.T) {
	require.Nil(t, copiedPayload(nil, 0))
	require.Nil(t, copiedPayload(make([]byte, MaxPayloadSize), 0))
}

func TestPayloadTruncated(t *testing.T) {
	require.True(t, payloadTruncated(4096, MaxPayloadSize))
	require.False(t, payloadTruncated(uint64(MaxPayloadSize), MaxPayloadSize))
	require.False(t, payloadTruncated(100, 100))
	require.False(t, payloadTruncated(0, 0))
}

func TestParseL7EventHeaderSize(t *testing.T) {
	require.Equal(t, 48, binary.Size(l7Event{}))
}

func TestConnectionMapValueSize(t *testing.T) {
	require.Equal(t, 48, binary.Size(Connection{}))
}

func TestParseL7EventVariableRecord(t *testing.T) {
	body := []byte("GET / HTTP/1.1\r\n\r\n")
	raw := encodeL7Sample(t, l7Event{
		Fd:                  7,
		ConnectionTimestamp: 99,
		Pid:                 42,
		Status:              200,
		Protocol:            uint8(l7.ProtocolHTTP),
		PayloadSize:         uint64(len(body)),
	}, body)

	got, truncated, err := parseL7Event(raw)
	require.NoError(t, err)
	require.False(t, truncated)
	require.Equal(t, uint32(42), got.Pid)
	require.Equal(t, uint64(7), got.Fd)
	require.Equal(t, uint64(99), got.Timestamp)
	require.Equal(t, body, got.L7Request.Payload)
	require.Equal(t, l7.ProtocolHTTP, got.L7Request.Protocol)
	require.Equal(t, l7.Status(200), got.L7Request.Status)
}

func TestParseL7EventTruncatedKeeps1024(t *testing.T) {
	body := bytes.Repeat([]byte{'x'}, MaxPayloadSize)
	body[MaxPayloadSize-1] = 0x5a
	raw := encodeL7Sample(t, l7Event{PayloadSize: 4096}, body)

	got, truncated, err := parseL7Event(raw)
	require.NoError(t, err)
	require.True(t, truncated)
	require.Equal(t, MaxPayloadSize, len(got.L7Request.Payload))
	require.Equal(t, byte(0x5a), got.L7Request.Payload[MaxPayloadSize-1])
}

func TestParseL7EventHeaderOnly(t *testing.T) {
	raw := encodeL7Sample(t, l7Event{Protocol: uint8(l7.ProtocolNats), Method: uint8(l7.MethodProduce), PayloadSize: 0}, nil)
	got, truncated, err := parseL7Event(raw)
	require.NoError(t, err)
	require.False(t, truncated)
	require.Nil(t, got.L7Request.Payload)
	require.Equal(t, l7.ProtocolNats, got.L7Request.Protocol)
}

func TestParseL7EventTooShort(t *testing.T) {
	_, _, err := parseL7Event([]byte{1, 2, 3})
	require.Error(t, err)
}

func TestParseTcpEventSize(t *testing.T) {
	require.Equal(t, 110, binary.Size(tcpEvent{}))
}

func TestParseTcpEventConnectionOpen(t *testing.T) {
	raw := encodeTcpSample(t, tcpEvent{
		Fd:        9,
		Timestamp: 111,
		Duration:  222,
		Type:      EventTypeConnectionOpen,
		Pid:       4242,
		SPort:     12345,
		DPort:     80,
		SAddr:     [16]byte{127, 0, 0, 1},
		DAddr:     [16]byte{10, 0, 0, 2},
	})
	got, err := parseTcpEvent(raw)
	require.NoError(t, err)
	require.Equal(t, EventTypeConnectionOpen, got.Type)
	require.Equal(t, uint32(4242), got.Pid)
	require.Equal(t, uint64(9), got.Fd)
	require.Equal(t, uint64(111), got.Timestamp)
	require.Equal(t, time.Duration(222), got.Duration)
	require.Nil(t, got.TrafficStats)
	require.Equal(t, uint16(12345), got.SrcAddr.Port())
	require.Equal(t, uint16(80), got.DstAddr.Port())
}

func TestParseTcpEventConnectionCloseHasTraffic(t *testing.T) {
	raw := encodeTcpSample(t, tcpEvent{
		Type:          EventTypeConnectionClose,
		Pid:           7,
		Fd:            3,
		BytesSent:     100,
		BytesReceived: 200,
		IsInbound:     1,
	})
	got, err := parseTcpEvent(raw)
	require.NoError(t, err)
	require.Equal(t, EventTypeConnectionClose, got.Type)
	require.True(t, got.IsInbound)
	require.NotNil(t, got.TrafficStats)
	require.Equal(t, uint64(100), got.TrafficStats.BytesSent)
	require.Equal(t, uint64(200), got.TrafficStats.BytesReceived)
}

func TestParseTcpEventTooShort(t *testing.T) {
	_, err := parseTcpEvent([]byte{1, 2, 3})
	require.Error(t, err)
}

func encodeTcpSample(t *testing.T, v tcpEvent) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, &v))
	return buf.Bytes()
}

func encodeL7Sample(t *testing.T, hdr l7Event, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, &hdr))
	_, err := buf.Write(payload)
	require.NoError(t, err)
	return buf.Bytes()
}
