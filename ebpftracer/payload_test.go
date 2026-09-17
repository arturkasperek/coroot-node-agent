package ebpftracer

import (
	"bytes"
	"encoding/binary"
	"testing"

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

func encodeL7Sample(t *testing.T, hdr l7Event, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, &hdr))
	_, err := buf.Write(payload)
	require.NoError(t, err)
	return buf.Bytes()
}
