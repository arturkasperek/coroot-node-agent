package ebpftracer

import (
	"bytes"
	"testing"

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
