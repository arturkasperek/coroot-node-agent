package ebpftracer

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/stretchr/testify/require"
)

func TestEmbeddedProgramsTargetKernel618(t *testing.T) {
	min := common.NewVersion(6, 18, 0)
	require.Contains(t, ebpfProgs, "amd64")
	require.Contains(t, ebpfProgs, "arm64")
	for arch, progs := range ebpfProgs {
		require.NotEmpty(t, progs, arch)
		for _, p := range progs {
			v, err := common.VersionFromString(p.version)
			require.NoError(t, err, arch)
			require.True(t, v.GreaterOrEqual(min), "%s blob %s is older than 6.18", arch, p.version)
		}
	}
}

func TestL7EventsMapIsRingbuf(t *testing.T) {
	spec := loadAmd64ProgramSpec(t)
	m, ok := spec.Maps["l7_events"]
	require.True(t, ok, "l7_events map missing")
	require.Equal(t, ebpf.RingBuf, m.Type)
	require.GreaterOrEqual(t, m.MaxEntries, uint32(8<<20), "ringbuf should be at least 8MiB")

	dropped, ok := spec.Maps["l7_events_dropped"]
	require.True(t, ok, "l7_events_dropped map missing")
	require.Equal(t, ebpf.PerCPUArray, dropped.Type)
}

func TestTcpConnectEventsMapIsRingbuf(t *testing.T) {
	spec := loadAmd64ProgramSpec(t)
	m, ok := spec.Maps["tcp_connect_events"]
	require.True(t, ok, "tcp_connect_events map missing")
	require.Equal(t, ebpf.RingBuf, m.Type)
	require.GreaterOrEqual(t, m.MaxEntries, uint32(8<<20), "ringbuf should be at least 8MiB")

	dropped, ok := spec.Maps["tcp_connect_events_dropped"]
	require.True(t, ok, "tcp_connect_events_dropped map missing")
	require.Equal(t, ebpf.PerCPUArray, dropped.Type)
}

func loadAmd64ProgramSpec(t *testing.T) *ebpf.CollectionSpec {
	t.Helper()
	var blob []byte
	for _, p := range ebpfProgs["amd64"] {
		if p.flags == "" {
			blob = p.prog
			break
		}
	}
	require.NotEmpty(t, blob)
	zr, err := gzip.NewReader(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(blob)))
	require.NoError(t, err)
	obj, err := io.ReadAll(zr)
	require.NoError(t, err)
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	require.NoError(t, err)
	return spec
}
