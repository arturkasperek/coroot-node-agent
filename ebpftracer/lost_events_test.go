//go:build linux && amd64

package ebpftracer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Losses are reported per buffer: the L7 ring and the connection ring overflow under
// different loads (a flood of requests, a churn of connections), and a lost connection
// event costs memory (a connection never closed), a lost L7 event only a span.
func TestLostEventsPerBuffer(t *testing.T) {
	tr, _, stop := startTracer(t)
	defer stop()
	lost := tr.LostEvents()
	require.Contains(t, lost, "perf")
	require.Contains(t, lost, "l7_events")
	require.Contains(t, lost, "tcp_connect_events")
	require.Equal(t, tr.LostSamples(), lost["perf"]+lost["l7_events"]+lost["tcp_connect_events"],
		"node_ebpf_lost_samples_total stays their sum")
}
