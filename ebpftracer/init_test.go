package ebpftracer

import (
	"testing"

	"github.com/coroot/coroot-node-agent/proc"
	"github.com/stretchr/testify/require"
	"inet.af/netaddr"
)

// The eBPF side keys its per-connection protocol state (where a response body
// ends, ...) by the connection timestamp. Connections open before the agent
// started all shared one, so they shared that state: a response of one was taken
// for the body of another and lost.
func TestPreexistingConnectionsGetATimestampEach(t *testing.T) {
	socket := func(pid uint32, fd uint64, src, dst string, listen bool) sock {
		return sock{pid: pid, fd: fd, Sock: proc.Sock{SAddr: netaddr.MustParseIPPort(src), DAddr: netaddr.MustParseIPPort(dst), Listen: listen}}
	}
	socks := []sock{
		socket(10, 3, "0.0.0.0:3000", "0.0.0.0:0", true),
		socket(10, 5, "10.0.0.1:41000", "10.0.0.2:8080", false),
		socket(10, 6, "10.0.0.1:41001", "10.0.0.3:9000", false),
		socket(20, 5, "10.0.0.4:42000", "10.0.0.2:8080", false),
		socket(10, 7, "10.0.0.1:3000", "10.0.0.9:50000", false), // inbound to the listen
	}

	events, entries := preexistingConnections(socks, 1000)

	timestamps := map[uint64]bool{}
	for _, entry := range entries {
		require.False(t, timestamps[entry.conn.Timestamp], "two connections share timestamp %d", entry.conn.Timestamp)
		timestamps[entry.conn.Timestamp] = true
	}
	require.Len(t, entries, 4, "every connection, inbound ones too, but not the listen")

	byConnection := map[ConnectionId]Connection{}
	for _, entry := range entries {
		byConnection[entry.id] = entry.conn
	}
	reported := 0
	for _, event := range events {
		if event.Type != EventTypeConnectionOpen {
			continue
		}
		reported++
		conn, ok := byConnection[ConnectionId{FD: event.Fd, PID: event.Pid}]
		require.True(t, ok)
		require.Equal(t, conn.Timestamp, event.Timestamp, "the event names the connection the eBPF side knows")
		require.True(t, event.Preexisting, "its requests before the tracer started were not seen")
		require.Equal(t, conn.IsInbound == 1, event.IsInbound)
	}
	require.Equal(t, 4, reported, "inbound connections too: their server spans need the client's address")
	require.Equal(t, uint8(1), byConnection[ConnectionId{FD: 7, PID: 10}].IsInbound)
}
