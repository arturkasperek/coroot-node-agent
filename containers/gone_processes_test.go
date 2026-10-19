package containers

import (
	"os"
	"testing"
	"time"

	"github.com/coroot/coroot-node-agent/proc"
	"github.com/coroot/coroot-node-agent/tracing"
	"github.com/stretchr/testify/require"
	"inet.af/netaddr"
)

// The server side of the requests of a process that was gone when the agent
// handled its events (a server forks it for one connection, as Postgres does):
// the connection is recorded on a stand-in process, which has the flags of its
// parent (whether eBPF traces are disabled, for one), and which is forgotten
// once the events of an exited process stop coming.
func TestInboundConnectionOfAGoneProcess(t *testing.T) {
	parentProcess := &Process{Pid: 100, Flags: proc.Flags{EbpfTracesDisabled: true}, netNsId: "net:[4026532]"}
	c := &Container{processes: map[uint32]*Process{100: parentProcess}, tracer: &tracing.Tracer{}}
	c.registry = &Registry{parentPid: func(pid uint32) (uint32, bool) { return 100, true }}
	c.registry.rememberExited(goneChildPid, c)

	server, client := netaddr.MustParseIPPort("10.42.0.20:5432"), netaddr.MustParseIPPort("10.42.0.150:40000")
	c.onInboundConnectionOpen(goneChildPid, 7, server, client, 1234, true)

	child := c.processes[goneChildPid]
	require.NotNil(t, child, "a stand-in for the gone process")
	require.Equal(t, server, child.inboundConnection(7, 1234).server)
	require.Equal(t, client, child.inboundConnection(7, 1234).client)
	require.True(t, child.Flags.EbpfTracesDisabled, "the flags of its parent")
	require.Equal(t, "net:[4026532]", child.NetNsId(), "the network namespace of its parent")

	live := uint32(os.Getpid())
	c.onInboundConnectionOpen(live, 7, server, client, 1234, true)
	require.Nil(t, c.processes[live], "no stand-in for a live process the container does not have")
	require.Equal(t, uint64(1), c.registry.l7InboundDroppedNoProcess.Load(), "counted")

	c.forgetGoneProcesses(time.Now())
	require.NotNil(t, c.processes[goneChildPid], "its late events may still come")
	c.forgetGoneProcesses(time.Now().Add(RecentlyExitedTTL + time.Second))
	require.Nil(t, c.processes[goneChildPid])
	require.NotNil(t, c.processes[100])
}

// The exit of a process (from its own ring) can be handled before the L7
// events it sent before it exited: the state of its inbound connections (their
// ends, the requests held for their bodies) stays with a stand-in until the
// events of an exited process stop coming. The container has no live process
// any more.
func TestExitedProcessKeepsItsInboundConnections(t *testing.T) {
	live := newGoneProcess(200, nil, time.Now())
	live.goneAt = time.Time{} // a live process
	server, client := netaddr.MustParseIPPort("10.42.0.20:8081"), netaddr.MustParseIPPort("10.42.0.150:40000")
	live.inboundConnections = map[uint64]*inboundConnection{7: {timestamp: 1234, server: server, client: client, seenOpen: true}}
	idle := newGoneProcess(201, nil, time.Now())
	idle.goneAt = time.Time{}
	c := &Container{processes: map[uint32]*Process{200: live, 201: idle}}

	c.onProcessExitLocked(201, false)
	require.Nil(t, c.processes[201], "nothing to keep for")

	c.onProcessExitLocked(200, false)
	stand := c.processes[200]
	require.NotNil(t, stand)
	require.False(t, stand.goneAt.IsZero())
	require.Equal(t, client, stand.inboundConnection(7, 1234).client)
	require.False(t, c.zombieAt.IsZero(), "no live process")

	c.forgetGoneProcesses(time.Now().Add(RecentlyExitedTTL + time.Second))
	require.Empty(t, c.processes)
}

// Whether eBPF traces are disabled for a container is asked at every L7 event:
// it is kept as processes come and go, stand-ins included, rather than looked
// up among all of them, which a server forking per connection makes many.
func TestEbpfTracesDisabledFollowsTheProcesses(t *testing.T) {
	c := &Container{processes: map[uint32]*Process{}}
	disabled := newGoneProcess(300, nil, time.Now())
	disabled.goneAt, disabled.Flags = time.Time{}, proc.Flags{EbpfTracesDisabled: true}
	disabled.inboundConnections = map[uint64]*inboundConnection{7: {timestamp: 1}}

	c.setProcessLocked(300, disabled)
	require.True(t, c.ebpfTracesDisabled())

	c.onProcessExitLocked(300, false)
	require.NotNil(t, c.processes[300], "a stand-in with its inbound connections")
	require.True(t, c.ebpfTracesDisabled(), "the stand-in has its flags")

	c.forgetGoneProcesses(time.Now().Add(RecentlyExitedTTL + time.Second))
	require.False(t, c.ebpfTracesDisabled())
}
