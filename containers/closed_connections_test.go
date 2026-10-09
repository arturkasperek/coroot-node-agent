package containers

import (
	"runtime"
	"testing"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/coroot/coroot-node-agent/tracing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"inet.af/netaddr"
)

func newConnectionsTestContainer() *Container {
	return &Container{
		registry:             &Registry{},
		tracer:               &tracing.Tracer{},
		l7Stats:              L7Stats{},
		activeConnections:    map[ConnectionKey]*ActiveConnection{},
		connectionsByPidFd:   map[PidFd]*ActiveConnection{},
		connectionsByPidFdTs: map[PidFdTs]*ActiveConnection{},
		pendingHttp1Parsers:  map[PidFdTs]*pendingHttp1State{},
		pendingHttp2Parsers:  map[PidFdTs]*pendingHttp2State{},
	}
}

// addConnection registers a connection the way onConnectionOpen does.
func addConnection(c *Container, srcPort uint16, pid uint32, fd, timestamp uint64) (ConnectionKey, *ActiveConnection) {
	k := ConnectionKey{
		src: netaddr.IPPortFrom(netaddr.MustParseIP("10.0.0.1"), srcPort),
		dst: netaddr.MustParseIPPort("10.0.0.5:8080"),
	}
	conn := &ActiveConnection{Pid: pid, Fd: fd, Timestamp: timestamp, key: k}
	c.activeConnections[k] = conn
	c.connectionsByPidFd[PidFd{Pid: pid, Fd: fd}] = conn
	c.connectionsByPidFdTs[PidFdTs{Pid: pid, Fd: fd, Timestamp: timestamp}] = conn
	return k, conn
}

func requireKnown(t *testing.T, c *Container, k ConnectionKey, conn *ActiveConnection) {
	t.Helper()
	require.Same(t, conn, c.activeConnections[k])
	require.Same(t, conn, c.connectionsByPidFdTs[PidFdTs{Pid: conn.Pid, Fd: conn.Fd, Timestamp: conn.Timestamp}],
		"a late L7 event looks its connection up by (pid, fd, timestamp)")
}

// Close events and L7 events come through different ring buffers that are read
// independently, so the last response of a connection can be read after its close.
// A closed connection is kept for closedConnectionGrace for those, and not longer:
// with 10 minutes, connection churn kept hundreds of MB of connections and parsers.
func TestClosedConnectionIsKeptForTheGraceOnly(t *testing.T) {
	c := newConnectionsTestContainer()
	k, conn := addConnection(c, 41822, 4321, 7, 1000)
	t0 := time.Now()
	conn.Closed = t0

	_, _ = c.gcClosedConnections(t0.Add(closedConnectionGrace / 2))
	requireKnown(t, c, k, conn)

	c.gcClosedConnections(t0.Add(closedConnectionGrace + time.Second))
	assert.NotContains(t, c.activeConnections, k)
	assert.NotContains(t, c.connectionsByPidFd, PidFd{Pid: 4321, Fd: 7})
	assert.NotContains(t, c.connectionsByPidFdTs, PidFdTs{Pid: 4321, Fd: 7, Timestamp: 1000})
}

func TestOpenConnectionsAreNotCollected(t *testing.T) {
	c := newConnectionsTestContainer()
	k, conn := addConnection(c, 41822, 4321, 7, 1000)
	c.gcClosedConnections(time.Now().Add(24 * time.Hour))
	requireKnown(t, c, k, conn)
}

// The fd of a closed connection is often reused right away: forgetting the old
// connection must not forget the new one that now owns the fd.
func TestForgettingAClosedConnectionKeepsTheNewOwnerOfItsFd(t *testing.T) {
	c := newConnectionsTestContainer()
	t0 := time.Now()
	oldKey, old := addConnection(c, 41822, 4321, 7, 1000)
	old.Closed = t0
	newKey, cur := addConnection(c, 41823, 4321, 7, 2000) // same pid and fd, a later connection

	c.gcClosedConnections(t0.Add(closedConnectionGrace + time.Second))
	assert.NotContains(t, c.activeConnections, oldKey)
	assert.NotContains(t, c.connectionsByPidFdTs, PidFdTs{Pid: 4321, Fd: 7, Timestamp: 1000})
	requireKnown(t, c, newKey, cur)
	assert.Same(t, cur, c.connectionsByPidFd[PidFd{Pid: 4321, Fd: 7}])
}

// A response held back for its body becomes a span before its connection is
// forgotten, and the connection does not stay referenced by the body holders.
func TestHeldResponseIsReleasedBeforeTheConnectionIsForgotten(t *testing.T) {
	c := newConnectionsTestContainer()
	k, conn := addConnection(c, 41822, 4321, 7, 1000)
	opts := l7.DefaultBodyOptions()
	opts.Enabled = true
	conn.http1Parser = l7.NewHttp1ParserWithBodies(opts)
	t0 := time.Now()
	p := conn.http1Parser
	p.ParseAt(l7.MethodHttpClientHeaders, []byte("GET /stream HTTP/1.1\r\nHost: x\r\n\r\n"), 1, t0)
	p.ParseAt(l7.MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n"), 2, t0)
	p.ParseAt(l7.MethodHttpServerData, []byte("hello"), 3, t0)
	c.noteBodyHolder(conn)
	conn.Closed = t0

	c.gcClosedConnections(t0.Add(closedConnectionGrace + time.Second))
	assert.Equal(t, uint64(1), c.registry.http1RequestsParsed.Load(), "the held response is a span")
	assert.NotContains(t, c.activeConnections, k)
	assert.NotContains(t, c.bodyHolders, conn)
}

// Parsers of L7 events that came before their connection was registered wait for it
// for the grace too: a connection that has not shown up by then will not.
func TestPendingParsersExpireAfterTheGrace(t *testing.T) {
	c := newConnectionsTestContainer()
	t0 := time.Now()
	k1 := PidFdTs{Pid: 4321, Fd: 7, Timestamp: 1000}
	k2 := PidFdTs{Pid: 4321, Fd: 8, Timestamp: 1000}
	c.pendingHttp1Parsers[k1] = &pendingHttp1State{parser: l7.NewHttp1Parser(), timestamp: 1000, updatedAt: t0}
	c.pendingHttp2Parsers[k2] = &pendingHttp2State{parser: l7.NewHttp2Parser(), timestamp: 1000, updatedAt: t0}

	c.gcClosedConnections(t0.Add(closedConnectionGrace / 2))
	assert.Contains(t, c.pendingHttp1Parsers, k1)
	assert.Contains(t, c.pendingHttp2Parsers, k2)

	c.gcClosedConnections(t0.Add(closedConnectionGrace + time.Second))
	assert.NotContains(t, c.pendingHttp1Parsers, k1)
	assert.NotContains(t, c.pendingHttp2Parsers, k2)
}

// gcClosedConnections reports what it keeps, which the registry exports: open
// connections that are never closed (their close event was lost) show up there.
func TestGcClosedConnectionsCountsWhatItKeeps(t *testing.T) {
	c := newConnectionsTestContainer()
	t0 := time.Now()
	addConnection(c, 41821, 4321, 6, 1000) // open
	_, inGrace := addConnection(c, 41822, 4321, 7, 1000)
	inGrace.Closed = t0
	_, expired := addConnection(c, 41823, 4321, 8, 1000)
	expired.Closed = t0.Add(-2 * closedConnectionGrace)

	open, closed := c.gcClosedConnections(t0.Add(time.Second))
	assert.Equal(t, 1, open)
	assert.Equal(t, 1, closed, "the expired one is forgotten, the one in its grace is kept")
}

func newOpenTestContainer() *Container {
	c := newConnectionsTestContainer()
	c.processes = map[uint32]*Process{4321: {Pid: 4321}}
	c.connectionStats = map[common.DestinationKey]*ConnectionStats{}
	c.lastConnectionAttempts = map[common.HostPort]time.Time{}
	c.failedConnectionAttempts = map[common.HostPort]int64{}
	return c
}

// A server that closes its side frees the client's port for the next connection right
// away, so the same addresses are used again and the new connection takes the place of
// the old one in activeConnections. The old one stayed in connectionsByPidFdTs for good:
// 129890 of 308711 connections of a churn test were never forgotten.
func TestConnectionWhoseAddressesAreReusedIsForgotten(t *testing.T) {
	c := newOpenTestContainer()
	src := netaddr.MustParseIPPort("10.0.0.1:41822")
	dst := netaddr.MustParseIPPort("10.0.0.5:8080")
	c.onConnectionOpen(4321, 7, src, dst, dst, 1000, false, 0)
	c.onConnectionOpen(4321, 8, src, dst, dst, 2000, false, 0) // the same addresses, a new connection

	now := time.Now()
	open, closed := c.gcClosedConnections(now)
	assert.Equal(t, 1, open)
	assert.Equal(t, 1, closed, "a connection whose addresses a newer one took is closed")
	require.Contains(t, c.connectionsByPidFdTs, PidFdTs{Pid: 4321, Fd: 7, Timestamp: 1000}, "kept for its grace")

	c.gcClosedConnections(now.Add(closedConnectionGrace + time.Second))
	assert.NotContains(t, c.connectionsByPidFdTs, PidFdTs{Pid: 4321, Fd: 7, Timestamp: 1000})
	assert.Contains(t, c.connectionsByPidFdTs, PidFdTs{Pid: 4321, Fd: 8, Timestamp: 2000})
	assert.Len(t, c.activeConnections, 1)
}

// Go maps do not give memory back when their entries are deleted. After a burst of
// connections the maps that indexed them are rebuilt once few entries are left.
func TestConnectionMapsAreRebuiltAfterABurst(t *testing.T) {
	c := newOpenTestContainer()
	dst := netaddr.MustParseIPPort("10.0.0.5:8080")
	heap := func() int64 {
		runtime.GC()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		return int64(ms.HeapAlloc)
	}
	before := heap()
	const burst = 100000
	for i := 0; i < burst; i++ {
		src := netaddr.IPPortFrom(netaddr.IPv4(10, 1, byte(i>>8), byte(i)), uint16(1024+i%60000))
		c.onConnectionOpen(4321, uint64(10+i), src, dst, dst, uint64(1+i), false, 0)
	}
	now := time.Now()
	for _, conn := range c.activeConnections {
		conn.Closed = now
	}
	c.gcClosedConnections(now.Add(closedConnectionGrace + time.Second))
	require.Empty(t, c.activeConnections)
	require.Empty(t, c.connectionsByPidFdTs)
	kept := heap() - before
	t.Logf("%d bytes kept after %d connections were forgotten", kept, burst)
	assert.Less(t, kept, int64(1<<20), "the maps that indexed %d connections hold nothing any more", burst)
	runtime.KeepAlive(c) // the container lives on in the agent: without this the GC frees it, maps and all
}
