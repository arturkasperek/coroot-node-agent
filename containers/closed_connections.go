package containers

import "time"

// Close events and L7 events reach the agent through different ring buffers
// (tcp_connect_events and l7_events) read by different goroutines, so the L7
// events of a connection can be handled after its close: the L7 ring is the one
// that falls behind under load. closedConnectionGrace is how long a closed
// connection, with its parsers, is kept for them. It is what the registry
// allows for events queued behind a process exit (RecentlyExitedTTL), far more
// than the L7 ring can lag (128 MiB at the ~55 MB/s a 1-CPU agent reads it is
// 2-3 s) and than a response is held back for its body (5 s).
//
// gc keeps forgetting closed connections after gcInterval as a fallback, but
// that was the only rule before: with connections kept 10-20 minutes after
// their close, connection churn held hundreds of MB of connections and parsers.
const (
	closedConnectionGrace       = RecentlyExitedTTL
	closedConnectionsGcInterval = 10 * time.Second

	// Go maps keep their memory when entries are deleted: the maps that indexed a
	// burst of 100000 connections kept 19 MB after all of them were forgotten. They
	// are rebuilt once they hold a quarter of their peak, if the peak was large.
	connectionMapsRebuildMin = 4096
)

// gcClosedConnections forgets the connections closed more than
// closedConnectionGrace ago, after their parsers have released the responses
// still held back for a body, and the parsers of L7 events whose connection was
// not registered within closedConnectionGrace. It returns how many connections
// it keeps, open and closed.
func (c *Container) gcClosedConnections(now time.Time) (open, closed int) {
	c.lock.Lock()
	defer c.lock.Unlock()
	for k, conn := range c.activeConnections {
		if conn.Closed.IsZero() {
			open++
			continue
		}
		if now.Sub(conn.Closed) <= closedConnectionGrace {
			closed++
			continue
		}
		c.flushConnectionBodies(conn, now)
		c.forgetConnection(k, conn)
	}
	// A server that closes its side frees the client's port right away, so a new
	// connection can have the addresses of an old one and take its place in
	// activeConnections. The old one is closed (the kernel has one socket per
	// addresses) and only connectionsByPidFdTs still has it.
	for _, conn := range c.connectionsByPidFdTs {
		if c.activeConnections[conn.key] == conn {
			continue // counted above
		}
		if conn.Closed.IsZero() {
			conn.Closed = now
		}
		if now.Sub(conn.Closed) <= closedConnectionGrace {
			closed++
			continue
		}
		c.flushConnectionBodies(conn, now)
		c.forgetConnection(conn.key, conn)
	}
	c.rebuildConnectionMaps()
	for k, st := range c.pendingHttp1Parsers {
		if now.Sub(st.updatedAt) > closedConnectionGrace {
			delete(c.pendingHttp1Parsers, k)
		}
	}
	for k, st := range c.pendingHttp2Parsers {
		if now.Sub(st.updatedAt) > closedConnectionGrace {
			delete(c.pendingHttp2Parsers, k)
		}
	}
	return open, closed
}

// forgetConnection removes a connection from every index. The (pid, fd) of a
// closed connection is often owned by a newer one already, which stays.
// Called with c.lock held.
func (c *Container) forgetConnection(k ConnectionKey, conn *ActiveConnection) {
	if c.activeConnections[k] == conn {
		delete(c.activeConnections, k)
	}
	pidFd := PidFd{Pid: conn.Pid, Fd: conn.Fd}
	if c.connectionsByPidFd[pidFd] == conn {
		delete(c.connectionsByPidFd, pidFd)
	}
	if conn.Timestamp != 0 {
		kts := PidFdTs{Pid: conn.Pid, Fd: conn.Fd, Timestamp: conn.Timestamp}
		if c.connectionsByPidFdTs[kts] == conn {
			delete(c.connectionsByPidFdTs, kts)
		}
	}
	delete(c.bodyHolders, conn)
}

// rebuildConnectionMaps copies the connection maps into new ones when they hold a
// quarter of what they held at their peak, so that the memory of a burst is given
// back. Called with c.lock held.
func (c *Container) rebuildConnectionMaps() {
	n := max(len(c.activeConnections), len(c.connectionsByPidFdTs))
	if c.connectionsPeak < connectionMapsRebuildMin || n > c.connectionsPeak/4 {
		return
	}
	c.activeConnections = rebuilt(c.activeConnections)
	c.connectionsByPidFd = rebuilt(c.connectionsByPidFd)
	c.connectionsByPidFdTs = rebuilt(c.connectionsByPidFdTs)
	c.connectionsPeak = n
}

// rebuilt is a copy of m sized for what m holds now (maps.Clone keeps the size of m).
func rebuilt[K comparable, V any](m map[K]V) map[K]V {
	out := make(map[K]V, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
