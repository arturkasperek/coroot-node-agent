package containers

import "time"

// Close events and L7 events come through different ring buffers
// (tcp_connect_events and l7_events), merged in the order they happened by
// ebpftracer's ringMerger: the close of a connection is handled after its L7
// events. closedConnectionGrace covers what the order does not: a socket closed by
// another thread while one is still in read(), and a response held back for its
// body, which is released before the connection is forgotten anyway.
//
// Read by two independent goroutines, the L7 events of a connection were handled
// seconds after its close under load, so closed connections were kept for 60 s:
// a connection churn test peaked at 299k closed connections and 700 MB of memory
// (81-100k and 370-406 MB merged).
const (
	closedConnectionGrace       = 5 * time.Second
	closedConnectionsGcInterval = 2 * time.Second
)

const (
	// Go maps keep their memory when entries are deleted: the maps that indexed a
	// burst of 100000 connections kept 19 MB after all of them were forgotten. They
	// are rebuilt once they hold a quarter of their peak, if the peak was large.
	connectionMapsRebuildMin = 4096
)

// gcClosedConnections forgets the connections closed more than
// closedConnectionGrace ago, after their parsers have released the responses
// still held back for a body. It returns how many connections it keeps, open and
// closed.
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
