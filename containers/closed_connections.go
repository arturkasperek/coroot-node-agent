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
)

// gcClosedConnections forgets the connections closed more than
// closedConnectionGrace ago, after their parsers have released the responses
// still held back for a body, and the parsers of L7 events whose connection was
// not registered within closedConnectionGrace.
func (c *Container) gcClosedConnections(now time.Time) {
	c.lock.Lock()
	defer c.lock.Unlock()
	for k, conn := range c.activeConnections {
		if conn.Closed.IsZero() || now.Sub(conn.Closed) <= closedConnectionGrace {
			continue
		}
		c.flushConnectionBodies(conn, now)
		c.forgetConnection(k, conn)
	}
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
