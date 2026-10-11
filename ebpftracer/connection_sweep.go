package ebpftracer

import (
	"encoding/binary"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/coroot/coroot-node-agent/proc"
	"k8s.io/klog/v2"
)

// An entry of active_connections is deleted by sys_enter_close. A process that exits
// closes its sockets in the kernel, not through close(), so the entries of short-lived
// processes stayed for good: 93% of the entries of an idle node after 5 minutes,
// growing by ~14 a second. The map is an LRU, so they were not a leak, but they were
// what the LRU would evict last instead of a live connection that has been idle for
// longer, and they forced the map to be sized for them. A live process closes sockets
// without close() too (see isSocketOpen). The entries of closed sockets are swept every
// connectionSweepInterval.
const connectionSweepInterval = 30 * time.Second

// connectionId is the key of active_connections (struct connection_id).
type connectionId struct {
	Fd  uint64
	Pid uint32
	_   uint32
}

// staleConnection is an entry of active_connections whose socket is closed, with the
// timestamp of the connection it was found with (struct connection starts with it).
type staleConnection struct {
	id        connectionId
	timestamp uint64
}

// isSocketOpen tells whether the fd of a connection is still a socket of its process.
// A live process closes a socket without close() too (dup2() over its fd, an exec
// that closes it, close_range()), and then the next open() can reuse its fd.
func isSocketOpen(connection connectionId) bool {
	target, err := os.Readlink(proc.Path(connection.Pid, "fd", strconv.FormatUint(connection.Fd, 10)))
	if err != nil {
		// the process or the fd is gone; other errors (EACCES) say nothing about it
		return !errors.Is(err, os.ErrNotExist)
	}
	return strings.HasPrefix(target, "socket:")
}

func findStaleConnections(activeConnections *ebpf.Map) (kept int, stale []staleConnection, err error) {
	var key connectionId
	value := make([]byte, activeConnections.ValueSize())
	iterator := activeConnections.Iterate()
	for iterator.Next(&key, value) {
		if isSocketOpen(key) {
			kept++
		} else {
			stale = append(stale, staleConnection{id: key, timestamp: binary.NativeEndian.Uint64(value)})
		}
	}
	return kept, stale, iterator.Err()
}

// deleteStaleConnections deletes the stale entries that still hold the connection
// they were found with: the process may have opened a new one on the same fd since,
// and every connection gets its own timestamp (conn_timestamp).
func deleteStaleConnections(activeConnections *ebpf.Map, stale []staleConnection) (removed int, err error) {
	value := make([]byte, activeConnections.ValueSize())
	for _, connection := range stale {
		if err := activeConnections.Lookup(connection.id, value); errors.Is(err, ebpf.ErrKeyNotExist) {
			continue
		} else if err != nil {
			return removed, err
		}
		if binary.NativeEndian.Uint64(value) != connection.timestamp {
			continue
		}
		if err := activeConnections.Delete(connection.id); err == nil {
			removed++
		} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return removed, err
		}
	}
	return removed, nil
}

// sweepClosedConnections deletes the entries of activeConnections whose socket is
// closed, and returns how many entries it kept and how many it deleted.
func sweepClosedConnections(activeConnections *ebpf.Map) (kept, removed int, err error) {
	kept, stale, err := findStaleConnections(activeConnections)
	if err != nil {
		return kept, 0, err
	}
	// deleted after the iteration: deleting while iterating a hash map restarts it
	removed, err = deleteStaleConnections(activeConnections, stale)
	return kept, removed, err
}

// ForgetClosedConnections sweeps active_connections (see connectionSweepInterval)
// and keeps the counts for ActiveConnectionsStats.
func (t *Tracer) ForgetClosedConnections() (kept, removed int, err error) {
	kept, removed, err = sweepClosedConnections(t.collection.Maps["active_connections"])
	t.activeConnectionsKept.Store(int64(kept))
	t.activeConnectionsSwept.Add(uint64(removed))
	return kept, removed, err
}

// ActiveConnectionsStats returns how many entries active_connections had after the
// last sweep, and how many entries of closed sockets the sweeps deleted.
func (t *Tracer) ActiveConnectionsStats() (kept int64, swept uint64) {
	return t.activeConnectionsKept.Load(), t.activeConnectionsSwept.Load()
}

func (t *Tracer) runConnectionSweeper() {
	ticker := time.NewTicker(connectionSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.stopped:
			return
		case <-ticker.C:
			if _, _, err := t.ForgetClosedConnections(); err != nil {
				klog.Warningln("failed to sweep active_connections:", err)
			}
		}
	}
}
