package ebpftracer

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newConnectionsTestMap is a map laid out like active_connections.
func newConnectionsTestMap(t *testing.T) *ebpf.Map {
	t.Helper()
	activeConnections, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LRUHash, KeySize: 16, ValueSize: 56, MaxEntries: 64})
	if errors.Is(err, os.ErrPermission) {
		t.Skip("creating a BPF map needs CAP_BPF")
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = activeConnections.Close() })
	return activeConnections
}

// connectionValue is a value of active_connections (struct connection) with the given
// timestamp.
func connectionValue(timestamp uint64) []byte {
	value := make([]byte, 56)
	binary.NativeEndian.PutUint64(value, timestamp)
	return value
}

// exitedPid is the pid of a process that has exited (and was waited for).
func exitedPid(t *testing.T) uint32 {
	t.Helper()
	cmd := testBinary("^$")
	require.NoError(t, cmd.Run())
	return uint32(cmd.Process.Pid)
}

// openSocketFd is a socket open in this process.
func openSocketFd(t *testing.T) uint64 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	rawConn, err := listener.(*net.TCPListener).SyscallConn()
	require.NoError(t, err)
	var fd uintptr
	require.NoError(t, rawConn.Control(func(socketFd uintptr) { fd = socketFd }))
	return uint64(fd)
}

// openFileFd is a regular file open in this process.
func openFileFd(t *testing.T) uint64 {
	t.Helper()
	file, err := os.Open(os.Args[0])
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })
	return uint64(file.Fd())
}

// testBinary runs the tests matching run in a new process of this test binary,
// without VM: TestMain would start another tracer in it.
func testBinary(run string, env ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run="+run)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "VM=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, env...)
	return cmd
}

// A process that exits closes its sockets in the kernel, not through close(), so the
// entries sys_enter_close deletes stayed in active_connections for good: 93% of the
// entries of an idle node after 5 minutes, growing by ~14 a second.
func TestSweepForgetsTheConnectionsOfExitedProcesses(t *testing.T) {
	activeConnections := newConnectionsTestMap(t)
	alive := connectionId{Fd: openSocketFd(t), Pid: uint32(os.Getpid())}
	exited := exitedPid(t)
	for _, connection := range []connectionId{alive, {Fd: 4, Pid: exited}, {Fd: 5, Pid: exited}} {
		require.NoError(t, activeConnections.Put(connection, connectionValue(1)))
	}

	kept, removed, err := sweepClosedConnections(activeConnections)
	require.NoError(t, err)
	assert.Equal(t, 1, kept)
	assert.Equal(t, 2, removed)
	value := make([]byte, 56)
	require.NoError(t, activeConnections.Lookup(alive, value), "the socket of a live process stays")
	require.ErrorIs(t, activeConnections.Lookup(connectionId{Fd: 4, Pid: exited}, value), ebpf.ErrKeyNotExist)
	require.ErrorIs(t, activeConnections.Lookup(connectionId{Fd: 5, Pid: exited}, value), ebpf.ErrKeyNotExist)
}

// A live process closes a socket without close() too: dup2() over its fd, an exec
// that closes it (FD_CLOEXEC), close_range().
func TestSweepForgetsTheConnectionsWhoseFdIsClosed(t *testing.T) {
	activeConnections := newConnectionsTestMap(t)
	const notOpenFd = 999999 // above any RLIMIT_NOFILE of a test
	closed := connectionId{Fd: notOpenFd, Pid: uint32(os.Getpid())}
	require.NoError(t, activeConnections.Put(closed, connectionValue(1)))

	kept, removed, err := sweepClosedConnections(activeConnections)
	require.NoError(t, err)
	assert.Equal(t, 0, kept)
	assert.Equal(t, 1, removed)
}

// The fd of a closed socket is reused by the next open() of the process.
func TestSweepForgetsTheConnectionsWhoseFdIsNoLongerASocket(t *testing.T) {
	activeConnections := newConnectionsTestMap(t)
	reused := connectionId{Fd: openFileFd(t), Pid: uint32(os.Getpid())}
	require.NoError(t, activeConnections.Put(reused, connectionValue(1)))

	kept, removed, err := sweepClosedConnections(activeConnections)
	require.NoError(t, err)
	assert.Equal(t, 0, kept)
	assert.Equal(t, 1, removed)
}

// Between the check of an entry and its deletion, the process can open a new
// connection on the same fd: its entry has the same key and a new timestamp.
func TestSweepKeepsAConnectionOpenedOnTheFdOfAStaleOne(t *testing.T) {
	activeConnections := newConnectionsTestMap(t)
	connection := connectionId{Fd: 7, Pid: exitedPid(t)}
	require.NoError(t, activeConnections.Put(connection, connectionValue(1)))
	_, stale, err := findStaleConnections(activeConnections)
	require.NoError(t, err)
	require.Len(t, stale, 1)

	require.NoError(t, activeConnections.Put(connection, connectionValue(2)))
	removed, err := deleteStaleConnections(activeConnections, stale)
	require.NoError(t, err)
	assert.Zero(t, removed)
	require.NoError(t, activeConnections.Lookup(connection, make([]byte, 56)), "the new connection stays")
}

func TestSweepOfAnEmptyMap(t *testing.T) {
	kept, removed, err := sweepClosedConnections(newConnectionsTestMap(t))
	require.NoError(t, err)
	assert.Zero(t, kept)
	assert.Zero(t, removed)
}
