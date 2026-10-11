//go:build linux && amd64

package ebpftracer

import (
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestHelperConnectWriteAndExit is the process of the test below: it connects to
// CONNECT_TO, sends a request and exits without closing the socket.
func TestHelperConnectWriteAndExit(t *testing.T) {
	addr := os.Getenv("CONNECT_TO")
	if addr == "" {
		t.Skip("a helper process of TestConnectionOfAProcessThatExitsWithoutCloseIsForgotten")
	}
	c, err := net.Dial("tcp", addr)
	if err != nil {
		os.Exit(2)
	}
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	_, _ = c.Read(make([]byte, 1024))
	os.Exit(0) // no close(): the kernel closes the socket
}

// listenHttp is a server that answers every request of a connection with an empty
// 200 and returns its address.
func listenHttp(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = c.Read(make([]byte, 1024))
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
				_, _ = io.Copy(io.Discard, c)
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

// activeConnectionEntries counts the entries of active_connections that match.
func activeConnectionEntries(t *testing.T, match func(connectionId) bool) int {
	t.Helper()
	connections := sharedTr.collection.Maps["active_connections"]
	n := 0
	var key connectionId
	value := make([]byte, connections.ValueSize())
	iterator := connections.Iterate()
	for iterator.Next(&key, value) {
		if match(key) {
			n++
		}
	}
	require.NoError(t, iterator.Err())
	return n
}

func TestConnectionOfAProcessThatExitsWithoutCloseIsForgotten(t *testing.T) {
	skipIfNotVMSerial(t)
	_, stop := runTracer(t)
	defer stop()

	child := testBinary("^TestHelperConnectWriteAndExit$", "CONNECT_TO="+listenHttp(t))
	require.NoError(t, child.Run())
	ofChild := func(key connectionId) bool { return key.Pid == uint32(child.Process.Pid) }
	require.Eventually(t, func() bool { return activeConnectionEntries(t, ofChild) > 0 }, 2*time.Second, 50*time.Millisecond,
		"the connection of the exited process stays in active_connections: nothing called close() for it")

	_, removed, err := sharedTr.ForgetClosedConnections()
	require.NoError(t, err)
	require.Positive(t, removed)
	require.Zero(t, activeConnectionEntries(t, ofChild))
}

func TestConnectionWhoseFdIsReplacedByDup2IsForgotten(t *testing.T) {
	skipIfNotVMSerial(t)
	_, stop := runTracer(t)
	defer stop()

	c, err := net.Dial("tcp", listenHttp(t))
	require.NoError(t, err)
	defer c.Close()
	_, err = c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	require.NoError(t, err)
	_, _ = c.Read(make([]byte, 1024))
	rawConn, err := c.(*net.TCPConn).SyscallConn()
	require.NoError(t, err)
	var fd uintptr
	require.NoError(t, rawConn.Control(func(socketFd uintptr) { fd = socketFd }))
	connection := connectionId{Fd: uint64(fd), Pid: uint32(os.Getpid())}
	isConnection := func(key connectionId) bool { return key == connection }
	require.Eventually(t, func() bool { return activeConnectionEntries(t, isConnection) == 1 }, 2*time.Second, 50*time.Millisecond)

	devNull, err := os.Open(os.DevNull)
	require.NoError(t, err)
	defer devNull.Close()
	require.NoError(t, unix.Dup2(int(devNull.Fd()), int(fd)))
	require.Equal(t, 1, activeConnectionEntries(t, isConnection),
		"the socket is closed by dup2(), not close(): its entry stays")

	_, _, err = sharedTr.ForgetClosedConnections()
	require.NoError(t, err)
	require.Zero(t, activeConnectionEntries(t, isConnection))
}
