//go:build linux && amd64

package ebpftracer

import (
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// openSentOffset is the offset of open_sent in struct connection.
const openSentOffset = 27

// acceptAndDiscard accepts the connections of l and reads them until they close.
func acceptAndDiscard(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			_, _ = io.Copy(io.Discard, c)
			_ = c.Close()
		}()
	}
}

// A connection whose open was never sent is announced by its first write, with the
// addresses read from its struct sock_common (through CO-RE).
func TestConnectionOpenIsSentFromTheSocketOfAConnection(t *testing.T) {
	skipIfNotVMSerial(t)
	getEvent, stop := runTracer(t)
	defer stop()
	watchSelf(t)
	pid := uint32(os.Getpid())

	// distinct source and destination addresses, so that swapping them is caught
	for _, address := range []string{"fd00::1", "fd00::2"} {
		output, err := exec.Command("ip", "-6", "addr", "add", address+"/128", "dev", "lo", "nodad").CombinedOutput()
		require.NoError(t, err, string(output))
		defer exec.Command("ip", "-6", "addr", "del", address+"/128", "dev", "lo").Run()
	}
	for _, network := range []struct{ name, from, to string }{
		{"tcp4", "127.0.0.3", "127.0.0.2"},
		{"tcp6", "fd00::1", "fd00::2"},
	} {
		t.Run(network.name, func(t *testing.T) {
			l, err := net.Listen(network.name, net.JoinHostPort(network.to, "0"))
			require.NoError(t, err)
			defer l.Close()
			go acceptAndDiscard(l)

			dialer := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(network.from)}}
			c, err := dialer.Dial(network.name, l.Addr().String())
			require.NoError(t, err)
			defer c.Close()
			localAddr, remoteAddr := c.LocalAddr().String(), l.Addr().String()
			waitFor(t, getEvent, 15*time.Second, tcpMatch(EventTypeConnectionOpen, localAddr, remoteAddr, pid))

			rawConn, err := c.(*net.TCPConn).SyscallConn()
			require.NoError(t, err)
			var fd uintptr
			require.NoError(t, rawConn.Control(func(socketFd uintptr) { fd = socketFd }))
			connections := sharedTr.collection.Maps["active_connections"]
			connection := connectionId{Fd: uint64(fd), Pid: pid}
			value := make([]byte, connections.ValueSize())
			require.NoError(t, connections.Lookup(connection, value))
			require.Equal(t, byte(1), value[openSentOffset])
			value[openSentOffset] = 0
			require.NoError(t, connections.Put(connection, value))

			_, err = c.Write([]byte("hello"))
			require.NoError(t, err)
			waitFor(t, getEvent, 15*time.Second, tcpMatch(EventTypeConnectionOpen, localAddr, remoteAddr, pid))
		})
	}
}

// The destination a connection was DNATed to is read from its struct nf_conn
// (through CO-RE) and reported as the actual destination.
func TestConnectionOpenReportsTheDestinationOfDNAT(t *testing.T) {
	skipIfNotVMSerial(t)
	getEvent, stop := runTracer(t)
	defer stop()
	watchSelf(t)
	pid := uint32(os.Getpid())

	l, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	go acceptAndDiscard(l)
	actual := l.Addr().String()
	unused, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	dialed := unused.Addr().String()
	require.NoError(t, unused.Close())

	_, dialedPort, _ := net.SplitHostPort(dialed)
	rule := []string{"OUTPUT", "-p", "tcp", "-d", "127.0.0.1", "--dport", dialedPort, "-j", "DNAT", "--to-destination", actual}
	output, err := exec.Command("iptables", append([]string{"-t", "nat", "-A"}, rule...)...).CombinedOutput()
	require.NoError(t, err, string(output))
	defer exec.Command("iptables", append([]string{"-t", "nat", "-D"}, rule...)...).Run()

	// conntrack delivers the events nf_ct_deliver_cached_events is probed for only
	// when they are enabled in the network namespace of the connection
	const eventsParameter = "/proc/sys/net/netfilter/nf_conntrack_events"
	previous, err := os.ReadFile(eventsParameter)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(eventsParameter, []byte("1"), 0644))
	defer os.WriteFile(eventsParameter, previous, 0644)

	c, err := net.DialTimeout("tcp4", dialed, time.Second)
	require.NoError(t, err)
	defer c.Close()
	localAddr := c.LocalAddr().String()
	event := waitFor(t, getEvent, 15*time.Second, tcpMatch(EventTypeConnectionOpen, localAddr, dialed, pid))
	_, actualPort, _ := net.SplitHostPort(actual)
	require.Equal(t, actualPort, strconv.Itoa(int(event.ActualDstAddr.Port())), "actual destination %s", event.ActualDstAddr)
	require.Equal(t, "127.0.0.1", event.ActualDstAddr.IP().Unmap().String())
}
