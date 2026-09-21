//go:build linux && amd64

package ebpftracer

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/coroot/coroot-node-agent/proc"

	"github.com/containerd/cgroups"
	cgroupsV2 "github.com/containerd/cgroups/v2"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"
)

func skipIfNotVM(t *testing.T) {
	if os.Getenv("VM") == "" {
		t.SkipNow()
	}
}

func TestWaitSeenAcceptsOutOfOrder(t *testing.T) {
	ch := make(chan Event, 3)
	ch <- Event{Type: EventTypeFileOpen, Pid: 7, Fd: 3}
	ch <- Event{Type: EventTypeProcessStart, Pid: 7}
	get := func() *Event {
		select {
		case e := <-ch:
			return &e
		default:
			return nil
		}
	}
	waitSeen(t, get, 7, false, EventTypeProcessStart, EventTypeFileOpen)
}

func TestWaitForSkipsUnrelatedEvents(t *testing.T) {
	ch := make(chan Event, 3)
	ch <- Event{Type: EventTypeProcessStart, Pid: 1}
	ch <- Event{Type: EventTypeProcessStart, Pid: 99}
	ch <- Event{Type: EventTypeProcessExit, Pid: 99}
	get := func() *Event {
		select {
		case e := <-ch:
			return &e
		default:
			return nil
		}
	}

	got := waitFor(t, get, time.Second, func(e *Event) bool {
		return e.Type == EventTypeProcessExit && e.Pid == 99
	})
	require.Equal(t, EventTypeProcessExit, got.Type)
	require.Equal(t, uint32(99), got.Pid)
}

func TestFormatAddrUnmapsIPv4(t *testing.T) {
	v4 := netaddr.MustParseIPPort("127.0.0.1:8080")
	require.Equal(t, "127.0.0.1:8080", formatAddr(v4))

	mapped := netaddr.IPPortFrom(netaddr.IPv6Raw([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1}), 8080)
	require.Equal(t, "127.0.0.1:8080", formatAddr(mapped))

	stuffed := netaddr.IPPortFrom(netaddr.IPv6Raw([16]byte{127, 0, 0, 1}), 8080)
	require.Equal(t, "127.0.0.1:8080", formatAddr(stuffed))

	unspec6 := netaddr.IPPortFrom(netaddr.IPv6Unspecified(), 0)
	require.Equal(t, "0.0.0.0:0", formatAddr(unspec6))

	var invalid netaddr.IPPort
	require.Equal(t, "0.0.0.0:0", formatAddr(invalid))
}

func TestProcessEvents(t *testing.T) {
	skipIfNotVM(t)
	src := `
		package main

		import (
			"os"
			"runtime"
			"strconv"
			"time"
		)

		func main() {
			mb, _ := strconv.Atoi(os.Args[1])
			sleep, _ := time.ParseDuration(os.Args[2])
			time.Sleep(300 * time.Millisecond)
			buf := make([]byte, mb*1024*1024)
			for i := 0; i < len(buf); i += 4096 {
				buf[i] = 1
			}
			time.Sleep(sleep)
			runtime.KeepAlive(buf)
		}
	`
	program := path.Join(t.TempDir(), "program")
	require.NoError(t, os.WriteFile(program+".go", []byte(src), 0644))
	require.NoError(t, exec.Command("go", "build", "-o", program, program+".go").Run())

	getEvent, stop := runTracer(t, true)
	defer stop()

	p := exec.Command(program, "1", "200ms")
	require.NoError(t, p.Start())
	pid := uint32(p.Process.Pid)
	waitForEvent(t, getEvent, Event{Type: EventTypeProcessStart, Pid: pid})
	require.NoError(t, p.Wait())
	waitForEvent(t, getEvent, Event{Type: EventTypeProcessExit, Pid: pid})

	var limit int64 = 32 * 1024 * 1024
	oom := exec.Command(program, "64", "30s")
	startInMemoryCgroup(t, oom, limit)
	oomPid := uint32(oom.Process.Pid)
	waitForEvent(t, getEvent, Event{Type: EventTypeProcessStart, Pid: oomPid})
	require.Error(t, waitCmd(t, oom, 20*time.Second))
	waitForEvent(t, getEvent, Event{Type: EventTypeProcessExit, Reason: EventReasonOOMKill, Pid: oomPid})
}

func TestTcpEvents(t *testing.T) {
	skipIfNotVM(t)
	getEvent, stop := runTracer(t, true)
	defer stop()

	pid := uint32(os.Getpid())
	waitTCP := func(typ EventType, sAddr, dAddr string, eventPid uint32) {
		t.Helper()
		waitFor(t, getEvent, 15*time.Second, tcpMatch(typ, sAddr, dAddr, eventPid))
	}

	l, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	listenAddr := l.Addr().String()
	waitTCP(EventTypeListenOpen, listenAddr, "0.0.0.0:0", pid)

	c, err := net.DialTimeout("tcp4", listenAddr, time.Second)
	require.NoError(t, err)
	localAddr := c.LocalAddr().String()
	waitTCP(EventTypeConnectionOpen, localAddr, listenAddr, pid)

	require.NoError(t, c.Close())
	waitTCP(EventTypeConnectionClose, localAddr, listenAddr, pid)

	require.NoError(t, l.Close())
	waitTCP(EventTypeListenClose, listenAddr, "0.0.0.0:0", pid)

	_, err = net.DialTimeout("tcp4", listenAddr, 100*time.Millisecond)
	require.Error(t, err)
	waitTCP(EventTypeConnectionError, "127.0.0.1:", listenAddr, pid)

	l, err = net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	listenAddr = l.Addr().String()
	waitTCP(EventTypeListenOpen, listenAddr, "0.0.0.0:0", pid)

	c, err = net.DialTimeout("tcp4", listenAddr, time.Second)
	require.NoError(t, err)
	localAddr = c.LocalAddr().String()
	waitTCP(EventTypeConnectionOpen, localAddr, listenAddr, pid)

	require.NoError(t, exec.Command("tc", "qdisc", "add", "dev", "lo", "root", "netem", "loss", "100%").Run())
	defer exec.Command("tc", "qdisc", "del", "dev", "lo", "root", "netem").Run()
	_, _ = c.Write([]byte("hello"))
	waitTCP(EventTypeTCPRetransmit, localAddr, listenAddr, 0)

	require.NoError(t, exec.Command("tc", "qdisc", "del", "dev", "lo", "root", "netem").Run())
	require.NoError(t, c.Close())
	waitTCP(EventTypeConnectionClose, localAddr, listenAddr, pid)

	require.NoError(t, l.Close())
	waitTCP(EventTypeListenClose, listenAddr, "0.0.0.0:0", pid)
}

func TestFileEvents(t *testing.T) {
	skipIfNotVM(t)
	src := `
		package main

		import (
			"os"
			"strconv"
			"syscall"
			"unsafe"
			"time"
		)

		func main() {
			call, _ := strconv.Atoi(os.Args[1])
			path := os.Args[2]
			flags, _ := strconv.Atoi(os.Args[3])
			filename, _ := syscall.BytePtrFromString(path)
			var err syscall.Errno
			switch call {
			case syscall.SYS_OPEN:
				_, _, err = syscall.Syscall6(syscall.SYS_OPEN, uintptr(unsafe.Pointer(filename)), uintptr(flags), 0, 0, 0, 0)
			case syscall.SYS_OPENAT:
				AT_FDCWD := -100
				_, _, err = syscall.Syscall6(syscall.SYS_OPENAT, uintptr(AT_FDCWD), uintptr(unsafe.Pointer(filename)), uintptr(flags), 0, 0, 0)
			}
			time.Sleep(100 * time.Millisecond)
			os.Exit(int(err))
		}
	`
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(path.Join(dir, "program.go"), []byte(src), 0644))
	out, err := exec.Command("go", "build", "-o", path.Join(dir, "program"), path.Join(dir, "program.go")).CombinedOutput()
	require.Equal(t, "", string(out))
	require.NoError(t, err)

	origWD, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(origWD) })

	absSrc, err := filepath.Abs("program.go")
	require.NoError(t, err)
	absBin, err := filepath.Abs("program")
	require.NoError(t, err)

	getEvent, stop := runTracer(t, true)
	defer stop()

	for _, call := range []int{syscall.SYS_OPEN, syscall.SYS_OPENAT} {
		run := func(file string, flag int) (uint32, <-chan error) {
			t.Helper()
			p := exec.Command(absBin, strconv.Itoa(call), file, strconv.Itoa(flag))
			require.NoError(t, p.Start())
			ch := make(chan error, 1)
			go func() { ch <- p.Wait() }()
			return uint32(p.Process.Pid), ch
		}
		reap := func(ch <-chan error, wantErr bool) {
			t.Helper()
			err := <-ch
			if wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		}

		pid, done := run("program.go", os.O_WRONLY)
		waitSeen(t, getEvent, pid, true, EventTypeProcessStart, EventTypeProcessExit)
		reap(done, false)

		pid, done = run(absSrc, os.O_RDONLY)
		waitSeen(t, getEvent, pid, true, EventTypeProcessStart, EventTypeProcessExit)
		reap(done, false)

		pid, done = run(absSrc, os.O_WRONLY)
		waitSeen(t, getEvent, pid, false, EventTypeProcessStart, EventTypeFileOpen, EventTypeProcessExit)
		reap(done, false)

		pid, done = run(absSrc, os.O_RDWR)
		waitSeen(t, getEvent, pid, false, EventTypeProcessStart, EventTypeFileOpen, EventTypeProcessExit)
		reap(done, false)

		pid, done = run(absBin, os.O_RDWR)
		waitSeen(t, getEvent, pid, true, EventTypeProcessStart, EventTypeProcessExit)
		reap(done, true)

		for _, f := range []string{"/proc/sys/fs/file-max", "/dev/null", "/sys/kernel/profiling"} {
			pid, done = run(f, os.O_RDWR)
			waitSeen(t, getEvent, pid, true, EventTypeProcessStart, EventTypeProcessExit)
			reap(done, false)
		}
	}
}

func TestHttpIngressEvents(t *testing.T) {
	skipIfNotVM(t)
	getEvent, stop := runTracer(t, false)
	defer stop()

	serverPid, addr, stopServer := startHTTPUsersServer(t)
	defer stopServer()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			ForceAttemptHTTP2: false,
		},
	}
	resp, err := client.Get("http://" + addr + "/users")
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)

	got := waitHTTP(t, getEvent, serverPid, true)
	method, uri := l7.ParseHttp(got.L7Request.Payload)
	require.Equal(t, "GET", method)
	require.Equal(t, "/users", uri)
	require.Equal(t, l7.Status(http.StatusOK), got.L7Request.Status)
}

func TestHttpEgressEvents(t *testing.T) {
	skipIfNotVM(t)
	clientSrc := `
		package main

		import (
			"io"
			"net/http"
			"os"
			"time"
		)

		func main() {
			client := &http.Client{
				Timeout: 5 * time.Second,
				Transport: &http.Transport{
					DisableKeepAlives: true,
					ForceAttemptHTTP2: false,
				},
			}
			resp, err := client.Get(os.Args[1])
			if err != nil {
				os.Exit(1)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				os.Exit(1)
			}
		}
	`
	dir := t.TempDir()
	clientBin := path.Join(dir, "httpclient")
	require.NoError(t, os.WriteFile(clientBin+".go", []byte(clientSrc), 0644))
	out, err := exec.Command("go", "build", "-o", clientBin, clientBin+".go").CombinedOutput()
	require.Equal(t, "", string(out))
	require.NoError(t, err)

	getEvent, stop := runTracer(t, false)
	defer stop()

	_, addr, stopServer := startHTTPUsersServer(t)
	defer stopServer()

	cmd := exec.Command(clientBin, "http://"+addr+"/users")
	require.NoError(t, cmd.Start())
	clientPid := uint32(cmd.Process.Pid)
	require.NoError(t, cmd.Wait())

	var conn, l7ev *Event
	conns := map[uint64]Event{}
	l7s := map[uint64]Event{}
	waitFor(t, getEvent, 15*time.Second, func(e *Event) bool {
		if e.Pid != clientPid {
			return false
		}
		if e.Type == EventTypeConnectionOpen && addrMatches(e.DstAddr, addr) {
			conns[e.Fd] = *e
		}
		if e.Type == EventTypeL7Request && e.L7Request != nil && !e.L7Request.IsInbound &&
			e.L7Request.Protocol == l7.ProtocolHTTP {
			method, uri := l7.ParseHttp(e.L7Request.Payload)
			if method == "GET" && uri == "/users" {
				req := *e.L7Request
				ev := *e
				ev.L7Request = &req
				l7s[e.Fd] = ev
			}
		}
		for fd, c := range conns {
			if l, ok := l7s[fd]; ok {
				cc, ll := c, l
				conn, l7ev = &cc, &ll
				return true
			}
		}
		return false
	})
	require.Equal(t, conn.Fd, l7ev.Fd, "L7 egress should be on the same socket eBPF opened to the server")
	require.Equal(t, addr, formatAddr(conn.DstAddr))
	method, uri := l7.ParseHttp(l7ev.L7Request.Payload)
	require.Equal(t, "GET", method)
	require.Equal(t, "/users", uri)
	require.Equal(t, l7.Status(http.StatusOK), l7ev.L7Request.Status)
}

func TestHttpPayloadCopies1024(t *testing.T) {
	skipIfNotVM(t)

	t.Run("write", func(t *testing.T) {
		assertHTTPPayloadCopies1024(t, false)
	})
	t.Run("writev", func(t *testing.T) {
		assertHTTPPayloadCopies1024(t, true)
	})
}

func assertHTTPPayloadCopies1024(t *testing.T, writev bool) {
	t.Helper()
	getEvent, stop := runTracer(t, false)
	defer stop()

	_, addr, stopServer := startHTTPUsersServer(t)
	defer stopServer()

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer conn.Close()

	const markerIdx = MaxPayloadSize - 1
	req := paddedHTTPGetUsers(addr, MaxPayloadSize+400, markerIdx, 0x5a)
	require.Equal(t, byte(0x5a), req[markerIdx])

	tcp, ok := conn.(*net.TCPConn)
	require.True(t, ok)
	raw, err := tcp.SyscallConn()
	require.NoError(t, err)

	var wrote int
	require.NoError(t, raw.Write(func(fd uintptr) bool {
		var n int
		var werr error
		if writev {
			n, werr = unix.Writev(int(fd), [][]byte{req[:MaxPayloadSize+10], req[MaxPayloadSize+10:]})
		} else {
			n, werr = unix.Write(int(fd), req)
		}
		require.NoError(t, werr)
		wrote = n
		return true
	}))
	require.Equal(t, len(req), wrote)

	buf := make([]byte, 256)
	_, err = conn.Read(buf)
	require.NoError(t, err)

	pid := uint32(os.Getpid())
	got := waitFor(t, getEvent, 15*time.Second, func(e *Event) bool {
		if e.Type != EventTypeL7Request || e.Pid != pid || e.L7Request == nil {
			return false
		}
		if e.L7Request.Protocol != l7.ProtocolHTTP || e.L7Request.IsInbound {
			return false
		}
		method, uri := l7.ParseHttp(e.L7Request.Payload)
		return method == "GET" && uri == "/users"
	})
	require.Equal(t, MaxPayloadSize, len(got.L7Request.Payload), "captured payload must be 1024, not 1023")
	require.Equal(t, byte(0x5a), got.L7Request.Payload[markerIdx])
	require.Equal(t, l7.Status(http.StatusOK), got.L7Request.Status)
}

func paddedHTTPGetUsers(addr string, total, markerIdx int, marker byte) []byte {
	head := fmt.Sprintf("GET /users HTTP/1.1\r\nHost: %s\r\nX-Pad: ", addr)
	tail := "\r\n\r\n"
	buf := bytes.Repeat([]byte{'a'}, total)
	copy(buf, head)
	copy(buf[len(buf)-len(tail):], tail)
	buf[markerIdx] = marker
	return buf
}

func TestHttp2IngressEvents(t *testing.T) {
	skipIfNotVM(t)
	getEvent, stop := runTracer(t, false)
	defer stop()

	serverPid, addr, stopServer := startHTTP2UsersServer(t)
	defer stopServer()

	require.NoError(t, h2cGetUsers(addr))

	got := waitHTTP2(t, getEvent, serverPid, true)
	require.Equal(t, l7.ProtocolHTTP2, got.L7Request.Protocol)
	require.True(t, got.L7Request.IsInbound)
}

func TestHttp2EgressEvents(t *testing.T) {
	skipIfNotVM(t)
	clientBin := buildHTTP2Prog(t, "http2client", http2ClientSrc)

	getEvent, stop := runTracer(t, false)
	defer stop()

	_, addr, stopServer := startHTTP2UsersServer(t)
	defer stopServer()

	cmd := exec.Command(clientBin, "http://"+addr+"/users")
	require.NoError(t, cmd.Start())
	clientPid := uint32(cmd.Process.Pid)
	require.NoError(t, cmd.Wait())

	conn, l7ev := waitHTTP2Egress(t, getEvent, clientPid, addr)
	require.Equal(t, conn.Fd, l7ev.Fd, "L7 HTTP2 egress should be on the same socket eBPF opened to the server")
	require.Equal(t, addr, formatAddr(conn.DstAddr))
	require.Equal(t, l7.ProtocolHTTP2, l7ev.L7Request.Protocol)
}

func TestHttp2TlsIngressEvents(t *testing.T) {
	t.Skip("pre-existing: HTTP2 HEADERS often arrive split, so GET /users is not in one L7 event")
	tr, getEvent, stop := startTracer(t, false)
	defer stop()

	serverPid, addr, stopServer := startHTTP2TlsUsersServer(t)
	defer stopServer()
	attachGoTls(t, tr, serverPid)

	clientBin := buildStdGoProg(t, "http2tlsclient", http2TlsClientSrc)
	runHTTP2TlsClient(t, clientBin, addr, tr)

	got := waitHTTP2(t, getEvent, serverPid, true)
	require.Equal(t, l7.ProtocolHTTP2, got.L7Request.Protocol)
	require.True(t, got.L7Request.IsInbound)
}

func TestHttp2TlsEgressEvents(t *testing.T) {
	skipIfNotVM(t)
	tr, getEvent, stop := startTracer(t, false)
	defer stop()

	_, addr, stopServer := startHTTP2TlsUsersServer(t)
	defer stopServer()

	clientBin := buildStdGoProg(t, "http2tlsclient", http2TlsClientSrc)
	clientPid := runHTTP2TlsClient(t, clientBin, addr, tr)

	conn, l7ev := waitHTTP2Egress(t, getEvent, clientPid, addr)
	require.Equal(t, conn.Fd, l7ev.Fd, "L7 HTTP2 TLS egress should be on the same socket eBPF opened to the server")
	require.Equal(t, addr, formatAddr(conn.DstAddr))
	require.Equal(t, l7.ProtocolHTTP2, l7ev.L7Request.Protocol)
	require.False(t, l7ev.L7Request.IsInbound)
}

func TestHttp2WriteTilesDataThenHeaders(t *testing.T) {
	skipIfNotVM(t)
	getEvent, stop := runTracer(t, false)
	defer stop()

	addr, stopDiscard := startTCPDiscard(t)
	defer stopDiscard()

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer conn.Close()

	headers := http2HeadersGETUsers(t, addr)
	payload := append(http2DataFrame([]byte("hello"), 1, false), headers...)
	n, err := conn.Write(payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)

	got := waitFor(t, getEvent, 15*time.Second, func(e *Event) bool {
		return e.Type == EventTypeL7Request && e.Pid == uint32(os.Getpid()) &&
			e.L7Request != nil && e.L7Request.Protocol == l7.ProtocolHTTP2 &&
			!e.L7Request.IsInbound && bytes.Equal(e.L7Request.Payload, payload)
	})
	require.Equal(t, l7.ProtocolHTTP2, got.L7Request.Protocol)
	require.False(t, got.L7Request.IsInbound)
}

func TestHttp2SendmmsgWalksMoreThanTwoMessages(t *testing.T) {
	skipIfNotVM(t)
	getEvent, stop := runTracer(t, false)
	defer stop()

	addr, stopDiscard := startTCPDiscard(t)
	defer stopDiscard()

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer conn.Close()

	tcp, ok := conn.(*net.TCPConn)
	require.True(t, ok)
	raw, err := tcp.SyscallConn()
	require.NoError(t, err)

	const nmsg = 5
	settings := []byte{0, 0, 0, 4, 0, 0, 0, 0, 0}
	bufs := make([][]byte, nmsg)
	iov := make([]unix.Iovec, nmsg)
	msgs := make([]mmsghdr, nmsg)
	for i := 0; i < nmsg; i++ {
		bufs[i] = append([]byte(nil), settings...)
		iov[i].Base = &bufs[i][0]
		iov[i].Len = uint64(len(bufs[i]))
		msgs[i].Hdr.Iov = &iov[i]
		msgs[i].Hdr.Iovlen = 1
	}

	var sent int
	require.NoError(t, raw.Write(func(fd uintptr) bool {
		n, werr := sendmmsg(int(fd), msgs, 0)
		require.NoError(t, werr)
		sent = n
		return true
	}))
	require.Equal(t, nmsg, sent)

	pid := uint32(os.Getpid())
	got := 0
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && got < nmsg {
		e := getEvent()
		if e == nil || e.Pid != pid || e.Type != EventTypeL7Request || e.L7Request == nil {
			continue
		}
		if e.L7Request.Protocol == l7.ProtocolHTTP2 && !e.L7Request.IsInbound {
			got++
		}
	}
	require.GreaterOrEqual(t, got, nmsg, "sendmmsg must walk more than the old 2-slot unroll")
}

func startHTTPUsersServer(t *testing.T) (uint32, string, func()) {
	t.Helper()
	src := `
		package main

		import (
			"net"
			"net/http"
			"os"
		)

		func main() {
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				os.Exit(1)
			}
			if err := os.WriteFile(os.Args[1], []byte(ln.Addr().String()), 0644); err != nil {
				os.Exit(1)
			}
			http.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok"))
			})
			_ = http.Serve(ln, nil)
		}
	`
	dir := t.TempDir()
	program := path.Join(dir, "httpserver")
	require.NoError(t, os.WriteFile(program+".go", []byte(src), 0644))
	out, err := exec.Command("go", "build", "-o", program, program+".go").CombinedOutput()
	require.Equal(t, "", string(out))
	require.NoError(t, err)

	addrFile := path.Join(dir, "addr")
	cmd := exec.Command(program, addrFile)
	require.NoError(t, cmd.Start())
	stop := func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	t.Cleanup(stop)

	var addr string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(addrFile)
		if err == nil && len(bytes.TrimSpace(b)) > 0 {
			addr = string(bytes.TrimSpace(b))
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.NotEmpty(t, addr, "http helper did not write listen address")
	return uint32(cmd.Process.Pid), addr, stop
}

func waitHTTP(t *testing.T, get func() *Event, pid uint32, inbound bool) *Event {
	t.Helper()
	return waitFor(t, get, 15*time.Second, func(e *Event) bool {
		if e.Type != EventTypeL7Request || e.Pid != pid || e.L7Request == nil {
			return false
		}
		if e.L7Request.Protocol != l7.ProtocolHTTP || e.L7Request.IsInbound != inbound {
			return false
		}
		method, uri := l7.ParseHttp(e.L7Request.Payload)
		return method == "GET" && uri == "/users"
	})
}

func startHTTP2UsersServer(t *testing.T) (uint32, string, func()) {
	t.Helper()
	program := buildHTTP2Prog(t, "http2server", http2ServerSrc)

	addrFile := path.Join(path.Dir(program), "addr")
	cmd := exec.Command(program, addrFile)
	require.NoError(t, cmd.Start())
	stop := func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	t.Cleanup(stop)

	var addr string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(addrFile)
		if err == nil && len(bytes.TrimSpace(b)) > 0 {
			addr = string(bytes.TrimSpace(b))
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.NotEmpty(t, addr, "http2 helper did not write listen address")
	return uint32(cmd.Process.Pid), addr, stop
}

func startHTTP2TlsUsersServer(t *testing.T) (uint32, string, func()) {
	t.Helper()
	program := buildStdGoProg(t, "http2tlsserver", http2TlsServerSrc)
	certFile, keyFile := writeTlsTestCerts(t, path.Dir(program))

	addrFile := path.Join(path.Dir(program), "addr")
	cmd := exec.Command(program, addrFile, certFile, keyFile)
	require.NoError(t, cmd.Start())
	stop := func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	t.Cleanup(stop)

	var addr string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(addrFile)
		if err == nil && len(bytes.TrimSpace(b)) > 0 {
			addr = string(bytes.TrimSpace(b))
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.NotEmpty(t, addr, "http2 tls helper did not write listen address")
	return uint32(cmd.Process.Pid), addr, stop
}

func runHTTP2TlsClient(t *testing.T, clientBin, addr string, tr *Tracer) uint32 {
	t.Helper()
	ready := path.Join(t.TempDir(), "ready")
	cmd := exec.Command(clientBin, "https://"+addr+"/users", ready)
	require.NoError(t, cmd.Start())
	pid := uint32(cmd.Process.Pid)
	attachGoTls(t, tr, pid)
	require.NoError(t, os.WriteFile(ready, []byte("1"), 0644))
	require.NoError(t, cmd.Wait())
	return pid
}

func attachGoTls(t *testing.T, tr *Tracer, pid uint32) {
	t.Helper()
	key, isGo := tr.AttachGoTlsUprobes(pid)
	require.True(t, isGo, "pid=%d is not a Go binary", pid)
	require.NotNil(t, key, "failed to attach crypto/tls uprobes to pid=%d", pid)
	t.Cleanup(func() { tr.ReleaseGlobalUprobes(*key) })
}

func writeTlsTestCerts(t *testing.T, dir string) (string, string) {
	t.Helper()
	certFile := path.Join(dir, "cert.pem")
	keyFile := path.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, []byte(tlsTestCertPEM), 0644))
	require.NoError(t, os.WriteFile(keyFile, []byte(tlsTestKeyPEM), 0644))
	return certFile, keyFile
}

func buildStdGoProg(t *testing.T, name, src string) string {
	t.Helper()
	dir := t.TempDir()
	srcFile := path.Join(dir, name+".go")
	require.NoError(t, os.WriteFile(srcFile, []byte(src), 0644))
	bin := path.Join(dir, name)
	out, err := exec.Command("go", "build", "-o", bin, srcFile).CombinedOutput()
	require.Equal(t, "", string(out), "%s", out)
	require.NoError(t, err)
	return bin
}

type mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
	_   [4]byte
}

func sendmmsg(fd int, msgvec []mmsghdr, flags int) (int, error) {
	var p unsafe.Pointer
	if len(msgvec) > 0 {
		p = unsafe.Pointer(&msgvec[0])
	}
	n, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(fd), uintptr(p), uintptr(len(msgvec)), uintptr(flags), 0, 0)
	if errno != 0 {
		return int(n), errno
	}
	return int(n), nil
}

func startTCPDiscard(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(io.Discard, c)
	}()
	return ln.Addr().String(), func() {
		ln.Close()
		<-done
	}
}

func http2HeadersGETUsers(t *testing.T, addr string) []byte {
	t.Helper()
	var hdr bytes.Buffer
	enc := hpack.NewEncoder(&hdr)
	for _, hf := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/users"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: addr},
	} {
		require.NoError(t, enc.WriteField(hf))
	}
	var buf bytes.Buffer
	fr := http2.NewFramer(&buf, nil)
	require.NoError(t, fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hdr.Bytes(),
		EndStream:     true,
		EndHeaders:    true,
	}))
	return buf.Bytes()
}

func http2DataFrame(payload []byte, streamID uint32, endStream bool) []byte {
	flags := byte(0)
	if endStream {
		flags = 0x1
	}
	n := len(payload)
	hdr := [9]byte{
		byte(n >> 16), byte(n >> 8), byte(n),
		0, flags,
		byte(streamID >> 24), byte(streamID >> 16), byte(streamID >> 8), byte(streamID),
	}
	return append(hdr[:], payload...)
}

func waitHTTP2(t *testing.T, get func() *Event, pid uint32, inbound bool) *Event {
	t.Helper()
	accs := map[uint64]*http2Acc{}
	var seen []string
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		e := get()
		if e == nil || e.Pid != pid {
			continue
		}
		line := fmt.Sprintf("%s fd=%d src=%s dst=%s", e.Type, e.Fd, formatAddr(e.SrcAddr), formatAddr(e.DstAddr))
		if e.L7Request != nil {
			line += fmt.Sprintf(" proto=%s l7method=%s inbound=%v n=%d payload=%q",
				e.L7Request.Protocol, e.L7Request.Method, e.L7Request.IsInbound, len(e.L7Request.Payload), truncateForLog(e.L7Request.Payload, 80))
		}
		seen = append(seen, line)
		if len(seen) > 32 {
			seen = seen[1:]
		}
		if e.Type != EventTypeL7Request || e.L7Request == nil {
			continue
		}
		if e.L7Request.Protocol != l7.ProtocolHTTP2 || e.L7Request.IsInbound != inbound {
			continue
		}
		if http2UsersOK(feedHTTP2(accs, e)) {
			return e
		}
	}
	msg := fmt.Sprintf("timed out waiting for HTTP2 GET /users pid=%d inbound=%v", pid, inbound)
	if len(seen) > 0 {
		msg += "\npid events:\n" + strings.Join(seen, "\n")
	}
	t.Fatal(msg)
	return nil
}

func waitHTTP2Egress(t *testing.T, get func() *Event, pid uint32, addr string) (*Event, *Event) {
	t.Helper()
	conns := map[uint64]Event{}
	parsed := map[uint64]Event{}
	accs := map[uint64]*http2Acc{}
	var seen []string
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		e := get()
		if e == nil || e.Pid != pid {
			continue
		}
		line := fmt.Sprintf("%s fd=%d src=%s dst=%s", e.Type, e.Fd, formatAddr(e.SrcAddr), formatAddr(e.DstAddr))
		if e.L7Request != nil {
			line += fmt.Sprintf(" proto=%s l7method=%s inbound=%v n=%d payload=%q",
				e.L7Request.Protocol, e.L7Request.Method, e.L7Request.IsInbound, len(e.L7Request.Payload), truncateForLog(e.L7Request.Payload, 80))
		}
		seen = append(seen, line)
		if len(seen) > 32 {
			seen = seen[1:]
		}
		if e.Type == EventTypeConnectionOpen && addrMatches(e.DstAddr, addr) {
			conns[e.Fd] = *e
		}
		if e.Type == EventTypeL7Request && e.L7Request != nil && !e.L7Request.IsInbound &&
			e.L7Request.Protocol == l7.ProtocolHTTP2 && http2UsersOK(feedHTTP2(accs, e)) {
			parsed[e.Fd] = cloneL7Event(e)
		}
		for fd, c := range conns {
			if l, ok := parsed[fd]; ok {
				cc, ll := c, l
				return &cc, &ll
			}
		}
	}
	msg := fmt.Sprintf("timed out waiting for HTTP2 egress GET /users pid=%d dst=%s", pid, addr)
	if len(seen) > 0 {
		msg += "\npid events:\n" + strings.Join(seen, "\n")
	}
	t.Fatal(msg)
	return nil, nil
}

func h2cGetUsers(addr string) error {
	c, err := net.DialTimeout("tcp4", addr, 2*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(http2.ClientPreface)); err != nil {
		return err
	}
	fr := http2.NewFramer(c, nil)
	if err := fr.WriteSettings(); err != nil {
		return err
	}
	var hdr bytes.Buffer
	enc := hpack.NewEncoder(&hdr)
	for _, hf := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/users"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: addr},
	} {
		if err := enc.WriteField(hf); err != nil {
			return err
		}
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hdr.Bytes(),
		EndStream:     true,
		EndHeaders:    true,
	}); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	var acc bytes.Buffer
	for {
		n, err := c.Read(buf)
		if n > 0 {
			acc.Write(buf[:n])
		}
		if hasHTTP2Headers(acc.Bytes(), 1) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func hasHTTP2Headers(p []byte, streamID uint32) bool {
	fr := http2.NewFramer(nil, bytes.NewReader(p))
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return false
		}
		h, ok := f.(*http2.HeadersFrame)
		if ok && h.Header().StreamID == streamID {
			return true
		}
	}
}

func buildHTTP2Prog(t *testing.T, name, src string) string {
	t.Helper()
	ver, err := exec.Command("go", "list", "-m", "-f", "{{.Version}}", "golang.org/x/net").Output()
	require.NoError(t, err)
	dir := t.TempDir()
	mod := fmt.Sprintf("module %s\n\ngo 1.24.7\n\nrequire golang.org/x/net %s\n", name, strings.TrimSpace(string(ver)))
	require.NoError(t, os.WriteFile(path.Join(dir, "go.mod"), []byte(mod), 0644))
	require.NoError(t, os.WriteFile(path.Join(dir, "main.go"), []byte(src), 0644))
	bin := path.Join(dir, name)
	tidy := exec.Command("go", "mod", "tidy")
	tidy.Dir = dir
	out, err := tidy.CombinedOutput()
	require.NoError(t, err, "%s", out)
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = dir
	out, err = cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)
	return bin
}

const tlsTestCertPEM = `-----BEGIN CERTIFICATE-----
MIIDGjCCAgKgAwIBAgIUGj7Ttd77TnhjjXX0PFpL6qO+4dAwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJMTI3LjAuMC4xMB4XDTI2MDkxNjA2NDkwMVoXDTM2MDkx
MzA2NDkwMVowFDESMBAGA1UEAwwJMTI3LjAuMC4xMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAklzAaoEVI+sHxe0CKNjhYS5c5o/LXi1n3MX/KxCcyqvr
CjVeSaSZ1v9ncWCfIx0FKKwi21clEANyCSVOFCc/j5JVyTEpb9EGGSNvj7f0uJAt
2XAdHa0snXyAjQ8obqC4pCNiuiAIGaO7UpI2ptZhfxAjqlfy9YA+d1OUcjxDMgtm
p+bsFGJ1OmnO5aTE9ur+kSMFVv+UANm3xqA0AvyOzHFAiKTo6r7ol6gO1RPwjUec
TT6ZV0W4e0NMWZ/6TSfmG5mFeGgfanW45jCPzXRd4b1Qb4ME1SIHTLnqSUE0wict
LceqIkQN4TcpJr9HUhnGdGgAhs+B1jScUTC5qZjjKwIDAQABo2QwYjAdBgNVHQ4E
FgQUiWPR+I6JYFjGBXZGqeheDLYkbHgwHwYDVR0jBBgwFoAUiWPR+I6JYFjGBXZG
qeheDLYkbHgwDwYDVR0TAQH/BAUwAwEB/zAPBgNVHREECDAGhwR/AAABMA0GCSqG
SIb3DQEBCwUAA4IBAQAQo9jRS07VPw06/r+dNGS9v4ws1dg6O6iNXMMC4i3uR4tN
McYvuDuZHENZaA95+7TQowEYrCIW3dBSXT8KCBW3vO6Of5ofg+RutFLcIrPndi2N
VDzitYY0iNTfQnv4hV+fvjydUfsmweWBbmzVYreUJBsNDnR2l0XdVI6GNU3jG/wX
rp3GM758v6DpH1S1ae7BeMh/ANnelzkZqvtPbVyw1O9IZDyrO0pDU3sJpxCJG3mG
dG7/NW5OWEpdw22uKPC/+Df0cHfi6N/3beDSSEj5yp8V+8T7KP6o849jl7pe0BmP
D5WZJ7ebc44bitnajvDaueFhzgIxHKv0m0jmcotE
-----END CERTIFICATE-----
`

const tlsTestKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCSXMBqgRUj6wfF
7QIo2OFhLlzmj8teLWfcxf8rEJzKq+sKNV5JpJnW/2dxYJ8jHQUorCLbVyUQA3IJ
JU4UJz+PklXJMSlv0QYZI2+Pt/S4kC3ZcB0drSydfICNDyhuoLikI2K6IAgZo7tS
kjam1mF/ECOqV/L1gD53U5RyPEMyC2an5uwUYnU6ac7lpMT26v6RIwVW/5QA2bfG
oDQC/I7McUCIpOjqvuiXqA7VE/CNR5xNPplXRbh7Q0xZn/pNJ+YbmYV4aB9qdbjm
MI/NdF3hvVBvgwTVIgdMuepJQTTCJy0tx6oiRA3hNykmv0dSGcZ0aACGz4HWNJxR
MLmpmOMrAgMBAAECggEAFDYOtCZjHvSjvCdAdxeL9/mJBqWwta6bexc0Z2QB4tLe
wCgifxTl0ZSvWi63iwfE4Jr0rUlZat6u7qhiIdJRqqfQhNnvGOvKZcpI65XBi4MN
cctTmfeCA7VfoxsGwFAdbz0bswwdUj0T7xEVzvAnwn4eDrXabSBqf9vg0e2UceJ/
lk89qdZsg1ODTGXdIm1euTQQSu+BeDEy5PnTW0gHqdXjXkHpX339uzTLtQqjQFvN
R+XPd3/32ndtrlWJt4otw4nfh0+TZ5Tcuu5WihtC6pSVyVhmJYe98Ne3ZrNW2lk0
+UP6mZgpMNYIPE7NW9v9bH7mxYc9gWwi+1Hf2fQ1gQKBgQDObuOFwz9mSpVwCL9l
iTYo2SNYoQ2w0VjqE4pVfcbh1jvZeFfFYVsODf2hwSeI0huRvxjy7YvKhgBSTyKg
H+KV1NyaL8JVGo0OQfT5QLXdTX9cZoz5sK8wT2kJIpraL3HCco80hvqrGZrV8ftd
okQaBOc5ivNG4Q+LIyLxhnx8CwKBgQC1gWfDhXdJuZLlZlbf5rSE+HizspzYKXzB
h/SJkhHH1qcVXai+V3Pi4H4orwqNGUhIOuUdzgyL9WUkwvHk+vqZJwKIPqjEvC9g
QHYoYvDwF5DTHE3rEQvyEnwJ/GyakVljpWmR5+x32pXJ49WS0369HH+5HGPsac/M
OxktPaSJYQKBgC2Zxz7MI5woC5zFAeqfBcy+MpWodgrCI/8JM/ywnRdUKMJgWBss
511Sb92kemQ57YcjjJJVMRUaxsVn38E5aecpL1YMCMSd6dzlawUIa2Qoc2Lo8GlT
w09Lq2suLsDVzC5k+gdjbcoQDOkH3DwR1TNeM+m9LQJSQwm8SELML4GDAoGAC+it
sjpzlTbD2KFaWd59Qaw73y589AHk2Z3eAZi/6ei/lbtLcxGx3NT18h1qB8/82iBj
IA2A7T3woPTZgjilcJ8Kn33c/OuMADi6h/PV8yrYqcFVq3K24e8sjEsvpQScZNlZ
j+Uzsrl40oJMZRHTYv0XtEGUnNJke/X0tO8yeIECgYEAoBbocG5qbvSvXHH/q90/
DenRojKrafPeutedPQVk71RNufWfatBB4qqYHkT8V/wsX6cdq8co6zTKy+WBJweA
5YFWkNvqXtky/dywpEyd1vpAsXMWRfahc2ZwTx6FOceVN5KmuxNoXlYStDgyTLzV
ZUWufuwTfq1BQMxdYy2f9xA=
-----END PRIVATE KEY-----
`

const http2TlsServerSrc = `package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"os"
)

func main() {
	cert, err := tls.LoadX509KeyPair(os.Args[2], os.Args[3])
	if err != nil {
		os.Exit(1)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		os.Exit(1)
	}
	if err := os.WriteFile(os.Args[1], []byte(ln.Addr().String()), 0644); err != nil {
		os.Exit(1)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	srv := &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}
	_ = srv.ServeTLS(ln, "", "")
}
`

const http2TlsClientSrc = `package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	ready := os.Args[2]
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			os.Exit(1)
		}
		time.Sleep(10 * time.Millisecond)
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: true,
		},
	}
	resp, err := client.Get(os.Args[1])
	if err != nil {
		os.Exit(1)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
}
`

const http2ServerSrc = `package main

import (
	"bytes"
	"net"
	"os"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func main() {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		os.Exit(1)
	}
	if err := os.WriteFile(os.Args[1], []byte(ln.Addr().String()), 0644); err != nil {
		os.Exit(1)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var acc bytes.Buffer
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			acc.Write(buf[:n])
		}
		if hasRequestHeaders(acc.Bytes()) {
			break
		}
		if err != nil {
			return
		}
	}
	fr := http2.NewFramer(conn, nil)
	if err := fr.WriteSettings(); err != nil {
		return
	}
	var hdr bytes.Buffer
	enc := hpack.NewEncoder(&hdr)
	if err := enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"}); err != nil {
		return
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hdr.Bytes(),
		EndHeaders:    true,
	}); err != nil {
		return
	}
	_ = fr.WriteData(1, true, []byte("ok"))
}

func hasRequestHeaders(p []byte) bool {
	if !bytes.HasPrefix(p, []byte(http2.ClientPreface)) {
		return false
	}
	fr := http2.NewFramer(nil, bytes.NewReader(p[len(http2.ClientPreface):]))
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return false
		}
		h, ok := f.(*http2.HeadersFrame)
		if ok && h.Header().StreamID == 1 {
			return true
		}
	}
}
`

const http2ClientSrc = `package main

import (
	"bytes"
	"net"
	"net/url"
	"os"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func main() {
	u, err := url.Parse(os.Args[1])
	if err != nil || u.Host == "" {
		os.Exit(1)
	}
	if err := h2cGetUsers(u.Host); err != nil {
		os.Exit(1)
	}
}

func h2cGetUsers(addr string) error {
	c, err := net.DialTimeout("tcp4", addr, 2*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(http2.ClientPreface)); err != nil {
		return err
	}
	fr := http2.NewFramer(c, nil)
	if err := fr.WriteSettings(); err != nil {
		return err
	}
	var hdr bytes.Buffer
	enc := hpack.NewEncoder(&hdr)
	for _, hf := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/users"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: addr},
	} {
		if err := enc.WriteField(hf); err != nil {
			return err
		}
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hdr.Bytes(),
		EndStream:     true,
		EndHeaders:    true,
	}); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	var acc bytes.Buffer
	for {
		n, err := c.Read(buf)
		if n > 0 {
			acc.Write(buf[:n])
		}
		if hasHTTP2Headers(acc.Bytes(), 1) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func hasHTTP2Headers(p []byte, streamID uint32) bool {
	fr := http2.NewFramer(nil, bytes.NewReader(p))
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return false
		}
		h, ok := f.(*http2.HeadersFrame)
		if ok && h.Header().StreamID == streamID {
			return true
		}
	}
}
`

func feedHTTP2(accs map[uint64]*http2Acc, e *Event) []l7.Http2Request {
	a := accs[e.Fd]
	if a == nil {
		a = &http2Acc{}
		accs[e.Fd] = a
	}
	payload := append([]byte(nil), e.L7Request.Payload...)
	switch e.L7Request.Method {
	case l7.MethodHttp2ClientFrames:
		a.client = append(a.client, payload)
	case l7.MethodHttp2ServerFrames:
		a.server = append(a.server, payload)
	default:
		return nil
	}
	p := l7.NewHttp2Parser()
	for _, b := range a.client {
		p.Parse(l7.MethodHttp2ClientFrames, b, 1)
	}
	var got []l7.Http2Request
	for i, b := range a.server {
		got = append(got, p.Parse(l7.MethodHttp2ServerFrames, b, uint64(i+2))...)
	}
	return got
}

type http2Acc struct {
	client [][]byte
	server [][]byte
}

func http2UsersOK(reqs []l7.Http2Request) bool {
	for _, req := range reqs {
		if req.Method == "GET" && req.Path == "/users" && req.Status == l7.Status(http.StatusOK) {
			return true
		}
	}
	return false
}

func cloneL7Event(e *Event) Event {
	ev := *e
	if e.L7Request == nil {
		return ev
	}
	req := *e.L7Request
	if req.Payload != nil {
		req.Payload = append([]byte(nil), req.Payload...)
	}
	ev.L7Request = &req
	return ev
}

func tcpMatch(typ EventType, sAddr, dAddr string, eventPid uint32) func(*Event) bool {
	return func(e *Event) bool {
		if e.Type != typ {
			return false
		}
		if eventPid != 0 && e.Pid != eventPid {
			return false
		}
		switch typ {
		case EventTypeListenOpen, EventTypeListenClose:
			want, err := netaddr.ParseIPPort(sAddr)
			if err != nil {
				return false
			}
			return e.SrcAddr.Port() == want.Port()
		case EventTypeConnectionClose:
			// sys_enter_close emits close events without filling addresses
			return true
		default:
			if !addrMatches(e.SrcAddr, sAddr) {
				return false
			}
			return addrMatches(e.DstAddr, dAddr)
		}
	}
}

func addrMatches(got netaddr.IPPort, want string) bool {
	gotStr := formatAddr(got)
	if strings.HasSuffix(want, ":") {
		return strings.HasPrefix(gotStr, want)
	}
	return gotStr == formatAddr(mustParseIPPort(want))
}

func formatAddr(p netaddr.IPPort) string {
	ip := p.IP()
	if !ip.IsValid() {
		return netaddr.IPPortFrom(netaddr.IPv4(0, 0, 0, 0), p.Port()).String()
	}
	ip = ip.Unmap()
	if ip.Is6() {
		b := ip.As16()
		restZero := true
		for i := 4; i < 16; i++ {
			if b[i] != 0 {
				restZero = false
				break
			}
		}
		if restZero {
			ip = netaddr.IPv4(b[0], b[1], b[2], b[3])
		} else if ip.IsUnspecified() {
			ip = netaddr.IPv4(0, 0, 0, 0)
		}
	}
	return netaddr.IPPortFrom(ip, p.Port()).String()
}

func truncateForLog(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}

func mustParseIPPort(s string) netaddr.IPPort {
	p, err := netaddr.ParseIPPort(s)
	if err != nil {
		return netaddr.IPPort{}
	}
	return p
}

func waitSeen(t *testing.T, get func() *Event, pid uint32, forbidFileOpen bool, types ...EventType) {
	t.Helper()
	need := make(map[EventType]struct{}, len(types))
	for _, typ := range types {
		need[typ] = struct{}{}
	}
	waitFor(t, get, 15*time.Second, func(e *Event) bool {
		if e.Pid != pid {
			return false
		}
		if forbidFileOpen && e.Type == EventTypeFileOpen {
			t.Fatalf("unexpected FileOpen pid=%d fd=%d", pid, e.Fd)
		}
		delete(need, e.Type)
		return len(need) == 0
	})
}

func waitForEvent(t *testing.T, get func() *Event, want Event) *Event {
	t.Helper()
	return waitFor(t, get, 10*time.Second, func(e *Event) bool {
		if e.Type != want.Type || e.Pid != want.Pid || e.Reason != want.Reason {
			return false
		}
		if want.Fd != 0 && e.Fd != want.Fd {
			return false
		}
		return true
	})
}

func waitFor(t *testing.T, get func() *Event, timeout time.Duration, match func(*Event) bool) *Event {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var seen []string
	for time.Now().Before(deadline) {
		e := get()
		if e == nil {
			continue
		}
		if match(e) {
			return e
		}
		interesting := e.Type == EventTypeListenOpen || e.Type == EventTypeListenClose ||
			e.Type == EventTypeFileOpen || e.Type == EventTypeTCPRetransmit ||
			e.Type == EventTypeConnectionError || e.Type == EventTypeL7Request
		if !interesting && e.Type == EventTypeProcessStart {
			continue
		}
		if !interesting && e.Type != EventTypeConnectionOpen && e.Type != EventTypeConnectionClose && e.Type != EventTypeProcessExit {
			continue
		}
		line := fmt.Sprintf("%s pid=%d src=%s dst=%s fd=%d reason=%s",
			e.Type, e.Pid, formatAddr(e.SrcAddr), formatAddr(e.DstAddr), e.Fd, e.Reason)
		if e.L7Request != nil {
			method, uri := l7.ParseHttp(e.L7Request.Payload)
			line += fmt.Sprintf(" proto=%s l7method=%s inbound=%v status=%s method=%s uri=%s payload=%q",
				e.L7Request.Protocol, e.L7Request.Method, e.L7Request.IsInbound, e.L7Request.Status, method, uri, truncateForLog(e.L7Request.Payload, 64))
		}
		seen = append(seen, line)
		if len(seen) > 24 {
			seen = seen[1:]
		}
	}
	msg := fmt.Sprintf("timed out after %s waiting for matching event", timeout)
	if len(seen) > 0 {
		msg += "\nlast non-start events:\n" + strings.Join(seen, "\n")
	}
	t.Fatal(msg)
	return nil
}

func waitCmd(t *testing.T, cmd *exec.Cmd, timeout time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("command pid=%d did not exit within %s", cmd.Process.Pid, timeout)
		return nil
	}
}

func startInMemoryCgroup(t *testing.T, cmd *exec.Cmd, limit int64) {
	t.Helper()
	name := fmt.Sprintf("/coroot-node-agent-oom-%d-%d", os.Getpid(), time.Now().UnixNano())
	var noSwap int64
	switch cgroups.Mode() {
	case cgroups.Legacy, cgroups.Hybrid:
		control, err := cgroups.New(cgroups.V1, cgroups.StaticPath(name), &specs.LinuxResources{
			Memory: &specs.LinuxMemory{Limit: &limit, Swap: &limit},
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = control.Delete() })
		require.NoError(t, cmd.Start())
		require.NoError(t, control.Add(cgroups.Process{Pid: cmd.Process.Pid}))
	case cgroups.Unified:
		control, err := cgroupsV2.NewManager("/sys/fs/cgroup", name, &cgroupsV2.Resources{
			Memory: &cgroupsV2.Memory{Max: &limit, Swap: &noSwap},
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = control.Delete() })
		fd, err := unix.Open(path.Join("/sys/fs/cgroup", name), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		require.NoError(t, err)
		t.Cleanup(func() { _ = unix.Close(fd) })
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
		require.NoError(t, cmd.Start())
	default:
		t.Fatal("cgroups are not available")
	}
}

func runTracer(t *testing.T, disableL7Tracing bool) (func() *Event, func()) {
	t.Helper()
	_, get, stop := startTracer(t, disableL7Tracing)
	return get, stop
}

func startTracer(t *testing.T, disableL7Tracing bool) (*Tracer, func() *Event, func()) {
	t.Helper()
	events := make(chan Event, 65536)
	done := make(chan struct{})
	type ready struct {
		tr  *Tracer
		err error
	}
	started := make(chan ready, 1)

	var uname unix.Utsname
	require.NoError(t, unix.Uname(&uname))
	require.NoError(t, common.SetKernelVersion(string(bytes.Split(uname.Release[:], []byte{0})[0])))

	hostNs, err := proc.GetHostNetNs()
	require.NoError(t, err)
	selfNs, err := proc.GetSelfNetNs()
	require.NoError(t, err)

	go func() {
		tt := NewTracer(hostNs, selfNs, disableL7Tracing)
		err := tt.Run(events)
		started <- ready{tr: tt, err: err}
		if err != nil {
			return
		}
		<-done
		tt.Close()
	}()
	r := <-started
	require.NoError(t, r.err)

	// init() snapshots every host pid when tests share the host PID namespace.
	// Drop that burst so the VM tests wait on events from the actions below.
	drainUntil := time.Now().Add(2 * time.Second)
	for time.Now().Before(drainUntil) {
		select {
		case <-events:
		case <-time.After(20 * time.Millisecond):
		}
	}

	stop := func() {
		select {
		case <-done:
		default:
			close(done)
		}
	}
	get := func() *Event {
		select {
		case e := <-events:
			return &e
		case <-time.After(200 * time.Millisecond):
			return nil
		}
	}
	return r.tr, get, stop
}
