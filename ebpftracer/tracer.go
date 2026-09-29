package ebpftracer

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

const MaxPayloadSize = 1024

// Http1CaptureMax mirrors HTTP1_CAPTURE_MAX in ebpf/l7/http1.c: the
// independent per-direction cap on HTTP/1 HEADERS and DATA capture,
// analogous to HTTP2_STREAM_CAPTURE_MAX.
const Http1CaptureMax = 4096

// Http2StreamCaptureMax is the cumulative number of HTTP2 body bytes the
// kernel side captures per (connection, direction, stream) — across as many
// frames and events as it takes — not per individual frame. HEADERS and
// CONTINUATION share one such budget; DATA has its own, equally sized,
// independent budget on the same stream, so a large body can never crowd
// out trailing HEADERS (trailers) and a heavy header block (e.g. cookies)
// can never crowd out the body. Must match HTTP2_STREAM_CAPTURE_MAX in
// ebpf/l7/http2.c.
const Http2StreamCaptureMax = 4096

type EventType uint32
type EventReason uint32

const (
	EventTypeProcessStart    EventType = 1
	EventTypeProcessExit     EventType = 2
	EventTypeConnectionOpen  EventType = 3
	EventTypeConnectionClose EventType = 4
	EventTypeConnectionError EventType = 5
	EventTypeListenOpen      EventType = 6
	EventTypeListenClose     EventType = 7
	EventTypeFileOpen        EventType = 8
	EventTypeTCPRetransmit   EventType = 9
	EventTypeL7Request       EventType = 10

	EventReasonNone    EventReason = 0
	EventReasonOOMKill EventReason = 1
)

type TrafficStats struct {
	BytesSent     uint64
	BytesReceived uint64
}

type Event struct {
	Type          EventType
	Reason        EventReason
	Pid           uint32
	SrcAddr       netaddr.IPPort
	DstAddr       netaddr.IPPort
	ActualDstAddr netaddr.IPPort
	Fd            uint64
	Timestamp     uint64
	Duration      time.Duration
	L7Request     *l7.RequestData
	TrafficStats  *TrafficStats
	Mnt           uint64
	Log           bool
	IsInbound     bool
}

type perfMapType uint8

const (
	perfMapTypeProcEvents perfMapType = 1
	perfMapTypeTCPEvents  perfMapType = 2
	perfMapTypeFileEvents perfMapType = 3
)

type UprobeKey struct {
	Dev uint64
	Ino uint64
}

type globalUprobe struct {
	links    []link.Link
	refcount int
}

type Tracer struct {
	disableL7Tracing bool
	hostNetNs        netns.NsHandle
	selfNetNs        netns.NsHandle

	collectionSpec   *ebpf.CollectionSpec
	collection       *ebpf.Collection
	readers          map[string]*perf.Reader
	l7Reader         *ringbuf.Reader
	tcpConnectReader *ringbuf.Reader
	links            []link.Link
	uprobes          map[string]*ebpf.Program

	globalUprobes     map[UprobeKey]*globalUprobe
	globalUprobesLock sync.Mutex

	lostSamples         atomic.Uint64
	truncatedPayloads   atomic.Uint64
	goTlsAttachFailures atomic.Uint64
}

func NewTracer(hostNetNs, selfNetNs netns.NsHandle, disableL7Tracing bool) *Tracer {
	if disableL7Tracing {
		klog.Infoln("L7 tracing is disabled")
	}
	return &Tracer{
		disableL7Tracing: disableL7Tracing,
		hostNetNs:        hostNetNs,
		selfNetNs:        selfNetNs,

		readers:       map[string]*perf.Reader{},
		uprobes:       map[string]*ebpf.Program{},
		globalUprobes: map[UprobeKey]*globalUprobe{},
	}
}

func (t *Tracer) Run(events chan<- Event) error {
	if err := proc.ExecuteInNetNs(t.hostNetNs, t.selfNetNs, ensureConntrackEventsAreEnabled); err != nil {
		return err
	}
	if err := t.ebpf(events); err != nil {
		return err
	}
	if err := t.init(events); err != nil {
		return err
	}
	if err := t.attachPrograms(); err != nil {
		return err
	}
	return nil
}

func (t *Tracer) Close() {
	for _, p := range t.uprobes {
		_ = p.Close()
	}
	for _, l := range t.links {
		_ = l.Close()
	}
	for _, r := range t.readers {
		_ = r.Close()
	}
	if t.l7Reader != nil {
		_ = t.l7Reader.Close()
	}
	if t.tcpConnectReader != nil {
		_ = t.tcpConnectReader.Close()
	}
	t.globalUprobesLock.Lock()
	for _, gu := range t.globalUprobes {
		for _, l := range gu.links {
			_ = l.Close()
		}
	}
	t.globalUprobes = nil
	t.globalUprobesLock.Unlock()
	t.collection.Close()
}

func (t *Tracer) AcquireGlobalUprobe(path string, attach func() []link.Link) (UprobeKey, bool) {
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return UprobeKey{}, false
	}
	key := UprobeKey{Dev: stat.Dev, Ino: stat.Ino}

	t.globalUprobesLock.Lock()
	defer t.globalUprobesLock.Unlock()

	if gu, ok := t.globalUprobes[key]; ok {
		gu.refcount++
		return key, true
	}
	links := attach()
	if len(links) == 0 {
		return UprobeKey{}, false
	}
	t.globalUprobes[key] = &globalUprobe{links: links, refcount: 1}
	return key, true
}

func (t *Tracer) ReleaseGlobalUprobes(keys ...UprobeKey) {
	t.globalUprobesLock.Lock()
	defer t.globalUprobesLock.Unlock()

	for _, key := range keys {
		gu, ok := t.globalUprobes[key]
		if !ok {
			continue
		}
		gu.refcount--
		if gu.refcount <= 0 {
			for _, l := range gu.links {
				_ = l.Close()
			}
			delete(t.globalUprobes, key)
		}
	}
}

func (t *Tracer) ActiveConnectionsIterator() *ebpf.MapIterator {
	return t.collection.Maps["active_connections"].Iterate()
}

func (t *Tracer) DeleteActiveConnection(cid ConnectionId) error {
	return t.collection.Maps["active_connections"].Delete(&cid)
}

// LookupActiveConnection returns the kernel's current connection state for cid, if any.
// Connection.Timestamp uniquely identifies the connection generation living at cid's
// (pid, fd): the kernel resets it on every accept()/connect(), so it lets a caller tell
// a still-live connection apart from a later, unrelated one that reused the same fd.
func (t *Tracer) LookupActiveConnection(cid ConnectionId) (Connection, bool) {
	var conn Connection
	if err := t.collection.Maps["active_connections"].Lookup(&cid, &conn); err != nil {
		return Connection{}, false
	}
	return conn, true
}

func (t *Tracer) LostSamples() uint64 {
	return t.lostSamples.Load() + t.ringbufDrops("l7_events_dropped") + t.ringbufDrops("tcp_connect_events_dropped")
}

func (t *Tracer) ringbufDrops(mapName string) uint64 {
	if t.collection == nil {
		return 0
	}
	m := t.collection.Maps[mapName]
	if m == nil {
		return 0
	}
	var values []uint64
	if err := m.Lookup(uint32(0), &values); err != nil {
		return 0
	}
	var n uint64
	for _, v := range values {
		n += v
	}
	return n
}

func (t *Tracer) TruncatedPayloads() uint64 {
	return t.truncatedPayloads.Load()
}

func (t *Tracer) GoTlsAttachFailures() uint64 {
	return t.goTlsAttachFailures.Load()
}

func parseL7Event(raw []byte) (*Event, bool, error) {
	v := l7Event{}
	reader := bytes.NewBuffer(raw)
	if err := binary.Read(reader, binary.LittleEndian, &v); err != nil {
		return nil, false, err
	}
	payload := copiedPayload(reader.Bytes(), v.PayloadSize)
	req := &l7.RequestData{
		Protocol:    l7.Protocol(v.Protocol),
		Status:      l7.Status(v.Status),
		Duration:    time.Duration(v.Duration),
		Method:      l7.Method(v.Method),
		StatementId: v.StatementId,
		IsInbound:   v.IsInbound != 0,
		Payload:     payload,
	}
	return &Event{Type: EventTypeL7Request, Pid: v.Pid, Fd: v.Fd, Timestamp: v.ConnectionTimestamp, L7Request: req},
		payloadTruncated(v.PayloadSize, len(payload)), nil
}

func copiedPayload(payload []byte, payloadSize uint64) []byte {
	n := len(payload)
	if n > MaxPayloadSize {
		n = MaxPayloadSize
	}
	if payloadSize < uint64(n) {
		n = int(payloadSize)
	}
	if n == 0 {
		return nil
	}
	return payload[:n]
}

func payloadTruncated(payloadSize uint64, copied int) bool {
	return payloadSize > uint64(copied)
}

func (t *Tracer) NodejsStatsIterator() *ebpf.MapIterator {
	return t.collection.Maps["nodejs_stats"].Iterate()
}

func (t *Tracer) PythonStatsIterator() *ebpf.MapIterator {
	return t.collection.Maps["python_stats"].Iterate()
}

type NodejsStats struct {
	EventLoopBlockedTime time.Duration
}

type PythonStats struct {
	ThreadLockWaitTime time.Duration
}

type ConnectionId struct {
	FD  uint64
	PID uint32
	_   uint32
}

type Connection struct {
	Timestamp        uint64
	BytesSent        uint64
	BytesReceived    uint64
	IsInbound        uint8
	Protocol         uint8
	IsTLS            uint8
	_                uint8
	H2SkipReq        uint32
	H2SkipResp       uint32
	H2SkipReqStream  uint32
	H2SkipRespStream uint32
	H2SkipReqData    uint8
	H2SkipRespData   uint8
	_                [2]uint8
}

type perfMap struct {
	name                  string
	perCPUBufferSizePages int
	typ                   perfMapType
	readTimeout           time.Duration
}

type loadedProgram struct {
	name string
	prog *ebpf.Program
	err  error
}

// loadCollection creates maps once, then verifies programs in parallel.
// Privileged BPF_PROG_LOAD is not serialized by bpf_verifier_lock, so the
// wall time is about the slowest program instead of the sum.
func loadCollection(spec *ebpf.CollectionSpec) (*ebpf.Collection, error) {
	mapsSpec := spec.Copy()
	mapsSpec.Programs = map[string]*ebpf.ProgramSpec{}
	coll, err := ebpf.NewCollection(mapsSpec)
	if err != nil {
		return nil, fmt.Errorf("load maps: %w", err)
	}

	var names []string
	for name, prog := range spec.Programs {
		if prog.Type == ebpf.UnspecifiedProgram {
			continue
		}
		names = append(names, name)
	}

	results := make(chan loadedProgram, len(names))
	var wg sync.WaitGroup
	for _, name := range names {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			one := spec.Copy()
			one.Programs = map[string]*ebpf.ProgramSpec{name: one.Programs[name]}
			loaded, err := ebpf.NewCollectionWithOptions(one, ebpf.CollectionOptions{
				MapReplacements: coll.Maps,
			})
			if err != nil {
				var vErr *ebpf.VerifierError
				if errors.As(err, &vErr) {
					klog.Errorf("%s: %+v", name, vErr)
				}
				results <- loadedProgram{name: name, err: err}
				return
			}
			prog := loaded.DetachProgram(name)
			loaded.Close()
			if prog == nil {
				results <- loadedProgram{name: name, err: fmt.Errorf("program missing after load")}
				return
			}
			results <- loadedProgram{name: name, prog: prog}
		}(name)
	}
	wg.Wait()
	close(results)

	progs := make(map[string]*ebpf.Program, len(names))
	var errs []error
	for result := range results {
		if result.err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", result.name, result.err))
			continue
		}
		progs[result.name] = result.prog
	}
	if len(errs) > 0 {
		for _, prog := range progs {
			prog.Close()
		}
		coll.Close()
		return nil, errors.Join(errs...)
	}
	coll.Programs = progs
	return coll, nil
}

func installHTTP2TailProgs(c *ebpf.Collection) error {
	if err := putHTTP2TailProgs(c, "http2_tail_progs", "http2_resume", "http2_iov"); err != nil {
		return err
	}
	if err := putHTTP2TailProgs(c, "http2_tail_progs_kprobe", "http2_resume_kp", "http2_iov_kp"); err != nil {
		return err
	}
	if err := putHTTP2ReadTailProgs(c, "http2_tail_progs", "http2_readv", "http2_read_exit"); err != nil {
		return err
	}
	// HTTP/1's own verifier-budget-isolated stage (see http1.c) shares these
	// same prog arrays with HTTP2 — one more program-type-keyed jump table
	// slot, not a second set of maps.
	if err := putHTTP1TailProg(c, "http2_tail_progs", "http1_walk"); err != nil {
		return err
	}
	return putHTTP1TailProg(c, "http2_tail_progs_kprobe", "http1_walk_kp")
}

func putHTTP1TailProg(c *ebpf.Collection, mapName, walkName string) error {
	m := c.Maps[mapName]
	walk := c.Programs[walkName]
	if m == nil || walk == nil {
		return fmt.Errorf("http1 tail program missing: %s", mapName)
	}
	if err := m.Put(uint32(4), walk); err != nil {
		return fmt.Errorf("walk %s: %w", mapName, err)
	}
	return nil
}

func putHTTP2ReadTailProgs(c *ebpf.Collection, mapName, readvName, exitName string) error {
	m := c.Maps[mapName]
	readv := c.Programs[readvName]
	readExit := c.Programs[exitName]
	if m == nil || readv == nil || readExit == nil {
		return fmt.Errorf("http2 read tail programs missing: %s", mapName)
	}
	if err := m.Put(uint32(2), readv); err != nil {
		return fmt.Errorf("readv %s: %w", mapName, err)
	}
	if err := m.Put(uint32(3), readExit); err != nil {
		return fmt.Errorf("read exit %s: %w", mapName, err)
	}
	return nil
}

func putHTTP2TailProgs(c *ebpf.Collection, mapName, resumeName, iovName string) error {
	m := c.Maps[mapName]
	resume := c.Programs[resumeName]
	iov := c.Programs[iovName]
	if m == nil || resume == nil || iov == nil {
		return fmt.Errorf("http2 tail programs missing: %s", mapName)
	}
	if err := m.Put(uint32(0), resume); err != nil {
		return fmt.Errorf("resume %s: %w", mapName, err)
	}
	if err := m.Put(uint32(1), iov); err != nil {
		return fmt.Errorf("iov %s: %w", mapName, err)
	}
	return nil
}

func (t *Tracer) ebpf(ch chan<- Event) error {
	if _, ok := ebpfProgs[runtime.GOARCH]; !ok {
		return fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}

	var traceFsPath string
	for _, p := range []string{"/sys/kernel/debug/tracing", "/sys/kernel/tracing"} {
		if _, err := os.Stat(p); err == nil {
			traceFsPath = p
			break
		}
	}
	if traceFsPath == "" {
		return fmt.Errorf("kernel tracing is not available: debugfs or tracefs must be mounted")
	}

	var flags string
	if isCtxExtraPaddingRequired(traceFsPath) {
		flags = "ctx-extra-padding"
	}
	kv := common.GetKernelVersion()
	var prog []byte
	for _, p := range ebpfProgs[runtime.GOARCH] {
		pv, _ := common.VersionFromString(p.version)
		if !kv.GreaterOrEqual(pv) {
			continue
		}
		if flags != p.flags {
			continue
		}
		prog = p.prog
		break
	}
	if len(prog) == 0 {
		return fmt.Errorf("unsupported kernel version: %s %s", kv, flags)
	}

	reader, err := gzip.NewReader(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(prog)))
	if err != nil {
		return fmt.Errorf("invalid program encoding: %w", err)
	}
	prog, err = io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to ungzip program: %w", err)
	}
	collectionSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(prog))
	if err != nil {
		return fmt.Errorf("failed to load collection spec: %w", err)
	}
	_ = unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY})
	loadStarted := time.Now()
	c, err := loadCollection(collectionSpec)
	if err != nil {
		return fmt.Errorf("failed to load collection: %w", err)
	}
	if err = installHTTP2TailProgs(c); err != nil {
		c.Close()
		return fmt.Errorf("http2 tail calls: %w", err)
	}
	klog.Infof("loaded ebpf collection in %s", time.Since(loadStarted).Round(time.Millisecond))
	t.collection = c

	for _, programSpec := range collectionSpec.Programs {
		if strings.HasPrefix(programSpec.SectionName, "uprobe/") {
			t.uprobes[programSpec.Name] = c.Programs[programSpec.Name]
		}
	}

	perfMaps := []perfMap{
		{name: "proc_events", typ: perfMapTypeProcEvents, perCPUBufferSizePages: 4},
		{name: "tcp_listen_events", typ: perfMapTypeTCPEvents, perCPUBufferSizePages: 4},
		{name: "tcp_retransmit_events", typ: perfMapTypeTCPEvents, perCPUBufferSizePages: 4},
		{name: "file_events", typ: perfMapTypeFileEvents, perCPUBufferSizePages: 4},
	}

	pageSize := os.Getpagesize()
	for _, pm := range perfMaps {
		r, err := perf.NewReaderWithOptions(t.collection.Maps[pm.name], pm.perCPUBufferSizePages*pageSize, perf.ReaderOptions{WakeupEvents: 100})
		if err != nil {
			t.Close()
			return fmt.Errorf("failed to create ebpf reader: %w", err)
		}
		t.readers[pm.name] = r
		go t.runEventsReader(pm.name, r, ch, pm.typ, pm.readTimeout)
	}

	if !t.disableL7Tracing {
		rd, err := ringbuf.NewReader(t.collection.Maps["l7_events"])
		if err != nil {
			t.Close()
			return fmt.Errorf("failed to create l7 ringbuf reader: %w", err)
		}
		t.l7Reader = rd
		go t.runL7EventsReader(rd, ch)
	}

	tcpRd, err := ringbuf.NewReader(t.collection.Maps["tcp_connect_events"])
	if err != nil {
		t.Close()
		return fmt.Errorf("failed to create tcp_connect ringbuf reader: %w", err)
	}
	t.tcpConnectReader = tcpRd
	go t.runTcpConnectEventsReader(tcpRd, ch)

	t.collectionSpec = collectionSpec
	return nil
}

func (t *Tracer) attachPrograms() error {
	for _, programSpec := range t.collectionSpec.Programs {
		program := t.collection.Programs[programSpec.Name]
		switch programSpec.Name {
		case "http2_resume", "http2_iov", "http2_readv", "http2_read_exit", "http2_resume_kp", "http2_iov_kp",
			"http1_walk", "http1_walk_kp":
			continue
		}
		if t.disableL7Tracing {
			switch programSpec.Name {
			case "sys_enter_writev", "sys_enter_write", "sys_enter_sendto", "sys_enter_sendmsg", "sys_enter_sendmmsg":
				continue
			case "sys_enter_read", "sys_enter_readv", "sys_enter_recvfrom", "sys_enter_recvmsg":
				continue
			case "sys_exit_read", "sys_exit_readv", "sys_exit_recvfrom", "sys_exit_recvmsg":
				continue
			}
		}
		var l link.Link
		var err error
		switch programSpec.Type {
		case ebpf.TracePoint:
			parts := strings.SplitN(programSpec.AttachTo, "/", 2)
			l, err = link.Tracepoint(parts[0], parts[1], program, nil)
		case ebpf.Kprobe:
			if strings.HasPrefix(programSpec.SectionName, "uprobe/") { // attached to a process on demand
				continue
			}
			l, err = link.Kprobe(programSpec.AttachTo, program, nil)
			if err != nil && programSpec.SectionName == "kprobe/nf_ct_deliver_cached_events" {
				klog.Warningln("nf_conntrack may not be in use:", err)
				continue
			}
		}
		if err != nil {
			t.Close()
			return fmt.Errorf("failed to link program '%s': %w", programSpec.Name, err)
		}
		t.links = append(t.links, l)
	}

	return nil
}

func (t EventType) String() string {
	switch t {
	case EventTypeProcessStart:
		return "process-start"
	case EventTypeProcessExit:
		return "process-exit"
	case EventTypeConnectionOpen:
		return "connection-open"
	case EventTypeConnectionClose:
		return "connection-close"
	case EventTypeConnectionError:
		return "connection-error"
	case EventTypeListenOpen:
		return "listen-open"
	case EventTypeListenClose:
		return "listen-close"
	case EventTypeFileOpen:
		return "file-open"
	case EventTypeTCPRetransmit:
		return "tcp-retransmit"
	case EventTypeL7Request:
		return "l7-request"
	}
	return "unknown: " + strconv.Itoa(int(t))
}

func (t EventReason) String() string {
	switch t {
	case EventReasonNone:
		return "none"
	case EventReasonOOMKill:
		return "oom-kill"
	}
	return "unknown: " + strconv.Itoa(int(t))
}

type procEvent struct {
	Type   EventType
	Pid    uint32
	Reason uint32
}

type tcpEvent struct {
	Fd            uint64
	Timestamp     uint64
	Duration      uint64
	Type          EventType
	Pid           uint32
	BytesSent     uint64
	BytesReceived uint64
	SPort         uint16
	DPort         uint16
	Aport         uint16
	SAddr         [16]byte
	DAddr         [16]byte
	AAddr         [16]byte
	IsInbound     uint8
	_             [7]uint8
}

type fileEvent struct {
	Type EventType
	Pid  uint32
	Fd   uint64
	Mnt  uint64
	Log  uint64
}

type l7Event struct {
	Fd                  uint64
	ConnectionTimestamp uint64
	Pid                 uint32
	Status              int32
	Duration            uint64
	Protocol            uint8
	Method              uint8
	IsInbound           uint8
	Padding             uint8
	StatementId         uint32
	PayloadSize         uint64
}

func (t *Tracer) runEventsReader(name string, r *perf.Reader, ch chan<- Event, typ perfMapType, readTimeout time.Duration) {
	if readTimeout == 0 {
		readTimeout = 100 * time.Millisecond
	}
	for {
		r.SetDeadline(time.Now().Add(readTimeout))
		rec, err := r.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				break
			}
			continue
		}
		if rec.LostSamples > 0 {
			t.lostSamples.Add(rec.LostSamples)
			klog.Errorln(name, "lost samples:", rec.LostSamples)
			continue
		}
		var event Event

		switch typ {
		case perfMapTypeFileEvents:
			v := &fileEvent{}
			if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, v); err != nil {
				klog.Warningln("failed to read msg:", err)
				continue
			}
			event = Event{Type: v.Type, Pid: v.Pid, Fd: v.Fd, Mnt: v.Mnt, Log: v.Log > 0}
		case perfMapTypeProcEvents:
			v := &procEvent{}
			if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, v); err != nil {
				klog.Warningln("failed to read msg:", err)
				continue
			}
			event = Event{Type: v.Type, Reason: EventReason(v.Reason), Pid: v.Pid}
		case perfMapTypeTCPEvents:
			parsed, err := parseTcpEvent(rec.RawSample)
			if err != nil {
				klog.Warningln("failed to read msg:", err)
				continue
			}
			event = *parsed
		default:
			continue
		}

		ch <- event
	}
}

func parseTcpEvent(raw []byte) (*Event, error) {
	v := tcpEvent{}
	if err := binary.Read(bytes.NewBuffer(raw), binary.LittleEndian, &v); err != nil {
		return nil, err
	}
	event := Event{
		Type:          v.Type,
		Pid:           v.Pid,
		SrcAddr:       ipPort(v.SAddr, v.SPort),
		DstAddr:       ipPort(v.DAddr, v.DPort),
		ActualDstAddr: ipPort(v.AAddr, v.Aport),
		Fd:            v.Fd,
		Timestamp:     v.Timestamp,
		Duration:      time.Duration(v.Duration),
		IsInbound:     v.IsInbound != 0,
	}
	if v.Type == EventTypeConnectionClose {
		event.TrafficStats = &TrafficStats{
			BytesSent:     v.BytesSent,
			BytesReceived: v.BytesReceived,
		}
	}
	return &event, nil
}

func (t *Tracer) runTcpConnectEventsReader(r *ringbuf.Reader, ch chan<- Event) {
	for {
		r.SetDeadline(time.Now().Add(10 * time.Millisecond))
		rec, err := r.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			continue
		}
		event, err := parseTcpEvent(rec.RawSample)
		if err != nil {
			klog.Warningln("failed to read tcp_connect ringbuf record:", err)
			continue
		}
		ch <- *event
	}
}

func (t *Tracer) runL7EventsReader(r *ringbuf.Reader, ch chan<- Event) {
	for {
		r.SetDeadline(time.Now().Add(100 * time.Millisecond))
		rec, err := r.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			continue
		}
		event, truncated, err := parseL7Event(rec.RawSample)
		if err != nil {
			klog.Warningln("failed to read l7 ringbuf record:", err)
			continue
		}
		if truncated {
			t.truncatedPayloads.Add(1)
		}
		ch <- *event
	}
}

func ipPort(ip [16]byte, port uint16) netaddr.IPPort {
	i, _ := netaddr.FromStdIP(ip[:])
	return netaddr.IPPortFrom(i, port)
}

func isCtxExtraPaddingRequired(traceFsPath string) bool {
	f, err := os.Open(path.Join(traceFsPath, "events/task/task_newtask/format"))
	if err != nil {
		klog.Errorln(err)
		return false
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		klog.Errorln(err)
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "common_preempt_lazy_count") {
			return true
		}
	}
	return false
}

const nfConntrackEventsParameterPath = "/proc/sys/net/netfilter/nf_conntrack_events"

func ensureConntrackEventsAreEnabled() error {
	v, err := common.ReadUintFromFile(nfConntrackEventsParameterPath)
	if err != nil {
		if common.IsNotExist(err) {
			klog.Warningf(
				"unable to check the value of %s, it appears that nf_conntrack is not loaded: %s",
				nfConntrackEventsParameterPath, err)
			return nil
		}
		return err
	}
	if v != 1 {
		klog.Infof("%s = %d, setting to 1", nfConntrackEventsParameterPath, v)
		if err = os.WriteFile(nfConntrackEventsParameterPath, []byte("1"), 0644); err != nil {
			return err
		}
	}
	return nil
}
