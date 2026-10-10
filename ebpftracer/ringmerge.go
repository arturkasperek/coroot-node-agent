package ebpftracer

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// The connection events (tcp_connect_events) and the L7 events (l7_events) come
// through two ring buffers. Read by two goroutines, the last response of a
// connection could be handled after its close, and its first request before its
// open, which is why closed connections had to be kept for a long time and L7
// events of an unknown connection buffered. ringMerger reads both rings in one
// goroutine and hands their records over in the order of the time the eBPF side
// stamped them with (the ts field), the way Falco's libpman reads its per-CPU
// rings.
//
// The order holds for the events that are ordered in the traced application: the
// L7 event of a read or write is committed before the syscall returns, so before
// the application can close the socket; the open of a connection is committed
// before connect or accept returns. A record of one ring is handed over only when
// the head of the other ring is known: a committed record with a later time, or an
// empty ring looked at again after the record was read (anything that happened
// before the record is committed by then).

// Offsets of the ts field in the records (see the _Static_assert in the eBPF code).
const (
	tcpEventTsOffset = 24
	l7EventTsOffset  = 48
)

// The record header of a BPF ring buffer (struct bpf_ringbuf_hdr): len with these
// flags in its high bits, then pg_off.
const (
	ringbufBusyBit    = 1 << 31
	ringbufDiscardBit = 1 << 30
	ringbufHdrSize    = 8
)

type headState int

const (
	headEmpty headState = iota // nothing to read
	headBusy                   // reserved and not committed yet
	headReady
)

// mergeSource is one ring as the merge sees it.
type mergeSource interface {
	// head returns the oldest record, without consuming it, and its timestamp.
	head() (rec []byte, ts uint64, st headState)
	// pop consumes the record head returned.
	pop()
}

// nextRecord picks the record to hand over: from the l7 or the connections ring, or
// none (busy or idle). On equal times the connection record goes first: the open of
// a connection sent from the same eBPF program as its first data.
func nextRecord(l7, connections mergeSource) (source mergeSource, record []byte, state headState) {
	l7Record, l7Time, l7State := l7.head()
	connectionRecord, connectionTime, connectionState := connections.head()
	if l7State == headBusy || connectionState == headBusy {
		// a record being written may be older than anything committed
		return nil, nil, headBusy
	}
	switch {
	case l7State == headReady && connectionState == headReady:
	case l7State == headReady:
		// the connections ring was empty: look at it again now that the L7 record has been read
		if connectionRecord, connectionTime, connectionState = connections.head(); connectionState == headBusy {
			return nil, nil, headBusy
		}
	case connectionState == headReady:
		// the L7 ring was empty: look at it again now that the connection record has been read
		if l7Record, l7Time, l7State = l7.head(); l7State == headBusy {
			return nil, nil, headBusy
		}
	default:
		return nil, nil, headEmpty
	}
	if l7State == headReady && (connectionState != headReady || l7Time < connectionTime) {
		return l7, l7Record, headReady
	}
	return connections, connectionRecord, headReady
}

// queuedRing takes the committed records out of a ring into memory, so that they
// can wait there for the older records of the other ring. The connection ring is
// 16 MiB, 2-3 s of connection churn, and the L7 ring lags behind by more than that
// under load: left in the ring, the connection records waiting for the L7 ones were
// dropped by the kernel. The records keep their order: the queue first, then the ring.
type queuedRing struct {
	ring        mergeSource
	records     []queuedRecord
	queuedBytes int
	maxBytes    int
}

type queuedRecord struct {
	rec []byte
	ts  uint64
}

func newQueuedRing(ring mergeSource, maxBytes int) *queuedRing {
	return &queuedRing{ring: ring, maxBytes: maxBytes}
}

// fill moves the committed records from the ring to the queue, while the queue
// holds less than maxBytes.
func (q *queuedRing) fill() {
	for q.queuedBytes < q.maxBytes {
		rec, ts, st := q.ring.head()
		if st != headReady {
			return
		}
		own := make([]byte, len(rec))
		copy(own, rec)
		q.ring.pop()
		q.records = append(q.records, queuedRecord{rec: own, ts: ts})
		q.queuedBytes += len(own)
	}
}

func (q *queuedRing) head() ([]byte, uint64, headState) {
	if len(q.records) > 0 {
		return q.records[0].rec, q.records[0].ts, headReady
	}
	return q.ring.head()
}

func (q *queuedRing) pop() {
	if len(q.records) == 0 {
		q.ring.pop()
		return
	}
	q.queuedBytes -= len(q.records[0].rec)
	q.records[0] = queuedRecord{}
	q.records = q.records[1:]
	if len(q.records) == 0 {
		q.records = nil // let the backing array of a burst go
	}
}

// mmapRing is a BPF ring buffer read through its mmap'ed pages, like libbpf does:
// the consumer position page (read-write), then the producer position page and the
// data pages, mapped twice in a row so that a record that wraps is contiguous.
type mmapRing struct {
	name     string
	tsOffset int
	consumer []byte
	producer []byte
	data     []byte
	mask     uint64
	cons     uint64
	headLen  uint64 // the length of the record head returned, for pop
}

func newMmapRing(name string, m *ebpf.Map, tsOffset int) (*mmapRing, error) {
	size := int(m.MaxEntries())
	page := os.Getpagesize()
	consumer, err := unix.Mmap(m.FD(), 0, page, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("mmap the consumer page of %s: %w", name, err)
	}
	producer, err := unix.Mmap(m.FD(), int64(page), page+2*size, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		_ = unix.Munmap(consumer)
		return nil, fmt.Errorf("mmap the data pages of %s: %w", name, err)
	}
	r := &mmapRing{
		name:     name,
		tsOffset: tsOffset,
		consumer: consumer,
		producer: producer,
		data:     producer[page:],
		mask:     uint64(size - 1),
	}
	r.cons = atomic.LoadUint64((*uint64)(unsafe.Pointer(&consumer[0])))
	return r, nil
}

func (r *mmapRing) head() ([]byte, uint64, headState) {
	for {
		prod := atomic.LoadUint64((*uint64)(unsafe.Pointer(&r.producer[0])))
		if r.cons >= prod {
			return nil, 0, headEmpty
		}
		off := r.cons & r.mask
		hdr := atomic.LoadUint32((*uint32)(unsafe.Pointer(&r.data[off])))
		if hdr&ringbufBusyBit != 0 {
			return nil, 0, headBusy
		}
		n := uint64(hdr &^ (ringbufBusyBit | ringbufDiscardBit))
		r.headLen = n
		if hdr&ringbufDiscardBit != 0 {
			r.pop()
			continue
		}
		rec := r.data[off+ringbufHdrSize : off+ringbufHdrSize+n]
		var ts uint64
		if len(rec) >= r.tsOffset+8 {
			ts = binary.LittleEndian.Uint64(rec[r.tsOffset:])
		}
		return rec, ts, headReady
	}
}

func (r *mmapRing) pop() {
	r.cons += (r.headLen + ringbufHdrSize + 7) &^ 7
	atomic.StoreUint64((*uint64)(unsafe.Pointer(&r.consumer[0])), r.cons)
}

func (r *mmapRing) close() {
	_ = unix.Munmap(r.producer)
	_ = unix.Munmap(r.consumer)
}

// ringMerger reads the two rings in one goroutine.
// tcpQueueMaxBytes bounds the connection records waiting out of their ring for older
// L7 records: twice the ring, ~260k connection events.
const tcpQueueMaxBytes = 32 << 20

type ringMerger struct {
	l7, tcpRing *mmapRing
	tcp         *queuedRing // tcpRing, taken out of it as soon as possible
	epfd        int
	stopped     atomic.Bool
	done        chan struct{}
}

func newRingMerger(l7Map, tcpMap *ebpf.Map) (*ringMerger, error) {
	l7, err := newMmapRing("l7_events", l7Map, l7EventTsOffset)
	if err != nil {
		return nil, err
	}
	tcp, err := newMmapRing("tcp_connect_events", tcpMap, tcpEventTsOffset)
	if err != nil {
		l7.close()
		return nil, err
	}
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		l7.close()
		tcp.close()
		return nil, err
	}
	for _, fd := range []int{l7Map.FD(), tcpMap.FD()} {
		if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, fd, &unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fd)}); err != nil {
			_ = unix.Close(epfd)
			l7.close()
			tcp.close()
			return nil, err
		}
	}
	return &ringMerger{l7: l7, tcpRing: tcp, tcp: newQueuedRing(tcp, tcpQueueMaxBytes), epfd: epfd, done: make(chan struct{})}, nil
}

// run hands every record over to emit, a copy it owns, until close.
func (m *ringMerger) run(emit func(fromL7 bool, rec []byte)) {
	defer close(m.done)
	events := make([]unix.EpollEvent, 2)
	busy := 0
	for !m.stopped.Load() {
		m.tcp.fill()
		source, record, state := nextRecord(m.l7, m.tcp)
		switch state {
		case headReady:
			busy = 0
			own := make([]byte, len(record))
			copy(own, record)
			source.pop()
			emit(source == mergeSource(m.l7), own)
		case headBusy:
			// a record is being written: it is a matter of microseconds
			if busy++; busy < 64 {
				runtime.Gosched()
			} else {
				time.Sleep(20 * time.Microsecond)
			}
		default:
			// both rings drained: wait for the kernel to wake us up (or stop)
			_, _ = unix.EpollWait(m.epfd, events, 100)
		}
	}
}

// close stops run. The rings stay mapped if run does not stop within a second (it
// is blocked handing a record over to a channel nobody reads any more): unmapped,
// they would crash it once it is unblocked.
func (m *ringMerger) close() {
	m.stopped.Store(true)
	select {
	case <-m.done:
	case <-time.After(time.Second):
		return
	}
	_ = unix.Close(m.epfd)
	m.l7.close()
	m.tcpRing.close()
}
