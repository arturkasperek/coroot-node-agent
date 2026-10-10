package ebpftracer

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRing is a ring for nextRecord: committed records with their times, and maybe
// one being written (busy) after them.
type fakeRing struct {
	name   string
	ts     []uint64
	busy   bool
	onHead func() // called on every head(): lets a test write into the other ring meanwhile
}

func (r *fakeRing) head() ([]byte, uint64, headState) {
	if r.onHead != nil {
		r.onHead()
	}
	if len(r.ts) > 0 {
		return []byte(fmt.Sprintf("%s:%d", r.name, r.ts[0])), r.ts[0], headReady
	}
	if r.busy {
		return nil, 0, headBusy
	}
	return nil, 0, headEmpty
}

func (r *fakeRing) pop() { r.ts = r.ts[1:] }

type handed struct {
	ring string
	ts   uint64
}

// drain hands over what nextRecord allows, stopping when it has to wait.
func drain(l7, connections mergeSource) (out []handed, last headState) {
	for {
		source, record, state := nextRecord(l7, connections)
		if state != headReady {
			return out, state
		}
		name, time, _ := strings.Cut(string(record), ":")
		timeValue, _ := strconv.ParseUint(time, 10, 64)
		out = append(out, handed{name, timeValue})
		source.pop()
	}
}

func TestMergeHandsRecordsOverInTheOrderOfTheirTimes(t *testing.T) {
	l7 := &fakeRing{name: "l7", ts: []uint64{10, 30, 50}}
	tcp := &fakeRing{name: "tcp", ts: []uint64{5, 20, 60}}
	out, last := drain(l7, tcp)
	assert.Equal(t, []handed{{"tcp", 5}, {"l7", 10}, {"tcp", 20}, {"l7", 30}, {"l7", 50}, {"tcp", 60}}, out)
	assert.Equal(t, headEmpty, last)
}

// The open of a connection sent from the same eBPF program as its first data can
// have the same time: the connection ring goes first.
func TestMergeHandsTheConnectionRecordFirstOnEqualTimes(t *testing.T) {
	out, _ := drain(&fakeRing{name: "l7", ts: []uint64{7}}, &fakeRing{name: "tcp", ts: []uint64{7}})
	assert.Equal(t, []handed{{"tcp", 7}, {"l7", 7}}, out)
}

// A record that is still being written may be older than anything committed in the
// other ring, so nothing is handed over until it is committed.
func TestMergeWaitsForARecordBeingWritten(t *testing.T) {
	l7 := &fakeRing{name: "l7", ts: []uint64{50}}
	tcp := &fakeRing{name: "tcp", busy: true}
	out, last := drain(l7, tcp)
	assert.Empty(t, out)
	assert.Equal(t, headBusy, last)

	tcp.busy = false
	tcp.ts = []uint64{40} // committed: it was older
	out, _ = drain(l7, tcp)
	assert.Equal(t, []handed{{"tcp", 40}, {"l7", 50}}, out)
}

// The race the merge closes: the L7 ring is empty when it is looked at, then the
// application writes (L7 event) and closes (connection event), and the connection
// ring is looked at. The close must not go before the write.
func TestMergeLooksAtAnEmptyRingAgainAfterReadingTheOther(t *testing.T) {
	l7 := &fakeRing{name: "l7"}
	tcp := &fakeRing{name: "tcp"}
	written := false
	tcp.onHead = func() {
		if !written {
			written = true
			l7.ts = append(l7.ts, 100) // the write, committed before the close was stamped
			tcp.ts = append(tcp.ts, 101)
		}
	}
	out, _ := drain(l7, tcp)
	require.Len(t, out, 2)
	assert.Equal(t, []handed{{"l7", 100}, {"tcp", 101}}, out)
}

func TestMergeHandsOverWhenTheOtherRingStaysEmpty(t *testing.T) {
	out, last := drain(&fakeRing{name: "l7", ts: []uint64{1, 2}}, &fakeRing{name: "tcp"})
	assert.Equal(t, []handed{{"l7", 1}, {"l7", 2}}, out)
	assert.Equal(t, headEmpty, last)

	out, _ = drain(&fakeRing{name: "l7"}, &fakeRing{name: "tcp", ts: []uint64{3}})
	assert.Equal(t, []handed{{"tcp", 3}}, out)
}

// The connection ring is 16 MiB, a few seconds of connection churn, and the L7 ring
// can lag behind by more under load. Its records are taken out of it as soon as they
// are committed, so that it does not overflow while they wait for older L7 records.
func TestConnectionRecordsWaitForOlderL7RecordsOutOfTheirRing(t *testing.T) {
	l7 := &fakeRing{name: "l7", ts: []uint64{10, 20, 30}}
	tcp := &fakeRing{name: "tcp", ts: []uint64{15, 25, 35}}
	queued := newQueuedRing(tcp, 1<<20)
	queued.fill()
	assert.Empty(t, tcp.ts, "taken out of the ring")

	out, _ := drain(l7, queued)
	assert.Equal(t, []handed{{"l7", 10}, {"tcp", 15}, {"l7", 20}, {"tcp", 25}, {"l7", 30}, {"tcp", 35}}, out)
}

// Over its limit the queue leaves the records in the ring.
func TestConnectionRecordQueueIsBounded(t *testing.T) {
	tcp := &fakeRing{name: "tcp", ts: []uint64{1, 2, 3, 4}}
	queued := newQueuedRing(tcp, 2*len("tcp:1"))
	queued.fill()
	assert.Equal(t, []uint64{3, 4}, tcp.ts)

	out, _ := drain(&fakeRing{name: "l7"}, queued)
	assert.Equal(t, []handed{{"tcp", 1}, {"tcp", 2}, {"tcp", 3}, {"tcp", 4}}, out, "the queue first, then the ring")
}

// An empty queue is the ring: what is being written there is still waited for.
func TestQueuedRingIsBusyWhileItsRingIs(t *testing.T) {
	queued := newQueuedRing(&fakeRing{name: "tcp", busy: true}, 1<<20)
	queued.fill()
	out, last := drain(&fakeRing{name: "l7", ts: []uint64{50}}, queued)
	assert.Empty(t, out)
	assert.Equal(t, headBusy, last)
}
