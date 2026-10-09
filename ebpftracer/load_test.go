package ebpftracer

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Loading all the programs at once costs memory: each loader holds a copy of the whole
// collection spec (2.8 MB) and, in the kernel, the state of the verifier (about 50 MB).
func TestForEachLimitedBoundsConcurrency(t *testing.T) {
	names := make([]string, 50)
	for i := range names {
		names[i] = fmt.Sprintf("program_%d", i)
	}
	var running, highest atomic.Int32
	var mu sync.Mutex
	calls := map[string]int{}

	forEachLimited(names, 4, func(name string) {
		n := running.Add(1)
		for {
			h := highest.Load()
			if n <= h || highest.CompareAndSwap(h, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		running.Add(-1)
		mu.Lock()
		calls[name]++
		mu.Unlock()
	})

	assert.Equal(t, int32(4), highest.Load(), "the limit is reached, and never exceeded")
	assert.Len(t, calls, len(names))
	for name, n := range calls {
		assert.Equal(t, 1, n, name)
	}
}

func TestForEachLimitedWaitsForAllCalls(t *testing.T) {
	var done atomic.Int32
	forEachLimited([]string{"a", "b", "c"}, 2, func(string) {
		time.Sleep(10 * time.Millisecond)
		done.Add(1)
	})
	assert.Equal(t, int32(3), done.Load(), "it returns only when every call is finished")
}

func TestForEachLimitedWithoutALimitStillRunsEverything(t *testing.T) {
	var done atomic.Int32
	forEachLimited([]string{"a", "b", "c"}, 0, func(string) { done.Add(1) })
	assert.Equal(t, int32(3), done.Load(), "a limit below 1 is one at a time, not none at all")
	forEachLimited(nil, 4, func(string) { t.Fatal("no names, no calls") })
}
