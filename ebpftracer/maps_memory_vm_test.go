//go:build linux && amd64

package ebpftracer

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// mapMemlock is the memory the kernel accounts for a loaded map (the memlock line of
// its fdinfo). Since 5.11 it is charged to the cgroup of the agent, so it counts
// against the memory limit of its pod like the Go heap does.
func mapMemlock(t *testing.T, fd int) int64 {
	t.Helper()
	f, err := os.Open(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
	require.NoError(t, err)
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "memlock:"); ok {
			n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			require.NoError(t, err)
			return n
		}
	}
	t.Fatalf("no memlock in the fdinfo of fd %d", fd)
	return 0
}

// The maps took 412 MB of an idle agent, before its Go heap (~40 MB): the LRU maps of
// connections are preallocated, and were sized for 1M entries while a node has
// hundreds of live connections (see connectionSweepInterval).
func TestBpfMapsFitInTheirMemoryBudget(t *testing.T) {
	skipIfNotVMSerial(t)
	_, stop := runTracer(t)
	defer stop()

	const budget = 256 << 20
	type sized struct {
		name  string
		bytes int64
	}
	var maps []sized
	var total int64
	for name, m := range sharedTr.collection.Maps {
		n := mapMemlock(t, m.FD())
		maps = append(maps, sized{name, n})
		total += n
	}
	sort.Slice(maps, func(i, j int) bool { return maps[i].bytes > maps[j].bytes })
	for _, m := range maps[:6] {
		t.Logf("%8.1f MB %s", float64(m.bytes)/(1<<20), m.name)
	}
	t.Logf("%8.1f MB in %d maps", float64(total)/(1<<20), len(maps))
	require.LessOrEqual(t, total, int64(budget), "the eBPF maps are charged to the memory of the agent")
}
