package ebpftracer

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingLink is a link.Link that counts its Close calls.
type countingLink struct {
	link.Link
	closed *int
}

func (l countingLink) Close() error {
	*l.closed++
	return nil
}

func TestGlobalUprobesStayAttachedWhileIdle(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "app")
	require.NoError(t, os.WriteFile(binary, []byte("x"), 0o755))
	tracer := &Tracer{globalUprobes: map[UprobeKey]*globalUprobe{}}
	attached, closed := 0, 0
	attach := func() []link.Link {
		attached++
		return []link.Link{countingLink{closed: &closed}}
	}
	start := time.Unix(1_000_000, 0)

	key, ok := tracer.acquireGlobalUprobe(binary, attach, start)
	require.True(t, ok)
	_, ok = tracer.acquireGlobalUprobe(binary, attach, start)
	require.True(t, ok)
	assert.Equal(t, 1, attached, "one attach per binary")

	tracer.releaseGlobalUprobes(start, key)
	tracer.releaseGlobalUprobes(start.Add(time.Second), key)
	assert.Equal(t, 0, closed, "the last process exited: still attached")

	// the binary is started again within the idle time: the same uprobes
	_, ok = tracer.acquireGlobalUprobe(binary, attach, start.Add(time.Minute))
	require.True(t, ok)
	assert.Equal(t, 1, attached, "not attached again")
	tracer.releaseGlobalUprobes(start.Add(2*time.Minute), key)
	tracer.releaseGlobalUprobes(start.Add(2*time.Minute), key)
	assert.Equal(t, 0, closed, "a release of an unused key changes nothing")

	// unused for the idle time: detached on the next acquire or release
	tracer.releaseGlobalUprobes(start.Add(2*time.Minute + globalUprobeIdleTTL))
	assert.Equal(t, 1, closed)
	assert.Empty(t, tracer.globalUprobes)

	_, ok = tracer.acquireGlobalUprobe(binary, attach, start.Add(time.Hour))
	require.True(t, ok)
	assert.Equal(t, 2, attached, "attached again after being detached")
}
