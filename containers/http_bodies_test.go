package containers

import (
	"testing"
	"time"

	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/coroot/coroot-node-agent/tracing"
	"github.com/stretchr/testify/require"
)

func newBodyTestContainer() (*Container, *ActiveConnection) {
	opts := l7.DefaultBodyOptions()
	opts.Enabled = true
	conn := &ActiveConnection{http1Parser: l7.NewHttp1ParserWithBodies(opts)}
	c := &Container{
		registry: &Registry{},
		tracer:   &tracing.Tracer{},
		l7Stats:  L7Stats{},
	}
	return c, conn
}

func TestFlushReleasesWaitingBodies(t *testing.T) {
	c, conn := newBodyTestContainer()
	t0 := time.Now()
	p := conn.http1Parser
	p.ParseAt(l7.MethodHttpClientHeaders, []byte("GET /stream HTTP/1.1\r\nHost: x\r\n\r\n"), 1, t0)
	p.ParseAt(l7.MethodHttpServerHeaders, []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n"), 2, t0)
	p.ParseAt(l7.MethodHttpServerData, []byte("hello"), 3, t0.Add(time.Millisecond))
	c.noteBodyHolder(conn)
	require.Contains(t, c.bodyHolders, conn)

	c.flushHttpBodies(t0.Add(50 * time.Millisecond))
	require.Equal(t, uint64(0), c.registry.http1RequestsParsed.Load(), "still within the wait")
	require.Contains(t, c.bodyHolders, conn)

	c.flushHttpBodies(t0.Add(time.Second))
	require.Equal(t, uint64(1), c.registry.http1RequestsParsed.Load())
	require.NotContains(t, c.bodyHolders, conn, "nothing held any more")
}

func TestNoteBodyHolderIgnoresPlainParsers(t *testing.T) {
	c := &Container{}
	conn := &ActiveConnection{http1Parser: l7.NewHttp1Parser()}
	c.noteBodyHolder(conn)
	require.Empty(t, c.bodyHolders)
}
