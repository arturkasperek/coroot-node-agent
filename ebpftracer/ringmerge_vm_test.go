//go:build linux && amd64

package ebpftracer

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The events of a connection reach the channel in the order they happened: its
// open, then its L7 events, then its close. Background requests keep the L7 ring
// busy meanwhile, which is when two independent readers of the rings handed over
// a close before the last response of its connection (36-68 of the 300
// connections had an L7 event before their open, and 108-194 L7 events came after
// their close).
func TestConnectionEventsAreInOrderWithTheirL7Events(t *testing.T) {
	skipIfNotVMSerial(t)
	getEvent, stop := runTracer(t)
	defer stop()
	watchSelf(t)

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write(bytes.Repeat([]byte("a"), 512))
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go srv.Serve(ln)
	defer srv.Close()
	addr := ln.Addr().String()

	// Collect from the start: the subscription drops events it has no room for, and the
	// background load fills it quickly.
	var events []Event
	collected := make(chan struct{})
	stopCollecting := make(chan struct{})
	go func() {
		defer close(collected)
		for {
			select {
			case <-stopCollecting:
				return
			default:
			}
			if e := getEvent(); e != nil {
				events = append(events, *e)
			}
		}
	}()

	// background load on other connections
	ctx, cancel := context.WithCancel(context.Background())
	var bg sync.WaitGroup
	for i := 0; i < 8; i++ {
		bg.Add(1)
		go func() {
			defer bg.Done()
			client := &http.Client{}
			body := bytes.Repeat([]byte("b"), 2048)
			for ctx.Err() == nil {
				if resp, err := client.Post("http://"+addr+"/bg", "text/plain", bytes.NewReader(body)); err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}
		}()
	}

	// the watched connections: one request each, then the client closes
	const conns = 300
	ports := map[uint16]bool{}
	for i := 0; i < conns; i++ {
		c, err := net.Dial("tcp", addr)
		require.NoError(t, err)
		ports[uint16(c.LocalAddr().(*net.TCPAddr).Port)] = true
		_, err = c.Write([]byte("GET /watched HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, c)
		require.NoError(t, c.Close())
	}
	cancel()
	bg.Wait()
	time.Sleep(2 * time.Second) // the last events on their way
	close(stopCollecting)
	<-collected

	type connKey struct{ fd, ts uint64 }
	type seen struct{ open, firstL7, lastL7, close int }
	byConn := map[connKey]*seen{}
	for i := range events {
		e := &events[i]
		k := connKey{e.Fd, e.Timestamp}
		switch {
		case e.Type == EventTypeConnectionOpen && !e.IsInbound && ports[e.SrcAddr.Port()]:
			byConn[k] = &seen{open: i, firstL7: -1, lastL7: -1, close: -1}
		case e.Type == EventTypeL7Request && byConn[k] != nil && byConn[k].close < 0:
			s := byConn[k]
			if s.firstL7 < 0 {
				s.firstL7 = i
			}
			s.lastL7 = i
		case e.Type == EventTypeL7Request:
			if s := byConn[k]; s != nil {
				t.Errorf("an L7 event of connection fd=%d after its close", e.Fd)
			}
		case e.Type == EventTypeConnectionClose && byConn[k] != nil:
			byConn[k].close = i
		}
	}
	t.Logf("%d events collected", len(events))
	require.Equal(t, conns, len(byConn), "the open of every watched connection")
	withL7 := 0
	for k, s := range byConn {
		require.GreaterOrEqual(t, s.close, 0, "the close of fd=%d", k.fd)
		if s.firstL7 >= 0 {
			withL7++
			require.Less(t, s.open, s.firstL7, "open before the L7 events of fd=%d", k.fd)
			require.Less(t, s.lastL7, s.close, "the L7 events of fd=%d before its close", k.fd)
		}
	}
	require.Equal(t, conns, withL7, "every watched connection had its request and response")
	t.Logf("%d connections, each with its open, its L7 events and its close in order; lost: %v", conns, sharedTr.LostEvents())
}
