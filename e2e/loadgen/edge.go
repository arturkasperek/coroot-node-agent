package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Edge scenarios: HTTP/1 traffic shaped to sit at or past the limits of the
// eBPF capture (header cap, per-event payload cap, pipelining depth, bodies
// delimited by chunking or by closing the connection). Each request is
// written by hand over a raw TCP connection so its bytes are exactly as
// listed. Served by e2e/services/go's /edge/ handler.
// edgePipelineDepth: pipelined requests written in one syscall. The capture
// spends one tail call per HTTP/1 phase (a response with a body takes two;
// HTTP1_MAX_ROUNDS, bounded by the kernel's 33-tail-call limit), so roughly 14
// responses with bodies arriving in one read is the most it can walk; deeper
// pipelines lose the tail of the buffer. Stay inside the limit.
const edgePipelineDepth = 12

var edgeScenarios = []string{
	"pipeline", "bighdr", "postbig", "chunkedreq", "chunkedresp", "closedelim", "bigresp",
}

type edgeResult struct {
	method, path string
	status       int
	id           int
}

func edgeRequest(method, path, host, extra string, body []byte, chunked bool) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n%s", method, path, host, extra)
	switch {
	case chunked:
		b.WriteString("Transfer-Encoding: chunked\r\n\r\n")
		for len(body) > 0 {
			n := 100
			if n > len(body) {
				n = len(body)
			}
			fmt.Fprintf(&b, "%x\r\n", n)
			b.Write(body[:n])
			b.WriteString("\r\n")
			body = body[n:]
		}
		b.WriteString("0\r\n\r\n")
	case body != nil:
		fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n", len(body))
		b.Write(body)
	default:
		b.WriteString("\r\n")
	}
	return b.Bytes()
}

// runEdge runs scenario number i (a repetition counter) against host:port.
func runEdge(addr, scenario string, i int) ([]edgeResult, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	q := func(id int) string { return fmt.Sprintf("?n=%d&r=%s", id, runID) }
	read := func(method string) (int, error) {
		resp, err := http.ReadResponse(br, &http.Request{Method: method})
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, nil
	}
	path := "/edge/" + scenario
	switch scenario {
	case "pipeline":
		var w bytes.Buffer
		for k := 0; k < edgePipelineDepth; k++ {
			w.Write(edgeRequest("GET", path+q(i*1000+k), addr, "", nil, false))
		}
		if _, err := conn.Write(w.Bytes()); err != nil {
			return nil, err
		}
		var out []edgeResult
		for k := 0; k < edgePipelineDepth; k++ {
			st, err := read("GET")
			if err != nil {
				return out, err
			}
			out = append(out, edgeResult{"GET", path, st, i*1000 + k})
		}
		return out, nil
	case "bighdr":
		_, err = conn.Write(edgeRequest("GET", path+q(i), addr, "X-Pad: "+strings.Repeat("a", 6000)+"\r\n", nil, false))
	case "postbig":
		_, err = conn.Write(edgeRequest("POST", path+q(i), addr, "", bytes.Repeat([]byte("p"), 100*1024), false))
	case "chunkedreq":
		_, err = conn.Write(edgeRequest("POST", path+q(i), addr, "", bytes.Repeat([]byte("c"), 5000), true))
	default: // chunkedresp, closedelim, bigresp
		_, err = conn.Write(edgeRequest("GET", path+q(i), addr, "", nil, false))
	}
	if err != nil {
		return nil, err
	}
	method := "GET"
	if scenario == "postbig" || scenario == "chunkedreq" {
		method = "POST"
	}
	st, err := read(method)
	if err != nil {
		return nil, err
	}
	return []edgeResult{{method, path, st, i}}, nil
}

// driveEdge runs every edge scenario n times (n capped: they are heavy).
func driveEdge(t target, n, concurrency int) manifestEntry {
	if n > 300 {
		n = 300
	}
	u, err := url.Parse(t.baseURL)
	if err != nil {
		log.Fatalf("[%s] bad base url: %v", t.name, err)
	}
	counts := map[[3]any]int64{}
	ids := map[[3]any][]int{}
	var mu sync.Mutex
	var failed int64
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, sc := range edgeScenarios {
		for i := 0; i < n; i++ {
			sc, i := sc, i
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				res, err := runEdge(u.Host, sc, i)
				if err != nil {
					atomic.AddInt64(&failed, 1)
					log.Printf("[%s] %s %d failed: %v", t.name, sc, i, err)
				}
				mu.Lock()
				for _, r := range res {
					k := [3]any{r.method, r.path, r.status}
					counts[k]++
					ids[k] = append(ids[k], r.id)
				}
				mu.Unlock()
			}()
		}
	}
	wg.Wait()
	var outcomes []outcome
	for k, c := range counts {
		sort.Ints(ids[k])
		outcomes = append(outcomes, outcome{Method: k[0].(string), Path: k[1].(string), Status: k[2].(int), Count: c, IDs: ids[k]})
	}
	if failed > 0 {
		log.Printf("[%s] %d edge requests failed", t.name, failed)
	}
	log.Printf("[%s] done: edge scenarios x%d, %d outcome buckets", t.name, n, len(outcomes))
	return manifestEntry{Run: runID, Target: t.name, BaseURL: t.baseURL, Proto: t.proto, Outcomes: outcomes}
}
