// latbench measures request latency against the e2e example services and
// compares two runs (without and with the agent) side by side.
//
//	latbench -targets 'name|proto|baseurl,...' -out run.json       # measure
//	latbench -compare base.json,agent.json[,base2.json,agent2.json] # report
//
// Every case sends -total-bytes in total as POST /echo bodies of -body-bytes
// each and reads the echo back, so the same amount of data crosses every
// protocol. proto is one of:
//
//	h1        HTTP/1.1, a new connection per request
//	h1-ka     HTTP/1.1, one reused connection
//	h1-tls    HTTP/1.1 over TLS, a new connection (and handshake) per request
//	h1-tls-ka HTTP/1.1 over TLS, one reused connection
//	h2c       HTTP/2 without TLS, one multiplexed connection
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

type target struct {
	Name    string `json:"name"`
	Proto   string `json:"proto"`
	BaseURL string `json:"base_url"`
}

// Result is one case of one run.
type Result struct {
	Target   string  `json:"target"`
	Proto    string  `json:"proto"`
	Requests int     `json:"requests"`
	Errors   int     `json:"errors"`
	MeanUs   float64 `json:"mean_us"`
	P50Us    float64 `json:"p50_us"`
	P90Us    float64 `json:"p90_us"`
	P99Us    float64 `json:"p99_us"`
	P999Us   float64 `json:"p999_us"`
	MaxUs    float64 `json:"max_us"`
	MBPerSec float64 `json:"mb_per_sec"`
}

func newClient(proto string) *http.Client {
	switch proto {
	case "h2c":
		return &http.Client{Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		}, Timeout: 30 * time.Second}
	case "h1":
		return &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 30 * time.Second}
	case "h1-ka":
		return &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 1}, Timeout: 30 * time.Second}
	case "h1-tls":
		return &http.Client{Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		}, Timeout: 30 * time.Second}
	case "h1-tls-ka":
		return &http.Client{Transport: &http.Transport{
			MaxIdleConnsPerHost: 1,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		}, Timeout: 30 * time.Second}
	}
	log.Fatalf("unknown proto %q", proto)
	return nil
}

func pct(sorted []time.Duration, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(float64(len(sorted)-1) * p)
	return float64(sorted[i].Microseconds())
}

func runOne(t target, requests, bodyBytes, warmup, concurrency int) Result {
	client := newClient(t.Proto)
	body := bytes.Repeat([]byte("x"), bodyBytes)
	do := func() (time.Duration, error) {
		req, err := http.NewRequest(http.MethodPost, t.BaseURL+"/echo?case="+t.Name, bytes.NewReader(body))
		if err != nil {
			return 0, err
		}
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		n, err := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if err != nil {
			return 0, err
		}
		if n != int64(bodyBytes) {
			return 0, fmt.Errorf("echo returned %d bytes, want %d", n, bodyBytes)
		}
		return time.Since(start), nil
	}
	for i := 0; i < warmup; i++ {
		_, _ = do()
	}

	var mu sync.Mutex
	var lat []time.Duration
	errs := 0
	work := make(chan struct{}, requests)
	for i := 0; i < requests; i++ {
		work <- struct{}{}
	}
	close(work)
	begin := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range work {
				d, err := do()
				mu.Lock()
				if err != nil {
					errs++
				} else {
					lat = append(lat, d)
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(begin)

	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	var sum time.Duration
	for _, d := range lat {
		sum += d
	}
	r := Result{Target: t.Name, Proto: t.Proto, Requests: len(lat), Errors: errs}
	if len(lat) > 0 {
		r.MeanUs = float64(sum.Microseconds()) / float64(len(lat))
		r.P50Us = pct(lat, 0.50)
		r.P90Us = pct(lat, 0.90)
		r.P99Us = pct(lat, 0.99)
		r.P999Us = pct(lat, 0.999)
		r.MaxUs = float64(lat[len(lat)-1].Microseconds())
		r.MBPerSec = float64(len(lat)*bodyBytes*2) / 1e6 / elapsed.Seconds()
	}
	return r
}

func parseTargets(spec string) []target {
	var out []target
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		f := strings.SplitN(part, "|", 3)
		if len(f) != 3 {
			log.Fatalf("bad target %q, want name|proto|baseurl", part)
		}
		out = append(out, target{Name: f[0], Proto: f[1], BaseURL: f[2]})
	}
	return out
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	return s[len(s)/2]
}

func loadResults(path string) []Result {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	var rs []Result
	if err := json.Unmarshal(data, &rs); err != nil {
		log.Fatalf("%s: %v", path, err)
	}
	return rs
}

func fmtUs(us float64) string {
	if us >= 1000 {
		return fmt.Sprintf("%.2fms", us/1000)
	}
	return fmt.Sprintf("%.0fus", us)
}

func delta(base, with float64) string {
	if base <= 0 {
		return "n/a"
	}
	return fmt.Sprintf("%+.1f%%", (with-base)/base*100)
}

// compare takes alternating baseline,agent files (one pair per round) and
// prints, per case, the median over rounds of each statistic.
func compare(files []string) {
	if len(files)%2 != 0 || len(files) == 0 {
		log.Fatal("-compare wants base,agent[,base,agent...] pairs")
	}
	type acc struct {
		proto                         string
		baseP50, baseP99, baseMean    []float64
		agentP50, agentP99, agentMean []float64
		errs                          int
	}
	cases := map[string]*acc{}
	var order []string
	for i := 0; i < len(files); i += 2 {
		for k, f := range files[i : i+2] {
			for _, r := range loadResults(f) {
				a := cases[r.Target]
				if a == nil {
					a = &acc{proto: r.Proto}
					cases[r.Target] = a
					order = append(order, r.Target)
				}
				a.errs += r.Errors
				if k == 0 {
					a.baseP50 = append(a.baseP50, r.P50Us)
					a.baseP99 = append(a.baseP99, r.P99Us)
					a.baseMean = append(a.baseMean, r.MeanUs)
				} else {
					a.agentP50 = append(a.agentP50, r.P50Us)
					a.agentP99 = append(a.agentP99, r.P99Us)
					a.agentMean = append(a.agentMean, r.MeanUs)
				}
			}
		}
	}
	fmt.Printf("%-16s %-10s | %9s %9s %8s | %9s %9s %8s | %9s %9s %8s\n",
		"case", "proto", "p50 off", "p50 on", "delta", "p99 off", "p99 on", "delta", "mean off", "mean on", "delta")
	fmt.Println(strings.Repeat("-", 124))
	for _, name := range order {
		a := cases[name]
		bp50, ap50 := median(a.baseP50), median(a.agentP50)
		bp99, ap99 := median(a.baseP99), median(a.agentP99)
		bm, am := median(a.baseMean), median(a.agentMean)
		note := ""
		if a.errs > 0 {
			note = fmt.Sprintf("  (%d errors)", a.errs)
		}
		fmt.Printf("%-16s %-10s | %9s %9s %8s | %9s %9s %8s | %9s %9s %8s%s\n", name, a.proto,
			fmtUs(bp50), fmtUs(ap50), delta(bp50, ap50),
			fmtUs(bp99), fmtUs(ap99), delta(bp99, ap99),
			fmtUs(bm), fmtUs(am), delta(bm, am), note)
	}
}

func main() {
	targetsSpec := flag.String("targets", "", "name|proto|baseurl,...")
	totalBytes := flag.Int("total-bytes", 10*1024*1024, "bytes sent per case (the echo comes back too)")
	bodyBytes := flag.Int("body-bytes", 10*1024, "bytes per request body")
	warmup := flag.Int("warmup", 50, "uncounted requests before measuring each case")
	concurrency := flag.Int("concurrency", 1, "concurrent requests (1 measures latency, not throughput)")
	out := flag.String("out", "", "write the results as JSON here")
	cmp := flag.String("compare", "", "comma-separated base.json,agent.json[,base.json,agent.json...]")
	hold := flag.Duration("hold", 0, "stay alive this long after finishing (keeps the process visible to the agent)")
	flag.Parse()

	if *cmp != "" {
		compare(strings.Split(*cmp, ","))
		return
	}
	targets := parseTargets(*targetsSpec)
	if len(targets) == 0 {
		log.Fatal("no targets")
	}
	requests := *totalBytes / *bodyBytes
	if requests < 1 {
		requests = 1
	}
	var results []Result
	for _, t := range targets {
		r := runOne(t, requests, *bodyBytes, *warmup, *concurrency)
		log.Printf("[%s] %s n=%d err=%d p50=%s p99=%s", t.Name, t.Proto, r.Requests, r.Errors, fmtUs(r.P50Us), fmtUs(r.P99Us))
		results = append(results, r)
	}
	if *out != "" {
		data, _ := json.MarshalIndent(results, "", "  ")
		if err := os.WriteFile(*out, data, 0o644); err != nil {
			log.Fatal(err)
		}
	}
	if *hold > 0 {
		time.Sleep(*hold)
	}
}
