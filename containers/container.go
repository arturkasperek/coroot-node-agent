package containers

import (
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coroot/coroot-node-agent/apptype"
	"github.com/coroot/coroot-node-agent/cgroup"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/jvm"
	"github.com/coroot/coroot-node-agent/logs"
	"github.com/coroot/coroot-node-agent/metrics"
	"github.com/coroot/coroot-node-agent/node"
	"github.com/coroot/coroot-node-agent/pinger"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/coroot/coroot-node-agent/tracing"
	"github.com/coroot/logparser"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netns"
	"golang.org/x/exp/maps"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

var (
	gcInterval             = 10 * time.Minute
	tlsAttachRetryInterval = 5 * time.Second
	pingTimeout            = 300 * time.Millisecond
	gpuStatsWindow         = 15 * time.Second
)

type ContainerID string

type ContainerNetwork struct {
	NetworkID string
}

type ContainerMetadata struct {
	name        string
	labels      map[string]string
	volumes     map[string]string
	logPath     string
	image       string
	logDecoder  logparser.Decoder
	hostListens map[string][]netaddr.IPPort
	networks    map[string]ContainerNetwork
	env         map[string]string
	systemd     SystemdProperties
}

type Delays struct {
	cpu  time.Duration
	disk time.Duration
}

type ConnectionKey struct {
	src netaddr.IPPort
	dst netaddr.IPPort
}

type ActiveConnection struct {
	DestinationKey common.DestinationKey
	Pid            uint32
	Fd             uint64
	Timestamp      uint64
	Closed         time.Time

	BytesSent     uint64
	BytesReceived uint64

	http1Parser    *l7.Http1Parser
	http2Parser    *l7.Http2Parser
	postgresParser *l7.PostgresParser
	mysqlParser    *l7.MysqlParser
}

type ListenDetails struct {
	ClosedAt time.Time
	NsIPs    []netaddr.IP
}

type PidFd struct {
	Pid uint32
	Fd  uint64
}

// PidFdTs identifies one specific connection instance rather than just
// "whichever connection currently owns this fd" — see connectionsByPidFdTs.
type PidFdTs struct {
	Pid       uint32
	Fd        uint64
	Timestamp uint64
}

type pendingHttp2State struct {
	parser    *l7.Http2Parser
	timestamp uint64
	updatedAt time.Time
	// Requests the parser completed while still waiting for their own
	// connection to register — see feedPendingHttp2/emitPendingHttp2Requests.
	completed []pendingHttp2CompletedRequest
}

type pendingHttp2CompletedRequest struct {
	req l7.Http2Request
	at  time.Time
}

type pendingHttp1State struct {
	parser    *l7.Http1Parser
	timestamp uint64
	updatedAt time.Time
	// Requests the parser completed while still waiting for their own
	// connection to register — see feedPendingHttp1/emitPendingHttp1Requests.
	completed []pendingHttp1CompletedRequest
}

type pendingHttp1CompletedRequest struct {
	req l7.Http1Request
	at  time.Time
}

// pendingL7RequestMaxAge bounds how long a request/response pair completed
// by feedPendingHttp1/feedPendingHttp2 (before its connection was
// registered) can wait for onConnectionOpen to recover it. Trace.createSpan
// (see tracing/tracing.go) stamps a span's absolute start/end from
// time.Now() at emission, not from any kernel timestamp — the request's
// Duration is still correct either way (it comes from kernel timestamps),
// but the longer we hold a completed request before emitting it, the
// further its reported position in the trace timeline drifts from when it
// actually happened. Past this age it's better to drop it than emit a
// visibly stale span.
const pendingL7RequestMaxAge = 2 * time.Second

type ConnectionStats struct {
	Count           uint64
	TotalTime       time.Duration
	Retransmissions uint64
	BytesSent       uint64
	BytesReceived   uint64
}

type Container struct {
	id       ContainerID
	appId    string
	cgroup   *cgroup.Cgroup
	metadata *ContainerMetadata

	processes map[uint32]*Process

	createdAt time.Time
	startedAt time.Time
	zombieAt  time.Time
	restarts  int

	delays      Delays
	delaysByPid map[uint32]Delays

	listens map[netaddr.IPPort]map[uint32]*ListenDetails

	connectionStats          map[common.DestinationKey]*ConnectionStats
	failedConnectionAttempts map[common.HostPort]int64
	lastConnectionAttempts   map[common.HostPort]time.Time
	activeConnections        map[ConnectionKey]*ActiveConnection
	connectionsByPidFd       map[PidFd]*ActiveConnection
	// Every live connection also indexed by its own (pid, fd, timestamp)
	// triple, not just the latest one per (pid, fd) — see onL7Request's
	// fallback lookup for why a late event needs to find its exact,
	// possibly-superseded connection rather than whatever now owns the fd.
	connectionsByPidFdTs map[PidFdTs]*ActiveConnection
	// Keyed by the exact (pid, fd, timestamp) of the connection each
	// buffered parser belongs to, not just (pid, fd) — fd churn (see
	// onL7Request) means several distinct, not-yet-registered connections
	// can share the same (pid, fd) simultaneously, and each needs its own
	// slot so a newer one's pending events don't clobber an older one's.
	pendingHttp2Parsers map[PidFdTs]*pendingHttp2State
	pendingHttp1Parsers map[PidFdTs]*pendingHttp1State

	l7Stats        L7Stats
	l7InboundStats L7InboundStats
	dnsStats       *L7Metrics
	seenFQDNs      map[string]struct{}

	gpuStats map[string]*GpuUsage

	oomKills    int
	nodejsStats *ebpftracer.NodejsStats
	pythonStats *ebpftracer.PythonStats

	jvmProfilingStats *JvmProfilingStats
	goProfilingStats  *GoProfilingStats

	mounts     map[string]proc.MountInfo
	seenMounts map[uint64]struct{}

	logParsers map[string]*logs.Pipeline

	tracer *tracing.Tracer

	registry *Registry

	lock sync.Mutex

	done chan struct{}
}

func NewContainer(id ContainerID, cg *cgroup.Cgroup, md *ContainerMetadata, pid uint32, registry *Registry) (*Container, error) {
	netNs, err := proc.GetNetNs(pid)
	if err != nil {
		return nil, err
	}
	defer netNs.Close()

	cid := string(id)
	appId := common.ContainerIdToOtelServiceName(cid)
	if appId == cid {
		appId = ""
	}
	c := &Container{
		id:       id,
		appId:    appId,
		cgroup:   cg,
		metadata: md,

		createdAt: time.Now(),

		processes: map[uint32]*Process{},

		delaysByPid: map[uint32]Delays{},

		listens: map[netaddr.IPPort]map[uint32]*ListenDetails{},

		connectionStats:          map[common.DestinationKey]*ConnectionStats{},
		failedConnectionAttempts: map[common.HostPort]int64{},
		lastConnectionAttempts:   map[common.HostPort]time.Time{},
		activeConnections:        map[ConnectionKey]*ActiveConnection{},
		connectionsByPidFd:       map[PidFd]*ActiveConnection{},
		connectionsByPidFdTs:     map[PidFdTs]*ActiveConnection{},
		pendingHttp2Parsers:      map[PidFdTs]*pendingHttp2State{},
		pendingHttp1Parsers:      map[PidFdTs]*pendingHttp1State{},
		l7Stats:                  L7Stats{},
		l7InboundStats:           L7InboundStats{},
		dnsStats:                 &L7Metrics{},
		seenFQDNs:                map[string]struct{}{},

		gpuStats: map[string]*GpuUsage{},

		mounts:     map[string]proc.MountInfo{},
		seenMounts: map[uint64]struct{}{},

		logParsers: map[string]*logs.Pipeline{},

		tracer: tracing.GetContainerTracer(string(id)),

		registry: registry,

		done: make(chan struct{}),
	}
	c.runLogParser("")

	go func() {
		ticker := time.NewTicker(gcInterval)
		defer ticker.Stop()
		for {
			select {
			case <-c.done:
				return
			case t := <-ticker.C:
				c.gc(t)
			}
		}
	}()

	return c, nil
}

func (c *Container) Close() {
	for _, p := range c.logParsers {
		p.Stop()
	}
	close(c.done)
}

func (c *Container) Dead(now time.Time) bool {
	return !c.zombieAt.IsZero() && now.Sub(c.zombieAt) > gcInterval
}

func (c *Container) Describe(ch chan<- *prometheus.Desc) {
	// some fixed metric description is required here to register/unregister the collector correctly
	ch <- prometheus.NewDesc("container", "", nil, nil)
}

func (c *Container) Collect(ch chan<- prometheus.Metric) {
	c.registry.updateStatsFromEbpfMapsIfNecessary()

	c.lock.Lock()
	defer c.lock.Unlock()

	if taskstatsClient != nil {
		deadPids := c.updateDelaysLocked()
		for _, pid := range deadPids {
			c.onProcessExitLocked(pid, false)
		}
	}

	if minAge := *flags.MinContainerAge; minAge > 0 {
		since := c.startedAt
		if since.IsZero() || c.createdAt.Before(since) {
			since = c.createdAt
		}
		end := time.Now()
		if !c.zombieAt.IsZero() && c.zombieAt.Before(end) {
			end = c.zombieAt
		}
		if end.Sub(since) < minAge {
			return
		}
	}

	if c.metadata.image != "" || !c.metadata.systemd.IsEmpty() {
		ch <- metrics.Gauge(metrics.ContainerInfo, 1, c.metadata.image, c.metadata.systemd.TriggeredBy, c.metadata.systemd.Type)
	}

	ch <- metrics.Counter(metrics.Restarts, float64(c.restarts))

	if cpu := c.cgroup.CpuStat(); cpu != nil {
		if cpu.LimitCores > 0 {
			ch <- metrics.Gauge(metrics.CPULimit, cpu.LimitCores)
		}
		ch <- metrics.Counter(metrics.CPUUsage, cpu.UsageSeconds)
		ch <- metrics.Counter(metrics.ThrottledTime, cpu.ThrottledTimeSeconds)
	}

	if taskstatsClient != nil {
		ch <- metrics.Counter(metrics.CPUDelay, float64(c.delays.cpu)/float64(time.Second))
		ch <- metrics.Counter(metrics.DiskDelay, float64(c.delays.disk)/float64(time.Second))
	}

	if s := c.cgroup.MemoryStat(); s != nil {
		ch <- metrics.Gauge(metrics.MemoryRss, float64(s.RSS))
		ch <- metrics.Gauge(metrics.MemoryCache, float64(s.Cache))
		if s.Limit > 0 {
			ch <- metrics.Gauge(metrics.MemoryLimit, float64(s.Limit))
		}
	}

	if psi := c.cgroup.PSI(); psi != nil {
		ch <- metrics.Counter(metrics.PsiCPU, psi.CPUSecondsSome, "some")
		ch <- metrics.Counter(metrics.PsiCPU, psi.CPUSecondsFull, "full")
		ch <- metrics.Counter(metrics.PsiMemory, psi.MemorySecondsSome, "some")
		ch <- metrics.Counter(metrics.PsiMemory, psi.MemorySecondsFull, "full")
		ch <- metrics.Counter(metrics.PsiIO, psi.IOSecondsSome, "some")
		ch <- metrics.Counter(metrics.PsiIO, psi.IOSecondsFull, "full")
	}

	if c.oomKills > 0 {
		ch <- metrics.Counter(metrics.OOMKills, float64(c.oomKills))
	}

	if disks, err := node.GetDisks(); err == nil {
		ioStat := c.cgroup.IOStat()
		seenVolumes := map[string]struct{}{}
		for majorMinor, mounts := range c.getMounts() {
			var device string
			if dev := disks.GetParentBlockDevice(majorMinor); dev != nil {
				device = dev.Name
			}
			for mountPoint, fsStat := range mounts {
				if _, ok := seenVolumes[mountPoint+":"+device]; ok {
					continue
				}
				seenVolumes[mountPoint+":"+device] = struct{}{}
				dls := []string{mountPoint, device, c.metadata.volumes[mountPoint]}
				ch <- metrics.Gauge(metrics.DiskSize, float64(fsStat.CapacityBytes), dls...)
				ch <- metrics.Gauge(metrics.DiskUsed, float64(fsStat.UsedBytes), dls...)
				ch <- metrics.Gauge(metrics.DiskReserved, float64(fsStat.ReservedBytes), dls...)
				if ioStat != nil {
					if io, ok := ioStat[majorMinor]; ok {
						ch <- metrics.Counter(metrics.DiskReadOps, float64(io.ReadOps), dls...)
						ch <- metrics.Counter(metrics.DiskReadBytes, float64(io.ReadBytes), dls...)
						ch <- metrics.Counter(metrics.DiskWriteOps, float64(io.WriteOps), dls...)
						ch <- metrics.Counter(metrics.DiskWriteBytes, float64(io.WrittenBytes), dls...)
					}
				}
			}
		}
	}

	for addr, open := range c.getListens() {
		ch <- metrics.Gauge(metrics.NetListenInfo, float64(open), addr.String(), "")
	}
	for proxy, addrs := range c.getProxiedListens() {
		for addr := range addrs {
			ch <- metrics.Gauge(metrics.NetListenInfo, 1, addr.String(), proxy)
		}
	}

	for d, stats := range c.connectionStats {
		ch <- metrics.Counter(metrics.NetConnectionsSuccessful, float64(stats.Count), d.DestinationLabelValue(), d.ActualDestinationLabelValue())
		ch <- metrics.Counter(metrics.NetConnectionsTotalTime, stats.TotalTime.Seconds(), d.DestinationLabelValue(), d.ActualDestinationLabelValue())
		if stats.Retransmissions > 0 {
			ch <- metrics.Counter(metrics.NetRetransmits, float64(stats.Retransmissions), d.DestinationLabelValue(), d.ActualDestinationLabelValue())
		}
		ch <- metrics.Counter(metrics.NetBytesSent, float64(stats.BytesSent), d.DestinationLabelValue(), d.ActualDestinationLabelValue())
		ch <- metrics.Counter(metrics.NetBytesReceived, float64(stats.BytesReceived), d.DestinationLabelValue(), d.ActualDestinationLabelValue())
	}
	for dst, count := range c.failedConnectionAttempts {
		ch <- metrics.Counter(metrics.NetConnectionsFailed, float64(count), dst.String())
	}

	connections := map[common.DestinationKey]int{}
	for _, conn := range c.activeConnections {
		if !conn.Closed.IsZero() {
			continue
		}
		connections[conn.DestinationKey]++
	}
	for d, count := range connections {
		ch <- metrics.Gauge(metrics.NetConnectionsActive, float64(count), d.DestinationLabelValue(), d.ActualDestinationLabelValue())
	}

	for source, p := range c.logParsers {
		for _, c := range p.Counters() {
			ch <- metrics.Counter(metrics.LogMessages, float64(c.Messages), source, c.Level.String(), c.Hash, common.TruncateUtf8(c.Sample, *flags.MaxLabelLength))
		}
	}

	appTypes := map[string]struct{}{}
	seenJvms := map[string]bool{}
	seenDotNetApps := map[string]bool{}
	pids := maps.Keys(c.processes)
	sort.Slice(pids, func(i, j int) bool {
		return pids[i] < pids[j]
	})

	for _, pid := range pids {
		process := c.processes[pid]
		cmdline := proc.GetCmdline(pid)
		if len(cmdline) == 0 {
			continue
		}
		if appType := apptype.GuessByCmdline(cmdline); appType != "" {
			appTypes[appType] = struct{}{}
		} else {
			if exe, err := os.Readlink(proc.Path(pid, "exe")); err == nil {
				if appType = apptype.GuessByExe(exe); appType != "" {
					appTypes[appType] = struct{}{}
				}
			}
		}
		if process.isGolangApp {
			appTypes["golang"] = struct{}{}
		}
		if process.isRustApp {
			appTypes["rust"] = struct{}{}
		}
		switch {
		case proc.IsJvm(cmdline):
			jvm, jMetrics := jvmMetrics(pid, c)
			if len(jMetrics) > 0 && !seenJvms[jvm] {
				seenJvms[jvm] = true
				for _, m := range jMetrics {
					ch <- m
				}
			}
		case process.dotNetMonitor != nil:
			appTypes["dotnet"] = struct{}{}
			appName := process.dotNetMonitor.AppName()
			if !seenDotNetApps[appName] {
				seenDotNetApps[appName] = true
				process.dotNetMonitor.Collect(ch)
			}
		}

		for _, usage := range c.gpuStats {
			usage.Reset()
		}
		if usage := process.getGPUUsage(); usage != nil {
			for uuid, u := range usage {
				tu := c.gpuStats[uuid]
				if tu == nil {
					tu = &GpuUsage{}
					c.gpuStats[uuid] = tu
				}
				tu.GPU += u.GPU
				tu.Memory += u.Memory
			}
		}
	}
	for uuid, usage := range c.gpuStats {
		ch <- metrics.Gauge(metrics.GpuUsagePercent, usage.GPU, uuid)
		ch <- metrics.Gauge(metrics.GpuMemoryUsagePercent, usage.Memory, uuid)
	}

	for appType := range appTypes {
		ch <- metrics.Gauge(metrics.ApplicationType, 1, appType)
	}
	if c.pythonStats != nil {
		ch <- metrics.Counter(metrics.PythonThreadLockWaitTime, c.pythonStats.ThreadLockWaitTime.Seconds())
	}
	if c.nodejsStats != nil {
		ch <- metrics.Counter(metrics.NodejsEventLoopBlockedTime, c.nodejsStats.EventLoopBlockedTime.Seconds())
	}
	if s := c.goProfilingStats; s != nil {
		ch <- metrics.Counter(metrics.GoAllocBytes, float64(s.AllocBytes))
		ch <- metrics.Counter(metrics.GoAllocObjects, float64(s.AllocObjects))
	}

	if c.dnsStats.Requests != nil {
		c.dnsStats.Requests.Collect(ch)
	}
	if c.dnsStats.Latency != nil {
		c.dnsStats.Latency.Collect(ch)
	}
	c.l7Stats.collect(ch)
	c.l7InboundStats.collect(ch)

	if !*flags.DisablePinger {
		for ip, rtt := range c.ping() {
			ch <- metrics.Gauge(metrics.NetLatency, rtt, ip.String())
		}
	}
}

func (c *Container) ensureProcess(pid uint32) *Process {
	c.lock.Lock()
	p := c.processes[pid]
	c.lock.Unlock()
	if p != nil {
		return p
	}
	return c.onProcessStart(pid)
}

func (c *Container) onProcessStart(pid uint32) *Process {
	c.lock.Lock()
	defer c.lock.Unlock()
	stats, err := TaskstatsPID(pid)
	if err != nil {
		return nil
	}
	c.zombieAt = time.Time{}
	p := NewProcess(pid, stats, c.registry.tracer)

	if p == nil {
		return nil
	}
	c.processes[pid] = p

	if c.startedAt.IsZero() {
		c.startedAt = stats.BeginTime
	} else {
		min := stats.BeginTime
		for _, p := range c.processes {
			if p.StartedAt.Before(min) {
				min = p.StartedAt
			}
		}
		if min.After(c.startedAt) {
			c.restarts++
			c.startedAt = min
		}
	}
	return p
}

func (c *Container) onProcessExitLocked(pid uint32, oomKill bool) {
	if p := c.processes[pid]; p != nil {
		p.Close()
	}
	delete(c.processes, pid)
	if len(c.processes) == 0 {
		c.zombieAt = time.Now()
	}
	delete(c.delaysByPid, pid)
	if oomKill {
		c.oomKills++
	}
}

func (c *Container) onProcessExit(pid uint32, oomKill bool) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.onProcessExitLocked(pid, oomKill)
}

func (c *Container) onFileOpen(pid uint32, fd uint64, mnt uint64, log bool) {
	if mnt > 0 && !log {
		c.lock.Lock()
		_, ok := c.seenMounts[mnt]
		c.lock.Unlock()
		if ok {
			return
		}
	}
	mntId, logPath := resolveFd(pid, fd)
	func() {
		if mntId == "" {
			return
		}
		c.lock.Lock()
		if mnt > 0 {
			c.seenMounts[mnt] = struct{}{}
		}
		_, ok := c.mounts[mntId]
		c.lock.Unlock()
		if ok {
			return
		}
		byMountId := proc.GetMountInfo(pid)
		if byMountId == nil {
			return
		}
		if mi, ok := byMountId[mntId]; ok {
			c.lock.Lock()
			c.mounts[mntId] = mi
			c.lock.Unlock()
		}
	}()
	if logPath != "" {
		c.lock.Lock()
		c.runLogParser(logPath)
		c.lock.Unlock()
	}
}

func (c *Container) onListenOpen(pid uint32, addr netaddr.IPPort, safe bool) {
	klog.Infof("TCP listen open pid=%d id=%s addr=%s", pid, c.id, addr)
	if common.PortFilter.ShouldBeSkipped(addr.Port()) {
		return
	}
	if !safe {
		c.lock.Lock()
		defer c.lock.Unlock()
	}
	if _, ok := c.listens[addr]; !ok {
		c.listens[addr] = map[uint32]*ListenDetails{}
	}
	details := &ListenDetails{}
	c.listens[addr][pid] = details

	if addr.IP().IsUnspecified() {
		ns, err := proc.GetNetNs(pid)
		if err != nil {
			if !common.IsNotExist(err) {
				klog.Warningln(err)
			}
			return
		}
		defer ns.Close()
		ips, err := proc.GetNsIps(ns)
		if err != nil {
			klog.Warningln(err)
			return
		}
		klog.Infof("got IPs %s for %s", ips, ns.UniqueId())
		details.NsIPs = ips
	}
}

func (c *Container) onListenClose(pid uint32, addr netaddr.IPPort) {
	klog.Infof("TCP listen close pid=%d id=%s addr=%s", pid, c.id, addr)
	c.lock.Lock()
	defer c.lock.Unlock()
	if _, byAddr := c.listens[addr]; byAddr {
		if _, byPid := c.listens[addr][pid]; byPid {
			if details := c.listens[addr][pid]; details != nil {
				details.ClosedAt = time.Now()
			}
		}
	}
}

func (c *Container) onConnectionOpen(pid uint32, fd uint64, src, dst, actualDst netaddr.IPPort, timestamp uint64, failed bool, duration time.Duration) {
	if common.PortFilter.ShouldBeSkipped(dst.Port()) {
		return
	}
	p := c.processes[pid]
	if p == nil {
		return
	}
	if dst.IP().IsLoopback() && !p.isHostNs() {
		return
	}
	if actualDst.Port() == 0 {
		if a := lookupCiliumConntrackTable(src, dst); a != nil {
			actualDst = *a
		} else {
			actualDst = dst
		}
	}
	if actualDst.IP().IsLoopback() && !p.isHostNs() {
		return
	}
	if common.ConnectionFilter.ShouldBeSkipped(dst.IP(), actualDst.IP()) {
		return
	}
	key := common.NewDestinationKey(dst, actualDst, c.registry.getDomain(dst.IP()))
	c.lock.Lock()
	defer c.lock.Unlock()
	if failed {
		c.failedConnectionAttempts[key.Destination()]++
	} else {
		stats := c.connectionStats[key]
		if stats == nil {
			stats = &ConnectionStats{}
			c.connectionStats[key] = stats
		}
		stats.Count++
		stats.TotalTime += duration
		connection := &ActiveConnection{
			DestinationKey: key,
			Pid:            pid,
			Fd:             fd,
			Timestamp:      timestamp,
		}
		c.activeConnections[ConnectionKey{src: src, dst: dst}] = connection
		k := PidFd{Pid: pid, Fd: fd}
		prev := c.connectionsByPidFd[k]
		if prev != nil {
			prev.Closed = time.Now()
		}
		c.connectionsByPidFd[k] = connection
		if timestamp != 0 {
			c.connectionsByPidFdTs[PidFdTs{Pid: pid, Fd: fd, Timestamp: timestamp}] = connection
		}
		if timestamp != 0 {
			kts := PidFdTs{Pid: pid, Fd: fd, Timestamp: timestamp}
			if pending, ok := c.pendingHttp2Parsers[kts]; ok {
				connection.http2Parser = pending.parser
				c.emitPendingHttp2Requests(connection, pending.completed)
				delete(c.pendingHttp2Parsers, kts)
			}
		}
		if timestamp != 0 {
			kts := PidFdTs{Pid: pid, Fd: fd, Timestamp: timestamp}
			if pending, ok := c.pendingHttp1Parsers[kts]; ok {
				connection.http1Parser = pending.parser
				c.emitPendingHttp1Requests(connection, pending.completed)
				delete(c.pendingHttp1Parsers, kts)
			}
		}
	}
	c.lastConnectionAttempts[key.Destination()] = time.Now()
}

// feedPendingHttp2 mirrors feedPendingHttp1 (see there for why this race is
// routine, not exceptional): an HTTP/2 L7 event can arrive for a (pid, fd)
// before onConnectionOpen has registered that connection, most likely for
// this protocol when a long-lived multiplexed connection gets transparently
// redialed (a TCP-level hiccup, a PING timeout, ...) — invisible to the
// application, but it re-triggers the exact same connection-registration
// race HTTP/1 hits on every request. A request/response pair that
// completes entirely before the connection registers is queued in
// st.completed (bounded by pendingL7RequestMaxAge) and emitted
// retroactively by emitPendingHttp2Requests once onConnectionOpen finds
// this state.
func (c *Container) feedPendingHttp2(pid uint32, fd uint64, timestamp uint64, r *l7.RequestData) {
	k := PidFdTs{Pid: pid, Fd: fd, Timestamp: timestamp}
	st := c.pendingHttp2Parsers[k]
	if st == nil {
		st = &pendingHttp2State{parser: l7.NewHttp2Parser(), timestamp: timestamp}
		c.pendingHttp2Parsers[k] = st
	}
	st.updatedAt = time.Now()
	for _, req := range st.parser.Parse(r.Method, r.Payload, uint64(r.Duration)) {
		st.completed = append(st.completed, pendingHttp2CompletedRequest{req: req, at: st.updatedAt})
	}
}

// emitPendingHttp2Requests replays request/response pairs that completed
// while their connection was still unregistered (see feedPendingHttp2), now
// that onConnectionOpen has found the real connection for them. Mirrors
// the l7.ProtocolHTTP2 case in onL7Request's switch — see
// emitPendingHttp1Requests for why this recomputes stats/trace rather than
// sharing the live path's.
func (c *Container) emitPendingHttp2Requests(conn *ActiveConnection, completed []pendingHttp2CompletedRequest) {
	if len(completed) == 0 {
		return
	}
	now := time.Now()
	stats := c.l7Stats.get(l7.ProtocolHTTP2, conn.DestinationKey)
	ebpfTracesDisabled := false
	for _, p := range c.processes {
		if p.Flags.EbpfTracesDisabled {
			ebpfTracesDisabled = true
			break
		}
	}
	var trace *tracing.Trace
	if !ebpfTracesDisabled {
		trace = c.tracer.NewTrace(conn.DestinationKey.ActualDestinationIfKnown())
	}
	for _, cr := range completed {
		if now.Sub(cr.at) > pendingL7RequestMaxAge {
			continue
		}
		if !common.HttpFilter.ShouldBeSkipped(cr.req.Path) {
			status := cr.req.Status.Http()
			if cr.req.GrpcStatus >= 0 {
				status = cr.req.GrpcStatus.GRPC()
			}
			stats.observe(status, "", cr.req.Duration)
			trace.Http2Request(cr.req.Method, cr.req.Path, cr.req.Scheme, cr.req.Status, cr.req.GrpcStatus, cr.req.Duration)
		}
	}
}

// feedPendingHttp1 mirrors feedPendingHttp2: an HTTP/1 L7 event can arrive
// for a (pid, fd) before onConnectionOpen has registered that connection —
// the tcp-connect-events and l7-events ring buffers are read by two
// independent goroutines with no ordering guarantee between them (see
// runTcpConnectEventsReader/runL7EventsReader in ebpftracer/tracer.go), so
// this race is routine, not exceptional. Rather than dropping the event
// (as onL7Request otherwise would for l7.ProtocolHTTP when conn == nil),
// keep parsing into a pending Http1Parser so header/body framing state
// isn't lost; onConnectionOpen attaches it to the real connection once
// registered, and normal dispatch continues from there. A request/response
// pair that completes entirely before the connection registers is queued
// in st.completed (bounded by pendingL7RequestMaxAge) and emitted
// retroactively by emitPendingHttp1Requests once onConnectionOpen finds
// this state.
func (c *Container) feedPendingHttp1(pid uint32, fd uint64, timestamp uint64, r *l7.RequestData) {
	k := PidFdTs{Pid: pid, Fd: fd, Timestamp: timestamp}
	st := c.pendingHttp1Parsers[k]
	if st == nil {
		st = &pendingHttp1State{parser: l7.NewHttp1Parser(), timestamp: timestamp}
		c.pendingHttp1Parsers[k] = st
	}
	st.updatedAt = time.Now()
	for _, req := range st.parser.Parse(r.Method, r.Payload, uint64(r.Duration)) {
		st.completed = append(st.completed, pendingHttp1CompletedRequest{req: req, at: st.updatedAt})
	}
}

// emitPendingHttp1Requests replays request/response pairs that completed
// while their connection was still unregistered (see feedPendingHttp1),
// now that onConnectionOpen has found the real connection for them.
// Mirrors the l7.ProtocolHTTP case in onL7Request's switch, but that
// path's stats/trace are computed once per live event and reused across
// protocols, whereas this one is only reached rarely (once per recovered
// connection), so it computes its own rather than restructuring the live
// path to share them.
func (c *Container) emitPendingHttp1Requests(conn *ActiveConnection, completed []pendingHttp1CompletedRequest) {
	if len(completed) == 0 {
		return
	}
	now := time.Now()
	stats := c.l7Stats.get(l7.ProtocolHTTP, conn.DestinationKey)
	ebpfTracesDisabled := false
	for _, p := range c.processes {
		if p.Flags.EbpfTracesDisabled {
			ebpfTracesDisabled = true
			break
		}
	}
	var trace *tracing.Trace
	if !ebpfTracesDisabled {
		trace = c.tracer.NewTrace(conn.DestinationKey.ActualDestinationIfKnown())
	}
	for _, cr := range completed {
		if now.Sub(cr.at) > pendingL7RequestMaxAge {
			continue
		}
		c.registry.http1RequestsParsed.Add(1)
		if !common.HttpFilter.ShouldBeSkipped(cr.req.Path) {
			stats.observe(cr.req.Status.Http(), "", cr.req.Duration)
			trace.HttpRequest(cr.req.Method, cr.req.Path, cr.req.Status, cr.req.Duration)
		}
	}
}

func (c *Container) onConnectionClose(e ebpftracer.Event) {
	if e.IsInbound {
		c.lock.Lock()
		defer c.lock.Unlock()
		if p := c.processes[e.Pid]; p != nil {
			delete(p.inboundHttp1Parsers, e.Fd)
			delete(p.inboundHttp2Parsers, e.Fd)
		}
		return
	}
	c.lock.Lock()
	conn := c.connectionsByPidFd[PidFd{Pid: e.Pid, Fd: e.Fd}]
	c.lock.Unlock()
	if conn != nil {
		if conn.Timestamp != 0 && conn.Timestamp != e.Timestamp {
			return
		}
		if conn.Closed.IsZero() {
			if e.TrafficStats != nil {
				c.lock.Lock()
				c.updateConnectionTrafficStats(conn, e.TrafficStats.BytesSent, e.TrafficStats.BytesReceived)
				c.lock.Unlock()
			}
			conn.Closed = time.Now()
		}
	}
}

func (c *Container) updateTrafficStats(u *TrafficStatsUpdate) {
	if u == nil {
		return
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	c.updateConnectionTrafficStats(c.connectionsByPidFd[PidFd{Pid: u.Pid, Fd: u.FD}], u.BytesSent, u.BytesReceived)
}

func (c *Container) updateConnectionTrafficStats(ac *ActiveConnection, sent, received uint64) {
	if ac == nil {
		return
	}
	stats := c.connectionStats[ac.DestinationKey]
	if stats == nil {
		stats = &ConnectionStats{}
		c.connectionStats[ac.DestinationKey] = stats
	}
	if sent > ac.BytesSent {
		stats.BytesSent += sent - ac.BytesSent
	}
	if received > ac.BytesReceived {
		stats.BytesReceived += received - ac.BytesReceived
	}
	ac.BytesSent = sent
	ac.BytesReceived = received
}

const fqdnOverflowLabel = "~other"

func (c *Container) onDNSRequest(r *l7.RequestData) map[netaddr.IP]*common.Domain {
	status := r.Status.DNS()
	if status == "" {
		return nil
	}
	t, fqdn, ips := l7.ParseDns(r.Payload)
	if t == "" {
		return nil
	}
	fqdn = common.NormalizeFQDN(fqdn, t)

	// To reduce the number of metrics, we ignore AAAA requests with empty results,
	// as they are typically performed simultaneously with A requests and do not add
	// any additional latency to the application.
	if t == "TypeAAAA" && r.Status == 0 && len(ips) == 0 {
		return nil
	}

	if c.dnsStats.Requests == nil {
		dnsReq := L7Requests[l7.ProtocolDNS]
		c.dnsStats.Requests = prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: dnsReq.Name, Help: dnsReq.Help},
			[]string{"request_type", "domain", "status"},
		)
	}
	metricFQDN := fqdn
	if fqdn != "" {
		if _, ok := c.seenFQDNs[fqdn]; !ok {
			if len(c.seenFQDNs) < *flags.MaxFQDNsPerContainer {
				c.seenFQDNs[fqdn] = struct{}{}
			} else {
				metricFQDN = fqdnOverflowLabel
			}
		}
	}
	if m, _ := c.dnsStats.Requests.GetMetricWithLabelValues(t, metricFQDN, status); m != nil {
		m.Inc()
	}
	if r.Duration != 0 {
		if c.dnsStats.Latency == nil {
			dnsLatency := L7Latency[l7.ProtocolDNS]
			c.dnsStats.Latency = prometheus.NewHistogram(prometheus.HistogramOpts{Name: dnsLatency.Name, Help: dnsLatency.Help})
		}
		c.dnsStats.Latency.Observe(r.Duration.Seconds())
	}
	ip2fqdn := map[netaddr.IP]*common.Domain{}
	if fqdn != "" {
		d := common.NewDomain(fqdn, ips)
		for _, ip := range ips {
			ip2fqdn[ip] = d
		}
	}
	return ip2fqdn
}

func (c *Container) onL7Request(pid uint32, fd uint64, timestamp uint64, r *l7.RequestData) map[netaddr.IP]*common.Domain {
	c.lock.Lock()
	defer c.lock.Unlock()

	if r.IsInbound {
		c.observeInboundL7(pid, fd, timestamp, r)
		return nil
	}

	if r.Protocol == l7.ProtocolDNS {
		return c.onDNSRequest(r)
	}

	conn := c.connectionsByPidFd[PidFd{Pid: pid, Fd: fd}]
	if conn == nil || (timestamp != 0 && conn.Timestamp != timestamp) {
		// (pid, fd) is reused across connections far faster than the
		// two independent ring-buffer readers (tcp-connect-events and
		// l7-events, see runTcpConnectEventsReader/runL7EventsReader in
		// ebpftracer/tracer.go) can be guaranteed to stay in order: a
		// late event for an older connection on this fd can arrive after
		// a newer connection has already reused the same fd and
		// overwritten connectionsByPidFd's entry. Before treating this
		// as unknown, check whether the *exact* connection this event
		// belongs to (identified by its own timestamp, not just the
		// latest one on this fd) is still around.
		if timestamp != 0 {
			if alt := c.connectionsByPidFdTs[PidFdTs{Pid: pid, Fd: fd, Timestamp: timestamp}]; alt != nil {
				conn = alt
			}
		}
	}
	if conn == nil || (timestamp != 0 && conn.Timestamp != timestamp) {
		// Still unresolved even after the connectionsByPidFdTs fallback
		// above: either this (pid, fd) has never been registered at all,
		// or it has but for a *different* connection than this event's
		// own timestamp (the fallback lookup itself came up empty,
		// meaning that connection's own connect-open event hasn't been
		// processed yet either — same cross-ring-buffer race, just late
		// enough that neither map has caught up). Both cases get one
		// more chance via feedPendingHttp1, keyed by the event's own
		// (pid, fd, timestamp) so concurrently-pending connections on a
		// fast-recycled fd don't clobber each other's buffered state;
		// onConnectionOpen attaches it once that connection's own
		// connect-open event finally arrives (see there).
		wasNil := conn == nil
		if r.Protocol == l7.ProtocolHTTP2 {
			c.feedPendingHttp2(pid, fd, timestamp, r)
		}
		if r.Protocol == l7.ProtocolHTTP {
			if wasNil {
				c.registry.http1DroppedNoConnection.Add(1)
			} else {
				c.registry.http1DroppedTsMismatch.Add(1)
			}
			c.feedPendingHttp1(pid, fd, timestamp, r)
		}
		return nil
	}
	stats := c.l7Stats.get(r.Protocol, conn.DestinationKey)

	ebpfTracesDisabled := false
	for _, p := range c.processes {
		if p.Flags.EbpfTracesDisabled {
			ebpfTracesDisabled = true
			break
		}
	}
	var trace *tracing.Trace
	if !ebpfTracesDisabled {
		trace = c.tracer.NewTrace(conn.DestinationKey.ActualDestinationIfKnown())
	}
	switch r.Protocol {
	case l7.ProtocolHTTP:
		c.registry.http1EventsSeen.Add(1)
		if conn.http1Parser == nil {
			conn.http1Parser = l7.NewHttp1Parser()
		}
		for _, req := range conn.http1Parser.Parse(r.Method, r.Payload, uint64(r.Duration)) {
			c.registry.http1RequestsParsed.Add(1)
			if !common.HttpFilter.ShouldBeSkipped(req.Path) {
				stats.observe(req.Status.Http(), "", req.Duration)
				trace.HttpRequest(req.Method, req.Path, req.Status, req.Duration)
			}
		}
	case l7.ProtocolHTTP2:
		if conn.http2Parser == nil {
			conn.http2Parser = l7.NewHttp2Parser()
		}
		requests := conn.http2Parser.Parse(r.Method, r.Payload, uint64(r.Duration))
		for _, req := range requests {
			if !common.HttpFilter.ShouldBeSkipped(req.Path) {
				status := req.Status.Http()
				if req.GrpcStatus >= 0 {
					status = req.GrpcStatus.GRPC()
				}
				stats.observe(status, "", req.Duration)
				trace.Http2Request(req.Method, req.Path, req.Scheme, req.Status, req.GrpcStatus, req.Duration)
			}
		}
	case l7.ProtocolPostgres:
		if r.Method != l7.MethodStatementClose {
			stats.observe(r.Status.String(), "", r.Duration)
		}
		if conn.postgresParser == nil {
			conn.postgresParser = l7.NewPostgresParser()
		}
		query := conn.postgresParser.Parse(r.Payload)
		trace.PostgresQuery(query, r.Status.Error(), r.Duration)
	case l7.ProtocolMysql:
		if r.Method != l7.MethodStatementClose {
			stats.observe(r.Status.String(), "", r.Duration)
		}
		if conn.mysqlParser == nil {
			conn.mysqlParser = l7.NewMysqlParser()
		}
		query := conn.mysqlParser.Parse(r.Payload, r.StatementId)
		trace.MysqlQuery(query, r.Status.Error(), r.Duration)
	case l7.ProtocolMemcached:
		stats.observe(r.Status.String(), "", r.Duration)
		cmd, items := l7.ParseMemcached(r.Payload)
		trace.MemcachedQuery(cmd, items, r.Status.Error(), r.Duration)
	case l7.ProtocolRedis:
		stats.observe(r.Status.String(), "", r.Duration)
		cmd, args := l7.ParseRedis(r.Payload)
		trace.RedisQuery(cmd, args, r.Status.Error(), r.Duration)
	case l7.ProtocolMongo:
		stats.observe(r.Status.String(), "", r.Duration)
		query := l7.ParseMongo(r.Payload)
		trace.MongoQuery(query, r.Status.Error(), r.Duration)
	case l7.ProtocolKafka, l7.ProtocolCassandra:
		stats.observe(r.Status.String(), "", r.Duration)
	case l7.ProtocolRabbitmq, l7.ProtocolNats:
		stats.observe(r.Status.String(), r.Method.String(), 0)
	case l7.ProtocolDubbo2:
		stats.observe(r.Status.String(), "", r.Duration)
	case l7.ProtocolClickhouse:
		stats.observe(r.Status.String(), "", r.Duration)
		query := l7.ParseClickhouse(r.Payload)
		trace.ClickhouseQuery(query, r.Status.Error(), r.Duration)
	case l7.ProtocolZookeeper:
		stats.observe(r.Status.Zookeeper(), "", r.Duration)
		op, arg := l7.ParseZookeeper(r.Payload)
		trace.ZookeeperRequest(op, arg, r.Status, r.Duration)
	case l7.ProtocolFoundationDB:
		stats.observe(r.Status.String(), "", r.Duration)
	}
	return nil
}

func (c *Container) observeInboundL7(pid uint32, fd uint64, timestamp uint64, r *l7.RequestData) {
	protocol := r.Protocol
	if protocol == l7.ProtocolHTTP {
		p := c.processes[pid]
		if p == nil {
			return
		}
		if p.inboundHttp1Parsers == nil {
			p.inboundHttp1Parsers = map[uint64]*inboundHttp1State{}
		}
		state := p.inboundHttp1Parsers[fd]
		if state == nil || state.connTimestamp != timestamp {
			state = &inboundHttp1State{
				parser:        l7.NewHttp1Parser(),
				connTimestamp: timestamp,
			}
			p.inboundHttp1Parsers[fd] = state
		}
		requests := state.parser.Parse(r.Method, r.Payload, uint64(r.Duration))
		if len(requests) == 0 {
			return
		}
		stats := c.l7InboundStats.get(l7.ProtocolHTTP)
		for _, req := range requests {
			if common.HttpFilter.ShouldBeSkipped(req.Path) {
				continue
			}
			stats.observe(req.Status.Http(), "", req.Duration)
		}
		return
	}
	if protocol == l7.ProtocolHTTP2 {
		p := c.processes[pid]
		if p == nil {
			return
		}
		if p.inboundHttp2Parsers == nil {
			p.inboundHttp2Parsers = map[uint64]*inboundHttp2State{}
		}
		state := p.inboundHttp2Parsers[fd]
		if state == nil || state.connTimestamp != timestamp {
			state = &inboundHttp2State{
				parser:        l7.NewHttp2Parser(),
				connTimestamp: timestamp,
			}
			p.inboundHttp2Parsers[fd] = state
		}
		requests := state.parser.Parse(r.Method, r.Payload, uint64(r.Duration))
		if len(requests) == 0 {
			return
		}
		stats := c.l7InboundStats.get(l7.ProtocolHTTP)
		for _, req := range requests {
			if common.HttpFilter.ShouldBeSkipped(req.Path) {
				continue
			}
			status := req.Status.Http()
			if req.GrpcStatus >= 0 {
				status = req.GrpcStatus.GRPC()
			}
			stats.observe(status, "", req.Duration)
		}
		return
	}
	if _, ok := L7InboundRequests[protocol]; !ok {
		return
	}
	stats := c.l7InboundStats.get(protocol)
	switch protocol {
	case l7.ProtocolZookeeper:
		stats.observe(r.Status.Zookeeper(), "", r.Duration)
	default:
		stats.observe(r.Status.String(), "", r.Duration)
	}
}

func (c *Container) onRetransmission(src netaddr.IPPort, dst netaddr.IPPort) bool {
	c.lock.Lock()
	defer c.lock.Unlock()
	conn, ok := c.activeConnections[ConnectionKey{src: src, dst: dst}]
	if !ok {
		return false
	}
	stats := c.connectionStats[conn.DestinationKey]
	if stats == nil {
		stats = &ConnectionStats{}
		c.connectionStats[conn.DestinationKey] = stats
	}
	stats.Retransmissions++
	return true
}

func (c *Container) updateDelaysLocked() []uint32 {
	var deadPids []uint32
	for pid := range c.processes {
		stats, err := TaskstatsTGID(pid)
		if err != nil {
			deadPids = append(deadPids, pid)
			continue
		}
		d := c.delaysByPid[pid]
		c.delays.cpu += stats.CPUDelay - d.cpu
		c.delays.disk += stats.BlockIODelay - d.disk
		d.cpu = stats.CPUDelay
		d.disk = stats.BlockIODelay
		c.delaysByPid[pid] = d
	}
	return deadPids
}

func (c *Container) updateJvmProfilingStats(u *ProfilingUpdate) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.jvmProfilingStats == nil {
		c.jvmProfilingStats = &JvmProfilingStats{}
	}
	c.jvmProfilingStats.AllocBytes += u.AllocBytes
	c.jvmProfilingStats.AllocObjects += u.AllocObjects
	c.jvmProfilingStats.LockContentions += u.LockContentions
	c.jvmProfilingStats.LockTimeNs += u.LockTimeNs
}

func (c *Container) updateGoProfilingStats(u *ProfilingUpdate) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.goProfilingStats == nil {
		c.goProfilingStats = &GoProfilingStats{}
	}
	c.goProfilingStats.AllocBytes += u.AllocBytes
	c.goProfilingStats.AllocObjects += u.AllocObjects
}

func (c *Container) updateNodejsStats(s NodejsStatsUpdate) {
	c.lock.Lock()
	defer c.lock.Unlock()

	p := c.processes[s.Pid]
	if p == nil || p.nodejsPrevStats == nil {
		return
	}
	if delta := s.Stats.EventLoopBlockedTime - p.nodejsPrevStats.EventLoopBlockedTime; delta > 0 {
		if c.nodejsStats == nil {
			c.nodejsStats = &ebpftracer.NodejsStats{}
		}
		c.nodejsStats.EventLoopBlockedTime += delta
	}
	p.nodejsPrevStats = &s.Stats
}

func (c *Container) updatePythonStats(s PythonStatsUpdate) {
	c.lock.Lock()
	defer c.lock.Unlock()

	p := c.processes[s.Pid]
	if p == nil || p.pythonPrevStats == nil {
		return
	}
	if delta := s.Stats.ThreadLockWaitTime - p.pythonPrevStats.ThreadLockWaitTime; delta > 0 {
		if c.pythonStats == nil {
			c.pythonStats = &ebpftracer.PythonStats{}
		}
		c.pythonStats.ThreadLockWaitTime += delta
	}
	p.pythonPrevStats = &s.Stats
}

func (c *Container) getMounts() map[string]map[string]*proc.FSStat {
	if len(c.mounts) == 0 {
		return nil
	}
	var current map[string]proc.MountInfo
	for pid := range c.processes {
		if current = proc.GetMountInfo(pid); current != nil {
			break
		}
	}
	if len(current) > 0 {
		for mntId := range c.mounts {
			if mi, ok := current[mntId]; ok {
				c.mounts[mntId] = mi
			} else {
				delete(c.mounts, mntId)
			}
		}
	}
	res := map[string]map[string]*proc.FSStat{}
	for _, mi := range c.mounts {
		var stat *proc.FSStat
		for pid := range c.processes {
			s, err := proc.StatFS(proc.Path(pid, "root", mi.MountPoint))
			if err == nil {
				stat = &s
				break
			}
		}
		if stat == nil {
			continue
		}
		if _, ok := res[mi.MajorMinor]; !ok {
			res[mi.MajorMinor] = map[string]*proc.FSStat{}
		}
		res[mi.MajorMinor][mi.MountPoint] = stat
	}
	return res
}

func (c *Container) getListens() map[netaddr.IPPort]int {
	res := map[netaddr.IPPort]int{}
	for addr, byPid := range c.listens {
		open := 0
		isHostNs := false
		ips := map[netaddr.IP]bool{}
		for pid, details := range byPid {
			p := c.processes[pid]
			if p == nil {
				continue
			}
			if p.isHostNs() {
				isHostNs = true
			}
			if details.ClosedAt.IsZero() {
				open = 1
			}
			for _, ip := range details.NsIPs {
				ips[ip] = true
			}
		}
		if !addr.IP().IsUnspecified() {
			ips = map[netaddr.IP]bool{addr.IP(): true}
		}
		for ip := range ips {
			if ip.IsLoopback() && !isHostNs {
				continue
			}
			res[netaddr.IPPortFrom(ip, addr.Port())] = open
		}
	}
	return res
}

func (c *Container) getProxiedListens() map[string]map[netaddr.IPPort]struct{} {
	if len(c.metadata.hostListens) == 0 {
		return nil
	}

	hasUnspecified := false
	for _, addrs := range c.metadata.hostListens {
		for _, addr := range addrs {
			if addr.IP().IsUnspecified() {
				hasUnspecified = true
				break
			}
		}
	}

	var hostIps []netaddr.IP
	if hasUnspecified {
		if ns, err := proc.GetHostNetNs(); err != nil {
			klog.Warningln(err)
		} else {
			ips, err := proc.GetNsIps(ns)
			_ = ns.Close()
			if err != nil {
				klog.Warningln(err)
			} else {
				hostIps = ips
			}
		}
	}

	res := map[string]map[netaddr.IPPort]struct{}{}
	for proxy, addrs := range c.metadata.hostListens {
		res[proxy] = map[netaddr.IPPort]struct{}{}
		for _, addr := range addrs {
			if addr.IP().IsUnspecified() {
				for _, ip := range hostIps {
					if addr.IP().Is4() && ip.Is4() || addr.IP().Is6() && ip.Is6() {
						res[proxy][netaddr.IPPortFrom(ip, addr.Port())] = struct{}{}
					}
				}
			} else {
				res[proxy][addr] = struct{}{}
			}
		}
	}
	return res
}

func (c *Container) ping() map[netaddr.IP]float64 {
	netNs := netns.None()
	for pid := range c.processes {
		if pid == agentPid {
			netNs = selfNetNs
			break
		}
		ns, err := proc.GetNetNs(pid)
		if err != nil {
			if !common.IsNotExist(err) {
				klog.Warningln(err)
			}
			continue
		}
		netNs = ns
		defer netNs.Close()
		break
	}
	if !netNs.IsOpen() {
		return nil
	}

	ips := map[netaddr.IP]struct{}{}
	for d := range c.connectionStats {
		if ip := d.ActualDestination().IP(); !ip.IsZero() {
			ips[ip] = struct{}{}
		}
	}
	for dst := range c.failedConnectionAttempts {
		if ip := dst.IP(); !ip.IsZero() {
			ips[dst.IP()] = struct{}{}
		}
	}
	if len(ips) == 0 {
		return nil
	}
	targets := make([]netaddr.IP, 0, len(ips))
	for ip := range ips {
		if ip.IsLoopback() {
			continue
		}
		if !ip.Is4() { // pinger doesn't support IPv6 yet
			continue
		}
		targets = append(targets, ip)
	}
	rtt, err := pinger.Ping(netNs, selfNetNs, targets, pingTimeout)
	if err != nil {
		klog.Warningln(err)
		return nil
	}
	return rtt
}

func (c *Container) runLogParser(logPath string) {
	if *flags.DisableLogParsing {
		return
	}

	for _, p := range c.processes {
		if p.Flags.LogMonitoringDisabled {
			klog.InfoS("skipping log monitoring due to COROOT_LOG_MONITORING=disabled", "cg", c.cgroup.Id)
			return
		}
	}

	containerId := string(c.id)

	if logPath != "" {
		if c.logParsers[logPath] != nil {
			return
		}
		ch := make(chan logparser.LogEntry)
		parser := logparser.NewParser(ch, nil, logs.OtelLogEmitter(containerId), logs.MultilineCollectorTimeout, *flags.LogPatternsPerContainer, !*flags.DisableJsonLogParsing, logs.PatternExtractionRateLimiter())
		reader, err := logs.NewTailReader(proc.HostPath(logPath), ch)
		if err != nil {
			klog.Warningln(err)
			parser.Stop()
			return
		}
		klog.InfoS("started varlog logparser", "cg", c.cgroup.Id, "log", logPath)
		c.logParsers[logPath] = logs.NewPipeline(parser, reader.Stop)
		return
	}

	switch c.cgroup.ContainerType {
	case cgroup.ContainerTypeSystemdService:
		ch := make(chan logparser.LogEntry)
		if err := JournaldSubscribe(c.metadata.systemd.Unit, ch); err != nil {
			klog.Warningln(err)
			return
		}
		parser := logparser.NewParser(ch, nil, logs.OtelLogEmitter(containerId), logs.MultilineCollectorTimeout, *flags.LogPatternsPerContainer, !*flags.DisableJsonLogParsing, logs.PatternExtractionRateLimiter())
		stop := func() {
			JournaldUnsubscribe(c.metadata.systemd.Unit)
		}
		klog.InfoS("started journald logparser", "cg", c.cgroup.Id)
		c.logParsers["journald"] = logs.NewPipeline(parser, stop)

	case cgroup.ContainerTypeDocker, cgroup.ContainerTypeContainerd, cgroup.ContainerTypeCrio:
		if c.metadata.logPath == "" {
			return
		}
		if parser := c.logParsers["stdout/stderr"]; parser != nil {
			parser.Stop()
			delete(c.logParsers, "stdout/stderr")
		}
		ch := make(chan logparser.LogEntry)
		parser := logparser.NewParser(ch, c.metadata.logDecoder, logs.OtelLogEmitter(containerId), logs.MultilineCollectorTimeout, *flags.LogPatternsPerContainer, !*flags.DisableJsonLogParsing, logs.PatternExtractionRateLimiter())
		reader, err := logs.NewTailReader(proc.HostPath(c.metadata.logPath), ch)
		if err != nil {
			klog.Warningln(err)
			parser.Stop()
			return
		}
		klog.InfoS("started container logparser", "cg", c.cgroup.Id)
		c.logParsers["stdout/stderr"] = logs.NewPipeline(parser, reader.Stop)
	}
}

func (c *Container) gc(now time.Time) {
	c.lock.Lock()
	defer c.lock.Unlock()

	established := map[ConnectionKey]struct{}{}
	listens := map[netaddr.IPPort]string{}
	seenNamespaces := map[string]bool{}
	for _, p := range c.processes {
		if len(p.inboundHttp1Parsers) > 0 || len(p.inboundHttp2Parsers) > 0 {
			fds, err := proc.ReadFds(p.Pid)
			if err == nil {
				openFds := map[uint64]struct{}{}
				for _, fd := range fds {
					if fd.SocketInode != "" {
						openFds[fd.Fd] = struct{}{}
					}
				}
				for fd := range p.inboundHttp1Parsers {
					if _, ok := openFds[fd]; !ok {
						delete(p.inboundHttp1Parsers, fd)
					}
				}
				for fd := range p.inboundHttp2Parsers {
					if _, ok := openFds[fd]; !ok {
						delete(p.inboundHttp2Parsers, fd)
					}
				}
			}
		}
		if seenNamespaces[p.NetNsId()] {
			continue
		}
		sockets, err := proc.GetSockets(p.Pid)
		if err != nil {
			continue
		}
		for _, s := range sockets {
			if s.Listen {
				listens[s.SAddr] = s.Inode
			} else {
				established[ConnectionKey{src: s.SAddr, dst: s.DAddr}] = struct{}{}
			}
		}
		seenNamespaces[p.NetNsId()] = true
	}

	c.revalidateListens(now, listens)

	establishedDst := map[common.HostPort]struct{}{}
	for k, conn := range c.activeConnections {
		pidFd := PidFd{Pid: conn.Pid, Fd: conn.Fd}
		if _, ok := established[k]; !ok {
			delete(c.activeConnections, k)
			if conn == c.connectionsByPidFd[pidFd] {
				delete(c.connectionsByPidFd, pidFd)
			}
			if conn.Timestamp != 0 {
				delete(c.connectionsByPidFdTs, PidFdTs{Pid: conn.Pid, Fd: conn.Fd, Timestamp: conn.Timestamp})
			}
			continue
		} else {
			establishedDst[conn.DestinationKey.Destination()] = struct{}{}
		}
		if !conn.Closed.IsZero() && now.Sub(conn.Closed) > gcInterval {
			delete(c.activeConnections, k)
			if conn == c.connectionsByPidFd[pidFd] {
				delete(c.connectionsByPidFd, pidFd)
			}
			if conn.Timestamp != 0 {
				delete(c.connectionsByPidFdTs, PidFdTs{Pid: conn.Pid, Fd: conn.Fd, Timestamp: conn.Timestamp})
			}
		}
	}
	for k, st := range c.pendingHttp2Parsers {
		if now.Sub(st.updatedAt) > gcInterval {
			delete(c.pendingHttp2Parsers, k)
		}
	}
	for k, st := range c.pendingHttp1Parsers {
		if now.Sub(st.updatedAt) > gcInterval {
			delete(c.pendingHttp1Parsers, k)
		}
	}
	for dst, at := range c.lastConnectionAttempts {
		_, active := establishedDst[dst]
		if !active && !at.IsZero() && now.Sub(at) > gcInterval {
			delete(c.lastConnectionAttempts, dst)
			delete(c.failedConnectionAttempts, dst)
			for d := range c.connectionStats {
				if d.Destination() == dst {
					delete(c.connectionStats, d)
				}
			}
			c.l7Stats.delete(dst)
		}
	}
}

func (c *Container) revalidateListens(now time.Time, actualListens map[netaddr.IPPort]string) {
	for addr, byPid := range c.listens {
		if _, open := actualListens[addr]; open {
			continue
		}
		klog.Warningln("deleting the outdated listen:", addr)
		for _, details := range byPid {
			if details.ClosedAt.IsZero() {
				details.ClosedAt = now
			}
		}
	}

	missingListens := map[netaddr.IPPort]string{}
	for addr, inode := range actualListens {
		byPids, found := c.listens[addr]
		if !found {
			missingListens[addr] = inode
			continue
		}
		open := false
		for _, details := range byPids {
			if details.ClosedAt.IsZero() {
				open = true
				break
			}
		}
		if !open {
			missingListens[addr] = inode
		}
	}

	if len(missingListens) > 0 {
		inodeToPid := map[string]uint32{}
		for pid := range c.processes {
			fds, err := proc.ReadFds(pid)
			if err != nil {
				klog.Warningln(err)
				continue
			}
			for _, fd := range fds {
				if fd.SocketInode != "" {
					inodeToPid[fd.SocketInode] = pid
				}
			}
		}
		for addr, inode := range missingListens {
			pid, found := inodeToPid[inode]
			if !found {
				continue
			}
			klog.Warningln("missing listen found:", addr, pid)
			c.onListenOpen(pid, addr, true)
		}
	}

	for addr, pids := range c.listens {
		for pid, details := range pids {
			if !details.ClosedAt.IsZero() && now.Sub(details.ClosedAt) > gcInterval {
				delete(c.listens[addr], pid)
			}
		}
		if len(c.listens[addr]) == 0 {
			delete(c.listens, addr)
		}
	}
}

func (c *Container) attachTlsUprobes(tracer *ebpftracer.Tracer, pid uint32, canBePostponed bool) bool {
	p := c.processes[pid]
	if p == nil {
		return true
	}
	if canBePostponed {
		if delay := *flags.InstrumentationDelay; delay > 0 && !p.StartedAt.IsZero() && time.Since(p.StartedAt) < delay {
			return false
		}
	}
	if !p.openSslUprobesChecked {
		if key := tracer.AttachOpenSslUprobes(pid); key != nil {
			p.addUprobeKey(*key)
		}
		p.openSslUprobesChecked = true
	}
	if !p.goTlsUprobesChecked {
		key, isGolangApp := tracer.AttachGoTlsUprobes(pid)
		p.isGolangApp = isGolangApp
		if key != nil {
			p.addUprobeKey(*key)
		}
		p.goTlsUprobesChecked = true
	}
	if !p.rustlsUprobesChecked {
		key, isRustApp := tracer.AttachRustlsUprobes(pid)
		p.isRustApp = isRustApp
		if key != nil {
			p.addUprobeKey(*key)
		}
		p.rustlsUprobesChecked = true
	}
	if !p.javaTlsUprobesChecked {
		p.javaTlsUprobesChecked = true
		if jvm.IsJavaProcess(pid) {
			if !*flags.EnableJavaTls {
				klog.Infof("pid=%d: Java process detected, but Java TLS instrumentation is disabled (use --enable-java-tls to enable)", pid)
			} else if nativeLibPath := jvm.EnsureTlsAgentLoaded(pid); nativeLibPath != "" {
				if key := tracer.AttachJavaTlsUprobes(pid, nativeLibPath); key != nil {
					p.addUprobeKey(*key)
				}
			}
		}
	}
	return true
}

func resolveFd(pid uint32, fd uint64) (mntId string, logPath string) {
	info := proc.GetFdInfo(pid, fd)
	if info == nil {
		return
	}
	switch {
	case info.Flags&os.O_WRONLY == 0 && info.Flags&os.O_RDWR == 0,
		!strings.HasPrefix(info.Dest, "/"),
		strings.HasPrefix(info.Dest, "/proc/"),
		strings.HasPrefix(info.Dest, "/dev/"),
		strings.HasPrefix(info.Dest, "/sys/"),
		strings.HasSuffix(info.Dest, "(deleted)"):
		return
	}
	mntId = info.MntId

	if info.Flags&os.O_WRONLY != 0 && strings.HasPrefix(info.Dest, "/var/log/") &&
		!strings.HasPrefix(info.Dest, "/var/log/pods/") &&
		!strings.HasPrefix(info.Dest, "/var/log/containers/") &&
		!strings.HasPrefix(info.Dest, "/var/log/journal/") {

		logPath = info.Dest
	}
	return
}
