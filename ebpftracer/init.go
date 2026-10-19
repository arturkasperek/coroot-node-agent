package ebpftracer

import (
	"fmt"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/florianl/go-conntrack"
	"github.com/vishvananda/netns"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

const (
	IPProtoTCP uint8 = 6
)

type sock struct {
	pid uint32
	fd  uint64
	proc.Sock
	actualDest netaddr.IPPort
}

type connId struct {
	src netaddr.IPPort
	dst netaddr.IPPort
}

func ipTupleValid(t *conntrack.IPTuple) bool {
	if t == nil {
		return false
	}
	if t.Src == nil || t.Dst == nil || t.Proto == nil {
		return false
	}
	if t.Proto.SrcPort == nil || t.Proto.DstPort == nil {
		return false
	}
	return true
}

func getConntrack(netNs netns.NsHandle) (map[connId]netaddr.IPPort, error) {
	c, err := conntrack.Open(&conntrack.Config{NetNS: int(netNs)})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	conns4, err := c.Dump(conntrack.Conntrack, conntrack.IPv4)
	if err != nil {
		return nil, err
	}
	conns6, err := c.Dump(conntrack.Conntrack, conntrack.IPv6)
	if err != nil {
		return nil, err
	}
	res := map[connId]netaddr.IPPort{}
	for _, conn := range append(conns4, conns6...) {
		if !ipTupleValid(conn.Origin) || !ipTupleValid(conn.Reply) {
			continue
		}
		if *conn.Origin.Proto.Number != IPProtoTCP {
			continue
		}
		id := connId{}
		if ip, ok := netaddr.FromStdIP(*conn.Origin.Src); ok {
			id.src = netaddr.IPPortFrom(ip, *conn.Origin.Proto.SrcPort)
		}
		if ip, ok := netaddr.FromStdIP(*conn.Origin.Dst); ok {
			id.dst = netaddr.IPPortFrom(ip, *conn.Origin.Proto.DstPort)
		}
		if ip, ok := netaddr.FromStdIP(*conn.Reply.Src); ok {
			if ip == id.dst.IP() {
				continue
			}
			res[id] = netaddr.IPPortFrom(ip, *conn.Reply.Proto.SrcPort)
		}
	}
	return res, err
}

func (t *Tracer) init(ch chan<- Event) error {
	pids, err := proc.ListPids()
	if err != nil {
		return fmt.Errorf("failed to list pids: %w", err)
	}
	for _, pid := range pids {
		ch <- Event{Type: EventTypeProcessStart, Pid: pid}
	}
	hostNsId := t.hostNetNs.UniqueId()
	hostConntrack, err := getConntrack(t.hostNetNs)
	if err != nil {
		return err
	}
	nss := map[string]map[string]sock{}
	var socks []sock

	for _, pid := range pids {
		ns, err := proc.GetNetNs(pid)
		if err != nil {
			klog.Warningf("failed to get net ns for %d: %s", pid, err)
			continue
		}
		nsId := ns.UniqueId()
		sockets, ok := nss[nsId]
		if !ok {
			var nsConntrack map[connId]netaddr.IPPort
			if nsId != hostNsId {
				if nsConntrack, err = getConntrack(ns); err != nil {
					klog.Warningf("failed to dump conntrack for ns %d: %s", pid, err)
				}
			}
			if ss, err := proc.GetSockets(pid); err != nil {
				klog.Warningf("failed to get sockets for %d: %s", pid, err)
			} else {
				sockets = map[string]sock{}
				nss[nsId] = sockets
				for _, s := range ss {
					id := connId{src: s.SAddr, dst: s.DAddr}
					actualDest, ok := hostConntrack[id]
					if !ok && nsConntrack != nil {
						actualDest, ok = nsConntrack[id]
					}
					sockets[s.Inode] = sock{Sock: s, actualDest: actualDest}
				}
			}
		}
		_ = ns.Close()

		fds, err := proc.ReadFds(pid)
		if err != nil {
			klog.Warningf("failed to read fds for %d: %s", pid, err)
			continue
		}
		for _, fd := range fds {
			switch {
			case fd.SocketInode != "":
				if s, ok := sockets[fd.SocketInode]; ok {
					s.fd = fd.Fd
					s.pid = pid
					socks = append(socks, s)
				}
			case strings.HasPrefix(fd.Dest, "/"):
				ch <- Event{Type: EventTypeFileOpen, Pid: pid, Fd: fd.Fd, Log: strings.HasPrefix(fd.Dest, "/var/log/")}
			}
		}
	}

	events, entries := preexistingConnections(socks, uint64(time.Now().UnixNano()))
	for _, event := range events {
		ch <- event
	}
	ebpfConnectionsMap := t.collection.Maps["active_connections"]
	for _, entry := range entries {
		if err := ebpfConnectionsMap.Update(entry.id, entry.conn, ebpf.UpdateNoExist); err != nil {
			klog.Warningln(err)
		}
	}
	return nil
}

type activeConnectionEntry struct {
	id   ConnectionId
	conn Connection
}

// preexistingConnections turns the sockets that were open before the tracer
// started into the events it reports (listens and connections, marked
// Preexisting; for an inbound one the source is the local end, as for an
// accepted connection) and the entries it adds to active_connections (every
// connection). Each connection gets
// a timestamp of its own, now plus its index: the timestamp is the identity of a
// connection, and the eBPF side keys its per-connection protocol state by it, so
// connections sharing one would share that state.
func preexistingConnections(socks []sock, now uint64) ([]Event, []activeConnectionEntry) {
	listens := map[uint64]bool{}
	for _, s := range socks {
		if s.Listen {
			listens[uint64(s.pid)<<32|uint64(s.SAddr.Port())] = true
		}
	}
	var events []Event
	var entries []activeConnectionEntry
	for index, s := range socks {
		timestamp := now + uint64(index)
		typ := EventTypeConnectionOpen
		inbound := false
		if s.Listen {
			typ = EventTypeListenOpen
		} else if listens[uint64(s.pid)<<32|uint64(s.SAddr.Port())] || s.DAddr.Port() > s.SAddr.Port() {
			inbound = true
		}
		events = append(events, Event{
			Type:          typ,
			Pid:           s.pid,
			Timestamp:     timestamp,
			Fd:            s.fd,
			SrcAddr:       s.SAddr,
			DstAddr:       s.DAddr,
			ActualDstAddr: s.actualDest,
			IsInbound:     inbound,
			Preexisting:   typ == EventTypeConnectionOpen,
		})
		if typ == EventTypeConnectionOpen {
			conn := Connection{Timestamp: timestamp}
			if inbound {
				conn.IsInbound = 1
			}
			entries = append(entries, activeConnectionEntry{id: ConnectionId{FD: s.fd, PID: s.pid}, conn: conn})
		}
	}
	return events, entries
}
