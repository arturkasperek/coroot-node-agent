package containers

import (
	"net/netip"
	"os"
	"path/filepath"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/coroot/coroot-node-agent/proc"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

var (
	ciliumCt4    *bpf.Map
	ciliumCt6    *bpf.Map
	backends4Map *bpf.Map
	backends6Map *bpf.Map
)

// openCiliumBackendMap opens a v3 backend map. A Cilium old enough to create only
// the v2 map is not supported: connections to its services keep the service
// address as their destination.
func openCiliumBackendMap(v3Name, v2Name string, key bpf.MapKey, value bpf.MapValue) *bpf.Map {
	path := proc.HostPath(filepath.Join(defaults.BPFFSRoot, defaults.TCGlobalsPath, v3Name))
	backendMap, err := bpf.OpenMap(path, key, value)
	if err == nil {
		klog.Infoln("found cilium ebpf-map:", v3Name)
		return backendMap
	}
	v2Path := proc.HostPath(filepath.Join(defaults.BPFFSRoot, defaults.TCGlobalsPath, v2Name))
	if _, statErr := os.Stat(v2Path); statErr == nil {
		klog.Warningf("found cilium ebpf-map %s but not %s: this Cilium version is not supported, service connections will not be resolved to their backends", v2Name, v3Name)
		return nil
	}
	klog.Infoln(err)
	return nil
}

// ciliumBackendAddress returns the address of a backend read from a backend map.
func ciliumBackendAddress(value bpf.MapValue) (netaddr.IPPort, bool) {
	var address netip.Addr
	var networkPort uint16
	switch backend := value.(type) {
	case *maps.Backend4ValueV3:
		address, networkPort = backend.Address.Addr(), backend.Port
	case *maps.Backend6ValueV3:
		address, networkPort = backend.Address.Addr(), backend.Port
	default:
		return netaddr.IPPort{}, false
	}
	var ip netaddr.IP
	if address.Is4() {
		ip = netaddr.IPFrom4(address.As4())
	} else {
		ip = netaddr.IPv6Raw(address.As16())
	}
	return netaddr.IPPortFrom(ip, byteorder.NetworkToHost16(networkPort)), true
}

func init() {
	var err error

	ciliumCt4, err = bpf.OpenMap(
		proc.HostPath(filepath.Join(defaults.BPFFSRoot, defaults.TCGlobalsPath, ctmap.MapNameTCP4Global)),
		&ctmap.CtKey4Global{},
		&ctmap.CtEntry{},
	)
	if err != nil {
		klog.Infoln(err)
	} else {
		klog.Infoln("found cilium ebpf-map:", ctmap.MapNameTCP4Global)
	}
	ciliumCt6, err = bpf.OpenMap(proc.HostPath(
		filepath.Join(defaults.BPFFSRoot, defaults.TCGlobalsPath, ctmap.MapNameTCP6Global)),
		&ctmap.CtKey6Global{},
		&ctmap.CtEntry{},
	)
	if err != nil {
		klog.Infoln(err)
	} else {
		klog.Infoln("found cilium ebpf-map:", ctmap.MapNameTCP6Global)
	}
	backends4Map = openCiliumBackendMap(maps.Backend4MapV3Name, maps.Backend4MapV2Name, &maps.Backend4KeyV3{}, &maps.Backend4ValueV3{})
	backends6Map = openCiliumBackendMap(maps.Backend6MapV3Name, maps.Backend6MapV2Name, &maps.Backend6KeyV3{}, &maps.Backend6ValueV3{})
}

func lookupCiliumConntrackTable(src, dst netaddr.IPPort) *netaddr.IPPort {
	if src.IP().Is4() {
		return lookupCilium4(src, dst)
	}
	if src.IP().Is6() {
		return lookupCilium6(src, dst)
	}
	return nil
}

func lookupCilium4(src, dst netaddr.IPPort) *netaddr.IPPort {
	if ciliumCt4 == nil || backends4Map == nil {
		return nil
	}
	key := &ctmap.CtKey4Global{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourcePort: dst.Port(),
				SourceAddr: src.IP().As4(),
				DestPort:   src.Port(),
				DestAddr:   dst.IP().As4(),
				NextHeader: u8proto.TCP,
				Flags:      ctmap.TUPLE_F_SERVICE,
			},
		},
	}
	v, err := ciliumCt4.Lookup(key.ToNetwork())
	if err != nil || v == nil {
		return nil
	}
	entry := v.(*ctmap.CtEntry)
	// A service entry keeps the backend ID in the second half of the union
	// (struct ct_entry in bpf/lib/conntrack.h).
	backendKey := maps.NewBackend4KeyV3(loadbalancer.BackendID(entry.Union0[1]))
	backend, err := backends4Map.Lookup(backendKey)
	if err != nil || backend == nil {
		return nil
	}
	address, found := ciliumBackendAddress(backend)
	if !found {
		return nil
	}
	return &address
}

func lookupCilium6(src, dst netaddr.IPPort) *netaddr.IPPort {
	if ciliumCt6 == nil || backends6Map == nil {
		return nil
	}
	key := &ctmap.CtKey6Global{
		TupleKey6Global: tuple.TupleKey6Global{
			TupleKey6: tuple.TupleKey6{
				SourcePort: dst.Port(),
				SourceAddr: src.IP().As16(),
				DestPort:   src.Port(),
				DestAddr:   dst.IP().As16(),
				NextHeader: u8proto.TCP,
				Flags:      ctmap.TUPLE_F_SERVICE,
			},
		},
	}
	v, err := ciliumCt6.Lookup(key.ToNetwork())
	if err != nil || v == nil {
		return nil
	}
	entry := v.(*ctmap.CtEntry)
	// A service entry keeps the backend ID in the second half of the union
	// (struct ct_entry in bpf/lib/conntrack.h).
	backendKey := maps.NewBackend6KeyV3(loadbalancer.BackendID(entry.Union0[1]))
	backend, err := backends6Map.Lookup(backendKey)
	if err != nil || backend == nil {
		return nil
	}
	address, found := ciliumBackendAddress(backend)
	if !found {
		return nil
	}
	return &address
}
