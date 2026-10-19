package ebpftracer

import (
	"inet.af/netaddr"
)

// SetTracedClients makes the traced_clients map hold these IPs: the clients
// whose requests a node agent records at the client, so that their servers
// skip the bodies of their requests (connection.skip_bodies, decided at
// accept). Only the IPs that changed are written.
func (t *Tracer) SetTracedClients(ips map[netaddr.IP]bool) error {
	if t.collection == nil || t.disableL7Tracing {
		return nil
	}
	clients := t.collection.Maps["traced_clients"]
	if clients == nil {
		return nil
	}
	t.tracedClientsLock.Lock()
	defer t.tracedClientsLock.Unlock()
	if t.tracedClients == nil {
		t.tracedClients = map[[16]byte]bool{}
	}
	wanted := map[[16]byte]bool{}
	for ip := range ips {
		wanted[ip.Unmap().As16()] = true
	}
	var one uint8 = 1
	for key := range wanted {
		if t.tracedClients[key] {
			continue
		}
		if err := clients.Put(key, one); err != nil {
			return err
		}
		t.tracedClients[key] = true
	}
	for key := range t.tracedClients {
		if wanted[key] {
			continue
		}
		if err := clients.Delete(key); err != nil {
			return err
		}
		delete(t.tracedClients, key)
	}
	return nil
}
