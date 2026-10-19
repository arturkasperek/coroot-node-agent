package containers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/coroot/coroot-node-agent/api"
	"github.com/coroot/coroot-node-agent/flags"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

const (
	// tracedClientsInterval is how often the agent asks Coroot for the clients
	// whose requests a node agent records at the client.
	tracedClientsInterval = 30 * time.Second
	// localTracedClientsInterval is how often it adds the local ones: the
	// clients of the containers of its node, which it knows at once.
	localTracedClientsInterval = 5 * time.Second
)

// tracedClientsResponse is what Coroot answers at /v1/traced-clients: the IPs
// of the pods on nodes with a node agent; not ready while Coroot does not know
// the world of the project yet.
type tracedClientsResponse struct {
	Ready   bool     `json:"ready"`
	Clients []string `json:"clients"`
}

// fetchTracedClients asks Coroot for the traced clients; nil when it does not
// know them (no endpoint, not ready, an error): the server then captures every
// body but those of the local clients.
func fetchTracedClients(client *http.Client, endpoint *url.URL) []netaddr.IP {
	request, err := http.NewRequest(http.MethodGet, endpoint.String(), nil)
	if err != nil {
		klog.Warningln(err)
		return nil
	}
	for name, value := range api.AuthHeaders(*flags.ApiKey) {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		klog.Warningln("traced clients:", err)
		return nil
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		// an older Coroot: only the local clients are known, nothing to warn of
		klog.V(2).Infoln("traced clients:", response.Status)
		return nil
	}
	if response.StatusCode != http.StatusOK {
		klog.Warningln("traced clients:", response.Status)
		return nil
	}
	var res tracedClientsResponse
	if err = json.NewDecoder(response.Body).Decode(&res); err != nil {
		klog.Warningln("traced clients:", err)
		return nil
	}
	if !res.Ready {
		return nil
	}
	ips := make([]netaddr.IP, 0, len(res.Clients))
	for _, value := range res.Clients {
		if ip, err := netaddr.ParseIP(value); err == nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

// runTracedClientsFetcher sends the traced clients Coroot knows to updates
// every tracedClientsInterval, nil when it does not know them.
func runTracedClientsFetcher(updates chan<- []netaddr.IP) {
	endpoint := *flags.CollectorEndpoint
	if endpoint == nil {
		return
	}
	tracedClientsEndpoint := endpoint.JoinPath("/v1/traced-clients")
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: api.TlsConfig(*flags.CAFile, *flags.InsecureSkipVerify)},
	}
	for {
		updates <- fetchTracedClients(client, tracedClientsEndpoint)
		time.Sleep(tracedClientsInterval)
	}
}

// localTracedClients are the IPs the outbound connections of the container's
// processes come from: the agent records the client side of their requests
// itself. A process in the host's network namespace is left out: a node IP is
// also where requests from outside arrive from once SNATed.
func (c *Container) localTracedClients(ips map[netaddr.IP]bool) {
	c.lock.Lock()
	defer c.lock.Unlock()
	for key, conn := range c.activeConnections {
		if !conn.Closed.IsZero() {
			continue
		}
		p := c.processes[conn.Pid]
		if p == nil || p.isHostNs() {
			continue
		}
		if ip := key.src.IP(); !ip.IsZero() && !ip.IsLoopback() {
			ips[ip] = true
		}
	}
}

// updateTracedClients sets the traced clients of the tracer: those Coroot
// sent last (r.remoteTracedClients) and the local ones.
func (r *Registry) updateTracedClients() {
	ips := map[netaddr.IP]bool{}
	for _, ip := range r.remoteTracedClients {
		ips[ip] = true
	}
	for _, c := range r.containersById {
		c.localTracedClients(ips)
	}
	if err := r.tracer.SetTracedClients(ips); err != nil {
		klog.Warningln(fmt.Errorf("traced clients: %w", err))
		return
	}
	r.tracedClients.Store(int64(len(ips)))
}
