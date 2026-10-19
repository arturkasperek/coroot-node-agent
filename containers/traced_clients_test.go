package containers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"inet.af/netaddr"
)

func TestFetchTracedClients(t *testing.T) {
	answer := ""
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/traced-clients", r.URL.Path)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	}))
	defer server.Close()
	endpoint, err := url.Parse(server.URL + "/v1/traced-clients")
	require.NoError(t, err)

	answer = `{"ready":true,"clients":["10.42.0.5","not an ip","fd00::7"]}`
	require.Equal(t, []netaddr.IP{netaddr.MustParseIP("10.42.0.5"), netaddr.MustParseIP("fd00::7")}, fetchTracedClients(server.Client(), endpoint))

	answer = `{"ready":false,"clients":null}`
	require.Nil(t, fetchTracedClients(server.Client(), endpoint), "Coroot does not know the world yet: no list")

	status = http.StatusNotFound
	require.Nil(t, fetchTracedClients(server.Client(), endpoint))
}

// The local clients are where the outbound connections of the container's
// processes come from, but not those of the host's network namespace (a node
// IP is also where SNATed requests from outside come from), nor loopback.
func TestLocalTracedClients(t *testing.T) {
	previous := hostNetNsId
	hostNetNsId = "net:[1]"
	defer func() { hostNetNsId = previous }()

	c := newConnectionsTestContainer()
	c.processes = map[uint32]*Process{
		10: {Pid: 10, netNsId: "net:[2]"},
		20: {Pid: 20, netNsId: "net:[1]"},
	}
	add := func(src string, pid uint32, closed bool) {
		k := ConnectionKey{src: netaddr.MustParseIPPort(src), dst: netaddr.MustParseIPPort("10.42.0.140:3000")}
		conn := &ActiveConnection{key: k, Pid: pid}
		if closed {
			conn.Closed = time.Now()
		}
		c.activeConnections[k] = conn
	}
	add("10.42.0.150:51234", 10, false)
	add("10.42.0.151:51235", 10, true)     // closed
	add("127.0.0.1:51236", 10, false)      // loopback
	add("192.168.100.76:51237", 20, false) // host network
	add("10.42.0.152:51238", 30, false)    // a process that is gone

	ips := map[netaddr.IP]bool{}
	c.localTracedClients(ips)
	require.Equal(t, map[netaddr.IP]bool{netaddr.MustParseIP("10.42.0.150"): true}, ips)
}
