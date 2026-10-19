package containers

import (
	"testing"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/stretchr/testify/require"
	"inet.af/netaddr"
)

// The client of a request (that connected to a Service's ClusterIP, which
// conntrack turned into the pod) and its server (that accepted the connection
// on the pod's IP) name the request the same.
func TestClientAndServerNameARequestAlike(t *testing.T) {
	client := netaddr.MustParseIPPort("10.42.0.150:51234")
	clusterIP := netaddr.MustParseIPPort("10.43.12.7:80")
	pod := netaddr.MustParseIPPort("10.42.0.140:3000")
	req := l7.Http1Request{Method: "GET", Path: "/products/42"}

	outbound := &ActiveConnection{key: ConnectionKey{src: client, dst: clusterIP}, DestinationKey: common.NewDestinationKey(clusterIP, pod, nil)}
	inbound := &inboundConnection{server: pod, client: client, seenOpen: true}
	for number := uint64(1); number <= 3; number++ {
		outbound.http1Requests = number
		key := outboundRequestKey(outbound, req)
		require.NotZero(t, key)
		require.Equal(t, key, inboundRequestKey(inbound, number, req), "request %d", number)
		require.NotEqual(t, key, inboundRequestKey(inbound, number+1, req), "the next request on the connection")
	}

	outbound.Preexisting = true
	require.Zero(t, outboundRequestKey(outbound, req), "a connection open before the agent: its requests cannot be numbered")
	inbound.seenOpen = false
	require.Zero(t, inboundRequestKey(inbound, 1, req))
	require.Zero(t, inboundRequestKey(nil, 1, req), "an accepted connection the agent did not see open")
}

// An HTTP/2 request is named by its stream, which both ends know however long
// the connection was open before the agent started.
func TestClientAndServerNameAnHttp2RequestAlike(t *testing.T) {
	client := netaddr.MustParseIPPort("10.42.0.150:51234")
	clusterIP := netaddr.MustParseIPPort("10.43.12.7:80")
	pod := netaddr.MustParseIPPort("10.42.0.140:3000")
	req := l7.Http2Request{Method: "POST", Path: "/pkg.Service/Method"}

	outbound := &ActiveConnection{key: ConnectionKey{src: client, dst: clusterIP}, DestinationKey: common.NewDestinationKey(clusterIP, pod, nil), Preexisting: true}
	inbound := &inboundConnection{server: pod, client: client}
	key := outboundHttp2RequestKey(outbound, req)
	require.NotZero(t, key)
	require.Equal(t, key, inboundHttp2RequestKey(inbound, req))
	require.Zero(t, inboundHttp2RequestKey(nil, req), "an accepted connection whose ends are not known")
}
