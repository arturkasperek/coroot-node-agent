package containers

import (
	"testing"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Cilium keeps the backend port in network byte order.
func TestCiliumBackendAddressReadsBackendMapValues(t *testing.T) {
	networkPort := byteorder.HostToNetwork16(8080)
	for _, testCase := range []struct {
		name     string
		value    bpf.MapValue
		expected string
	}{
		{"ipv4", &maps.Backend4ValueV3{Address: types.IPv4{10, 0, 0, 1}, Port: networkPort}, "10.0.0.1:8080"},
		{"ipv6", &maps.Backend6ValueV3{Address: types.IPv6{0xfd, 0x00, 15: 0x01}, Port: networkPort}, "[fd00::1]:8080"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			address, found := ciliumBackendAddress(testCase.value)
			require.True(t, found)
			assert.Equal(t, testCase.expected, address.String())
		})
	}
}

func TestCiliumBackendAddressRejectsAnUnknownValue(t *testing.T) {
	_, found := ciliumBackendAddress(&maps.Service4Value{})
	assert.False(t, found)
}
