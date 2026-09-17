package ebpftracer

import (
	"testing"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/stretchr/testify/require"
)

func TestEmbeddedProgramsTargetKernel618(t *testing.T) {
	min := common.NewVersion(6, 18, 0)
	require.Contains(t, ebpfProgs, "amd64")
	require.Contains(t, ebpfProgs, "arm64")
	for arch, progs := range ebpfProgs {
		require.NotEmpty(t, progs, arch)
		for _, p := range progs {
			v, err := common.VersionFromString(p.version)
			require.NoError(t, err, arch)
			require.True(t, v.GreaterOrEqual(min), "%s blob %s is older than 6.18", arch, p.version)
		}
	}
}
