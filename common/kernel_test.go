package common

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckKernelVersionRejectsOlderThan618(t *testing.T) {
	t.Cleanup(func() { kernelVersion = Version{} })

	require.NoError(t, SetKernelVersion("6.12.0"))
	err := CheckKernelVersion()
	require.Error(t, err)
	require.Contains(t, err.Error(), "6.18")
}

func TestCheckKernelVersionAccepts618(t *testing.T) {
	t.Cleanup(func() { kernelVersion = Version{} })

	require.NoError(t, SetKernelVersion("6.18.0"))
	require.NoError(t, CheckKernelVersion())

	require.NoError(t, SetKernelVersion("6.18.15"))
	require.NoError(t, CheckKernelVersion())
}
