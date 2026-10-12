package ebpftracer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The programs read kernel structs whose layout depends on the kernel version and
// config (struct nf_conn grows with lock debugging, a 5.14-el9 trace_entry has an
// extra field). They read them through CO-RE: the loader takes the offsets from the
// kernel's BTF, instead of offsets hardcoded at build time.
func TestEbpfProgramsReadKernelStructsThroughCORE(t *testing.T) {
	for arch := range ebpfProgs {
		t.Run(arch, func(t *testing.T) {
			spec, err := ebpfCollectionSpec(arch)
			require.NoError(t, err)
			relocated := map[string]bool{}
			for _, program := range spec.Programs {
				for _, instruction := range program.Instructions {
					if relocation := btf.CORERelocationMetadata(&instruction); relocation != nil {
						relocated[relocation.String()] = true
					}
				}
			}
			for _, kernelStruct := range []string{
				"sock_common",
				"nf_conn",
				"path",
				"trace_event_raw_inet_sock_set_state",
				"trace_event_raw_tcp_retransmit_skb",
				"trace_event_raw_task_newtask",
				"trace_event_raw_sched_process_exit",
				"trace_event_raw_mark_victim",
				"syscall_trace_enter",
				"syscall_trace_exit",
			} {
				assert.Truef(t, hasRelocationOf(relocated, kernelStruct), "no CO-RE relocation of struct %s", kernelStruct)
			}
		})
	}
}

// A stub is a struct written to match a kernel layout at build time (named
// *__stub). Every kernel struct is read through CO-RE instead.
func TestEbpfProgramsHaveNoStubsOfKernelStructs(t *testing.T) {
	for arch := range ebpfProgs {
		spec, err := ebpfCollectionSpec(arch)
		require.NoError(t, err)
		for typ, err := range spec.Types.All() {
			require.NoError(t, err)
			assert.Falsef(t, strings.HasSuffix(typ.TypeName(), "__stub"), "%s: %s", arch, typ.TypeName())
		}
	}
}

func hasRelocationOf(relocations map[string]bool, kernelStruct string) bool {
	for relocation := range relocations {
		if strings.Contains(relocation, `"`+kernelStruct+`"`) {
			return true
		}
	}
	return false
}

// CO-RE takes the layout of the tracepoint arguments from the kernel, so one build
// fits the kernels whose trace_entry has common_preempt_lazy_count too.
func TestEbpfProgramsHaveOneBuildPerArchitecture(t *testing.T) {
	for arch, builds := range ebpfProgs {
		assert.Lenf(t, builds, 1, "builds for %s", arch)
	}
}

func TestTracerRequiresKernelBTF(t *testing.T) {
	err := requireKernelBTF(filepath.Join(t.TempDir(), "vmlinux"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CONFIG_DEBUG_INFO_BTF")

	present := filepath.Join(t.TempDir(), "vmlinux")
	require.NoError(t, os.WriteFile(present, []byte("BTF"), 0o644))
	assert.NoError(t, requireKernelBTF(present))
}
