package ebpftracer

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
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

// The record of a tracepoint is the program's context, which the verifier lets the
// program load from directly. Its fields are read by a load whose offset CO-RE
// patches, not copied with bpf_probe_read_kernel (BPF_CORE_READ), which is for
// pointers the verifier does not trust, as a kprobe argument. Only an array field
// is copied: its copy needs a moved context pointer, which the verifier rejects.
func TestEbpfProgramsLoadTracepointRecordsDirectly(t *testing.T) {
	for arch := range ebpfProgs {
		spec, err := ebpfCollectionSpec(arch)
		require.NoError(t, err)
		for name, program := range spec.Programs {
			for _, instruction := range program.Instructions {
				relocation := btf.CORERelocationMetadata(&instruction)
				if relocation == nil {
					continue
				}
				record, field, found := tracepointRecordField(relocation.String())
				if !found || isArrayField(t, spec.Types, record, field) {
					continue
				}
				assert.Truef(t, instruction.OpCode.Class() == asm.LdXClass,
					"%s/%s: %s is not loaded from the context: %v", arch, name, relocation, instruction)
			}
		}
	}
}

var tracepointRecordRelocation = regexp.MustCompile(`Struct:"((?:trace_event_raw|syscall_trace)_\w+)"\[0:(\d+)`)

// tracepointRecordField returns the record and the index of its field that a
// relocation, such as CORERelocation(byte_off, Struct:"syscall_trace_exit"[0:0], ...),
// points at.
func tracepointRecordField(relocation string) (record string, field int, found bool) {
	match := tracepointRecordRelocation.FindStringSubmatch(relocation)
	if match == nil {
		return "", 0, false
	}
	field, err := strconv.Atoi(match[2])
	if err != nil {
		return "", 0, false
	}
	return match[1], field, true
}

func isArrayField(t *testing.T, types *btf.Spec, record string, field int) bool {
	var structType *btf.Struct
	require.NoError(t, types.TypeByName(record, &structType))
	require.Less(t, field, len(structType.Members), record)
	_, isArray := btf.UnderlyingType(structType.Members[field].Type).(*btf.Array)
	return isArray
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
