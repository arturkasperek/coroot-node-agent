# Shared L7 Byte Source Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** move the protocol-agnostic plumbing that HTTP/1 and HTTP/2 capture share out of `ebpftracer/ebpf/l7/http2.c` into two files of its own, with names that no longer say `http2_`, without changing what the eBPF programs do.

**Architecture:** today `http1.c` and `l7.c` call into `http2.c` for everything that walks the bytes of one syscall (the "iovec table": load, adopt, pull, copy, skip, clear), for the tail-call program arrays and their slot numbers, for the "is this scratch still mine" owner check and for a scratch output buffer. None of it is HTTP/2-specific; it sits in `http2.c` only because HTTP/2 was written first and HTTP/1 reused it. The plan creates `l7/tail_calls.c` (tail-call arrays, slots, owner check, walk output buffer) and `l7/byte_source.c` (the vector table and every function over it), includes both from `l7.c` right before `http2.c`, and renames every moved symbol and its callers. It is a pure move-and-rename: a normalized disassembly of the compiled object must be identical before and after, apart from the renamed symbols.

**Tech Stack:** eBPF C compiled by clang in `ebpftracer/Dockerfile` (alpine 3.19), embedded as `ebpftracer/ebpf.go`; Go loader in `ebpftracer/tracer.go` (cilium/ebpf v0.22); tests in Docker on the remote host (`Dockerfile.test`, `VM=1`).

**Spec:** none written. The request was: "extract what is shared into a separate file and fix the names". Background: the `http2_iov_adopt` stale-table bug (fixed in `http2.c`, test `TestHttp1ReadAfterSendmsgOnAnotherSocketCapturesTheResponse`) was an HTTP/1 bug whose fix had to live in `http2.c`, which is what prompted this.

## Global Constraints

- Pure refactor: no change to any instruction any eBPF program executes. Verified by the disassembly comparison of Task 1, not by reading.
- Do not rename eBPF **programs** (their `SEC()` functions): `http2_resume`, `http2_iov`, `http2_readv`, `http2_read_exit`, `http2_resume_kp`, `http2_iov_kp`, `http1_walk`, `http1_walk_kp` keep their names. Go looks them up by name in `ebpftracer/tracer.go` (`installHTTP2TailProgs`, `attachPrograms`).
- Do not change exported metric label values: `failed["http2_owner_mismatch"]`, `failed["http2_scratch_or_conn_missing"]`, `failed["http2_tail_call_failed"]` in `ebpftracer/tracer.go` stay as they are (dashboards and alerts may match on them).
- Tail-call slot numbers stay 0–4 exactly as now. Go puts programs into these slots by number.
- Map names that Go looks up by string change together with the Go strings in the same task: `http2_tail_progs` and `http2_tail_progs_kprobe`.
- Naming: descriptive, no abbreviations (`vector`, not `vec`; `programs`, not `progs`). `ebpftracer/ebpf/l7/*.c` keeps its comment density.
- `ebpftracer/ebpf.go` is generated: after any `.c` change run `make -C ebpftracer build` (see the backup note in Task 2, step 6).
- Docker runs on a remote host over ssh: retry a command that exits 255 or 125, and pass files through the build context or stdin, never bind mounts.
- The user commits. Each task ends with the working tree ready to commit and a suggested commit message, not with a `git commit`.

## Review Focus

- A `\b`-word-boundary rename that still catches a longer name: `http2_iov_pull` must not touch `http2_iov_pull_header_fast` / `http2_iov_pull_header_resumable`, and `http2_tail_progs` must not touch `http2_tail_progs_kprobe` handled separately. The disassembly comparison catches a wrong rename only if it changes code; the full build catches a dangling name. Task 2 and Task 3 grep for leftovers explicitly.
- Include order: `byte_source.c` and `tail_calls.c` use `scratch_lookup` and `MAX_PAYLOAD_SIZE` (from `tcp/state.c`, included earlier by `ebpf.c`) and must be included before `http2.c`. The build fails loudly if the order is wrong.
- `noinline` versus `__always_inline` attributes must move unchanged: they decide each program's verifier budget. The load test (`go test ./ebpftracer/` in the VM) fails if a program stops verifying; the disassembly comparison shows a changed inlining as a changed block.
- The HTTP/2 frame-cut fields of the vector table (`cut_hdr[HTTP2_FRAME_HEADER_SIZE]`, `cut_body`, `cut_length`) move with the struct. Their size must stay 9; Task 3 pins it with `_Static_assert` in `http2.c`.
- Go strings for the renamed maps: a missed one gives `http2 tail programs missing: ...` at startup. The VM tests start the tracer, so they fail on it.

---

## Rename table

Every rename in this plan, in the order the sed scripts apply them. Names not listed keep their names.

| Old | New | Moves to |
|---|---|---|
| `http2_owner_mismatch` | `scratch_owner_mismatch` | `tail_calls.c` |
| `http2_tail_progs_kprobe` | `l7_tail_programs_kprobe` | `tail_calls.c` |
| `http2_tail_progs` | `l7_tail_programs` | `tail_calls.c` |
| `HTTP2_TAIL_RESUME` | `L7_TAIL_HTTP2_RESUME` | `tail_calls.c` |
| `HTTP2_TAIL_IOV` | `L7_TAIL_HTTP2_WALK` | `tail_calls.c` |
| `HTTP2_TAIL_READV` | `L7_TAIL_READV_DISPATCH` | `tail_calls.c` |
| `HTTP2_TAIL_READ_EXIT` | `L7_TAIL_READ_EXIT` | `tail_calls.c` |
| `HTTP1_TAIL_WALK` | `L7_TAIL_HTTP1_WALK` | `tail_calls.c` |
| `http2_emit_heap` | `l7_walk_output_buffer` | `tail_calls.c` |
| `HTTP2_MAX_VECS` | `BYTE_SOURCE_MAX_VECTORS` | `byte_source.c` |
| `HTTP2_SRC_MAX` | `BYTE_SOURCE_MAX_BYTES` | `byte_source.c` |
| `HTTP2_SRC_BOUND` | `BYTE_SOURCE_BOUND` | `byte_source.c` |
| `http2_vec` | `byte_source_vector` | `byte_source.c` |
| `http2_iovec_table` | `byte_source` | `byte_source.c` |
| `http2_iovecs` | `byte_sources` | `byte_source.c` |
| `http2_iov_load_cb` | `byte_source_load_vector_cb` | `byte_source.c` |
| `http2_iov_load` | `byte_source_load_args` | `byte_source.c` |
| `http2_load_iovecs` | `byte_source_load_vectors` | `byte_source.c` |
| `http2_iov_clear` | `byte_source_clear` | `byte_source.c` |
| `http2_iov_adopt` | `byte_source_adopt` | `byte_source.c` |
| `http2_iov_pull` | `byte_source_pull_byte` | `byte_source.c` |
| `http2_iov_skip` | `byte_source_skip` | `byte_source.c` |
| `http2_iov_copy` | `byte_source_copy` | `byte_source.c` |
| `cut_hdr` | `http2_cut_header` | field of `struct byte_source` |
| `cut_body` | `http2_cut_body` | field of `struct byte_source` |
| `cut_length` | `http2_cut_length` | field of `struct byte_source` |

Deliberately not moved (HTTP/2-specific, they stay in `http2.c` with their names): `http2_iov_pull_header_fast`, `http2_iov_pull_header_resumable`, `http2_iov_cb`, `http2_iov_impl`, `http2_tail_state`, `http2_tail_emit`, `http2_emit_fresh`, `http2_partial_hdr`, `http2_stream_budget`, `HTTP2_TRIM_MAX_FRAMES`, `HTTP2_CAPTURE_MAX`, and the programs listed in Global Constraints. The read dispatchers `http2_readv` / `http2_read_exit` serve every protocol but branch into HTTP/2 code; moving them is a possible follow-up, not part of this plan.

## File structure

- Create `ebpftracer/ebpf/l7/tail_calls.c`: tail-call slot numbers, the two `PROG_ARRAY` maps, `scratch_owner_mismatch`, the `l7_walk_output_buffer` scratch map. Responsibility: what every stage of a tail-call chain needs to hand work to the next stage.
- Create `ebpftracer/ebpf/l7/byte_source.c`: `BYTE_SOURCE_*` limits, `struct byte_source_vector`, `struct byte_source`, the `byte_sources` map and every function over it (`clear`, `load_vectors`, `adopt`, `pull_byte`, `skip`, `copy`). Responsibility: the bytes of one syscall as a list of user pointers, walkable by any protocol.
- Modify `ebpftracer/ebpf/l7/l7.c`: include the two new files before `http2.c`; rename callers.
- Modify `ebpftracer/ebpf/l7/http2.c`: delete the moved code; rename callers; `_Static_assert` on the cut-header size.
- Modify `ebpftracer/ebpf/l7/http1.c`: rename callers; update the file comment that lists what it reuses from `http2.c`.
- Modify `ebpftracer/tracer.go`: the two map-name strings; Go constants for the slot numbers.
- Regenerate `ebpftracer/ebpf.go`.

---

### Task 1: Disassembly equivalence harness and baseline

No repository change. Builds the tool that proves Tasks 2 and 3 change no instruction, and records the baseline from the current commit.

**Files:**
- Create (outside the repo): `/tmp/bpf-equivalence/Dockerfile.disasm`, `/tmp/bpf-equivalence/normalize.py`, `/tmp/bpf-equivalence/disassemble.sh`, `/tmp/bpf-equivalence/renames-tail-calls.txt`, `/tmp/bpf-equivalence/renames-byte-source.txt`

**Interfaces:**
- Produces: `disassemble.sh <source dir containing ebpf/> <output file>` and `normalize.py <disassembly> [renames file]`, used by Tasks 2–4.

- [ ] **Step 1: Write the Dockerfile that compiles and disassembles**

`/tmp/bpf-equivalence/Dockerfile.disasm` (same compiler and flags as `ebpftracer/Dockerfile`, x86 only):

```dockerfile
FROM alpine:3.19
RUN apk add llvm clang libbpf-dev linux-headers
RUN mkdir -p /usr/include/uapi && ln -s ../linux /usr/include/uapi/linux
COPY ebpf /tmp/ebpf
WORKDIR /tmp/ebpf
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=618 -D__TARGET_ARCH_x86 -c ebpf.c -o ebpf.o \
    && llvm-objdump -d -r --no-show-raw-insn ebpf.o > /tmp/disasm.txt
```

- [ ] **Step 2: Write the build-and-extract script**

`/tmp/bpf-equivalence/disassemble.sh`:

```bash
#!/bin/bash
# Compiles <source dir>/ebpf/ebpf.c on the docker host and writes llvm-objdump's
# disassembly to <output file>. Retries the flaky ssh connection to the host.
set -u
source_dir="$1"
output_file="$2"
image="bpf-disasm-$(date +%s)"
for attempt in 1 2 3 4; do
  if docker build -q -f /tmp/bpf-equivalence/Dockerfile.disasm -t "$image" "$source_dir" >/dev/null \
     && docker run --rm "$image" cat /tmp/disasm.txt > "$output_file"; then
    exit 0
  fi
  sleep 5
done
echo "disassembly failed" >&2
exit 1
```

Run: `chmod +x /tmp/bpf-equivalence/disassemble.sh`

- [ ] **Step 3: Write the normalizer**

`/tmp/bpf-equivalence/normalize.py`:

```python
#!/usr/bin/env python3
"""Turns llvm-objdump output into one block per (section, symbol), sorted, without
instruction addresses, relocation offsets, call targets or branch labels, and with
the old names of a renames file replaced by the new ones, so that two builds of
the same code compare equal however their functions are ordered in the object."""
import re
import sys

text = open(sys.argv[1]).read()
if len(sys.argv) > 2:
    for line in open(sys.argv[2]):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        old_name, new_name = line.split()
        text = re.sub(r'\b%s\b' % re.escape(old_name), new_name, text)

blocks = {}
section = None
symbol = None
for line in text.splitlines():
    if line.startswith('Disassembly of section '):
        section = line[len('Disassembly of section '):].rstrip(':')
        symbol = None
        continue
    header = re.match(r'^[0-9a-f]+ <(.+)>:$', line)
    if header:
        symbol = header.group(1)
        blocks[(section, symbol)] = []
        continue
    if symbol is None or not line.strip():
        continue
    line = re.sub(r'^\s*[0-9a-f]+:\s*', '', line)
    line = re.sub(r'\bcall -?(0x[0-9a-f]+|\d+)', 'call TARGET', line)
    line = re.sub(r'(goto [+-]?\d+) <[^>]*>', r'\1', line)
    blocks[(section, symbol)].append(line.strip())

for key in sorted(blocks):
    print('== %s %s' % key)
    print('\n'.join(blocks[key]))
```

`call TARGET` hides pc-relative call offsets, which change when functions move within `.text`. That also hides helper ids; the full test suite (Task 2 step 7, Task 3 step 7) covers what this hides.

- [ ] **Step 4: Write the two rename files**

`/tmp/bpf-equivalence/renames-tail-calls.txt`:

```
http2_owner_mismatch scratch_owner_mismatch
http2_tail_progs_kprobe l7_tail_programs_kprobe
http2_tail_progs l7_tail_programs
HTTP2_TAIL_RESUME L7_TAIL_HTTP2_RESUME
HTTP2_TAIL_IOV L7_TAIL_HTTP2_WALK
HTTP2_TAIL_READV L7_TAIL_READV_DISPATCH
HTTP2_TAIL_READ_EXIT L7_TAIL_READ_EXIT
HTTP1_TAIL_WALK L7_TAIL_HTTP1_WALK
http2_emit_heap l7_walk_output_buffer
```

`/tmp/bpf-equivalence/renames-byte-source.txt` (the tail-call renames plus these, since Task 3's baseline is the original commit):

```
http2_owner_mismatch scratch_owner_mismatch
http2_tail_progs_kprobe l7_tail_programs_kprobe
http2_tail_progs l7_tail_programs
HTTP2_TAIL_RESUME L7_TAIL_HTTP2_RESUME
HTTP2_TAIL_IOV L7_TAIL_HTTP2_WALK
HTTP2_TAIL_READV L7_TAIL_READV_DISPATCH
HTTP2_TAIL_READ_EXIT L7_TAIL_READ_EXIT
HTTP1_TAIL_WALK L7_TAIL_HTTP1_WALK
http2_emit_heap l7_walk_output_buffer
HTTP2_MAX_VECS BYTE_SOURCE_MAX_VECTORS
HTTP2_SRC_MAX BYTE_SOURCE_MAX_BYTES
HTTP2_SRC_BOUND BYTE_SOURCE_BOUND
http2_vec byte_source_vector
http2_iovec_table byte_source
http2_iovecs byte_sources
http2_iov_load_cb byte_source_load_vector_cb
http2_iov_load byte_source_load_args
http2_load_iovecs byte_source_load_vectors
http2_iov_clear byte_source_clear
http2_iov_adopt byte_source_adopt
http2_iov_pull byte_source_pull_byte
http2_iov_skip byte_source_skip
http2_iov_copy byte_source_copy
cut_hdr http2_cut_header
cut_body http2_cut_body
cut_length http2_cut_length
```

- [ ] **Step 5: Record the baseline from the commit the refactor starts from**

```bash
cd /Users/artur/dev/jove/infra/coroot-node-agent
git status --short   # must be empty: start from a committed state
mkdir -p /tmp/bpf-equivalence/baseline
git archive HEAD ebpftracer/ebpf | tar -x -C /tmp/bpf-equivalence/baseline
/tmp/bpf-equivalence/disassemble.sh /tmp/bpf-equivalence/baseline/ebpftracer /tmp/bpf-equivalence/baseline.txt
python3 /tmp/bpf-equivalence/normalize.py /tmp/bpf-equivalence/baseline.txt > /tmp/bpf-equivalence/baseline.normalized
grep -c '^== ' /tmp/bpf-equivalence/baseline.normalized
```

Expected: a count in the hundreds (one block per program and noinline function).

- [ ] **Step 6: Prove the harness compares equal to itself and detects a change**

```bash
cd /Users/artur/dev/jove/infra/coroot-node-agent
/tmp/bpf-equivalence/disassemble.sh ebpftracer /tmp/bpf-equivalence/same.txt
python3 /tmp/bpf-equivalence/normalize.py /tmp/bpf-equivalence/same.txt | diff -q - /tmp/bpf-equivalence/baseline.normalized && echo IDENTICAL
```

Expected: `IDENTICAL`.

Then change one instruction temporarily and confirm the diff sees it:

```bash
cp ebpftracer/ebpf/l7/http2.c /tmp/bpf-equivalence/http2.c.keep
sed -i '' 's/#define HTTP2_MAX_VECS 1024/#define HTTP2_MAX_VECS 512/' ebpftracer/ebpf/l7/http2.c
/tmp/bpf-equivalence/disassemble.sh ebpftracer /tmp/bpf-equivalence/changed.txt
python3 /tmp/bpf-equivalence/normalize.py /tmp/bpf-equivalence/changed.txt | diff -q - /tmp/bpf-equivalence/baseline.normalized || echo DETECTED
cp /tmp/bpf-equivalence/http2.c.keep ebpftracer/ebpf/l7/http2.c
git status --short   # empty again
```

Expected: `DETECTED`, then a clean tree.

---

### Task 2: Extract `tail_calls.c`

**Files:**
- Create: `ebpftracer/ebpf/l7/tail_calls.c`
- Modify: `ebpftracer/ebpf/l7/http2.c` (remove the slot defines, `http2_owner_mismatch`, the two `PROG_ARRAY` maps, `http2_emit_heap`; rename callers)
- Modify: `ebpftracer/ebpf/l7/http1.c`, `ebpftracer/ebpf/l7/l7.c` and any other `ebpftracer/ebpf/**/*.c` that uses a renamed name (rename callers)
- Modify: `ebpftracer/tracer.go` (map names, slot constants)
- Regenerate: `ebpftracer/ebpf.go`

**Interfaces:**
- Consumes: Task 1's `disassemble.sh`, `normalize.py`, `renames-tail-calls.txt`, `baseline.normalized`.
- Produces, used by Task 3 and by `http1.c` / `http2.c` / `l7.c`:
  - `#define L7_TAIL_HTTP2_RESUME 0`, `L7_TAIL_HTTP2_WALK 1`, `L7_TAIL_READV_DISPATCH 2`, `L7_TAIL_READ_EXIT 3`, `L7_TAIL_HTTP1_WALK 4`
  - maps `l7_tail_programs`, `l7_tail_programs_kprobe` (`PROG_ARRAY`, 5 entries)
  - `static __always_inline int scratch_owner_mismatch(__u64 owner)`
  - map `l7_walk_output_buffer` (`TASK_STORAGE`, `char[MAX_PAYLOAD_SIZE]`)

- [ ] **Step 1: Create `tail_calls.c`**

Take the slot defines (with the HTTP/1 slot's comment), `http2_owner_mismatch` (with its comment), both `PROG_ARRAY` maps (with the kprobe comment) and the `http2_emit_heap` map verbatim from `http2.c`, under the new names:

```c
/* Tail calls shared by the L7 walkers. A bpf_tail_call replaces the running
   program, so a walk too big for one program's verifier budget is split into
   stages, each a program of its own in one of the arrays below, and whatever a
   stage hands to the next lives in a task-storage scratch map (see
   scratch_owner_mismatch). The slot numbers are also used by the Go loader
   (ebpftracer/tracer.go), which fills the arrays. */

#define L7_TAIL_HTTP2_RESUME 0
#define L7_TAIL_HTTP2_WALK 1
#define L7_TAIL_READV_DISPATCH 2
#define L7_TAIL_READ_EXIT 3
/* HTTP/1's own verifier-budget-isolated stage — see http1.c. Same prog
   arrays as HTTP2's (all tracepoint-type / all kprobe-type programs, tail
   calls only work within one PROG_ARRAY's program type), just one more
   slot: the bpf_loop-heavy header scan blows a caller like sys_enter_write
   or sys_exit_read's own budget if inlined directly into it, the same
   reason HTTP2's walk needs its own stage. */
#define L7_TAIL_HTTP1_WALK 4

/* True once, at the top of every SEC() program that resumes a chain another
   program's http2_tail_emit/byte_source_load_vectors started (i.e. every stage
   except those two themselves): is this scratch slot still actually mine? */
static __always_inline
int scratch_owner_mismatch(__u64 owner) {
    return owner != bpf_get_current_pid_tgid();
}

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u32);
} l7_tail_programs SEC(".maps");

/* Same programs, loaded as kprobe so an uprobe can tail-call them.
   A PROG_ARRAY holds one program type. Slots 2 and 3 stay empty:
   readv dispatch is tracepoint-only. */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u32);
} l7_tail_programs_kprobe SEC(".maps");

/* Scratch for the bytes a walker emits into the ring, one MAX_PAYLOAD_SIZE
   record at a time; too big for the 512-byte BPF stack. */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, char[MAX_PAYLOAD_SIZE]);
} l7_walk_output_buffer SEC(".maps");
```

Note on map order: moving a map definition earlier in the translation unit can change the order of maps in `.maps`; the disassembly references maps by name through relocations, so the comparison is unaffected, and cilium/ebpf loads maps by name.

- [ ] **Step 2: Delete the moved code from `http2.c`**

In `ebpftracer/ebpf/l7/http2.c` delete exactly:
- the five `#define HTTP2_TAIL_*` / `HTTP1_TAIL_WALK` lines and the HTTP/1 slot comment above `HTTP1_TAIL_WALK`;
- `http2_owner_mismatch` and its comment ("True once, at the top of every SEC() program ...");
- the `http2_tail_progs` and `http2_tail_progs_kprobe` map definitions and the kprobe comment;
- the `http2_emit_heap` map definition.

Leave the comment that introduces the vector table ("writev/readv/sendmsg. The bytes stay in the process. ...") in place: Task 3 moves it.

- [ ] **Step 3: Include `tail_calls.c` and rename every caller**

In `ebpftracer/ebpf/l7/l7.c`, replace:

```c
#include "http2.c"
#include "http1.c"
```

with:

```c
#include "tail_calls.c"
#include "http2.c"
#include "http1.c"
```

Then rename across the eBPF sources (macOS `sed -i ''`; the kprobe array first so the shorter name cannot eat it, though `\b` already protects it):

```bash
cd /Users/artur/dev/jove/infra/coroot-node-agent/ebpftracer/ebpf
for pass in 1 2; do
  while read -r old_name new_name; do
    [ -z "$old_name" ] && continue
    grep -rlw --include='*.c' --include='*.h' "$old_name" . | xargs -r sed -i '' -E "s/(^|[^A-Za-z0-9_])$old_name([^A-Za-z0-9_]|\$)/\1$new_name\2/g"
  done < /tmp/bpf-equivalence/renames-tail-calls.txt
done
```

Two passes because the `(^|[^A-Za-z0-9_])...` form does not match two occurrences separated by a single character in one pass. The second pass usually changes nothing.

- [ ] **Step 4: Check nothing kept an old name**

```bash
cd /Users/artur/dev/jove/infra/coroot-node-agent
grep -rnwE 'http2_owner_mismatch|http2_tail_progs|http2_tail_progs_kprobe|HTTP2_TAIL_RESUME|HTTP2_TAIL_IOV|HTTP2_TAIL_READV|HTTP2_TAIL_READ_EXIT|HTTP1_TAIL_WALK|http2_emit_heap' ebpftracer/ebpf
```

Expected: no output. Then update the HTTP/1 file comment at the top of `ebpftracer/ebpf/l7/http1.c`: the sentence "Reuses http2.c's iovec-table plumbing (http2_iovecs, ..., http2_iov_adopt, http2_owner_mismatch) and http2_emit_heap as scratch" now reads, for the part this task moved: "... scratch_owner_mismatch (tail_calls.c) and l7_walk_output_buffer as scratch". Task 3 finishes the sentence.

- [ ] **Step 5: Rename the maps in Go and name the slots**

In `ebpftracer/tracer.go`, inside `installHTTP2TailProgs`, replace every `"http2_tail_progs_kprobe"` with `"l7_tail_programs_kprobe"` and every `"http2_tail_progs"` with `"l7_tail_programs"` (four call sites: two `putHTTP2TailProgs`, one `putHTTP2ReadTailProgs`, two `putHTTP1TailProg`). Then add, right above `installHTTP2TailProgs`:

```go
// Slots of the l7_tail_programs arrays, as in ebpf/l7/tail_calls.c.
const (
	tailSlotHTTP2Resume  = 0
	tailSlotHTTP2Walk    = 1
	tailSlotReadvDispatch = 2
	tailSlotReadExit     = 3
	tailSlotHTTP1Walk    = 4
)
```

and replace the literals: `m.Put(uint32(4), walk)` → `m.Put(uint32(tailSlotHTTP1Walk), walk)`, `m.Put(uint32(2), readv)` → `m.Put(uint32(tailSlotReadvDispatch), readv)`, `m.Put(uint32(3), readExit)` → `m.Put(uint32(tailSlotReadExit), readExit)`, `m.Put(uint32(0), resume)` → `m.Put(uint32(tailSlotHTTP2Resume), resume)`, `m.Put(uint32(1), iov)` → `m.Put(uint32(tailSlotHTTP2Walk), iov)`. Leave `m.Lookup(uint32(0), &values)` (line ~340, a different map) alone. Run `gofmt -w ebpftracer/tracer.go`.

```bash
grep -n '"http2_tail_progs' /Users/artur/dev/jove/infra/coroot-node-agent/ebpftracer/*.go
```

Expected: no output.

- [ ] **Step 6: Compare the disassembly with the baseline**

```bash
cd /Users/artur/dev/jove/infra/coroot-node-agent
/tmp/bpf-equivalence/disassemble.sh ebpftracer /tmp/bpf-equivalence/tail-calls.txt
python3 /tmp/bpf-equivalence/normalize.py /tmp/bpf-equivalence/baseline.txt /tmp/bpf-equivalence/renames-tail-calls.txt > /tmp/bpf-equivalence/baseline-renamed.normalized
python3 /tmp/bpf-equivalence/normalize.py /tmp/bpf-equivalence/tail-calls.txt | diff - /tmp/bpf-equivalence/baseline-renamed.normalized && echo IDENTICAL
```

Expected: `IDENTICAL`. Any diff means the move changed code: read it, fix the move, repeat.

Then regenerate the embedded object. `make -C ebpftracer build` truncates `ebpf.go` before it knows the build succeeded, so keep a copy:

```bash
cp ebpftracer/ebpf.go /tmp/bpf-equivalence/ebpf.go.before-task-2
make -C ebpftracer build
head -c 40 ebpftracer/ebpf.go | grep -q generated || cp /tmp/bpf-equivalence/ebpf.go.before-task-2 ebpftracer/ebpf.go
```

Expected: `ebpf.go` starts with `// generated - do not edit`. Retry `make` on an ssh failure.

- [ ] **Step 7: Run the full test suite**

Same flags as `make docker-test`, with the retry for the remote host:

```bash
cd /Users/artur/dev/jove/infra/coroot-node-agent
make docker-test
```

Expected: every package `ok`; in `ebpftracer`, `TestHttp1ReadAfterSendmsgOnAnotherSocketCapturesTheResponse`, the `TestHttp1*`, `TestHttp2Readv*`, `TestHttp2Writev*` and `TestHttp2Tls*` tests PASS. A startup error `http2 tail programs missing: l7_tail_programs` means a Go string was missed in step 5.

- [ ] **Step 8: Hand over for commit**

Working tree: `ebpftracer/ebpf/l7/tail_calls.c` (new), `http2.c`, `http1.c`, `l7.c`, `ebpftracer/tracer.go`, `ebpftracer/ebpf.go`. Suggested message:

```
ebpf: move L7 tail-call arrays and the owner check out of http2.c

They serve HTTP/1 as much as HTTP/2. Pure move and rename: the normalized
disassembly is identical to the previous commit's.
```

---

### Task 3: Extract `byte_source.c`

**Files:**
- Create: `ebpftracer/ebpf/l7/byte_source.c`
- Modify: `ebpftracer/ebpf/l7/http2.c` (remove the vector table and its functions; rename callers; `_Static_assert`)
- Modify: `ebpftracer/ebpf/l7/http1.c`, `ebpftracer/ebpf/l7/l7.c` (rename callers; include; http1.c file comment)
- Regenerate: `ebpftracer/ebpf.go`

**Interfaces:**
- Consumes: from Task 2, `scratch_owner_mismatch(__u64 owner)` and `l7_walk_output_buffer`; from Task 1, the harness, `baseline.txt` and `renames-byte-source.txt`.
- Produces, used by `http1.c`, `http2.c`, `l7.c`:
  - `BYTE_SOURCE_MAX_VECTORS` (1024), `BYTE_SOURCE_MAX_BYTES` (128 MiB, `#ifndef`-guarded as today), `BYTE_SOURCE_BOUND(size)`, `BYTE_SOURCE_CUT_HEADER_SIZE` (9)
  - `struct byte_source_vector { __u64 base; __u32 len; __u32 pad; }`
  - `struct byte_source` (fields as `struct http2_iovec_table` today, the three `cut_*` fields renamed `http2_cut_header[BYTE_SOURCE_CUT_HEADER_SIZE]`, `http2_cut_body`, `http2_cut_length`)
  - map `byte_sources` (`TASK_STORAGE`, `struct byte_source`)
  - `void byte_source_clear(void)`, `void byte_source_load_vectors(char *iovec, __u64 iovlen, __u64 cap)`, `struct byte_source *byte_source_adopt(char *buf, __u64 size, __u8 from_heap)`, `int byte_source_pull_byte(__u8 *out)`, `__u32 byte_source_skip(__u32 n)`, `int byte_source_copy(char *dst, __u32 out, __u32 n)` — each with exactly the attributes (`static`, `__always_inline`, `__attribute__((noinline))`) its `http2_*` original has.

- [ ] **Step 1: Create `byte_source.c` with the moved definitions**

Start the file with the limits, which today sit near the top of `http2.c` (`#ifndef HTTP2_SRC_MAX` ... `HTTP2_SRC_BOUND`) and next to the table (`HTTP2_MAX_VECS`):

```c
/* The bytes of one syscall as a list of user pointers, walkable a byte (or a
   run of bytes) at a time by any L7 parser. A writev/readv/sendmsg loads its
   real vector list (byte_source_load_vectors); a plain write/read, TLS
   plaintext or a copy in iovec_buf_heap becomes a one-entry list
   (byte_source_adopt). The bytes stay in the process; only the pointers are
   kept here. The table lives in task storage so that it survives the
   bpf_tail_call chain of one syscall (see tail_calls.c). */

/* Pointer offsets have to be masked for the verifier. 128MiB matches the
   ring: a larger input cannot be stored as messages anyway. */
#ifndef BYTE_SOURCE_MAX_BYTES
#define BYTE_SOURCE_MAX_BYTES (128u * 1024u * 1024u)
#endif
#define BYTE_SOURCE_BOUND(size) ({                                          \
    asm volatile ("%0 &= %1" : "+r"(size) : "i"(BYTE_SOURCE_MAX_BYTES - 1)); \
})

/* One writev/readv/sendmsg. 1024 is IOV_MAX. */
#define BYTE_SOURCE_MAX_VECTORS 1024

/* The HTTP2 walker keeps a frame header cut at the end of one syscall here
   (see http2_cut_header). It is the size of an HTTP2 frame header; http2.c
   asserts that. */
#define BYTE_SOURCE_CUT_HEADER_SIZE 9

struct byte_source_vector {
    __u64 base;
    __u32 len;
    __u32 pad;
};
```

Then move from `http2.c`, verbatim apart from the renames, in this order:
1. `struct http2_iovec_table` with its field comment, as `struct byte_source`, with `cut_hdr[HTTP2_FRAME_HEADER_SIZE]` written as `http2_cut_header[BYTE_SOURCE_CUT_HEADER_SIZE]` and the other two cut fields renamed per the table, and above the three fields the comment `/* HTTP2 walker state for a frame cut at the end of the previous syscall; only http2.c reads or writes these. */`;
2. the `http2_iovecs` map, as `byte_sources`;
3. `struct http2_iov_load` (as `byte_source_load_args`), `http2_iov_clear`, `http2_iov_load_cb`, `http2_load_iovecs` with the "cap 0 means the whole list" comment;
4. `http2_iov_pull`, `http2_iov_skip`, `http2_iov_copy`, each with the comment above it;
5. `http2_iov_adopt` with its comment, including the stale-table check from the `http2_iov_adopt` fix.

Rewrite the comment of the table's `owner` field, which points at "the comment on http2_tail_state.owner below", to point at `scratch_owner_mismatch` in tail_calls.c. Do not move `http2_iov_pull_header_fast`, `http2_iov_pull_header_resumable`, `http2_iov_cb`, `http2_iov_impl` or the programs: they are HTTP/2 frame code.

- [ ] **Step 2: Delete the moved code from `http2.c` and pin the cut-header size**

Delete from `ebpftracer/ebpf/l7/http2.c` everything listed in step 1 (the `#ifndef HTTP2_SRC_MAX` block and `HTTP2_SRC_BOUND` macro, `HTTP2_MAX_VECS`, `struct http2_vec`, `struct http2_iovec_table`, the `http2_iovecs` map, `struct http2_iov_load`, `http2_iov_clear`, `http2_iov_load_cb`, `http2_load_iovecs`, `http2_iov_pull`, `http2_iov_skip`, `http2_iov_copy`, `http2_iov_adopt`), and the now-empty "writev/readv/sendmsg. The bytes stay in the process. ..." comment. Right after `#define HTTP2_FRAME_HEADER_SIZE 9` at the top of `http2.c` add:

```c
_Static_assert(BYTE_SOURCE_CUT_HEADER_SIZE == HTTP2_FRAME_HEADER_SIZE,
               "struct byte_source keeps one cut HTTP2 frame header");
```

- [ ] **Step 3: Include `byte_source.c` and rename every caller**

In `ebpftracer/ebpf/l7/l7.c`:

```c
#include "tail_calls.c"
#include "byte_source.c"
#include "http2.c"
#include "http1.c"
```

Then rename with the full byte-source list (it contains the Task 2 names too; those no longer match anything, which is harmless):

```bash
cd /Users/artur/dev/jove/infra/coroot-node-agent/ebpftracer/ebpf
for pass in 1 2; do
  while read -r old_name new_name; do
    [ -z "$old_name" ] && continue
    grep -rlw --include='*.c' --include='*.h' "$old_name" . | xargs -r sed -i '' -E "s/(^|[^A-Za-z0-9_])$old_name([^A-Za-z0-9_]|\$)/\1$new_name\2/g"
  done < /tmp/bpf-equivalence/renames-byte-source.txt
done
```

`http2_iov_pull_header_fast` and `http2_iov_pull_header_resumable` must survive: `http2_iov_pull` followed by `_` is not a word boundary, so the pattern does not match them. `cut_body` and friends are renamed everywhere they appear, which is only `http2.c` and the moved struct today; check with `git diff` that no unrelated identifier containing them as a whole word changed.

- [ ] **Step 4: Check nothing kept an old name, and finish the http1.c comment**

```bash
cd /Users/artur/dev/jove/infra/coroot-node-agent
grep -rnwE 'HTTP2_MAX_VECS|HTTP2_SRC_MAX|HTTP2_SRC_BOUND|http2_vec|http2_iovec_table|http2_iovecs|http2_iov_load_cb|http2_iov_load|http2_load_iovecs|http2_iov_clear|http2_iov_adopt|http2_iov_pull|http2_iov_skip|http2_iov_copy|cut_hdr|cut_body|cut_length' ebpftracer/ebpf
grep -rn 'http2_iov_pull_header_fast\|http2_iov_pull_header_resumable' ebpftracer/ebpf | head -3
```

Expected: the first grep prints nothing; the second still finds the HTTP/2 header functions. Then rewrite the file comment of `http1.c` that begins "Reuses http2.c's iovec-table plumbing" to:

```c
   Walks the bytes through byte_source.c (byte_source_adopt,
   byte_source_pull_byte, byte_source_copy, byte_source_skip) and hands its
   stages over through tail_calls.c (l7_tail_programs, scratch_owner_mismatch,
   l7_walk_output_buffer as scratch), the same as http2.c. */
```

keeping the paragraph before it.

- [ ] **Step 5: Compare the disassembly with the baseline**

```bash
cd /Users/artur/dev/jove/infra/coroot-node-agent
/tmp/bpf-equivalence/disassemble.sh ebpftracer /tmp/bpf-equivalence/byte-source.txt
python3 /tmp/bpf-equivalence/normalize.py /tmp/bpf-equivalence/baseline.txt /tmp/bpf-equivalence/renames-byte-source.txt > /tmp/bpf-equivalence/baseline-renamed-all.normalized
python3 /tmp/bpf-equivalence/normalize.py /tmp/bpf-equivalence/byte-source.txt | diff - /tmp/bpf-equivalence/baseline-renamed-all.normalized && echo IDENTICAL
```

Expected: `IDENTICAL`.

- [ ] **Step 6: Regenerate `ebpf.go`**

```bash
cp ebpftracer/ebpf.go /tmp/bpf-equivalence/ebpf.go.before-task-3
make -C ebpftracer build
head -c 40 ebpftracer/ebpf.go | grep -q generated || cp /tmp/bpf-equivalence/ebpf.go.before-task-3 ebpftracer/ebpf.go
```

- [ ] **Step 7: Run the full test suite**

```bash
make docker-test
```

Expected: every package `ok`, the same tests as in Task 2 step 7 PASS.

- [ ] **Step 8: Hand over for commit**

Suggested message:

```
ebpf: move the syscall byte source out of http2.c

The vector table and the functions that walk it (load, adopt, pull, copy,
skip, clear) are shared by the HTTP/1 and HTTP/2 walkers. Pure move and
rename: the normalized disassembly is identical to the previous commit's.
```

---

### Task 4: Comments that describe the maps wrongly

The comments around the moved maps and one test still say the scratch maps are `BPF_MAP_TYPE_PERCPU_ARRAY` with one slot per CPU; they have been `BPF_MAP_TYPE_TASK_STORAGE` (one per task) for a while. Comments only: no code changes.

**Files:**
- Modify: `ebpftracer/ebpf/l7/http2.c` (the long comment above `struct http2_tail_state` beginning "http2_tail_state and http2_iovecs are BPF_MAP_TYPE_PERCPU_ARRAY with a single slot")
- Modify: `ebpftracer/ebpf/l7/byte_source.c`, `ebpftracer/ebpf/l7/tail_calls.c` (any moved comment that says per-CPU)
- Modify: `ebpftracer/tracer_test.go` (comments near line 2225 and 2304–2306 that say `http2_tail_state` / `http2_iovecs` are per-CPU arrays)

- [ ] **Step 1: Find every such comment**

```bash
cd /Users/artur/dev/jove/infra/coroot-node-agent
grep -rn 'PERCPU_ARRAY\|per-CPU\|per CPU\|this CPU' ebpftracer/ebpf/l7/http2.c ebpftracer/ebpf/l7/http1.c ebpftracer/ebpf/l7/byte_source.c ebpftracer/ebpf/l7/tail_calls.c ebpftracer/ebpf/l7/l7.c ebpftracer/tracer_test.go
```

- [ ] **Step 2: Rewrite each to describe task storage**

For each hit that is about `http2_tail_state`, `byte_sources` (formerly `http2_iovecs`), `http1_tail_state` or the walk output buffer, state what is true now: the map is `BPF_MAP_TYPE_TASK_STORAGE`, one value per task, so another task cannot overwrite it mid-chain; `owner` (checked by `scratch_owner_mismatch`) still guards against a value left by an earlier syscall of the same task. Use the new names. Leave hits about genuinely per-CPU maps (if any) alone. In `tracer_test.go`, also replace `http2_iovecs` with `byte_sources` in those comments.

- [ ] **Step 3: Confirm no code changed**

```bash
/tmp/bpf-equivalence/disassemble.sh ebpftracer /tmp/bpf-equivalence/comments.txt
python3 /tmp/bpf-equivalence/normalize.py /tmp/bpf-equivalence/comments.txt | diff - /tmp/bpf-equivalence/baseline-renamed-all.normalized && echo IDENTICAL
git diff --stat
```

Expected: `IDENTICAL`; the diff touches only comments. `ebpf.go` needs no regeneration if the disassembly is identical, but regenerate it anyway (BTF line info embeds comments' line numbers): run Task 3 step 6 again, then `make docker-test`.

- [ ] **Step 4: Check in the dev cluster**

With Tilt running (`make dev` in the coroot repo), the agent image rebuilds from this tree. After the new `coroot-node-agent` pod logs `loaded ebpf collection`, wait 10 minutes and run:

```bash
kubectl --context k3s-server -n coroot-dev exec clickhouse-0 -- clickhouse-client -q "SELECT count(), countIf(Duration > 0.5e9), round(max(Duration)/1e9,3) FROM otel_traces_distributed WHERE Timestamp > now() - INTERVAL 10 MINUTE AND ServiceName LIKE '%coroot-node-agent%' AND SpanName='POST'"
curl -s localhost:18300/metrics | grep -E '^node_ebpf_(lost_events|user_memory_read_failures)_total' | grep -v ' 0$'
```

Expected: hundreds of spans, `0` slow ones, max well under a second; no non-zero lost-event or read-failure counters that were zero before.

- [ ] **Step 5: Hand over for commit**

Suggested message:

```
ebpf: describe the L7 scratch maps as task storage

They stopped being per-CPU arrays; the comments still said they were.
```

---

## Self-review notes

- Coverage: the request names two things, a separate file for the shared code and better names. Tasks 2–3 do both; Task 4 fixes comments the move would otherwise carry over wrong; Task 1 is how "no behavior change" is proven rather than assumed.
- Not covered on purpose: moving the read dispatchers (`http2_readv`, `http2_read_exit`), renaming programs, renaming metric labels. Each is a separate change with its own risk (Go program lookups, dashboards).
- Names are consistent across tasks: the rename table, the two rename files, the Interfaces blocks and the grep checks use the same names.
