/*
 * PID namespace translation.
 *
 * eBPF programs always observe PIDs of the root PID namespace, while the agent
 * resolves them through its own /proc. Those two agree on a plain host, but not
 * when the agent itself runs inside a nested PID namespace - a kind node, for
 * example - where every lookup by an eBPF-reported PID either fails or, worse,
 * silently hits an unrelated process that happens to carry the same number.
 *
 * When built with __CORE_PIDNS the programs walk task->thread_pid->numbers[] and
 * report the PID as seen from the namespace of the agent, which userspace passes
 * in through agent_pidns_inum. On a plain host the agent lives in the root
 * namespace, the very first entry matches and the reported PID is the same value
 * the programs emitted before, so the translation is a no-op there.
 *
 * Reaching into struct pid means reading kernel internals whose layout shifts
 * between versions and even between configurations of the same version, so this
 * is deliberately gated behind CO-RE: offsets come from the BTF of the running
 * kernel instead of being baked in at compile time. Builds without kernel BTF
 * keep using the untranslated objects.
 */

#ifndef __PIDNS_H__
#define __PIDNS_H__

#if defined(__CORE_PIDNS)

/*
 * Only the fields actually read are declared. preserve_access_index makes clang
 * emit CO-RE relocations for them, so the layout below never has to match the
 * running kernel - names are what gets matched.
 */
struct ns_common {
    unsigned int inum;
} __attribute__((preserve_access_index));

struct pid_namespace {
    struct ns_common ns;
} __attribute__((preserve_access_index));

struct upid {
    int nr;
    struct pid_namespace *ns;
} __attribute__((preserve_access_index));

struct pid {
    unsigned int level;
    struct upid numbers[];
} __attribute__((preserve_access_index));

struct task_struct {
    int pid;
    struct task_struct *group_leader;
    struct pid *thread_pid;
} __attribute__((preserve_access_index));

/*
 * The kernel allows MAX_PID_NS_LEVEL (32) levels of nesting. Anything close to
 * that is pathological, and the bound has to be a compile time constant for the
 * verifier to bound the loop.
 */
#define PIDNS_MAX_LEVEL 8

/* Offset of numbers[i] within struct pid. The member is a flexible array, so its
   offset and stride have to be applied by hand - a runtime index cannot be
   relocated on its own. */
#define PIDNS_UPID_AT(p, i)                                    \
    ((void *)(p) + bpf_core_field_offset(struct pid, numbers) + \
     (__u64)(i) * bpf_core_type_size(struct upid))

/* Inode of the PID namespace of the agent, set from userspace before loading.
   Zero disables the translation. */
const volatile __u32 agent_pidns_inum = 0;

/*
 * Returns the number this identity carries in the namespace of the agent, or 0
 * when the task lives outside the subtree the agent can see.
 *
 * Deliberately not inlined. Every program that reports a PID calls this, and
 * inlining the walk into each of them multiplies the work the verifier has to do.
 * As a subprogram it is verified once.
 *
 * The shape of the loop matters more than it looks. Nothing read from the kernel
 * may influence how many times it runs: given a trip count derived from level the
 * verifier loses the bound - level comes from memory, so it is unknown to it - and
 * walks the loop until it gives up with "the sequence of 8193 jumps is too complex"
 * or, once clang starts spilling level to the stack, until it runs out of its one
 * million instruction budget. Hence the constant bound, with level used only to
 * validate a hit.
 *
 * Entries past level are therefore read as well. That is harmless: those reads
 * either fail or return values that cannot match a live namespace inode, and the
 * scan runs from the root down, so a real hit is always found before any garbage
 * beyond the array could be mistaken for one.
 */
static __noinline __u32 pid_in_agent_ns(struct pid *p)
{
    if (!p) {
        return 0;
    }

    __u32 level = 0;
    bpf_probe_read_kernel(&level, sizeof(level),
                          (void *)p + bpf_core_field_offset(struct pid, level));

    for (__u32 i = 0; i < PIDNS_MAX_LEVEL; i++) {
        void *entry = PIDNS_UPID_AT(p, i);

        /* Failed reads leave the values at zero, which cannot match a real inode,
           so checking their return values would only add paths to walk. */
        struct pid_namespace *ns = NULL;
        bpf_probe_read_kernel(&ns, sizeof(ns),
                              entry + bpf_core_field_offset(struct upid, ns));
        __u32 inum = 0;
        bpf_probe_read_kernel(&inum, sizeof(inum),
                              (void *)ns + bpf_core_field_offset(struct pid_namespace, ns.inum));

        if (inum == agent_pidns_inum) {
            if (i > level) { /* past the real entries - not a namespace of this task */
                return 0;
            }
            __u32 nr = 0;
            bpf_probe_read_kernel(&nr, sizeof(nr),
                                  entry + bpf_core_field_offset(struct upid, nr));
            return nr;
        }
    }
    return 0;
}

#endif /* __CORE_PIDNS */

/*
 * The thread group id of the current task, as the agent sees it. Callers must
 * treat 0 as "not attributable" and drop the event: it means the task runs
 * outside the PID namespace of the agent.
 */
static __always_inline __u32 current_tgid(void)
{
#if defined(__CORE_PIDNS)
    if (agent_pidns_inum) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        return pid_in_agent_ns(BPF_CORE_READ(task, group_leader, thread_pid));
    }
#endif
    return bpf_get_current_pid_tgid() >> 32;
}

#endif /* __PIDNS_H__ */
