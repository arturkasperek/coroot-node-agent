#define TASK_COMM_LEN	16
#define CLONE_THREAD 	0x00010000

struct proc_event {
    __u32 type;
    __u32 pid;
    __u32 reason;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} proc_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 10240);
} oom_info SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, 1024);
} rustls_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, 1024);
} java_tls_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 10240);
} ssl_last_fd SEC(".maps");

#if defined(__CORE_PIDNS)

// The classic tracepoint only carries the fields the kernel copied into the ring
// buffer, and the child's task_struct is not one of them. bpf_get_current_task()
// is of no help either, since at this point the current task is the parent. The
// raw tracepoint receives the original TP_PROTO arguments instead:
//     TP_PROTO(struct task_struct *task, u64 clone_flags)
SEC("raw_tracepoint/task_newtask")
int task_newtask(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *child = (struct task_struct *)ctx->args[0];
    __u64 clone_flags = ctx->args[1];

    if (clone_flags & CLONE_THREAD) { // skipping threads
        return 0;
    }
    struct proc_event e = {
        .type = EVENT_TYPE_PROCESS_START,
    };
    if (agent_pidns_inum) {
        e.pid = pid_in_agent_ns(BPF_CORE_READ(child, thread_pid));
        if (!e.pid) { // outside of the agent's pid namespace
            return 0;
        }
    } else {
        e.pid = BPF_CORE_READ(child, pid);
    }
    bpf_perf_event_output(ctx, &proc_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

#else

struct trace_event_raw_task_newtask__stub {
    __u64 unused;
#if defined(__CTX_EXTRA_PADDING)
    __u32 unused2;
#endif
    __u32 pid;
    char comm[TASK_COMM_LEN];
    long unsigned int clone_flags;
};

SEC("tracepoint/task/task_newtask")
int task_newtask(struct trace_event_raw_task_newtask__stub *args)
{
    if (args->clone_flags & CLONE_THREAD) { // skipping threads
        return 0;
    }
    struct proc_event e = {
        .type = EVENT_TYPE_PROCESS_START,
        .pid = args->pid,
    };
    bpf_perf_event_output(args, &proc_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

#endif

struct trace_event_raw_sched_process_template__stub {
    __u64 unused;
#if defined(__CTX_EXTRA_PADDING)
    __u32 unused2;
#endif
    char comm[TASK_COMM_LEN];
    __u32 pid;
};

SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(struct trace_event_raw_sched_process_template__stub *args)
{
    __u64 id = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&ssl_last_fd, &id);
    if ((id >> 32) != (__u32)id) { // skipping threads for the rest
        return 0;
    }
    __u64 pid = current_tgid();
    if (!pid) {
        return 0;
    }

    bpf_map_delete_elem(&python_stats, &pid);
    bpf_map_delete_elem(&nodejs_stats, &pid);
    bpf_map_delete_elem(&nodejs_prev_event_loop_iter, &pid);
    bpf_map_delete_elem(&nodejs_current_io_cb, &pid);
    bpf_map_delete_elem(&rustls_pids, &pid);
    bpf_map_delete_elem(&java_tls_pids, &pid);

    struct proc_event e = {
        .type = EVENT_TYPE_PROCESS_EXIT,
        .pid = pid,
    };
    if (bpf_map_lookup_elem(&oom_info, &e.pid)) {
        e.reason = EVENT_REASON_OOM_KILL;
        bpf_map_delete_elem(&oom_info, &e.pid);
    }
    bpf_perf_event_output(args, &proc_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

struct trace_event_raw_mark_victim__stub {
    __u64 unused;
#if defined(__CTX_EXTRA_PADDING)
    __u32 unused2;
#endif
    int pid;
};

SEC("tracepoint/oom/mark_victim")
int oom_mark_victim(struct trace_event_raw_mark_victim__stub *args)
{
    __u32 pid = args->pid;
    bpf_map_update_elem(&oom_info, &pid, &pid, BPF_ANY);
    return 0;
}
