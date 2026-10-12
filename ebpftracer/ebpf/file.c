#include <asm-generic/fcntl.h>

struct file_event {
	__u32 type;
	__u32 pid;
	__u64 fd;
	__u64 mnt;
	__u64 log;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} file_events SEC(".maps");

struct file_info {
    __u64 mnt;
    __u64 log;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct file_info));
    __uint(max_entries, 10240);
} open_file_info SEC(".maps");

SEC("kprobe/path_get")
int path_get(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct file_info *i = bpf_map_lookup_elem(&open_file_info, &id);
    if (!i) {
        return 0;
    }
    struct path *p = (struct path *)PT_REGS_PARM1(ctx);
    BPF_CORE_READ_INTO(&i->mnt, p, mnt);
    return 0;
}

static __always_inline
int trace_enter_open(long int flags, char *filename)
{
	if (!(flags & O_ACCMODE & (O_WRONLY | O_RDWR))) {
		return 0;
	}
	char p[10];
	bpf_probe_read_str(&p, sizeof(p), (void *)filename);
	if (p[0] != '/') {
	    return 0;
	}
	if (p[1]=='p' && p[2]=='r' && p[3]=='o' && p[4]=='c' && p[5]=='/') {
		return 0;
	}
	if (p[1]=='d' && p[2]=='e' && p[3]=='v' && p[4]=='/') {
		return 0;
	}
	if (p[1]=='s' && p[2]=='y' && p[3]=='s' && p[4]=='/') {
		return 0;
	}
	struct file_info i = {};
	if (p[1]=='v' && p[2]=='a' && p[3]=='r' && p[4]=='/' && p[5]=='l' && p[6] == 'o' && p[7] == 'g' && p[8] == '/') {
        i.log = 1;
    }
	__u64 id = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&open_file_info, &id, &i, BPF_ANY);
	return 0;
}

static __always_inline
int trace_exit_open(struct syscall_trace_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct file_info *i = bpf_map_lookup_elem(&open_file_info, &id);
	if (!i) {
	    return 0;
	}
	if (ctx->ret < 0 || i->mnt == 0) {
	    bpf_map_delete_elem(&open_file_info, &id);
		return 0;
	}
	struct file_event e = {
		.type = EVENT_TYPE_FILE_OPEN,
		.pid = id >> 32,
		.fd = ctx->ret,
		.mnt = i->mnt,
		.log = i->log,
	};
	bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
	bpf_map_delete_elem(&open_file_info, &id);
	return 0;
}

#if defined(__TARGET_ARCH_x86)
SEC("tracepoint/syscalls/sys_enter_open")
int sys_enter_open(struct syscall_trace_enter *ctx)
{
	/* open(filename, flags, mode) */
	return trace_enter_open(ctx->args[1], (char *)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_open")
int sys_exit_open(struct syscall_trace_exit *ctx)
{
	return trace_exit_open(ctx);
}
#endif

SEC("tracepoint/syscalls/sys_enter_openat")
int sys_enter_openat(struct syscall_trace_enter *ctx)
{
	/* openat(dfd, filename, flags, mode) */
	return trace_enter_open(ctx->args[2], (char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int sys_exit_openat(struct syscall_trace_exit *ctx)
{
	return trace_exit_open(ctx);
}
