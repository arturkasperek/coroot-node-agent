SEC("uprobe/openssl_SSL_write_enter")
int openssl_SSL_write_enter(struct pt_regs *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    struct ssl_args args = {};
    args.buf = (char *)PT_REGS_PARM2(ctx);
    args.size = PT_REGS_PARM3(ctx);
    args.is_read = 0;
    bpf_map_update_elem(&ssl_pending, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uprobe/openssl_SSL_read_enter")
int openssl_SSL_read_enter(struct pt_regs *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    struct ssl_args args = {};
    args.buf = (char *)PT_REGS_PARM2(ctx);
    args.is_read = 1;
    bpf_map_update_elem(&ssl_pending, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uprobe/openssl_SSL_read_ex_enter")
int openssl_SSL_read_ex_enter(struct pt_regs *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    struct ssl_args args = {};
    args.buf = (char *)PT_REGS_PARM2(ctx);
    args.ret_ptr = (__u64 *)PT_REGS_PARM4(ctx);
    args.is_read = 1;
    bpf_map_update_elem(&ssl_pending, &tid, &args, BPF_ANY);
    return 0;
}

/* Diagnostic counters for the SSL_read_exit fallback below: index 0 counts
   every time SSL_read() returned already-buffered plaintext without its own
   inner read()/recvfrom() syscall (so we have to guess the fd from
   ssl_last_fd, the last fd *any* SSL_read on this thread actually saw a
   syscall for); index 1 counts the subset of those where even that fallback
   found nothing. On a single-threaded event-loop server (Node, Python)
   juggling many concurrent TLS connections on one OS thread, a nonzero
   index-0 count means requests are at real risk of being attributed to the
   wrong connection's fd whenever the fallback's "last touched" fd belongs to
   a different, interleaved connection than the one this buffered SSL_read()
   call is actually for — see e2e's h1-tls capture-ratio investigation. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} l7_ssl_read_no_syscall SEC(".maps");

static __attribute__((noinline))
void l7_ssl_read_no_syscall_inc(__u32 idx) {
    __u64 *n = bpf_map_lookup_elem(&l7_ssl_read_no_syscall, &idx);
    if (n) {
        __sync_fetch_and_add(n, 1);
    }
}

SEC("uprobe/openssl_SSL_read_exit")
int openssl_SSL_read_exit(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args *args = bpf_map_lookup_elem(&ssl_pending, &pid_tgid);
    if (!args || !args->is_read) {
        bpf_map_delete_elem(&ssl_pending, &pid_tgid);
        return 0;
    }
    __u64 fd = args->fd;
    if (!fd) {
        // SSL_read returned buffered plaintext without an inner syscall — fall back to the last
        // fd we saw an inner syscall for on this thread.
        __u32 zero = 0, one = 1;
        l7_ssl_read_no_syscall_inc(zero);
        __u64 *last = bpf_map_lookup_elem(&ssl_last_fd, &pid_tgid);
        if (last) {
            fd = *last;
        }
        if (!fd) {
            l7_ssl_read_no_syscall_inc(one);
            bpf_map_delete_elem(&ssl_pending, &pid_tgid);
            return 0;
        }
    }
    char *buf = args->buf;
    __u64 *ret_ptr = args->ret_ptr;
    bpf_map_delete_elem(&ssl_pending, &pid_tgid);

    __u32 pid = pid_tgid >> 32;
    __u64 id = pid_tgid | IS_TLS_READ_ID;
    trace_enter_read(id, pid, fd, 1, buf, ret_ptr, 0);

    int ret = (int)PT_REGS_RC(ctx);
    return trace_exit_read(ctx, id, pid, 1, ret, &http2_tail_progs_kprobe);
}
