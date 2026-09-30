#define MAX_CONNECTIONS 1000000
#define MAX_PAYLOAD_SIZE 1024

/* A connection's identity in the BPF-side state maps (http1_state,
   http2_stream_budget, http2_partial_hdr, ...) is its creation timestamp,
   not (pid, fd) — fds get reused. bpf_ktime_get_ns() alone is not unique:
   two connects racing on different CPUs (a Go client dialing two
   connections at once) can read the very same nanosecond, and both
   connections then shared one HTTP/1 state entry — one connection's
   response started out in the other's "body" phase, or its request headers
   were cut short — so requests silently vanished. Keep the creation time at
   ~8us resolution and fill the low 12 bits from a global atomic sequence, so
   two connections created within the same 4us bucket always differ. The
   result never exceeds the real time (callers subtract it from
   bpf_ktime_get_ns()) and is at most 8us before it. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} conn_seq SEC(".maps");

static __always_inline
__u64 conn_timestamp(__u32 pid, __u64 fd) {
    __u32 zero = 0;
    __u64 seq = 0;
    __u64 *p = bpf_map_lookup_elem(&conn_seq, &zero);
    if (p) {
        seq = __sync_fetch_and_add(p, 1);
    }
    return (bpf_ktime_get_ns() & ~0xFFFULL) - 0x1000 + (seq & 0xFFF);
}

/* Failed reads of the traced application's memory (pull = one byte of the
   header scan, copy = a payload copy, tls = the Go TLS fd chain, retried =
   reads a retry rescued); exported through the tracer's metrics. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 8);
} src_read_fail SEC(".maps");

static __always_inline
void count_src_fail(__u32 which) {
    __u64 *c = bpf_map_lookup_elem(&src_read_fail, &which);
    if (c) {
        __sync_fetch_and_add(c, 1);
    }
}

/* Working memory of the L7 pipeline (the event under construction, the iovec
   table, tail-call state, the emit heap, ...) is private to the *task*
   running the syscall. It used to live in one BPF_MAP_TYPE_PERCPU_ARRAY slot
   per CPU on the assumption that a syscall's whole BPF chain runs without
   another task getting the CPU. That does not hold: the Go TLS uprobes (and,
   on a preemptible kernel, the syscall hooks) run with preemption enabled,
   another task's chain then overwrites the very same slot, and the first
   task resumes on someone else's data — a response header block full of
   another request's body, headers cut short, events for the wrong
   connection. Task storage gives every thread its own copy, so there is
   nothing left to clobber. */
static __always_inline
void *scratch_lookup(void *map) {
    struct task_struct *t = (struct task_struct *)bpf_get_current_task_btf();
    return bpf_task_storage_get(map, t, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
}

/* Reads of the traced application's memory from a tracepoint/uprobe cannot
   fault a page in: a page that is momentarily unavailable — being migrated
   or compacted (THP fault compaction migrates hundreds of thousands of pages
   under load), being collapsed or split — makes bpf_probe_read fail even
   though the address is perfectly valid, and the capture then silently ends
   at that byte (a request head cut to 4, 50 or 100 bytes). Such a window
   lasts microseconds, so retry a bounded number of times before giving up;
   count_src_fail(3) counts the reads a retry rescued. */
#define PROBE_READ_RETRIES 48
static __always_inline
long probe_read_retry(void *dst, __u32 size, const void *src) {
    long r = bpf_probe_read(dst, size, src);
    if (!r) {
        return 0;
    }
#pragma nounroll
    for (int i = 0; i < PROBE_READ_RETRIES; i++) {
        r = bpf_probe_read(dst, size, src);
        if (!r) {
            count_src_fail(3);
            return 0;
        }
    }
    return r;
}

/* Wait (bounded) until the first 8 bytes at addr are not all zero. Used on a
   decrypted TLS read buffer that is still zero right after the Read returned
   n > 0. Global with a plain-number argument, so the loop is verified once.
   Returns 1 if data appeared, 0 if it stayed zero (or unreadable). */
__attribute__((noinline))
long tls_buf_wait_nonzero(__u64 addr) {
    __u64 first = 0;
#pragma nounroll
    for (int i = 0; i < 2048; i++) {
        if (!bpf_probe_read(&first, sizeof(first), (const void *)addr) && first) {
            return 1;
        }
    }
    return 0;
}

/* Argument block of sniff_read16: plain numbers only, which is the one shape
   the verifier accepts as the argument of a global function. `addr` carries
   the user pointer as a number (storing it here launders its type). */
struct sniff_arg {
    __u64 w0;
    __u64 w1;
    __u64 addr;
};

/* 16 bytes of the traced application's memory for protocol detection, with a
   long retry: a page that is momentarily unavailable (migration, compaction)
   comes back after tens of microseconds, and here one failed read means the
   whole connection is never recognised. Global on purpose — verified once, so
   the long loop does not multiply into every syscall program. */
__attribute__((noinline))
long sniff_read16(struct sniff_arg *a) {
    if (!a) {
        return -1;
    }
    __u64 w[2] = {};
    long r = bpf_probe_read(w, sizeof(w), (const void *)a->addr);
    if (r) {
#pragma nounroll
        for (int i = 0; i < 1024; i++) {
            r = bpf_probe_read(w, sizeof(w), (const void *)a->addr);
            if (!r) {
                count_src_fail(3);
                break;
            }
        }
    }
    if (r) {
        count_src_fail(6);
        return r;
    }
    a->w0 = w[0];
    a->w1 = w[1];
    return 0;
}

/* The first 16 bytes of buf in `w` for protocol detection
   (is_http_request/is_http_response). Returns 0 unless the 16 bytes were read
   and none of the first 15 is NUL (what the former
   bpf_probe_read_str(..., 16) < 16 test meant). */
static __always_inline
int sniff_first16(__u64 w[2], char *buf) {
    char *b = (char *)w;
    struct sniff_arg a = {};
    a.addr = (__u64)buf;
    if (sniff_read16(&a)) {
        return 0;
    }
    w[0] = a.w0;
    w[1] = a.w1;
#pragma unroll
    for (int i = 0; i < 15; i++) {
        if (b[i] == 0) {
            return 0;
        }
    }
    return 1;
}

struct tcp_event {
    __u64 fd;
    __u64 timestamp;
    __u64 duration;
    __u32 type;
    __u32 pid;
    __u64 bytes_sent;
    __u64 bytes_received;
    __u16 sport;
    __u16 dport;
    __u16 aport;
    __u8 saddr[16];
    __u8 daddr[16];
    __u8 aaddr[16];
    __u8 is_inbound;
    __u8 pad[7];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} tcp_listen_events SEC(".maps");

#define TCP_CONNECT_EVENTS_RINGBUF_SIZE (16 * 1024 * 1024)

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, TCP_CONNECT_EVENTS_RINGBUF_SIZE);
} tcp_connect_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} tcp_connect_events_dropped SEC(".maps");

static __always_inline
void tcp_connect_drop_event(void) {
    __u32 zero = 0;
    __u64 *n = bpf_map_lookup_elem(&tcp_connect_events_dropped, &zero);
    if (n) {
        __sync_fetch_and_add(n, 1);
    }
}

// Fixed-size tcp_event: copy into the ringbuf. Unlike L7 there is no variable
// payload, so bpf_ringbuf_output is enough (no dynptr / reserve lifecycle).
static __always_inline
void send_tcp_connect_event(struct tcp_event *e) {
    if (bpf_ringbuf_output(&tcp_connect_events, e, sizeof(*e), 0)) {
        tcp_connect_drop_event();
    }
}

struct trace_event_raw_inet_sock_set_state__stub {
    __u64 unused;
#if defined(__CTX_EXTRA_PADDING)
    __u64 unused2;
#endif
    void *skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 10240);
} fd_by_pid_tgid SEC(".maps");

struct connection_id {
    __u64 fd;
    __u32 pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(void *));
    __uint(value_size, sizeof(struct connection_id));
    __uint(max_entries, MAX_CONNECTIONS);
} connection_id_by_socket SEC(".maps");

struct connection {
    __u64 timestamp;
    __u64 bytes_sent;
    __u64 bytes_received;
    __u8 is_inbound;
    __u8 protocol;
    __u8 is_tls;
    __u8 open_sent; /* CONNECTION_OPEN already emitted for this connection */
    __u32 h2_skip_req;
    __u32 h2_skip_resp;
    /* HTTP2 stream ID a pending cross-syscall capture resume belongs to
       (the capture budget itself lives in http2_stream_budget, keyed by
       this ID; there is no cumulative have/expect counter to persist
       here anymore, so this field just carries the ID across calls). */
    __u32 h2_skip_req_stream;
    __u32 h2_skip_resp_stream;
    __u8 h2_skip_req_data;
    __u8 h2_skip_resp_data;
    __u8 pad2[2];
    /* struct sock * of a connect()ed socket, recorded at SYN_SENT (see
       emit_connection_open_lazy) */
    __u64 skaddr;
};

_Static_assert(sizeof(struct connection) == 56, "connection map value");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct connection_id));
    __uint(value_size, sizeof(struct connection));
    __uint(max_entries, MAX_CONNECTIONS);
} active_connections SEC(".maps");

struct l7_request_key {
    __u64 fd;
    __u32 pid;
    __u16 is_tls;
    __s16 stream_id;
};

struct l7_request {
    __u64 ns;
    __u8 protocol;
    __u8 partial;
    __u8 request_type;
    __s32 request_id;
    __u64 payload_size;
    char payload[MAX_PAYLOAD_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct l7_request_key));
    __uint(value_size, sizeof(struct l7_request));
    __uint(max_entries, 32768);
} active_l7_requests SEC(".maps");

/* CONNECTION_OPEN is normally sent when the socket reaches ESTABLISHED. That
   transition is processed in softirq, and the kernel skips a tracepoint
   program that would run while another tracepoint/kprobe program is
   already active on the same CPU (a long L7 walk in task context is enough)
   — the skipped open is never retried, the connection stays unknown to the
   agent and every request on it is lost. connect()'s own SYN_SENT runs in
   task context and is never nested, so it records the socket; the first
   data syscall on a connection whose open was never sent announces it from
   there, reading the addresses off the socket. */
/* The leading fields of the kernel's struct sock_common. Read at fixed
   offsets: this program is built without kernel BTF, and this prefix (plus
   the two IPv6 addresses at 56/72) has had the same layout for many
   releases. Every value is sanity-checked below. */
struct sock_common_head {
    __u32 daddr;
    __u32 rcv_saddr;
    __u32 hash;
    __u16 dport; /* network order */
    __u16 num;   /* host order */
    __u16 family;
};
#define SKC_V6_DADDR_OFF 56
#define SKC_V6_RCV_SADDR_OFF 72

/* Working memory lives in a map, not on the stack: this is inlined into
   programs (sendmmsg's per-message loop) that already sit at the 512-byte
   combined stack limit. */
struct open_scratch {
    struct tcp_event e;
    struct sock_common_head skc;
    struct connPair src;
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct open_scratch);
} open_scratch SEC(".maps");

static __attribute__((noinline))
void emit_connection_open_lazy(struct connection_id *cid, struct connection *conn) {
    struct open_scratch *sc = scratch_lookup(&open_scratch);
    struct ipPort *actualDst;

    if (!sc) {
        return;
    }
    __builtin_memset(sc, 0, sizeof(*sc));
    if (bpf_probe_read_kernel(&sc->skc, sizeof(sc->skc), (void *)conn->skaddr)) {
        return;
    }
    sc->e.sport = sc->skc.num;
    sc->e.dport = bpf_ntohs(sc->skc.dport);
    if (!sc->e.sport || !sc->e.dport) {
        return;
    }
    if (sc->skc.family == AF_INET) {
        /* v4-mapped, like the tracepoint's saddr_v6/daddr_v6 */
        sc->e.saddr[10] = 0xff;
        sc->e.saddr[11] = 0xff;
        sc->e.daddr[10] = 0xff;
        sc->e.daddr[11] = 0xff;
        __builtin_memcpy(&sc->e.saddr[12], &sc->skc.rcv_saddr, 4);
        __builtin_memcpy(&sc->e.daddr[12], &sc->skc.daddr, 4);
    } else if (sc->skc.family == AF_INET6) {
        if (bpf_probe_read_kernel(&sc->e.saddr, sizeof(sc->e.saddr), (void *)(conn->skaddr + SKC_V6_RCV_SADDR_OFF)) ||
            bpf_probe_read_kernel(&sc->e.daddr, sizeof(sc->e.daddr), (void *)(conn->skaddr + SKC_V6_DADDR_OFF))) {
            return;
        }
    } else {
        return;
    }
    conn->open_sent = 1;
    sc->e.type = EVENT_TYPE_CONNECTION_OPEN;
    sc->e.timestamp = conn->timestamp;
    sc->e.pid = cid->pid;
    sc->e.fd = cid->fd;
    __builtin_memcpy(&sc->src.src_ip, &sc->e.saddr, sizeof(sc->src.src_ip));
    __builtin_memcpy(&sc->src.dst_ip, &sc->e.daddr, sizeof(sc->src.dst_ip));
    sc->src.src_port = sc->e.sport;
    sc->src.dst_port = sc->e.dport;
    actualDst = bpf_map_lookup_elem(&actual_destinations, &sc->src);
    if (actualDst) {
        sc->e.aport = actualDst->port;
        __builtin_memcpy(&sc->e.aaddr, &actualDst->ip, sizeof(sc->e.aaddr));
    }
    send_tcp_connect_event(&sc->e);
}

SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(void *ctx)
{
    struct trace_event_raw_inet_sock_set_state__stub args = {};
    if (bpf_probe_read(&args, sizeof(args), ctx) < 0) {
        return 0;
    }
    if (args.protocol != IPPROTO_TCP) {
        return 0;
    }
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (args.oldstate == BPF_TCP_CLOSE && args.newstate == BPF_TCP_SYN_SENT) {
        __u64 *fdp = bpf_map_lookup_elem(&fd_by_pid_tgid, &id);

        if (!fdp) {
            return 0;
        }
        struct connection_id cid = {};
        cid.pid = pid;
        cid.fd = *fdp;

        struct connection conn = {};
        conn.timestamp = conn_timestamp(cid.pid, cid.fd);
        conn.skaddr = (__u64)args.skaddr;

        bpf_map_delete_elem(&fd_by_pid_tgid, &id);
        bpf_map_update_elem(&connection_id_by_socket, &args.skaddr, &cid, BPF_ANY);
        bpf_map_update_elem(&active_connections, &cid, &conn, BPF_ANY);
        return 0;
    }

    __u64 fd = 0;
    __u32 type = 0;
    __u64 timestamp = 0;
    __u64 duration = 0;

    struct tcp_event e = {};

    if (args.oldstate == BPF_TCP_SYN_SENT) {
        struct connection_id *cid = bpf_map_lookup_elem(&connection_id_by_socket, &args.skaddr);
        if (!cid) {
            return 0;
        }
        struct connection *conn = bpf_map_lookup_elem(&active_connections, cid);
        if (!conn) {
            return 0;
        }
        if (args.newstate == BPF_TCP_ESTABLISHED) {
            if (conn->open_sent) {
                return 0;
            }
            conn->open_sent = 1;
            timestamp = conn->timestamp;
            type = EVENT_TYPE_CONNECTION_OPEN;
        } else if (args.newstate == BPF_TCP_CLOSE) {
            bpf_map_delete_elem(&connection_id_by_socket, &args.skaddr);
            bpf_map_delete_elem(&active_connections, cid);
            type = EVENT_TYPE_CONNECTION_ERROR;
        }
        duration = bpf_ktime_get_ns() - conn->timestamp;
        pid = cid->pid;
        fd = cid->fd;
    }
    if (args.oldstate == BPF_TCP_ESTABLISHED && (args.newstate == BPF_TCP_FIN_WAIT1 || args.newstate == BPF_TCP_CLOSE_WAIT)) {
        bpf_map_delete_elem(&connection_id_by_socket, &args.skaddr);
    }
    if (args.oldstate == BPF_TCP_CLOSE && args.newstate == BPF_TCP_LISTEN) {
        type = EVENT_TYPE_LISTEN_OPEN;
    }
    if (args.oldstate == BPF_TCP_LISTEN && args.newstate == BPF_TCP_CLOSE) {
        type = EVENT_TYPE_LISTEN_CLOSE;
    }

    if (type == 0) {
        return 0;
    }
    e.type = type;
    e.duration = duration;
    e.timestamp = timestamp;
    e.pid = pid;
    e.sport = args.sport;
    e.dport = args.dport;
    e.fd = fd;
    __builtin_memcpy(&e.saddr, &args.saddr_v6, sizeof(e.saddr));
    __builtin_memcpy(&e.daddr, &args.daddr_v6, sizeof(e.saddr));

    struct connPair src = {};
    __builtin_memcpy(&src.src_ip, &args.saddr_v6, sizeof(args.saddr_v6));
    __builtin_memcpy(&src.dst_ip, &args.daddr_v6, sizeof(args.daddr_v6));
    src.src_port = args.sport;
    src.dst_port = args.dport;

    struct ipPort *actualDst = bpf_map_lookup_elem(&actual_destinations, &src);
    if (actualDst) {
        e.aport = actualDst->port;
        __builtin_memcpy(&e.aaddr, &actualDst->ip, sizeof(e.aaddr));
    }
    if (type == EVENT_TYPE_LISTEN_OPEN || type == EVENT_TYPE_LISTEN_CLOSE) {
        bpf_perf_event_output(ctx, &tcp_listen_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    } else {
        send_tcp_connect_event(&e);
    }
    return 0;
}

struct trace_event_raw_args_with_fd__stub {
    __u64 unused;
    __u64 unused2;
    __u64 fd;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int sys_enter_connect(void *ctx) {
    struct trace_event_raw_args_with_fd__stub args = {};
    if (bpf_probe_read(&args, sizeof(args), ctx) < 0) {
        return 0;
    }
    __u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&fd_by_pid_tgid, &id, &args.fd, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int sys_exit_connect(struct trace_event_raw_sys_exit__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u64 *fdp = bpf_map_lookup_elem(&fd_by_pid_tgid, &id);
    if (!fdp) {
        return 0;
    }
    struct connection_id cid = {};
    cid.pid = id >> 32;
    cid.fd = *fdp;
    struct connection *conn = bpf_map_lookup_elem(&active_connections, &cid);
    if (!conn && ctx->ret == 0) { // non-TCP connection
        struct connection conn = {};
        conn.timestamp = conn_timestamp(cid.pid, cid.fd);
        bpf_map_update_elem(&active_connections, &cid, &conn, BPF_ANY);
    }

    struct l7_request_key k = {
        .fd = cid.fd,
        .pid = cid.pid,
        .is_tls = 0,
        .stream_id = -1,
    };
    bpf_map_delete_elem(&active_l7_requests, &k);

    k.is_tls = 1;
    bpf_map_delete_elem(&active_l7_requests, &k);

    bpf_map_delete_elem(&fd_by_pid_tgid, &id);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int sys_enter_close(void *ctx) {
    struct trace_event_raw_args_with_fd__stub args = {};
    if (bpf_probe_read(&args, sizeof(args), ctx) < 0) {
        return 0;
    }
    __u64 id = bpf_get_current_pid_tgid();
    struct connection_id cid = {};
    cid.pid = id >> 32;
    cid.fd = args.fd;
    struct connection *conn = bpf_map_lookup_elem(&active_connections, &cid);
    if (conn) {
        struct tcp_event e = {};
        e.type = EVENT_TYPE_CONNECTION_CLOSE;
        e.pid = cid.pid;
        e.fd = cid.fd;
        e.bytes_sent = conn->bytes_sent;
        e.bytes_received = conn->bytes_received;
        e.timestamp = conn->timestamp;
        e.is_inbound = conn->is_inbound;
        send_tcp_connect_event(&e);
        bpf_map_delete_elem(&active_connections, &cid);
    }
    return 0;
}

static inline __attribute__((__always_inline__))
int handle_accept_exit(long int ret) {
    if (ret < 0) {
        return 0;
    }
    __u64 id = bpf_get_current_pid_tgid();
    struct connection_id cid = {};
    cid.pid = id >> 32;
    cid.fd = (__u64)ret;
    struct connection conn = {};
    conn.timestamp = conn_timestamp(cid.pid, cid.fd);
    conn.is_inbound = 1;
    bpf_map_update_elem(&active_connections, &cid, &conn, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int sys_exit_accept(struct trace_event_raw_sys_exit__stub* ctx) {
    return handle_accept_exit(ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int sys_exit_accept4(struct trace_event_raw_sys_exit__stub* ctx) {
    return handle_accept_exit(ctx->ret);
}
