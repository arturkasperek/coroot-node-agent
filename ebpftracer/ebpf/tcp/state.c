#define MAX_CONNECTIONS 1000000
#define MAX_PAYLOAD_SIZE 1024

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
    __u8 pad;
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
};

_Static_assert(sizeof(struct connection) == 48, "connection map value");

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
        conn.timestamp = bpf_ktime_get_ns();

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

    struct ipPort src = {};
    __builtin_memcpy(&src.ip, &args.saddr_v6, sizeof(args.saddr_v6));
    src.port = args.sport;

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
        conn.timestamp = bpf_ktime_get_ns();
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
    conn.timestamp = bpf_ktime_get_ns();
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
