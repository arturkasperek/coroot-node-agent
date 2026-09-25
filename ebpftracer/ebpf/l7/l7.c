#define PROTOCOL_UNKNOWN     0
#define PROTOCOL_HTTP	     1
#define PROTOCOL_POSTGRES    2
#define PROTOCOL_REDIS	     3
#define PROTOCOL_MEMCACHED   4
#define PROTOCOL_MYSQL       5
#define PROTOCOL_MONGO       6
#define PROTOCOL_KAFKA       7
#define PROTOCOL_CASSANDRA   8
#define PROTOCOL_RABBITMQ    9
#define PROTOCOL_NATS       10
#define PROTOCOL_HTTP2	    11
#define PROTOCOL_DUBBO2     12
#define PROTOCOL_DNS        13
#define PROTOCOL_CLICKHOUSE 14
#define PROTOCOL_ZOOKEEPER  15
#define PROTOCOL_FOUNDATIONDB 16

#define STATUS_UNKNOWN  0
#define STATUS_OK       200
#define STATUS_FAILED   500

#define METHOD_UNKNOWN              0
#define METHOD_PRODUCE              1
#define METHOD_CONSUME              2
#define METHOD_STATEMENT_PREPARE    3
#define METHOD_STATEMENT_CLOSE      4
#define METHOD_HTTP2_CLIENT_FRAMES  5
#define METHOD_HTTP2_SERVER_FRAMES  6

#define IOVEC_BUF_SIZE MAX_PAYLOAD_SIZE * 2  // must be double of MAX_PAYLOAD_SIZE
#define MAX_IOVEC_SIZE 32
#define SENDMMSG_MAX_MSGS 32

static __always_inline
__u32 payload_copy_len(__u64 size) {
    __u32 n = MAX_PAYLOAD_SIZE;
    if (size < MAX_PAYLOAD_SIZE) {
        n = size;
    }
    asm volatile ("%0 &= %1" : "+r"(n) : "i"(IOVEC_BUF_SIZE - 1));
    return n;
}

// noinline: a stack dynptr must not outlive this helper (inlining poisons later probe_read_str).
static __attribute__((noinline))
int copy_to_payload(char *dst, __u32 offset, __u32 size, const void *src) {
    struct bpf_dynptr d;
    if (!size) {
        return 0;
    }
    if (bpf_dynptr_from_mem(dst, MAX_PAYLOAD_SIZE, 0, &d)) {
        return -1;
    }
    if (bpf_probe_read_user_dynptr(&d, offset, size, src) &&
        bpf_probe_read_kernel_dynptr(&d, offset, size, src)) {
        return -1;
    }
    return 0;
}

static __always_inline
int copy_payload(char *dst, __u64 *size, const void *src) {
    __u32 n = payload_copy_len(*size);
    if (copy_to_payload(dst, 0, n, src)) {
        return -1;
    }
    *size = n;
    return 0;
}

#define COPY_PAYLOAD(dst, size, src) ({                                 \
    if (copy_payload((dst), &(size), (src))) {                          \
        return 0;                                                       \
    }                                                                   \
})

// Bound a payload offset for the verifier without clamping 1024 to 1023.
// IOVEC_BUF_SIZE is 2048, so SIZE-1 keeps 1024 and still fits map+user reads.
#define PAYLOAD_BOUND(size) ({                                          \
    asm volatile ("%0 &= %1" : "+r"(size) : "i"(IOVEC_BUF_SIZE - 1));   \
})

#define PAYLOAD_READ(buf, off, dst) ({                                  \
    __u32 __off = (off);                                                \
    PAYLOAD_BOUND(__off);                                               \
    bpf_read((buf) + __off, dst);                                       \
})

#include "http.c"
#include "postgres.c"
#include "redis.c"
#include "memcached.c"
#include "mysql.c"
#include "mongo.c"
#include "kafka.c"
#include "cassandra.c"
#include "rabbitmq.c"
#include "nats.c"
#include "dubbo2.c"
#include "dns.c"
#include "clickhouse.c"
#include "zookeeper.c"
#include "foundationdb.c"

struct l7_event {
    __u64 fd;
    __u64 connection_timestamp;
    __u32 pid;
    __s32 status;
    __u64 duration;
    __u8 protocol;
    __u8 method;
    __u8 is_inbound;
    __u8 padding;
    __u32 statement_id;
    __u64 payload_size;
};

struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, int);
     __type(value, struct l7_event);
     __uint(max_entries, 1);
} l7_event_heap SEC(".maps");

#define L7_EVENTS_RINGBUF_SIZE (128 * 1024 * 1024)

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, L7_EVENTS_RINGBUF_SIZE);
} l7_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} l7_events_dropped SEC(".maps");

struct read_args {
    __u64 fd;
    char* buf;
    __u64* ret;
    __u64 iovlen;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct read_args));
    __uint(max_entries, 10240);
} active_reads SEC(".maps");

struct ssl_args {
    char *buf;
    __u64 size;
    __u64 fd;
    __u64 *ret_ptr;
    __u8 is_read;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct ssl_args));
    __uint(max_entries, 10240);
} ssl_pending SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 10240);
} rustls_last_read_fd SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 10240);
} java_tls_last_read_fd SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct ssl_args));
    __uint(max_entries, 10240);
} rustls_write_pending SEC(".maps");

#if defined(__TARGET_ARCH_x86)
#define RUSTLS_RET_IS_OK(x) (PT_REGS_RC(x) == 0)
#define RUSTLS_RET_SIZE(x) ((x)->dx)
#elif defined(__TARGET_ARCH_arm64)
#define RUSTLS_RET_IS_OK(x) (PT_REGS_RC(x) == 0)
#define RUSTLS_RET_SIZE(x) (((PT_REGS_ARM64 *)(x))->regs[1])
#endif

struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, int);
     __type(value, struct l7_request);
     __uint(max_entries, 1);
} l7_request_heap SEC(".maps");

struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, int);
     __type(value, char[IOVEC_BUF_SIZE]);
     __uint(max_entries, 1);
} iovec_buf_heap SEC(".maps");

struct trace_event_raw_sys_enter_rw__stub {
    __u64 unused;
    __u64 unused2;
    __u64 fd;
    char* buf;
    __u64 size;
};

struct iovec {
    char* buf;
    __u64 size;
};

struct user_msghdr {
	void *msg_name;
	int msg_namelen;
	struct iovec *msg_iov;
	__u64 msg_iovlen;
	void *msg_control;
    __u64 msg_controllen;
    __u32 msg_flags;
};

// BPF noinline functions take at most 5 arguments, so emit args are packed here.
// SEND_EVENT fills this on the caller stack and passes one pointer.
struct l7_send_args {
    struct l7_event *e;
    struct connection_id cid;
    struct connection *conn;
    const void *src;
    __u64 size;
};

struct l7_write_args {
    char *buf;
    __u64 fd;
    __u64 size;
    __u64 iovlen;
    __u8 socket_only;
};

struct sendmmsg_iter {
    void *ctx;
    char *mmsg;
    __u64 fd;
    __u32 vlen;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct l7_write_args);
} l7_write_args_heap SEC(".maps");

static __always_inline
void l7_drop_event(void) {
    __u32 zero = 0;
    __u64 *n = bpf_map_lookup_elem(&l7_events_dropped, &zero);
    if (n) {
        __sync_fetch_and_add(n, 1);
    }
}

// noinline: the reserved ringbuf dynptr must be submit/discarded here; inlining
// poisons later probe_read_str. One pointer arg because BPF caps noinline at 5.
static __attribute__((noinline))
void send_event(struct l7_send_args *a) {
    struct bpf_dynptr d = {};
    struct l7_event *e = a->e;
    __u32 n = payload_copy_len(a->size);
    __u32 rec = sizeof(*e) + n;

    e->connection_timestamp = a->conn->timestamp;
    e->fd = a->cid.fd;
    e->pid = a->cid.pid;
    e->payload_size = a->size;

    if (bpf_ringbuf_reserve_dynptr(&l7_events, rec, 0, &d)) {
        l7_drop_event();
        bpf_ringbuf_discard_dynptr(&d, 0);
        return;
    }
    if (bpf_dynptr_write(&d, 0, e, sizeof(*e), 0)) {
        bpf_ringbuf_discard_dynptr(&d, 0);
        return;
    }
    if (n &&
        bpf_probe_read_user_dynptr(&d, sizeof(*e), n, a->src) &&
        bpf_probe_read_kernel_dynptr(&d, sizeof(*e), n, a->src)) {
        bpf_ringbuf_discard_dynptr(&d, 0);
        return;
    }
    bpf_ringbuf_submit_dynptr(&d, 0);
}

// Packs send_event args. Underscored names so the preprocessor does not rewrite
// designated initializers (.src / .size) when the call site uses those tokens.
#define SEND_EVENT(_e, _cid, _conn, _src, _n) ({                        \
    struct l7_send_args __a = {                                         \
        .e = (_e), .cid = (_cid), .conn = (_conn),                      \
        .src = (_src), .size = (_n),                                    \
    };                                                                  \
    send_event(&__a);                                                   \
})

#include "http2.c"

static __always_inline
__u64 read_iovec(char *iovec, __u64 iovlen, __u64 ret, char *buf, __u64 *total_size) {
    struct iovec iov = {};
    __u32 max = payload_copy_len(ret ? ret : MAX_PAYLOAD_SIZE);
    __u32 offset = 0;
    #pragma unroll
    for (int i = 0; i < MAX_IOVEC_SIZE; i++) {
        if (i >= iovlen) {
            break;
        }
        if (bpf_probe_read(&iov, sizeof(iov), (void *)(iovec+i*sizeof(iov)))) {
            return 0;
        }
        if (iov.size <= 0) {
            continue;
        }
        *total_size += iov.size;
        if (offset < max) {
            __u32 size = payload_copy_len(max - offset);
            if (iov.size < size) {
                size = iov.size;
            }
            if (copy_to_payload(buf, offset, size, (void *)iov.buf)) {
                return 0;
            }
            offset += size;
        }
    }
    return offset;
}

static inline __attribute__((__always_inline__))
int handle_request(void *ctx, struct connection_id cid, struct connection *conn,
                   __u16 is_tls, char *payload, __u64 size, __u64 total_size,
                   __u8 from_heap, void *tail_progs);

static inline __attribute__((__always_inline__))
int handle_response(void *ctx, struct connection_id cid, struct connection *conn,
                    __u16 is_tls, char *payload, __u64 ret, __u64 total_size,
                    __u8 from_heap, void *tail_progs);

static inline __attribute__((__always_inline__))
int trace_enter_write(void *ctx, __u64 fd, __u16 is_tls, __u8 socket_only, char *buf, __u64 size, __u64 iovlen, void *tail_progs) {
    __u64 id = bpf_get_current_pid_tgid();
    http2_iov_clear();
    char *plain_buf = 0;
    __u64 plain_size = 0;
    if (!is_tls) {
        struct ssl_args *rw = bpf_map_lookup_elem(&rustls_write_pending, &id);
        if (rw) {
            plain_buf = rw->buf;
            plain_size = rw->size;
            bpf_map_delete_elem(&rustls_write_pending, &id);
        }
    }
    __u32 zero = 0;
    struct connection_id cid = {};
    cid.pid = id >> 32;
    cid.fd = fd;
    __u64 total_size = size;

    struct connection *conn = bpf_map_lookup_elem(&active_connections, &cid);
    if (!conn) {
        if (!socket_only) {
            return 0;
        }
        struct connection new_conn = {};
        new_conn.timestamp = bpf_ktime_get_ns();
        new_conn.is_inbound = 0;
        /* BPF_ANY, not BPF_NOEXIST: this cid's slot can hold a stale entry
           from an earlier, unrelated connection that reused the same
           (pid, fd) — BPF_NOEXIST would silently keep it (and its leftover
           h2_skip_req/resp state) instead of inserting new_conn, and
           nothing here checks bpf_map_update_elem's return to notice. The
           lookup right after would then hand back that stale connection —
           observed live as a brand new connection's very first read
           reporting a pending HTTP2 DATA skip of hundreds of bytes it
           never received. Always overwriting is correct here: reaching
           this fallback already means the normal tcp/state.c connect/accept
           tracking has no entry for this cid, so nothing legitimate is
           being clobbered. */
        bpf_map_update_elem(&active_connections, &cid, &new_conn, BPF_ANY);
        conn = bpf_map_lookup_elem(&active_connections, &cid);
        if (!conn) {
            return 0;
        }
    }

    char* payload = buf;
    if (iovlen && !plain_buf) {
        http2_load_iovecs(buf, iovlen, 0);
        conn = bpf_map_lookup_elem(&active_connections, &cid);
        if (!conn) {
            return 0;
        }
    }
    if (iovlen) {
        payload = bpf_map_lookup_elem(&iovec_buf_heap, &zero);
        if (!payload) {
            return 0;
        }
        total_size = 0;
        size = read_iovec(buf, iovlen, 0, payload, &total_size);
    }
    if (!size) {
        return 0;
    }

    if (!is_tls) {
        __sync_fetch_and_add(&conn->bytes_sent, total_size);
    }

    if (plain_buf) {
        payload = plain_buf;
        size = plain_size;
        is_tls = 1;
    }

    /* Ciphertext on a TLS socket stays out. Plaintext, including an uprobe
       buffer, takes the tail pipeline. */
    __u8 topup = is_tls || !conn->is_tls;
    if (topup && iovlen) {
        if (http2_tail_emit(ctx, cid, conn, 0, size, !conn->is_inbound, 1, tail_progs)) {
            return 0;
        }
    } else if (topup && http2_tail_emit(ctx, cid, conn, payload, size, !conn->is_inbound, 0, tail_progs)) {
        return 0;
    }

    __u8 from_heap = 0;
    if (iovlen && !plain_buf) {
        from_heap = 1;
    }
    if (conn->is_inbound) {
        return handle_response(ctx, cid, conn, is_tls, payload, size, total_size, from_heap, tail_progs);
    }
    return handle_request(ctx, cid, conn, is_tls, payload, size, total_size, from_heap, tail_progs);
}

// The parser is not inlined into the syscall. write, writev, sendmsg, sendto
// and sendmmsg all enter here. A tail call from the sendmmsg loop callback
// would abandon the rest of bpf_loop, so this stays a call.
static __attribute__((noinline))
int trace_enter_plain(void *ctx, struct l7_write_args *a) {
    if (!a) {
        return 0;
    }
    return trace_enter_write(ctx, a->fd, 0, a->socket_only, a->buf, a->size, a->iovlen, &http2_tail_progs);
}

/* noinline so each copy constant-folds its own prog array. A shared function
   would put both tail targets in both program types. */
static __attribute__((noinline))
int trace_enter_tls(void *ctx, __u64 fd, char *buf, __u64 size) {
    return trace_enter_write(ctx, fd, 1, 1, buf, size, 0, &http2_tail_progs);
}

static __attribute__((noinline))
int trace_enter_tls_kp(void *ctx, __u64 fd, char *buf, __u64 size) {
    return trace_enter_write(ctx, fd, 1, 1, buf, size, 0, &http2_tail_progs_kprobe);
}

static __always_inline
int trace_enter_plain_pack(void *ctx, __u64 fd, __u8 socket_only, char *buf, __u64 size, __u64 iovlen) {
    __u32 zero = 0;
    struct l7_write_args *a = bpf_map_lookup_elem(&l7_write_args_heap, &zero);
    if (!a) {
        return 0;
    }
    a->fd = fd;
    a->socket_only = socket_only;
    a->buf = buf;
    a->size = size;
    a->iovlen = iovlen;
    return trace_enter_plain(ctx, a);
}

static inline __attribute__((__always_inline__))
int handle_request(void *ctx, struct connection_id cid, struct connection *conn,
                   __u16 is_tls, char *payload, __u64 size, __u64 total_size,
                   __u8 from_heap, void *tail_progs) {
    if (is_tls) {
        conn->is_tls = 1;
    } else if (conn->is_tls) {
        return 0;
    }
    if (conn->protocol == PROTOCOL_HTTP2) {
        return 0;
    }

    __u32 zero = 0;
    struct l7_request_key k = {.pid = cid.pid, .fd = cid.fd, .is_tls = is_tls, .stream_id = -1};

    struct l7_request *pending = bpf_map_lookup_elem(&active_l7_requests, &k);
    if (pending && pending->protocol == PROTOCOL_UNKNOWN && pending->partial == 1) {
        bpf_map_delete_elem(&active_l7_requests, &k);
    }

    struct l7_request *req = bpf_map_lookup_elem(&l7_request_heap, &zero);
    if (!req) {
        return 0;
    }
    req->protocol = PROTOCOL_UNKNOWN;
    req->partial = 0;
    req->request_id = 0;
    req->request_type = 0;
    req->ns = 0;
    req->payload_size = size;

    if (is_http_request(payload)) {
        req->protocol = PROTOCOL_HTTP;
        conn->protocol = PROTOCOL_HTTP;
    } else if (is_postgres_query(payload, size, &req->request_type)) {
        if (req->request_type == POSTGRES_FRAME_CLOSE) {
            if (conn->is_inbound) {
                return 0;
            }
            struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
            if (!e) {
                return 0;
            }
            e->protocol = PROTOCOL_POSTGRES;
            e->method = METHOD_STATEMENT_CLOSE;
            e->is_inbound = 0;
            SEND_EVENT(e, cid, conn, payload, size);
            return 0;
        }
        req->protocol = PROTOCOL_POSTGRES;
    } else if (is_redis_query(payload, size)) {
        req->protocol = PROTOCOL_REDIS;
    } else if (is_memcached_query(payload, size)) {
        req->protocol = PROTOCOL_MEMCACHED;
    } else if (is_mysql_query(payload, size, &req->request_type, pending)) {
        if (req->request_type == MYSQL_COM_STMT_CLOSE) {
            if (conn->is_inbound) {
                return 0;
            }
            struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
            if (!e) {
                return 0;
            }
            e->protocol = PROTOCOL_MYSQL;
            e->method = METHOD_STATEMENT_CLOSE;
            e->is_inbound = 0;
            SEND_EVENT(e, cid, conn, payload, size);
            return 0;
        }
        req->protocol = PROTOCOL_MYSQL;
    } else if (is_mongo_query(payload, size)) {
        req->protocol = PROTOCOL_MONGO;
    } else if (is_rabbitmq_method_frame(payload, size)) {
        if (!conn->is_inbound && rabbitmq_method_matches(payload, RABBITMQ_METHOD_PUBLISH)) {
            struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
            if (!e) {
                return 0;
            }
            e->protocol = PROTOCOL_RABBITMQ;
            e->method = METHOD_PRODUCE;
            e->status = STATUS_OK;
            e->is_inbound = 0;
            SEND_EVENT(e, cid, conn, 0, 0);
        }
        return 0;
    } else if (!conn->is_inbound && nats_method(payload, size) == METHOD_PRODUCE) {
        struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
        if (!e) {
            return 0;
        }
        e->protocol = PROTOCOL_NATS;
        e->method = METHOD_PRODUCE;
        e->status = STATUS_OK;
        e->is_inbound = 0;
        SEND_EVENT(e, cid, conn, 0, 0);
        return 0;
    } else if (is_cassandra_request(payload, size, &k.stream_id)) {
        req->protocol = PROTOCOL_CASSANDRA;
    } else if (conn->protocol == PROTOCOL_UNKNOWN && is_http2(payload, size)) {
        conn->protocol = PROTOCOL_HTTP2;
        return http2_emit_fresh(ctx, cid, conn, payload, size, 1, from_heap, tail_progs);
    } else if (is_clickhouse_query(payload, size)) {
        req->protocol = PROTOCOL_CLICKHOUSE;
    } else if (is_zk_request(payload, total_size)) {
        req->protocol = PROTOCOL_ZOOKEEPER;
    } else if (is_kafka_request(payload, size, &req->request_id)) {
        req->protocol = PROTOCOL_KAFKA;
        struct l7_request *prev_req = bpf_map_lookup_elem(&active_l7_requests, &k);
        if (prev_req && prev_req->protocol == PROTOCOL_KAFKA) {
            req->ns = prev_req->ns;
        }
    } else if (is_dubbo2_request(payload, size)) {
        req->protocol = PROTOCOL_DUBBO2;
    } else if (is_dns_request(payload, size, &k.stream_id)) {
        req->protocol = PROTOCOL_DNS;
    } else if (is_foundationdb_request(payload, size)) {
        req->protocol = PROTOCOL_FOUNDATIONDB;
    }

    if (req->protocol == PROTOCOL_UNKNOWN) {
        __u32 payload_length;
        if (conn->is_inbound && is_mysql_partial_header(payload, size, &payload_length)) {
            req->partial = 1;
            req->payload_size = payload_length;
            req->ns = bpf_ktime_get_ns();
            bpf_map_update_elem(&active_l7_requests, &k, req, BPF_NOEXIST);
        }
        return 0;
    }
    if (req->ns == 0) {
        req->ns = bpf_ktime_get_ns();
    }
    COPY_PAYLOAD(req->payload, size, payload);
    bpf_map_update_elem(&active_l7_requests, &k, req, BPF_NOEXIST);
    return 0;
}

static inline __attribute__((__always_inline__))
int trace_enter_read(__u64 id, __u32 pid, __u64 fd, __u8 socket_only, char *buf, __u64 *ret, __u64 iovlen) {
    if (bpf_map_lookup_elem(&rustls_pids, &pid)) {
        bpf_map_update_elem(&rustls_last_read_fd, &id, &fd, BPF_ANY);
    }
    if (bpf_map_lookup_elem(&java_tls_pids, &pid)) {
        bpf_map_update_elem(&java_tls_last_read_fd, &id, &fd, BPF_ANY);
    }

    if (!socket_only) {
        struct connection_id cid = {};
        cid.pid = pid;
        cid.fd = fd;
        if (!bpf_map_lookup_elem(&active_connections, &cid)) {
            return 0;
        }
    }

    struct read_args args = {};
    args.fd = fd;
    args.buf = buf;
    args.ret = ret;
    args.iovlen = iovlen;
    bpf_map_update_elem(&active_reads, &id, &args, BPF_ANY);
    return 0;
}

static inline __attribute__((__always_inline__))
int trace_exit_read(void *ctx, __u64 id, __u32 pid, __u16 is_tls, long int ret, void *tail_progs) {
    struct read_args *args = bpf_map_lookup_elem(&active_reads, &id);
    if (!args) {
        return 0;
    }
    struct connection_id cid = {};
    cid.pid = pid;
    cid.fd = args->fd;
    bpf_map_delete_elem(&active_reads, &id);

    if (ret <= 0) {
        return 0;
    }
    if (args->ret) {
        if (bpf_probe_read(&ret, sizeof(ret), (void*)args->ret)) {
            return 0;
        };
        if (ret <= 0) {
            return 0;
        }
    }

    struct connection *conn = bpf_map_lookup_elem(&active_connections, &cid);
    if (!conn) {
        struct connection new_conn = {};
        new_conn.timestamp = bpf_ktime_get_ns();
        new_conn.is_inbound = 1;
        /* BPF_ANY: see the matching fallback in trace_enter_write for why
           BPF_NOEXIST here can hand back a stale, unrelated connection's
           leftover HTTP2 skip state on a (pid, fd) reuse. */
        bpf_map_update_elem(&active_connections, &cid, &new_conn, BPF_ANY);
        conn = bpf_map_lookup_elem(&active_connections, &cid);
        if (!conn) {
            return 0;
        }
    }
    __u64 total_size = ret;
    int zero = 0;
    char* payload = args->buf;
    if (args->iovlen) {
        payload = bpf_map_lookup_elem(&iovec_buf_heap, &zero);
        if (!payload) {
            return 0;
        }
        total_size = 0;
        ret = read_iovec(args->buf, args->iovlen, ret, payload, &total_size);
        if (!ret) {
            return 0;
        }
    }

    if (!is_tls) {
        __sync_fetch_and_add(&conn->bytes_received, total_size);
    }

    __u8 topup = is_tls || !conn->is_tls;
    if (topup && args->iovlen) {
        if (http2_tail_emit(ctx, cid, conn, 0, ret, conn->is_inbound, 1, tail_progs)) {
            return 0;
        }
    } else if (topup && http2_tail_emit(ctx, cid, conn, payload, ret, conn->is_inbound, 0, tail_progs)) {
        return 0;
    }

    __u8 from_heap = 0;
    if (args->iovlen) {
        from_heap = 1;
    }
    if (conn->is_inbound) {
        return handle_request(ctx, cid, conn, is_tls, payload, ret, total_size, from_heap, tail_progs);
    }
    return handle_response(ctx, cid, conn, is_tls, payload, ret, total_size, from_heap, tail_progs);
}

static inline __attribute__((__always_inline__))
int handle_response(void *ctx, struct connection_id cid, struct connection *conn,
                    __u16 is_tls, char *payload, __u64 ret, __u64 total_size,
                    __u8 from_heap, void *tail_progs) {
    if (is_tls) {
        conn->is_tls = 1;
    } else if (conn->is_tls) {
        return 0;
    }
    if (conn->protocol == PROTOCOL_HTTP2) {
        return 0;
    }

    int zero = 0;
    struct l7_request_key k = {.pid = cid.pid, .fd = cid.fd, .is_tls = is_tls, .stream_id = -1};
    struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
    if (!e) {
        return 0;
    }
    e->protocol = PROTOCOL_UNKNOWN;
    e->status = STATUS_UNKNOWN;
    e->method = METHOD_UNKNOWN;
    e->statement_id = 0;
    e->payload_size = 0;
    e->is_inbound = conn->is_inbound;

    if (!conn->is_inbound) {
        if (is_rabbitmq_method_frame(payload, ret)) {
            if (rabbitmq_method_matches(payload, RABBITMQ_METHOD_DELIVER)) {
                e->protocol = PROTOCOL_RABBITMQ;
                e->method = METHOD_CONSUME;
                e->status = STATUS_OK;
                SEND_EVENT(e, cid, conn, 0, 0);
            }
            return 0;
        }
        if (nats_method(payload, ret) == METHOD_CONSUME) {
            e->protocol = PROTOCOL_NATS;
            e->method = METHOD_CONSUME;
            e->status = STATUS_OK;
            SEND_EVENT(e, cid, conn, 0, 0);
            return 0;
        }
    }

    struct l7_request *req = bpf_map_lookup_elem(&active_l7_requests, &k);
    int response = 0;
    if (!req) {
        if (is_dns_response(payload, ret, &k.stream_id, &e->status)) {
            req = bpf_map_lookup_elem(&active_l7_requests, &k);
            if (!req) {
                return 0;
            }
            e->protocol = PROTOCOL_DNS;
            e->duration = bpf_ktime_get_ns() - req->ns;
            SEND_EVENT(e, cid, conn, payload, ret);
            bpf_map_delete_elem(&active_l7_requests, &k);
            return 0;
        } else if (is_cassandra_response(payload, ret, &k.stream_id, &e->status)) {
            req = bpf_map_lookup_elem(&active_l7_requests, &k);
            if (!req) {
                return 0;
            }
            response = 1;
        } else if (conn->protocol == PROTOCOL_UNKNOWN && is_http2(payload, ret)) {
            conn->protocol = PROTOCOL_HTTP2;
            return http2_emit_fresh(ctx, cid, conn, payload, ret, 0, from_heap, tail_progs);
        } else {
            return 0;
        }
    }

    e->protocol = req->protocol;
    if (e->protocol == PROTOCOL_HTTP) {
        response = is_http_response(payload, &e->status);
        if (response) {
            conn->protocol = PROTOCOL_HTTP;
        }
    } else if (e->protocol == PROTOCOL_POSTGRES) {
        response = is_postgres_response(payload, ret, &e->status);
        if (req->request_type == POSTGRES_FRAME_PARSE) {
            e->method = METHOD_STATEMENT_PREPARE;
        }
    } else if (e->protocol == PROTOCOL_REDIS) {
        response = is_redis_response(payload, ret, &e->status);
    } else if (e->protocol == PROTOCOL_MEMCACHED) {
        response = is_memcached_response(payload, ret, &e->status);
    } else if (e->protocol == PROTOCOL_MYSQL) {
        response = is_mysql_response(payload, ret, req->request_type, &e->statement_id, &e->status);
        if (req->request_type == MYSQL_COM_STMT_PREPARE) {
            e->method = METHOD_STATEMENT_PREPARE;
        }
    } else if (e->protocol == PROTOCOL_MONGO) {
        response = is_mongo_response(payload, ret, req->partial);
        if (response == 2) { // partial
            req->partial = 1;
            return 0; // keeping the query in the map
        }
    } else if (e->protocol == PROTOCOL_KAFKA) {
        response = is_kafka_response(payload, req->request_id);
    } else if (e->protocol == PROTOCOL_CLICKHOUSE) {
        response = is_clickhouse_response(payload, ret, &e->status);
        if (!response) {
            return 0; // keeping the query in the map
        }
    } else if (e->protocol == PROTOCOL_ZOOKEEPER) {
        response = is_zk_response(payload, total_size, &e->status, req->partial);
        if (response == 2) { // partial
            req->partial = 1;
            return 0; // keeping the query in the map
        }
    } else if (e->protocol == PROTOCOL_DUBBO2) {
        response = is_dubbo2_response(payload, &e->status);
    } else if (e->protocol == PROTOCOL_FOUNDATIONDB) {
        response = is_foundationdb_response(payload, ret, &e->status);
        if (response == 2) { // partial
            return 0; // keeping the query in the map
        }
    }
    if (!response) {
        bpf_map_delete_elem(&active_l7_requests, &k);
        return 0;
    }
    e->duration = bpf_ktime_get_ns() - req->ns;
    SEND_EVENT(e, cid, conn, req->payload, req->payload_size);
    bpf_map_delete_elem(&active_l7_requests, &k);
    return 0;
}

static inline __attribute__((__always_inline__))
int ssl_check_write(__u64 tid, void *ctx, __u64 fd) {
    struct ssl_args *args = bpf_map_lookup_elem(&ssl_pending, &tid);
    if (!args || args->is_read) {
        return -1;
    }
    char *buf = args->buf;
    __u64 size = args->size;
    bpf_map_delete_elem(&ssl_pending, &tid);
    return trace_enter_tls(ctx, fd, buf, size);
}

// Not inlined into sys_enter_sendmmsg. That frame also holds the loop
// iterator, and the two together push the combined stack over 512 bytes.
static __attribute__((noinline))
int sendmmsg_ssl(__u64 tid, void *ctx, __u64 fd) {
    return ssl_check_write(tid, ctx, fd);
}

static inline __attribute__((__always_inline__))
int ssl_check_read_enter(__u64 tid, __u64 fd) {
    struct ssl_args *args = bpf_map_lookup_elem(&ssl_pending, &tid);
    if (!args || !args->is_read) {
        return -1;
    }
    if (!args->fd) {
        args->fd = fd;
        bpf_map_update_elem(&ssl_last_fd, &tid, &fd, BPF_ANY);
        return 0;
    }
    return -1;
}

static inline __attribute__((__always_inline__))
int ssl_check_read_exit(__u64 tid) {
    struct ssl_args *args = bpf_map_lookup_elem(&ssl_pending, &tid);
    if (!args || !args->is_read) {
        return -1;
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int sys_enter_write(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    if (ssl_check_write(tid, ctx, ctx->fd) >= 0) {
        return 0;
    }
    return trace_enter_plain_pack(ctx, ctx->fd, 0, ctx->buf, ctx->size, 0);
}

SEC("tracepoint/syscalls/sys_enter_writev")
int sys_enter_writev(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    if (ssl_check_write(tid, ctx, ctx->fd) >= 0) {
        return 0;
    }
    return trace_enter_plain_pack(ctx, ctx->fd, 0, ctx->buf, 0, ctx->size);
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int sys_enter_sendmsg(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    if (ssl_check_write(tid, ctx, ctx->fd) >= 0) {
        return 0;
    }
    struct user_msghdr msghdr = {};
    if (bpf_probe_read(&msghdr, sizeof(msghdr), (void *)ctx->buf)) {
        return 0;
    }
    return trace_enter_plain_pack(ctx, ctx->fd, 1, (char*)msghdr.msg_iov, 0, msghdr.msg_iovlen);
}

struct mmsghdr {
	struct user_msghdr msg_hdr;
	__u32 msg_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mmsghdr);
} sendmmsg_hdr SEC(".maps");

static long sendmmsg_cb(__u32 i, void *ctx) {
    struct sendmmsg_iter *it = ctx;
    struct mmsghdr *h;
    char *iov;
    __u64 iovlen;
    __u64 off;
    __u32 zero = 0;
    if (!it || i >= it->vlen) {
        return 1;
    }
    h = bpf_map_lookup_elem(&sendmmsg_hdr, &zero);
    if (!h) {
        return 1;
    }
    off = (__u64)i * sizeof(*h);
    if (bpf_probe_read(h, sizeof(*h), it->mmsg + off)) {
        return 1;
    }
    iov = (char *)h->msg_hdr.msg_iov;
    iovlen = h->msg_hdr.msg_iovlen;
    trace_enter_plain_pack(it->ctx, it->fd, 1, iov, 0, iovlen);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int sys_enter_sendmmsg(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    struct sendmmsg_iter it = {};
    __u32 n = SENDMMSG_MAX_MSGS;
    if (sendmmsg_ssl(tid, ctx, ctx->fd) >= 0) {
        return 0;
    }
    if (ctx->size < n) {
        n = ctx->size;
    }
    if (!n) {
        return 0;
    }
    it.ctx = ctx;
    it.mmsg = ctx->buf;
    it.fd = ctx->fd;
    it.vlen = n;
    bpf_loop(n, sendmmsg_cb, &it, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int sys_enter_sendto(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    if (ssl_check_write(tid, ctx, ctx->fd) >= 0) {
        return 0;
    }
    return trace_enter_plain_pack(ctx, ctx->fd, 1, ctx->buf, ctx->size, 0);
}

SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    if (ssl_check_read_enter(id, ctx->fd) >= 0) {
        return 0;
    }
    __u32 pid = id >> 32;
    return trace_enter_read(id, pid, ctx->fd, 0, ctx->buf, 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_readv")
int sys_enter_readv(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    if (ssl_check_read_enter(id, ctx->fd) >= 0) {
        return 0;
    }
    __u32 pid = id >> 32;
    return trace_enter_read(id, pid, ctx->fd, 0, ctx->buf, 0, ctx->size);
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int sys_enter_recvmsg(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    if (ssl_check_read_enter(id, ctx->fd) >= 0) {
        return 0;
    }
    struct user_msghdr msghdr = {};
    if (bpf_probe_read(&msghdr, sizeof(msghdr), (void *)ctx->buf)) {
        return 0;
    }
    __u32 pid = id >> 32;
    return trace_enter_read(id, pid, ctx->fd, 1, (char*)msghdr.msg_iov, 0, msghdr.msg_iovlen);
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int sys_enter_recvfrom(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    if (ssl_check_read_enter(id, ctx->fd) >= 0) {
        return 0;
    }
    __u32 pid = id >> 32;
    return trace_enter_read(id, pid, ctx->fd, 1, ctx->buf, 0, 0);
}

SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct trace_event_raw_sys_exit__stub* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if (ssl_check_read_exit(pid_tgid) >= 0) {
        return 0;
    }
    __u32 pid = pid_tgid >> 32;
    return trace_exit_read(ctx, pid_tgid, pid, 0, ctx->ret, &http2_tail_progs);
}

SEC("tracepoint/syscalls/sys_exit_readv")
int sys_exit_readv(struct trace_event_raw_sys_exit__stub* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if (ssl_check_read_exit(pid_tgid) >= 0) {
        return 0;
    }
    bpf_tail_call(ctx, &http2_tail_progs, HTTP2_TAIL_READV);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int sys_exit_recvmsg(struct trace_event_raw_sys_exit__stub* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if (ssl_check_read_exit(pid_tgid) >= 0) {
        return 0;
    }
    bpf_tail_call(ctx, &http2_tail_progs, HTTP2_TAIL_READV);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int sys_exit_recvfrom(struct trace_event_raw_sys_exit__stub* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if (ssl_check_read_exit(pid_tgid) >= 0) {
        return 0;
    }
    __u32 pid = pid_tgid >> 32;
    return trace_exit_read(ctx, pid_tgid, pid, 0, ctx->ret, &http2_tail_progs);
}

