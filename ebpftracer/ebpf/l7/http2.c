#define HTTP2_PREFACE_SIZE 24
#define HTTP2_FRAME_HEADER_SIZE 9
#define HTTP2_SNIFF_MAX_FRAMES 8
#define HTTP2_MAX_FRAME_LEN (1 << 22)

#define HTTP2_FRAME_DATA 0x0
#define HTTP2_FRAME_HEADERS 0x1
#define HTTP2_FRAME_PRIORITY 0x2
#define HTTP2_FRAME_RST_STREAM 0x3
#define HTTP2_FRAME_SETTINGS 0x4
#define HTTP2_FRAME_PUSH_PROMISE 0x5
#define HTTP2_FRAME_PING 0x6
#define HTTP2_FRAME_GOAWAY 0x7
#define HTTP2_FRAME_WINDOW 0x8
#define HTTP2_FRAME_CONTINUATION 0x9

#define HTTP2_FLAG_END_STREAM 0x1
#define HTTP2_FLAG_ACK 0x1
#define HTTP2_FLAG_END_HEADERS 0x4
#define HTTP2_FLAG_PADDED 0x8
#define HTTP2_FLAG_PRIORITY 0x20

struct http2_sniff_state {
    char *buf;
    __u64 size;
    __u32 pos;
    __u8 saw_headers;
    __u8 open_headers;
    __u8 ok;
    __u8 fail;
};

static __always_inline
int is_http2_preface(char *buf, __u64 size) {
    char p[6];
    if (size < HTTP2_PREFACE_SIZE) {
        return 0;
    }
    if (bpf_probe_read(p, sizeof(p), buf)) {
        return 0;
    }
    return p[0] == 'P' && p[1] == 'R' && p[2] == 'I' && p[3] == ' ' && p[4] == '*';
}

static __always_inline
int is_http2_settings(char *buf, __u64 size) {
    unsigned char hdr[HTTP2_FRAME_HEADER_SIZE];
    __u32 length;
    __u32 stream_id;
    if (size < HTTP2_FRAME_HEADER_SIZE) {
        return 0;
    }
    if (bpf_probe_read(hdr, sizeof(hdr), buf)) {
        return 0;
    }
    if (hdr[3] != HTTP2_FRAME_SETTINGS || (hdr[5] & 0x80)) {
        return 0;
    }
    stream_id = ((__u32)hdr[5] << 24) | ((__u32)hdr[6] << 16) | ((__u32)hdr[7] << 8) | hdr[8];
    if (stream_id != 0) {
        return 0;
    }
    length = ((__u32)hdr[0] << 16) | ((__u32)hdr[1] << 8) | hdr[2];
    if (length % 6 != 0) {
        return 0;
    }
    return HTTP2_FRAME_HEADER_SIZE + length <= size;
}

static __always_inline
__u8 http2_flags_mask(__u8 type) {
    switch (type) {
    case HTTP2_FRAME_DATA:
        return HTTP2_FLAG_END_STREAM | HTTP2_FLAG_PADDED;
    case HTTP2_FRAME_HEADERS:
        return HTTP2_FLAG_END_STREAM | HTTP2_FLAG_END_HEADERS | HTTP2_FLAG_PADDED | HTTP2_FLAG_PRIORITY;
    case HTTP2_FRAME_SETTINGS:
    case HTTP2_FRAME_PING:
        return HTTP2_FLAG_ACK;
    case HTTP2_FRAME_PUSH_PROMISE:
        return HTTP2_FLAG_END_HEADERS | HTTP2_FLAG_PADDED;
    case HTTP2_FRAME_CONTINUATION:
        return HTTP2_FLAG_END_HEADERS;
    default:
        return 0;
    }
}

static __always_inline
int http2_frame_plausible(__u8 type, __u8 flags, __u32 stream_id, __u32 length) {
    if (type > HTTP2_FRAME_CONTINUATION) {
        return 0;
    }
    if (flags & ~http2_flags_mask(type)) {
        return 0;
    }
    if (length > HTTP2_MAX_FRAME_LEN) {
        return 0;
    }
    switch (type) {
    case HTTP2_FRAME_DATA:
        if (stream_id == 0) {
            return 0;
        }
        return length > 0 || (flags & HTTP2_FLAG_END_STREAM);
    case HTTP2_FRAME_HEADERS:
    case HTTP2_FRAME_PUSH_PROMISE:
    case HTTP2_FRAME_CONTINUATION:
        return stream_id != 0 && length > 0;
    case HTTP2_FRAME_PRIORITY:
        return stream_id != 0 && length == 5;
    case HTTP2_FRAME_RST_STREAM:
        return stream_id != 0 && length == 4;
    case HTTP2_FRAME_SETTINGS:
        if (flags & HTTP2_FLAG_ACK) {
            return stream_id == 0 && length == 0;
        }
        return stream_id == 0 && length % 6 == 0;
    case HTTP2_FRAME_PING:
        return stream_id == 0 && length == 8;
    case HTTP2_FRAME_GOAWAY:
        return stream_id == 0 && length >= 8;
    case HTTP2_FRAME_WINDOW:
        return length == 4;
    }
    return 0;
}

static long looks_like_http2_cb(__u32 i, void *ctx) {
    struct http2_sniff_state *s = ctx;
    (void)i;
    unsigned char hdr[HTTP2_FRAME_HEADER_SIZE];
    __u32 pos;
    __u32 length;
    __u32 stream_id;
    __u64 next;
    __u8 type;
    __u8 flags;
    if (!s || s->fail || s->ok) {
        return 1;
    }
    pos = s->pos;
    if (pos >= s->size) {
        if (s->saw_headers && !s->open_headers && pos == s->size) {
            s->ok = 1;
        } else {
            s->fail = 1;
        }
        return 1;
    }
    if (pos > MAX_PAYLOAD_SIZE - HTTP2_FRAME_HEADER_SIZE) {
        s->fail = 1;
        return 1;
    }
    pos &= MAX_PAYLOAD_SIZE - 1;
    if (pos + HTTP2_FRAME_HEADER_SIZE > s->size) {
        s->fail = 1;
        return 1;
    }
    if (bpf_probe_read(hdr, sizeof(hdr), s->buf + pos)) {
        s->fail = 1;
        return 1;
    }
    if (hdr[5] & 0x80) {
        s->fail = 1;
        return 1;
    }
    type = hdr[3];
    flags = hdr[4];
    length = ((__u32)hdr[0] << 16) | ((__u32)hdr[1] << 8) | hdr[2];
    stream_id = ((__u32)hdr[5] << 24) | ((__u32)hdr[6] << 16) | ((__u32)hdr[7] << 8) | hdr[8];
    if (!http2_frame_plausible(type, flags, stream_id, length)) {
        s->fail = 1;
        return 1;
    }
    if (type == HTTP2_FRAME_HEADERS) {
        if (stream_id == 0 || (stream_id & 1) == 0 || s->open_headers) {
            s->fail = 1;
            return 1;
        }
        s->saw_headers = 1;
        s->open_headers = (flags & HTTP2_FLAG_END_HEADERS) == 0;
    } else if (type == HTTP2_FRAME_CONTINUATION) {
        if (!s->open_headers) {
            s->fail = 1;
            return 1;
        }
        s->open_headers = (flags & HTTP2_FLAG_END_HEADERS) == 0;
    } else if (s->open_headers) {
        s->fail = 1;
        return 1;
    }
    next = (__u64)pos + HTTP2_FRAME_HEADER_SIZE + length;
    if (next > s->size) {
        s->fail = 1;
        return 1;
    }
    s->pos = next;
    if (next == s->size) {
        if (s->saw_headers && !s->open_headers) {
            s->ok = 1;
        } else {
            s->fail = 1;
        }
        return 1;
    }
    return 0;
}

static __attribute__((noinline))
int looks_like_http2_frames(char *buf, __u64 size) {
    struct http2_sniff_state s = {};
    if (!buf || size < HTTP2_FRAME_HEADER_SIZE) {
        return 0;
    }
    s.buf = buf;
    s.size = size;
    bpf_loop(HTTP2_SNIFF_MAX_FRAMES, looks_like_http2_cb, &s, 0);
    return s.ok && !s.fail;
}

static __attribute__((noinline))
int is_http2(char *buf, __u64 size) {
    if (!buf) {
        return 0;
    }
    if (size > MAX_PAYLOAD_SIZE) {
        size = MAX_PAYLOAD_SIZE;
    }
    if (is_http2_preface(buf, size) || is_http2_settings(buf, size)) {
        return 1;
    }
    return looks_like_http2_frames(buf, size);
}

#ifndef HTTP2_TRIM_MAX_FRAMES
#define HTTP2_TRIM_MAX_FRAMES 8388608
#endif
/* Pointer offsets have to be masked for the verifier. 128MiB matches the
   ring: a larger input cannot be stored as messages anyway. */
#ifndef HTTP2_SRC_MAX
#define HTTP2_SRC_MAX (128u * 1024u * 1024u)
#endif
#define HTTP2_SRC_BOUND(size) ({                                        \
    asm volatile ("%0 &= %1" : "+r"(size) : "i"(HTTP2_SRC_MAX - 1));    \
})
/* Payload bytes that fit in one ring slot next to a 9-byte frame header. */
#define HTTP2_CAPTURE_MAX (MAX_PAYLOAD_SIZE - HTTP2_FRAME_HEADER_SIZE)

/* Clamp a body length to the slot, then give the verifier a 10-bit mask and
   clamp again. PAYLOAD_BOUND's 2047 mask is wider than the 1024-byte dynptr,
   so copy_to_payload inside bpf_loop crosses the 8192-jump limit. */
static __always_inline __u32 http2_bound_body(__u32 n) {
    if (n > HTTP2_CAPTURE_MAX) {
        n = HTTP2_CAPTURE_MAX;
    }
    asm volatile("%0 &= %1" : "+r"(n) : "i"(MAX_PAYLOAD_SIZE - 1));
    if (n > HTTP2_CAPTURE_MAX) {
        n = HTTP2_CAPTURE_MAX;
    }
    return n;
}
/* h2_skip_*_data value: skip_stream holds the HTTP2 stream ID the pending
   resume belongs to (the capture budget itself lives in http2_stream_budget,
   looked up fresh on every call — there is nothing else to persist). */
#define HTTP2_SKIP_HEADER 2
/* Walk stopped on a cut HEADERS, CONTINUATION or DATA frame. pos is the
   frame start. Not stored on the connection — http2_cut handles it. */
#define HTTP2_SKIP_CUT 3

/* Cumulative body bytes captured per (connection, direction, HTTP2 stream) —
   across as many frames and emitted events as it takes — replacing what used
   to be a flat per-frame cap (HTTP2_CAPTURE_MAX, still the per-ring-slot
   ceiling for a single captured chunk). */
#define HTTP2_STREAM_CAPTURE_MAX 4096

/* Keyed by conn->timestamp, not (fd, pid): fds get closed and reused by an
   unrelated later connection constantly (every short-lived HTTP2 connection
   in these tests, and plenty of real workloads too), and a fresh connection
   that happens to reuse both an old fd AND a low, common stream ID (most
   protocols start client streams at 1) would otherwise inherit whatever
   budget the previous, unrelated connection had already spent. The
   connection timestamp is reset by the kernel on every accept()/connect(),
   so it uniquely names this connection's generation regardless of fd
   reuse — the same fix as the test harness's own fd-reuse race (see
   watchConn in tracer_test.go). */
struct http2_stream_key {
    __u64 conn_ts;
    __u32 stream_id;
    __u8 is_req;
    __u8 pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct http2_stream_key));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 4096);
} http2_stream_budget SEC(".maps");

/* noinline: called from within bpf_loop callbacks that already juggle a lot
   of scalar-range state (frame parsing, ring-slot math); inlining another
   map lookup's branches into them was enough to blow up verifier state
   exploration in the iovec walker. As a real subprogram call this is
   verified once, with a fixed, narrow argument contract. */
static __attribute__((noinline))
__u32 http2_stream_used(__u64 conn_ts, __u32 stream_id, __u8 is_req) {
    struct http2_stream_key k = {.conn_ts = conn_ts, .stream_id = stream_id, .is_req = is_req};
    __u32 *v = bpf_map_lookup_elem(&http2_stream_budget, &k);
    return v ? *v : 0;
}

/* Bytes this stream may still capture before hitting HTTP2_STREAM_CAPTURE_MAX. */
static __attribute__((noinline))
__u32 http2_stream_remaining(__u64 conn_ts, __u32 stream_id, __u8 is_req) {
    __u32 used = http2_stream_used(conn_ts, stream_id, is_req);
    if (used >= HTTP2_STREAM_CAPTURE_MAX) {
        return 0;
    }
    return HTTP2_STREAM_CAPTURE_MAX - used;
}

static __attribute__((noinline))
void http2_stream_add(__u64 conn_ts, __u32 stream_id, __u8 is_req, __u32 n) {
    struct http2_stream_key k = {.conn_ts = conn_ts, .stream_id = stream_id, .is_req = is_req};
    __u32 *v;
    if (!n) {
        return;
    }
    v = bpf_map_lookup_elem(&http2_stream_budget, &k);
    if (v) {
        *v += n;
        return;
    }
    bpf_map_update_elem(&http2_stream_budget, &k, &n, BPF_ANY);
}

/* h2_skip_req/h2_skip_resp on struct connection hold the same three fields
   (skip, packed stream/progress, data kind) for the two directions. Both
   the contiguous walker and the iovec walker below resume from and save to
   this state, so the load/save pair lives here once. */
static __always_inline
void http2_skip_save(struct connection *conn, __u8 is_req, __u32 skip, __u32 packed, __u8 data) {
    if (!conn) {
        return;
    }
    if (is_req) {
        conn->h2_skip_req = skip;
        conn->h2_skip_req_stream = packed;
        conn->h2_skip_req_data = data;
    } else {
        conn->h2_skip_resp = skip;
        conn->h2_skip_resp_stream = packed;
        conn->h2_skip_resp_data = data;
    }
}

static __always_inline
void http2_skip_load(struct connection *conn, __u8 is_req, __u32 *skip, __u32 *packed, __u8 *data) {
    if (is_req) {
        *skip = conn->h2_skip_req;
        *packed = conn->h2_skip_req_stream;
        *data = conn->h2_skip_req_data;
    } else {
        *skip = conn->h2_skip_resp;
        *packed = conn->h2_skip_resp_stream;
        *data = conn->h2_skip_resp_data;
    }
}

/* want = min(skip left to top up, bytes available from this call's source,
   remaining stream budget), then bounded to one ring slot's capacity.
   Shared by the contiguous and iovec walkers' pending-skip top-up: both
   compute this identical chain, only "how much is available" and "how to
   copy/skip it" differ by source, and those stay at the call site. */
static __always_inline
__u32 http2_skip_topup_want(__u32 skip, __u32 left, __u32 budget) {
    __u32 want = skip;
    if (want > left) {
        want = left;
    }
    if (want > budget) {
        want = budget;
    }
    if (want > HTTP2_CAPTURE_MAX) {
        want = HTTP2_CAPTURE_MAX;
    }
    PAYLOAD_BOUND(want);
    return want;
}

/* After a top-up round drains `skip` down, decide whether the stream's
   pending skip-header resume persists (more to skip and the stream can
   still take more) or clears. Shared for the same reason as the above. */
static __always_inline
void http2_skip_topup_next(__u64 conn_ts, __u32 stream_id, __u8 is_req, __u32 skip,
                            __u32 *packed_out, __u8 *data_out) {
    if (!skip) {
        *packed_out = 0;
        *data_out = 0;
    } else if (http2_stream_remaining(conn_ts, stream_id, is_req)) {
        *packed_out = stream_id;
        *data_out = HTTP2_SKIP_HEADER;
    } else {
        *packed_out = 0;
        *data_out = 0;
    }
}

/* Builds a frame header with a (possibly trimmed) length field, keeping
   type/flags/stream_id from the original. Shared by every place that emits
   a frame: the two walkers and the two cut-frame completions. */
static __always_inline
void http2_encode_frame_header(unsigned char nh[HTTP2_FRAME_HEADER_SIZE], __u32 len,
                                const unsigned char hdr[HTTP2_FRAME_HEADER_SIZE]) {
    nh[0] = len >> 16;
    nh[1] = len >> 8;
    nh[2] = len;
    nh[3] = hdr[3];
    nh[4] = hdr[4];
    nh[5] = hdr[5];
    nh[6] = hdr[6];
    nh[7] = hdr[7];
    nh[8] = hdr[8];
}

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, char[MAX_PAYLOAD_SIZE]);
    __uint(max_entries, 1);
} http2_emit_heap SEC(".maps");

struct http2_trim_args {
    struct connection_id cid;
    char *src;
    char *dst;
    __u64 src_size;
    __u64 conn_ts;
    __u32 pos;
    __u32 out_len;
    __u32 first_stream;
    __u32 skip;
    __u32 skip_stream;
    __u8 is_req;
    __u8 skip_data;
    __u8 method;
};

// noinline: the reserved ringbuf dynptr must be submit/discarded here; inlining
// poisons later probe_read_str. One message is at most MAX_PAYLOAD_SIZE.
static __attribute__((noinline))
void http2_flush(struct http2_trim_args *a) {
    __u32 zero = 0;
    struct l7_event *e;
    struct connection *conn;
    __u32 n;
    if (!a || !a->out_len || !a->dst) {
        return;
    }
    conn = bpf_map_lookup_elem(&active_connections, &a->cid);
    if (!conn) {
        a->out_len = 0;
        a->first_stream = 0;
        return;
    }
    e = bpf_map_lookup_elem(&l7_event_heap, &zero);
    if (!e) {
        a->out_len = 0;
        a->first_stream = 0;
        return;
    }
    n = a->out_len;
    if (n > MAX_PAYLOAD_SIZE) {
        n = MAX_PAYLOAD_SIZE;
    }
    PAYLOAD_BOUND(n);
    e->protocol = PROTOCOL_HTTP2;
    e->method = a->method;
    e->is_inbound = conn->is_inbound;
    e->status = STATUS_UNKNOWN;
    e->statement_id = a->first_stream;
    e->duration = bpf_ktime_get_ns();
    /* Inline. SEND_EVENT's stack struct plus the send_event frame put
       sys_enter_sendmmsg's combined stack over 512 bytes. */
    {
        struct bpf_dynptr d = {};
        __u32 pn = payload_copy_len(n);
        __u32 rec = sizeof(*e) + pn;
        e->connection_timestamp = conn->timestamp;
        e->fd = a->cid.fd;
        e->pid = a->cid.pid;
        e->payload_size = n;
        if (bpf_ringbuf_reserve_dynptr(&l7_events, rec, 0, &d)) {
            l7_drop_event();
            bpf_ringbuf_discard_dynptr(&d, 0);
        } else if (bpf_dynptr_write(&d, 0, e, sizeof(*e), 0)) {
            bpf_ringbuf_discard_dynptr(&d, 0);
        } else if (pn &&
                   bpf_probe_read_user_dynptr(&d, sizeof(*e), pn, a->dst) &&
                   bpf_probe_read_kernel_dynptr(&d, sizeof(*e), pn, a->dst)) {
            bpf_ringbuf_discard_dynptr(&d, 0);
        } else {
            bpf_ringbuf_submit_dynptr(&d, 0);
        }
    }
    a->out_len = 0;
    a->first_stream = 0;
}

static __always_inline
int http2_copyable(__u8 type) {
    return type == HTTP2_FRAME_DATA || type == HTTP2_FRAME_HEADERS || type == HTTP2_FRAME_CONTINUATION;
}

/* Pure frame-header bookkeeping shared by the contiguous and iovec frame
   walkers: parses length/type/stream_id, decides how much of the frame is
   present (take) vs. missing from this buffer (a->skip), applies the
   MAX_PAYLOAD_SIZE flush timing, and — unless the frame turns out to be a
   copyable frame cut short of its captured length — writes the (possibly
   trimmed) frame header to a->dst and reserves the body's slot in a->dst.
   Body bytes themselves are NOT copied here: that is the one truly
   source-specific step (a contiguous bpf_probe_read vs. a multi-vector
   iovec-cursor copy), left to the caller.
   remain is the number of source bytes available right after the header.
   *stream_id_out is always set, cut or not, so the caller can key the
   stream's capture budget and stash a cut-resume record.
   Returns 0 with *copied_out (possibly 0) bytes to be copied by the caller
   at *body_off_out; 1 to stop the walk (space/read error); 2 if a copyable
   frame is cut short of its captured length AND the stream still has
   capture budget left — *take_out and *stream_id_out are still valid so the
   caller can stash a cut-resume record, but no header or body has been
   written to a->dst.
   copied is always bounded to one ring slot's body capacity
   (HTTP2_CAPTURE_MAX) here; a stream's remaining budget beyond that is
   drained over further frames or further cut/resume rounds on later
   syscalls, never by capturing more than one slot's worth in a single
   call. */
static __always_inline
int http2_classify_frame(struct http2_trim_args *a, const unsigned char hdr[HTTP2_FRAME_HEADER_SIZE],
                          __u32 remain, __u32 *take_out, __u32 *copied_out, __u32 *body_off_out,
                          __u32 *stream_id_out) {
    unsigned char nh[HTTP2_FRAME_HEADER_SIZE];
    __u32 length;
    __u32 stream_id;
    __u32 take;
    __u32 copied;
    __u32 out;
    __u32 budget;
    __u8 type;

    length = ((__u32)hdr[0] << 16) | ((__u32)hdr[1] << 8) | hdr[2];
    type = hdr[3];
    stream_id = ((__u32)hdr[5] << 24) | ((__u32)hdr[6] << 16) | ((__u32)hdr[7] << 8) | hdr[8];
    *stream_id_out = stream_id;

    take = length;
    if (take > remain) {
        take = remain;
    }
    HTTP2_SRC_BOUND(take);
    if (take < length) {
        a->skip = length - take;
        a->skip_stream = stream_id;
        a->skip_data = type == HTTP2_FRAME_DATA;
    } else {
        a->skip = 0;
        a->skip_data = 0;
    }
    *take_out = take;
    *copied_out = 0;
    if (!http2_copyable(type)) {
        return 0;
    }

    budget = http2_stream_remaining(a->conn_ts, stream_id, a->is_req);
    if (!budget) {
        /* This stream already hit HTTP2_STREAM_CAPTURE_MAX: nothing more to
           capture, ever, for it. The skip/skip_stream bookkeeping above
           still lets the walk find the NEXT frame correctly. */
        return 0;
    }

    out = a->out_len;
    if (out > MAX_PAYLOAD_SIZE) {
        return 1;
    }
    PAYLOAD_BOUND(out);
    /* DATA has its own 1KB slot, not the space left after headers. */
    if (type == HTTP2_FRAME_DATA && out > 0) {
        http2_flush(a);
        out = 0;
    }
    if (out > 0 &&
        take <= MAX_PAYLOAD_SIZE - HTTP2_FRAME_HEADER_SIZE &&
        out + HTTP2_FRAME_HEADER_SIZE + take > MAX_PAYLOAD_SIZE) {
        http2_flush(a);
        out = 0;
    } else if (out + HTTP2_FRAME_HEADER_SIZE > MAX_PAYLOAD_SIZE) {
        http2_flush(a);
        out = 0;
    }
    copied = take;
    if (copied > budget) {
        copied = budget;
    }
    if (out + HTTP2_FRAME_HEADER_SIZE + copied > MAX_PAYLOAD_SIZE) {
        copied = MAX_PAYLOAD_SIZE - out - HTTP2_FRAME_HEADER_SIZE;
    }
    copied = http2_bound_body(copied);

    if (copied == take && take < length && budget > copied) {
        /* Captured everything available, but the frame continues beyond
           this buffer and the stream can still take more: ask for a
           cross-syscall top-up instead of settling for `copied`. The
           caller needs this exact amount (equal to `take`) to stash a
           cut-resume record, so report it despite writing nothing. */
        *copied_out = copied;
        return 2;
    }

    http2_encode_frame_header(nh, copied, hdr);
    if (copy_to_payload(a->dst, out, HTTP2_FRAME_HEADER_SIZE, nh)) {
        return 1;
    }
    a->out_len = out + HTTP2_FRAME_HEADER_SIZE + copied;
    if (!a->first_stream) {
        a->first_stream = stream_id;
    }
    http2_stream_add(a->conn_ts, stream_id, a->is_req, copied);
    *copied_out = copied;
    *body_off_out = out + HTTP2_FRAME_HEADER_SIZE;
    return 0;
}

/* Frame walk for the tail-call path. A HEADERS, CONTINUATION or DATA frame
   cut before 1KB is captured stops the loop (HTTP2_SKIP_CUT) so http2_cut
   can promise the length without growing this callback. */
static long http2_topup_cb(__u32 i, void *ctx) {
    struct http2_trim_args *a = ctx;
    unsigned char hdr[HTTP2_FRAME_HEADER_SIZE];
    __u32 pos;
    __u32 remain;
    __u32 start;
    __u32 take;
    __u32 copied;
    __u32 body_off;
    __u32 stream_id;
    int rc;
    (void)i;
    if (!a || !a->src || !a->dst) {
        return 1;
    }
    pos = a->pos;
    HTTP2_SRC_BOUND(pos);
    start = pos;
    if (pos >= a->src_size || pos >= HTTP2_SRC_MAX) {
        return 1;
    }
    remain = 0;
    if (pos < a->src_size) {
        remain = a->src_size - pos;
    }
    if (remain < HTTP2_FRAME_HEADER_SIZE) {
        return 1;
    }
    if (bpf_probe_read(hdr, sizeof(hdr), a->src + pos)) {
        return 1;
    }
    pos += HTTP2_FRAME_HEADER_SIZE;
    HTTP2_SRC_BOUND(pos);
    remain = 0;
    if (pos < a->src_size && pos < HTTP2_SRC_MAX) {
        remain = a->src_size - pos;
        if (remain > HTTP2_SRC_MAX) {
            remain = HTTP2_SRC_MAX;
        }
    }
    rc = http2_classify_frame(a, hdr, remain, &take, &copied, &body_off, &stream_id);
    if (rc == 2) {
        a->pos = start;
        a->skip_data = HTTP2_SKIP_CUT;
        return 1;
    }
    if (rc) {
        return 1;
    }
    if (copied && copy_to_payload(a->dst, body_off, copied, a->src + pos)) {
        return 1;
    }
    a->pos = pos + take;
    return 0;
}

static __attribute__((noinline))
int http2_topup_trim(struct http2_trim_args *a) {
    __u32 n;
    if (!a || !a->src || !a->dst) {
        return 0;
    }
    if (a->src_size > HTTP2_SRC_MAX) {
        a->src_size = HTTP2_SRC_MAX;
    }
    if (a->skip) {
        n = a->skip;
        if (n > a->src_size) {
            n = a->src_size;
        }
        HTTP2_SRC_BOUND(n);
        a->pos = n;
        a->skip -= n;
        if (!a->skip) {
            a->skip_data = 0;
        }
    }
    if (a->pos == 0 && is_http2_preface(a->src, a->src_size)) {
        a->pos = HTTP2_PREFACE_SIZE;
    }
    bpf_loop(HTTP2_TRIM_MAX_FRAMES, http2_topup_cb, a, 0);
    http2_flush(a);
    return a->out_len;
}

/* writev/readv/sendmsg. The bytes stay in the process. This table is the
   list of pointers. The frame walk switches to the next pointer inside one
   bpf_loop. */

#define HTTP2_TAIL_RESUME 0
#define HTTP2_TAIL_WALK 1
#define HTTP2_TAIL_CUT 2
#define HTTP2_TAIL_IOV 3
#define HTTP2_TAIL_READV 4
#define HTTP2_TAIL_READ_EXIT 5

/* One writev/readv/sendmsg. 1024 is IOV_MAX. 16 bytes per entry fits in a per-CPU map. */
#define HTTP2_MAX_VECS 1024

struct http2_vec {
    __u64 base;
    __u32 len;
    __u32 pad;
};

struct http2_iovec_table {
    struct http2_vec v[HTTP2_MAX_VECS];
    __u32 n;
    __u32 idx;
    __u32 off;
    __u32 total;
    __u32 consumed;
    __u32 skip_left;
    __u32 cut_body;
    __u32 cut_length;
    __u8 cut_hdr[HTTP2_FRAME_HEADER_SIZE];
    __u8 ready;
};

struct http2_tail_state {
    struct connection_id cid;
    char *buf;
    __u64 size;
    __u32 pos;
    __u8 method;
    __u8 is_req;
    __u8 from_heap;
    __u8 from_iov;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct http2_tail_state);
} http2_tail_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct http2_iovec_table);
} http2_iovecs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 6);
    __type(key, __u32);
    __type(value, __u32);
} http2_tail_progs SEC(".maps");

/* Same programs, loaded as kprobe so an uprobe can tail-call them.
   A PROG_ARRAY holds one program type. Slots 4 and 5 stay empty:
   readv dispatch is tracepoint-only. */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 6);
    __type(key, __u32);
    __type(value, __u32);
} http2_tail_progs_kprobe SEC(".maps");

struct http2_iov_load {
    __u64 vec;
    __u32 n;
    __u32 cap;
};

static __always_inline
void http2_iov_clear(void) {
    __u32 zero = 0;
    struct http2_iovec_table *t;

    t = bpf_map_lookup_elem(&http2_iovecs, &zero);
    if (t) {
        t->ready = 0;
    }
}

static long http2_iov_load_cb(__u32 i, void *ctx) {
    struct http2_iov_load *a = ctx;
    struct http2_iovec_table *t;
    struct iovec u = {};
    __u32 zero = 0;
    __u32 idx;
    __u32 len;
    __u32 n;
    __u32 cap;
    __u64 addr;
    __u64 sum;

    if (!a) {
        return 1;
    }
    n = a->n;
    if (n > HTTP2_MAX_VECS) {
        n = HTTP2_MAX_VECS;
    }
    if (i >= n) {
        return 1;
    }
    idx = i;
    asm volatile("%0 &= %1" : "+r"(idx) : "i"(HTTP2_MAX_VECS - 1));
    if (idx >= n) {
        return 1;
    }
    addr = a->vec + ((__u64)idx * sizeof(u));
    if (bpf_probe_read_user(&u, sizeof(u), (void *)addr)) {
        return 1;
    }
    if (!u.size) {
        return 0;
    }
    len = u.size;
    if (u.size > HTTP2_SRC_MAX) {
        len = HTTP2_SRC_MAX;
    }
    t = bpf_map_lookup_elem(&http2_iovecs, &zero);
    if (!t) {
        return 1;
    }
    cap = a->cap;
    if (cap > HTTP2_SRC_MAX) {
        cap = HTTP2_SRC_MAX;
    }
    if (!cap || t->total >= cap) {
        return 1;
    }
    sum = t->total;
    if (sum + len > cap) {
        len = cap - t->total;
    }
    if (!len) {
        return 1;
    }
    idx = t->n;
    if (idx >= HTTP2_MAX_VECS) {
        return 1;
    }
    asm volatile("%0 &= %1" : "+r"(idx) : "i"(HTTP2_MAX_VECS - 1));
    t->v[idx].base = (__u64)u.buf;
    t->v[idx].len = len;
    t->n = idx + 1;
    t->total += len;
    return 0;
}

/* cap 0 means the whole list, up to HTTP2_SRC_MAX. A read passes the syscall
   return: iovec sizes are capacities, and only that many bytes were filled. */
static __attribute__((noinline))
void http2_load_iovecs(char *iovec, __u64 iovlen, __u64 cap) {
    struct http2_iovec_table *t;
    struct http2_iov_load arg = {};
    __u32 zero = 0;
    __u32 n;
    __u32 lim;

    t = bpf_map_lookup_elem(&http2_iovecs, &zero);
    if (!t || !iovec || !iovlen) {
        return;
    }
    n = iovlen;
    if (n > HTTP2_MAX_VECS) {
        n = HTTP2_MAX_VECS;
    }
    lim = HTTP2_SRC_MAX;
    if (cap && cap < HTTP2_SRC_MAX) {
        lim = cap;
    }
    t->n = 0;
    t->idx = 0;
    t->off = 0;
    t->total = 0;
    t->consumed = 0;
    t->skip_left = 0;
    t->cut_body = 0;
    t->cut_length = 0;
    t->ready = 0;
    arg.vec = (__u64)iovec;
    arg.n = n;
    arg.cap = lim;
    bpf_loop(n, http2_iov_load_cb, &arg, 0);
    t = bpf_map_lookup_elem(&http2_iovecs, &zero);
    if (t && t->n && t->total) {
        t->ready = 1;
    }
}

static __attribute__((noinline))
int http2_iov_pull(__u8 *out) {
    struct http2_iovec_table *t;
    __u32 zero = 0;
    __u32 idx;
    __u32 off;
    __u32 len;
    __u64 addr;

    t = bpf_map_lookup_elem(&http2_iovecs, &zero);
    if (!t || !out) {
        return -1;
    }
    if (t->idx >= t->n || t->idx >= HTTP2_MAX_VECS) {
        return -1;
    }
    idx = t->idx;
    asm volatile("%0 &= %1" : "+r"(idx) : "i"(HTTP2_MAX_VECS - 1));
    len = t->v[idx].len;
    if (len > HTTP2_SRC_MAX) {
        len = HTTP2_SRC_MAX;
    }
    off = t->off;
    HTTP2_SRC_BOUND(off);
    if (off >= len) {
        idx++;
        if (idx >= t->n || idx >= HTTP2_MAX_VECS) {
            return -1;
        }
        asm volatile("%0 &= %1" : "+r"(idx) : "i"(HTTP2_MAX_VECS - 1));
        t->idx = idx;
        t->off = 0;
        off = 0;
        len = t->v[idx].len;
        if (len > HTTP2_SRC_MAX) {
            len = HTTP2_SRC_MAX;
        }
        if (!len) {
            return -1;
        }
    }
    addr = t->v[idx].base + off;
    if (bpf_probe_read_user(out, 1, (void *)addr)) {
        return -1;
    }
    t->off = off + 1;
    t->consumed++;
    return 0;
}

/* Bytes still not skipped. One step can cross a whole vector. */
static __attribute__((noinline))
__u32 http2_iov_skip(__u32 n) {
    __u32 k;

#pragma unroll
    for (k = 0; k < 8; k++) {
        struct http2_iovec_table *t;
        __u32 zero = 0;
        __u32 idx;
        __u32 off;
        __u32 len;
        __u32 chunk;
        __u32 next;

        if (!n) {
            return 0;
        }
        t = bpf_map_lookup_elem(&http2_iovecs, &zero);
        if (!t || t->idx >= t->n || t->idx >= HTTP2_MAX_VECS) {
            return n;
        }
        idx = t->idx;
        asm volatile("%0 &= %1" : "+r"(idx) : "i"(HTTP2_MAX_VECS - 1));
        len = t->v[idx].len;
        if (len > HTTP2_SRC_MAX) {
            len = HTTP2_SRC_MAX;
        }
        off = t->off;
        HTTP2_SRC_BOUND(off);
        if (off >= len) {
            idx++;
            if (idx >= t->n || idx >= HTTP2_MAX_VECS) {
                return n;
            }
            asm volatile("%0 &= %1" : "+r"(idx) : "i"(HTTP2_MAX_VECS - 1));
            t->idx = idx;
            t->off = 0;
            off = 0;
            len = t->v[idx].len;
            if (len > HTTP2_SRC_MAX) {
                len = HTTP2_SRC_MAX;
            }
            if (!len) {
                continue;
            }
        }
        chunk = len - off;
        if (chunk > n) {
            chunk = n;
        }
        HTTP2_SRC_BOUND(chunk);
        if (!chunk) {
            return n;
        }
        next = off + chunk;
        HTTP2_SRC_BOUND(next);
        t->off = next;
        t->consumed += chunk;
        n -= chunk;
    }
    return n;
}

static __attribute__((noinline))
int http2_iov_copy(char *dst, __u32 out, __u32 n) {
    __u32 k;

#pragma unroll
    for (k = 0; k < 8; k++) {
        struct http2_iovec_table *t;
        __u32 zero = 0;
        __u32 idx;
        __u32 off;
        __u32 len;
        __u32 chunk;
        __u32 next;
        __u64 addr;

        if (!n) {
            return 0;
        }
        t = bpf_map_lookup_elem(&http2_iovecs, &zero);
        if (!t || t->idx >= t->n || t->idx >= HTTP2_MAX_VECS) {
            return -1;
        }
        idx = t->idx;
        asm volatile("%0 &= %1" : "+r"(idx) : "i"(HTTP2_MAX_VECS - 1));
        len = t->v[idx].len;
        if (len > HTTP2_SRC_MAX) {
            len = HTTP2_SRC_MAX;
        }
        off = t->off;
        HTTP2_SRC_BOUND(off);
        if (off >= len) {
            idx++;
            if (idx >= t->n || idx >= HTTP2_MAX_VECS) {
                return -1;
            }
            asm volatile("%0 &= %1" : "+r"(idx) : "i"(HTTP2_MAX_VECS - 1));
            t->idx = idx;
            t->off = 0;
            off = 0;
            len = t->v[idx].len;
            if (len > HTTP2_SRC_MAX) {
                len = HTTP2_SRC_MAX;
            }
            if (!len) {
                continue;
            }
        }
        chunk = len - off;
        if (chunk > n) {
            chunk = n;
        }
        if (chunk > MAX_PAYLOAD_SIZE) {
            chunk = MAX_PAYLOAD_SIZE;
        }
        PAYLOAD_BOUND(chunk);
        PAYLOAD_BOUND(out);
        if (!chunk) {
            return -1;
        }
        addr = t->v[idx].base + off;
        if (copy_to_payload(dst, out, chunk, (void *)addr)) {
            return -1;
        }
        next = off + chunk;
        HTTP2_SRC_BOUND(next);
        t->off = next;
        t->consumed += chunk;
        out += chunk;
        n -= chunk;
    }
    return n ? -1 : 0;
}

static long http2_iov_cb(__u32 i, void *ctx) {
    struct http2_trim_args *a = ctx;
    struct http2_iovec_table *t;
    unsigned char hdr[HTTP2_FRAME_HEADER_SIZE];
    __u32 zero = 0;
    __u32 remain;
    __u32 take;
    __u32 copied;
    __u32 body_off;
    __u32 stream_id;
    __u32 rest;
    int rc;
    (void)i;

    if (!a || !a->dst) {
        return 1;
    }
    t = bpf_map_lookup_elem(&http2_iovecs, &zero);
    if (!t) {
        return 1;
    }
    if (t->skip_left) {
        rest = http2_iov_skip(t->skip_left);
        t = bpf_map_lookup_elem(&http2_iovecs, &zero);
        if (!t) {
            return 1;
        }
        t->skip_left = rest;
        if (rest) {
            if (t->idx >= t->n) {
                a->skip = rest;
                a->skip_data = 0;
                t->skip_left = 0;
                return 1;
            }
            return 0;
        }
    }
    if (http2_iov_pull(&hdr[0]) || http2_iov_pull(&hdr[1]) || http2_iov_pull(&hdr[2]) ||
        http2_iov_pull(&hdr[3]) || http2_iov_pull(&hdr[4]) || http2_iov_pull(&hdr[5]) ||
        http2_iov_pull(&hdr[6]) || http2_iov_pull(&hdr[7]) || http2_iov_pull(&hdr[8])) {
        return 1;
    }
    t = bpf_map_lookup_elem(&http2_iovecs, &zero);
    if (!t) {
        return 1;
    }
    remain = 0;
    if (t->consumed < t->total) {
        remain = t->total - t->consumed;
    }

    rc = http2_classify_frame(a, hdr, remain, &take, &copied, &body_off, &stream_id);
    if (rc == 2) {
        /* Cut copyable frame: the iovec cursor already consumed the header,
           so — unlike the contiguous walker, which just rewinds a->pos —
           the header bytes and the captured-so-far body length must be
           stashed for http2_iov_impl to replay after the loop. */
        t = bpf_map_lookup_elem(&http2_iovecs, &zero);
        if (!t) {
            return 1;
        }
        t->cut_body = copied;
        t->cut_length = ((__u32)hdr[0] << 16) | ((__u32)hdr[1] << 8) | hdr[2];
        t->cut_hdr[0] = hdr[0];
        t->cut_hdr[1] = hdr[1];
        t->cut_hdr[2] = hdr[2];
        t->cut_hdr[3] = hdr[3];
        t->cut_hdr[4] = hdr[4];
        t->cut_hdr[5] = hdr[5];
        t->cut_hdr[6] = hdr[6];
        t->cut_hdr[7] = hdr[7];
        t->cut_hdr[8] = hdr[8];
        a->skip_data = HTTP2_SKIP_CUT;
        return 1;
    }
    if (rc) {
        return 1;
    }
    if (copied && http2_iov_copy(a->dst, body_off, copied)) {
        return 1;
    }
    /* Whatever of `take` wasn't copied — either a non-copyable frame's
       whole body, or a copyable frame's tail beyond the capture cap (or the
       stream's budget) — is still sitting in the iovec cursor and must be
       walked past for real. */
    if (take > copied) {
        rest = http2_iov_skip(take - copied);
        if (rest) {
            t = bpf_map_lookup_elem(&http2_iovecs, &zero);
            if (!t) {
                return 1;
            }
            if (t->idx >= t->n) {
                a->skip += rest;
                return 1;
            }
            t->skip_left = rest;
        }
    }
    return 0;
}

static __always_inline
int http2_iov_impl(void *ctx) {
    __u32 zero = 0;
    struct http2_tail_state *s;
    struct http2_iovec_table *iovs;
    struct connection *conn;
    struct http2_trim_args t = {};
    struct connection_id cid = {};
    char *dst;
    unsigned char nh[HTTP2_FRAME_HEADER_SIZE];
    __u32 skip;
    __u32 packed;
    __u32 have;
    __u32 want;
    __u32 need;
    __u32 left;
    __u32 rest;
    __u32 n;
    __u32 stream_id;
    __u32 budget;
    __u64 conn_ts;
    __u8 is_req;
    __u8 data;
    (void)ctx;

    s = bpf_map_lookup_elem(&http2_tail_state, &zero);
    if (!s || !s->size || !s->from_iov) {
        return 0;
    }
    cid = s->cid;
    is_req = s->is_req;
    iovs = bpf_map_lookup_elem(&http2_iovecs, &zero);
    if (!iovs || !iovs->n) {
        return 0;
    }
    conn = bpf_map_lookup_elem(&active_connections, &cid);
    if (!conn) {
        return 0;
    }
    conn_ts = conn->timestamp;
    http2_skip_load(conn, is_req, &skip, &packed, &data);
    dst = bpf_map_lookup_elem(&http2_emit_heap, &zero);
    if (!dst) {
        return 0;
    }
    if (data == HTTP2_SKIP_HEADER && skip) {
        stream_id = packed;
        budget = http2_stream_remaining(conn_ts, stream_id, is_req);
        if (!budget) {
            data = 0;
            packed = 0;
        } else {
            left = 0;
            if (iovs->consumed < iovs->total) {
                left = iovs->total - iovs->consumed;
            }
            need = http2_skip_topup_want(skip, left, budget);
            have = 0;
            if (need) {
                if (http2_iov_copy(dst, 0, need)) {
                    return 0;
                }
                t.cid = cid;
                t.conn_ts = conn_ts;
                t.dst = dst;
                t.is_req = is_req;
                t.method = s->method;
                t.out_len = need;
                http2_stream_add(conn_ts, stream_id, is_req, need);
                have = need;
                http2_flush(&t);
                skip -= have;
            }
            iovs = bpf_map_lookup_elem(&http2_iovecs, &zero);
            if (!iovs) {
                return 0;
            }
            left = 0;
            if (iovs->consumed < iovs->total) {
                left = iovs->total - iovs->consumed;
            }
            if (skip && left) {
                if (left > skip) {
                    left = skip;
                }
                rest = http2_iov_skip(left);
                if (left >= rest) {
                    skip -= left - rest;
                }
                if (rest) {
                    iovs = bpf_map_lookup_elem(&http2_iovecs, &zero);
                    if (iovs && iovs->idx < iovs->n) {
                        iovs->skip_left = rest;
                    }
                }
            }
            http2_skip_topup_next(conn_ts, stream_id, is_req, skip, &packed, &data);
            iovs = bpf_map_lookup_elem(&http2_iovecs, &zero);
            if (!iovs) {
                return 0;
            }
            if (iovs->consumed >= iovs->total || data == HTTP2_SKIP_HEADER) {
                conn = bpf_map_lookup_elem(&active_connections, &cid);
                http2_skip_save(conn, is_req, skip, packed, data);
                return 0;
            }
            skip = 0;
            packed = 0;
            data = 0;
        }
    }
    conn = bpf_map_lookup_elem(&active_connections, &cid);
    http2_skip_save(conn, is_req, skip, packed, data);
    iovs = bpf_map_lookup_elem(&http2_iovecs, &zero);
    if (iovs && iovs->n && iovs->v[0].len >= HTTP2_PREFACE_SIZE && iovs->idx == 0 && iovs->off == 0) {
        char p[6];
        if (!bpf_probe_read_user(p, sizeof(p), (void *)iovs->v[0].base) &&
            p[0] == 'P' && p[1] == 'R' && p[2] == 'I' && p[3] == ' ' && p[4] == '*') {
            http2_iov_skip(HTTP2_PREFACE_SIZE);
        }
    }
    t.cid = cid;
    t.conn_ts = conn_ts;
    t.dst = dst;
    t.method = s->method;
    t.is_req = is_req;
    bpf_loop(HTTP2_TRIM_MAX_FRAMES, http2_iov_cb, &t, 0);
    http2_flush(&t);
    if (t.skip_data == HTTP2_SKIP_CUT) {
        iovs = bpf_map_lookup_elem(&http2_iovecs, &zero);
        if (!iovs) {
            return 0;
        }
        stream_id = ((__u32)iovs->cut_hdr[5] << 24) | ((__u32)iovs->cut_hdr[6] << 16) |
                    ((__u32)iovs->cut_hdr[7] << 8) | iovs->cut_hdr[8];
        budget = http2_stream_remaining(conn_ts, stream_id, is_req);
        if (!budget) {
            conn = bpf_map_lookup_elem(&active_connections, &cid);
            http2_skip_save(conn, is_req, 0, 0, 0);
            return 0;
        }
        want = iovs->cut_length;
        if (want > budget) {
            want = budget;
        }
        n = iovs->cut_body;
        if (n > want) {
            n = want;
        }
        n = http2_bound_body(n);
        http2_encode_frame_header(nh, want, iovs->cut_hdr);
        if (copy_to_payload(dst, 0, HTTP2_FRAME_HEADER_SIZE, nh)) {
            return 0;
        }
        if (n && http2_iov_copy(dst, HTTP2_FRAME_HEADER_SIZE, n)) {
            return 0;
        }
        http2_stream_add(conn_ts, stream_id, is_req, n);
        t.out_len = HTTP2_FRAME_HEADER_SIZE + n;
        t.first_stream = stream_id;
        t.method = s->method;
        t.is_req = is_req;
        http2_flush(&t);
        conn = bpf_map_lookup_elem(&active_connections, &cid);
        if (!conn) {
            return 0;
        }
        if (iovs->cut_body >= iovs->cut_length) {
            http2_skip_save(conn, is_req, 0, 0, 0);
            return 0;
        }
        skip = iovs->cut_length - iovs->cut_body;
        if (http2_stream_remaining(conn_ts, stream_id, is_req)) {
            http2_skip_save(conn, is_req, skip, stream_id, HTTP2_SKIP_HEADER);
        } else {
            http2_skip_save(conn, is_req, 0, 0, 0);
        }
        return 0;
    }
    conn = bpf_map_lookup_elem(&active_connections, &cid);
    http2_skip_save(conn, is_req, t.skip, t.skip_stream, t.skip_data);
    return 0;
}

SEC("tracepoint/http2/iov")
int http2_iov(void *ctx) {
    return http2_iov_impl(ctx);
}

SEC("uprobe/http2_iov")
int http2_iov_kp(void *ctx) {
    return http2_iov_impl(ctx);
}

/* User buffer, or the per-CPU iovec scratch when from_heap is set.
   The map pointer is not stored across the tail call. */
static __always_inline
char *http2_tail_buf(struct http2_tail_state *s) {
    __u32 zero = 0;
    if (!s) {
        return 0;
    }
    if (s->from_heap) {
        return bpf_map_lookup_elem(&iovec_buf_heap, &zero);
    }
    return s->buf;
}

/* Inline: bpf_tail_call must see the caller's ctx, and tail_progs must be a
   constant map of the same program type. Every plaintext HTTP/2 buffer
   enters http2_resume; that program only finishes a cut frame, then
   tail-calls http2_walk for the bytes that follow. */
static __always_inline
int http2_tail_emit(void *ctx, struct connection_id cid, struct connection *conn,
                    char *buf, __u64 size, __u8 is_req, __u8 from_heap, void *tail_progs) {
    __u32 zero = 0;
    struct http2_tail_state *s;
    struct http2_iovec_table *iovs;
    if (!conn || conn->protocol != PROTOCOL_HTTP2) {
        return 0;
    }
    iovs = bpf_map_lookup_elem(&http2_iovecs, &zero);
    if (!(iovs && iovs->ready && iovs->total) && (!size || (!from_heap && !buf))) {
        return 0;
    }
    s = bpf_map_lookup_elem(&http2_tail_state, &zero);
    if (!s) {
        return 0;
    }
    s->cid = cid;
    s->pos = 0;
    s->is_req = is_req;
    s->method = is_req ? METHOD_HTTP2_CLIENT_FRAMES : METHOD_HTTP2_SERVER_FRAMES;
    if (iovs && iovs->ready && iovs->total) {
        s->from_iov = 1;
        s->from_heap = 0;
        s->buf = 0;
        s->size = iovs->total;
        if (s->size > HTTP2_SRC_MAX) {
            s->size = HTTP2_SRC_MAX;
        }
        iovs->idx = 0;
        iovs->off = 0;
        iovs->consumed = 0;
        iovs->skip_left = 0;
        iovs->ready = 0;
    } else {
        s->from_iov = 0;
        s->size = size;
        s->from_heap = from_heap;
        if (from_heap) {
            s->buf = 0;
        } else {
            s->buf = buf;
        }
    }
    bpf_tail_call(ctx, tail_progs, HTTP2_TAIL_RESUME);
    return 1;
}

/* The buffer that first sets PROTOCOL_HTTP2. Same walker as later calls,
   so a frame cut at the end of this buffer is topped up. from_heap is 0 or 1
   from the caller; the two stores stay in separate branches. */
static __always_inline
int http2_emit_fresh(void *ctx, struct connection_id cid, struct connection *conn,
                     char *payload, __u64 size, __u8 is_req, __u8 from_heap, void *tail_progs) {
    if (from_heap) {
        http2_tail_emit(ctx, cid, conn, 0, size, is_req, 1, tail_progs);
    } else {
        http2_tail_emit(ctx, cid, conn, payload, size, is_req, 0, tail_progs);
    }
    return 0;
}

/* Defined in l7.c, well after this file is included: the generic read-exit
   path shared by every non-HTTP2-aware protocol too. */
static inline __attribute__((__always_inline__))
int trace_exit_read(void *ctx, __u64 id, __u32 pid, __u16 is_tls, long int ret, void *tail_progs);

/* readv/recvmsg only. Loads the pointer list, then either walks it (protocol
   already HTTP/2) or tails to the unchanged read path so the first buffer can
   still be sniffed. Not attached. */
SEC("tracepoint/http2/readv")
int http2_readv(struct trace_event_raw_sys_exit__stub *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    struct read_args *args;
    struct connection_id cid = {};
    struct connection *conn;
    char *buf;
    __u64 iovlen;
    __u64 fd;
    long ret;
    __u8 is_req = 0;
    __u8 http2 = 0;

    http2_iov_clear();
    args = bpf_map_lookup_elem(&active_reads, &id);
    if (!args) {
        return 0;
    }
    ret = ctx->ret;
    if (ret <= 0) {
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }
    fd = args->fd;
    buf = args->buf;
    iovlen = args->iovlen;
    if (iovlen && buf) {
        http2_load_iovecs(buf, iovlen, (__u64)ret);
    }
    cid.pid = pid;
    cid.fd = fd;
    conn = bpf_map_lookup_elem(&active_connections, &cid);
    if (conn && conn->protocol == PROTOCOL_HTTP2 && !conn->is_tls) {
        http2 = 1;
        is_req = conn->is_inbound;
    }
    if (http2) {
        bpf_map_delete_elem(&active_reads, &id);
        conn = bpf_map_lookup_elem(&active_connections, &cid);
        if (!conn) {
            return 0;
        }
        __sync_fetch_and_add(&conn->bytes_received, (__u64)ret);
        http2_tail_emit(ctx, cid, conn, 0, (__u64)ret, is_req, 0, &http2_tail_progs);
        return 0;
    }
    bpf_tail_call(ctx, &http2_tail_progs, HTTP2_TAIL_READ_EXIT);
    http2_iov_clear();
    return 0;
}

/* Today's read path, with no pointer-table branch. The dispatch program
   leaves active_reads in place. If this returns, the table was not consumed. */
SEC("tracepoint/http2/read_exit")
int http2_read_exit(struct trace_event_raw_sys_exit__stub *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    int rc = trace_exit_read(ctx, id, id >> 32, 0, ctx->ret, &http2_tail_progs);
    http2_iov_clear();
    return rc;
}

/* Not attached. Plaintext HTTP/2 tail-calls here so the frame walk, including
   a cut HEADERS, CONTINUATION or DATA top-up, has its own verifier budget.
   tail_progs is the caller's prog array (tracepoint or kprobe). */
static __always_inline
int http2_resume_impl(void *ctx, void *tail_progs) {
    __u32 zero = 0;
    struct http2_tail_state *s;
    struct connection *conn;
    char *dst;
    char *buf;
    struct connection_id cid = {};
    struct http2_trim_args t = {};
    __u64 size;
    __u64 conn_ts;
    __u32 skip, packed, have, need, pos, left, stream_id, budget;
    __u8 is_req, method, data;

    s = bpf_map_lookup_elem(&http2_tail_state, &zero);
    if (!s || !s->size) {
        return 0;
    }
    if (s->from_iov) {
        bpf_tail_call(ctx, tail_progs, HTTP2_TAIL_IOV);
        return 0;
    }
    buf = http2_tail_buf(s);
    if (!buf) {
        return 0;
    }
    cid = s->cid;
    size = s->size;
    is_req = s->is_req;
    method = s->method;

    conn = bpf_map_lookup_elem(&active_connections, &cid);
    if (!conn) {
        return 0;
    }
    conn_ts = conn->timestamp;
    http2_skip_load(conn, is_req, &skip, &packed, &data);
    pos = 0;
    if (size > HTTP2_SRC_MAX) {
        size = HTTP2_SRC_MAX;
    }
    dst = bpf_map_lookup_elem(&http2_emit_heap, &zero);
    if (!dst) {
        return 0;
    }
    if (data == HTTP2_SKIP_HEADER && skip) {
        stream_id = packed;
        budget = http2_stream_remaining(conn_ts, stream_id, is_req);
        if (!budget) {
            /* Nothing left to ever capture for this stream; fall through to
               a plain numeric skip via the generic a->skip drain below. */
            data = 0;
            packed = 0;
        } else {
            need = http2_skip_topup_want(skip, size, budget);
            have = 0;
            if (need) {
                if (copy_to_payload(dst, 0, need, buf)) {
                    return 0;
                }
                t.cid = cid;
                t.conn_ts = conn_ts;
                t.dst = dst;
                t.is_req = is_req;
                t.method = method;
                t.out_len = need;
                http2_stream_add(conn_ts, stream_id, is_req, need);
                have = need;
                http2_flush(&t);
                skip -= have;
            }
            pos = have;
            if (skip && pos < size) {
                left = size - pos;
                if (left > skip) {
                    left = skip;
                }
                HTTP2_SRC_BOUND(left);
                pos += left;
                skip -= left;
            }
            http2_skip_topup_next(conn_ts, stream_id, is_req, skip, &packed, &data);
            if (pos >= size || data == HTTP2_SKIP_HEADER) {
                conn = bpf_map_lookup_elem(&active_connections, &cid);
                if (!conn) {
                    return 0;
                }
                http2_skip_save(conn, is_req, skip, packed, data);
                return 0;
            }
            skip = 0;
            packed = 0;
            data = 0;
        }
    }
    conn = bpf_map_lookup_elem(&active_connections, &cid);
    if (!conn) {
        return 0;
    }
    http2_skip_save(conn, is_req, skip, packed, data);
    s = bpf_map_lookup_elem(&http2_tail_state, &zero);
    if (!s) {
        return 0;
    }
    s->pos = pos;
    s->size = size;
    if (pos < size) {
        bpf_tail_call(ctx, tail_progs, HTTP2_TAIL_WALK);
    }
    return 0;
}

SEC("tracepoint/http2/resume")
int http2_resume(void *ctx) {
    return http2_resume_impl(ctx, &http2_tail_progs);
}

SEC("uprobe/http2_resume")
int http2_resume_kp(void *ctx) {
    return http2_resume_impl(ctx, &http2_tail_progs_kprobe);
}

static __always_inline
int http2_walk_impl(void *ctx, void *tail_progs) {
    __u32 zero = 0;
    struct http2_tail_state *s;
    struct connection *conn;
    char *dst;
    struct connection_id cid = {};
    struct http2_trim_args t = {};
    __u8 is_req;
    s = bpf_map_lookup_elem(&http2_tail_state, &zero);
    if (!s) {
        return 0;
    }
    cid = s->cid;
    is_req = s->is_req;
    t.cid = cid;
    t.src = http2_tail_buf(s);
    if (!t.src) {
        return 0;
    }
    t.src_size = s->size;
    t.pos = s->pos;
    t.method = s->method;
    t.is_req = is_req;
    conn = bpf_map_lookup_elem(&active_connections, &cid);
    if (!conn) {
        return 0;
    }
    t.conn_ts = conn->timestamp;
    http2_skip_load(conn, is_req, &t.skip, &t.skip_stream, &t.skip_data);
    dst = bpf_map_lookup_elem(&http2_emit_heap, &zero);
    if (!dst) {
        return 0;
    }
    t.dst = dst;
    http2_topup_trim(&t);
    if (t.skip_data == HTTP2_SKIP_CUT) {
        s = bpf_map_lookup_elem(&http2_tail_state, &zero);
        if (!s) {
            return 0;
        }
        s->pos = t.pos;
        bpf_tail_call(ctx, tail_progs, HTTP2_TAIL_CUT);
        return 0;
    }
    conn = bpf_map_lookup_elem(&active_connections, &cid);
    if (!conn) {
        return 0;
    }
    http2_skip_save(conn, is_req, t.skip, t.skip_stream, t.skip_data);
    return 0;
}

SEC("tracepoint/http2/walk")
int http2_walk(void *ctx) {
    return http2_walk_impl(ctx, &http2_tail_progs);
}

SEC("uprobe/http2_walk")
int http2_walk_kp(void *ctx) {
    return http2_walk_impl(ctx, &http2_tail_progs_kprobe);
}

/* One cut HEADERS, CONTINUATION or DATA frame. Captures up to one ring
   slot's worth (bounded further by the stream's remaining budget) and
   leaves whatever's still missing — of this ring slot's promise or of the
   frame itself — for http2_resume on a later call. */
static __always_inline
int http2_cut_impl(void *ctx) {
    __u32 zero = 0;
    struct http2_tail_state *s;
    struct connection *conn;
    char *buf;
    char *dst;
    struct connection_id cid = {};
    struct http2_trim_args t = {};
    unsigned char hdr[HTTP2_FRAME_HEADER_SIZE];
    unsigned char nh[HTTP2_FRAME_HEADER_SIZE];
    __u64 size;
    __u32 pos;
    __u32 off;
    __u32 length;
    __u32 remain;
    __u32 take;
    __u32 want;
    __u32 n;
    __u32 stream_id;
    __u32 budget;
    __u64 conn_ts;
    __u8 is_req;
    __u8 type;
    (void)ctx;
    s = bpf_map_lookup_elem(&http2_tail_state, &zero);
    if (!s) {
        return 0;
    }
    buf = http2_tail_buf(s);
    if (!buf) {
        return 0;
    }
    cid = s->cid;
    is_req = s->is_req;
    size = s->size;
    if (size > HTTP2_SRC_MAX) {
        size = HTTP2_SRC_MAX;
    }
    pos = s->pos;
    HTTP2_SRC_BOUND(pos);
    if (pos >= size || size - pos < HTTP2_FRAME_HEADER_SIZE) {
        return 0;
    }
    if (bpf_probe_read(hdr, sizeof(hdr), buf + pos)) {
        return 0;
    }
    off = pos + HTTP2_FRAME_HEADER_SIZE;
    HTTP2_SRC_BOUND(off);
    length = ((__u32)hdr[0] << 16) | ((__u32)hdr[1] << 8) | hdr[2];
    type = hdr[3];
    if (type != HTTP2_FRAME_HEADERS && type != HTTP2_FRAME_CONTINUATION && type != HTTP2_FRAME_DATA) {
        return 0;
    }
    stream_id = ((__u32)hdr[5] << 24) | ((__u32)hdr[6] << 16) | ((__u32)hdr[7] << 8) | hdr[8];
    remain = 0;
    if (off < size) {
        remain = size - off;
    }
    take = length;
    if (take > remain) {
        take = remain;
    }
    HTTP2_SRC_BOUND(take);

    conn = bpf_map_lookup_elem(&active_connections, &cid);
    if (!conn) {
        return 0;
    }
    conn_ts = conn->timestamp;
    budget = http2_stream_remaining(conn_ts, stream_id, is_req);
    if (!budget) {
        http2_skip_save(conn, is_req, 0, 0, 0);
        return 0;
    }
    want = length;
    if (want > budget) {
        want = budget;
    }
    n = take;
    if (n > want) {
        n = want;
    }
    n = http2_bound_body(n);
    http2_encode_frame_header(nh, want, hdr);
    dst = bpf_map_lookup_elem(&http2_emit_heap, &zero);
    if (!dst) {
        return 0;
    }
    if (copy_to_payload(dst, 0, HTTP2_FRAME_HEADER_SIZE, nh)) {
        return 0;
    }
    if (n && copy_to_payload(dst, HTTP2_FRAME_HEADER_SIZE, n, buf + off)) {
        return 0;
    }
    http2_stream_add(conn_ts, stream_id, is_req, n);
    t.cid = cid;
    t.conn_ts = conn_ts;
    t.dst = dst;
    t.is_req = is_req;
    t.method = s->method;
    t.out_len = HTTP2_FRAME_HEADER_SIZE + n;
    t.first_stream = stream_id;
    http2_flush(&t);
    conn = bpf_map_lookup_elem(&active_connections, &cid);
    if (!conn) {
        return 0;
    }
    if (take >= length) {
        http2_skip_save(conn, is_req, 0, 0, 0);
        return 0;
    }
    if (http2_stream_remaining(conn_ts, stream_id, is_req)) {
        http2_skip_save(conn, is_req, length - take, stream_id, HTTP2_SKIP_HEADER);
    } else {
        http2_skip_save(conn, is_req, 0, 0, 0);
    }
    return 0;
}

SEC("tracepoint/http2/cut")
int http2_cut(void *ctx) {
    return http2_cut_impl(ctx);
}

SEC("uprobe/http2_cut")
int http2_cut_kp(void *ctx) {
    return http2_cut_impl(ctx);
}
