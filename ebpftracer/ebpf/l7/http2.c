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
   looked up fresh on every call — there is nothing else to persist).
   HTTP2_SKIP_HEADER is for a pending HEADERS/CONTINUATION resume,
   HTTP2_SKIP_DATA for a pending DATA resume — the two draw from separate
   budgets (see HTTP2_STREAM_CAPTURE_MAX below), so which one is stashed
   decides which budget the resume rechecks. */
#define HTTP2_SKIP_HEADER 2
/* The iovec walk stopped on a HEADERS, CONTINUATION or DATA frame cut short
   of its declared length by this buffer's end. Transient: stashed on
   struct http2_trim_args for http2_iov_impl to turn into a cut-resume
   record (t.cut_hdr/cut_body/cut_length) before the loop returns — never
   persisted via http2_skip_save. */
#define HTTP2_SKIP_CUT 3
#define HTTP2_SKIP_DATA 4
/* A frame this walker never captures (SETTINGS, WINDOW_UPDATE, PING, ... —
   see http2_copyable) — or a copyable frame whose stream already hit
   HTTP2_STREAM_CAPTURE_MAX — was cut short of its declared length by this
   buffer's end. There is no header/body to reconstruct and no stream budget
   to track, just `skip` more raw bytes to walk past once they show up in a
   later buffer. */
#define HTTP2_SKIP_RAW 1

/* Cumulative body bytes captured per (connection, direction, HTTP2 stream,
   HEADERS/CONTINUATION vs. DATA) — across as many frames and emitted events
   as it takes. HEADERS and CONTINUATION share one budget (a header block is
   one logical unit split only by CONTINUATION's 16KB-ish framing limit);
   DATA gets its own, equally sized, independent budget on the same stream —
   so a stream's worth of headers (say, a heavy Cookie) can never crowd out
   its body, and a large body can never crowd out trailing HEADERS (trailers,
   sent after DATA — see TestHttp2HeadersNear72MiBInOneWrite). Both replace
   what used to be a flat per-frame cap (HTTP2_CAPTURE_MAX, still the
   per-ring-slot ceiling for a single captured chunk). */
#define HTTP2_STREAM_CAPTURE_MAX 4096

/* dir packs is_req (bit 0) and is_header (bit 1) into one byte: adding a
   4th scalar argument to these noinline calls (on top of the already
   tightly-verified classify_frame, inlined into both bpf_loop callbacks)
   was enough to blow the verifier's instruction budget for the contiguous
   walker. Packed, the call shape — and its verifier cost — stays exactly
   what it was before HEADERS and DATA got separate budgets. */
#define HTTP2_STREAM_DIR(is_req, is_header) ((__u8)((is_req) | ((is_header) << 1)))

/* Keyed by conn->timestamp, not (fd, pid): fds get closed and reused by an
   unrelated later connection constantly (every short-lived HTTP2 connection
   in these tests, and plenty of real workloads too), and a fresh connection
   that happens to reuse both an old fd AND a low, common stream ID (most
   protocols start client streams at 1) would otherwise inherit whatever
   budget the previous, unrelated connection had already spent. The
   connection timestamp is reset by the kernel on every accept()/connect(),
   so it uniquely names this connection's generation regardless of fd
   reuse — the same fix as the test harness's own fd-reuse race (see
   watchConn in tracer_test.go). dir (see HTTP2_STREAM_DIR) separates the
   HEADERS/CONTINUATION budget from the DATA budget on the same stream. */
struct http2_stream_key {
    __u64 conn_ts;
    __u32 stream_id;
    __u8 dir;
    __u8 pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct http2_stream_key));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 8192);
} http2_stream_budget SEC(".maps");

/* Keyed the same way as http2_stream_budget and for the same reason (fd
   reuse). A syscall boundary can land anywhere in the byte stream, including
   inside a frame's own 9-byte header — not just after it, which is all
   HTTP2_SKIP_HEADER/HTTP2_SKIP_DATA/HTTP2_SKIP_RAW (all *body*-continuation
   states) cover. This holds however many of those 9 header bytes a previous
   buffer for this connection+direction (is_req) already delivered but
   couldn't complete, so the next buffer can pick up in the middle of the
   header instead of misreading its leading bytes as a fresh one. */
struct http2_partial_hdr_key {
    __u64 conn_ts;
    __u8 is_req;
    __u8 pad[7];
};

struct http2_partial_hdr_val {
    __u8 hdr[HTTP2_FRAME_HEADER_SIZE - 1];
    __u8 len;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct http2_partial_hdr_key));
    __uint(value_size, sizeof(struct http2_partial_hdr_val));
    __uint(max_entries, 4096);
} http2_partial_hdr SEC(".maps");

/* noinline: called from within bpf_loop callbacks that already juggle a lot
   of scalar-range state (frame parsing, ring-slot math); inlining another
   map lookup's branches into them was enough to blow up verifier state
   exploration in the iovec walker. As a real subprogram call this is
   verified once, with a fixed, narrow argument contract. */
static __attribute__((noinline))
__u32 http2_stream_used(__u64 conn_ts, __u32 stream_id, __u8 dir) {
    struct http2_stream_key k = {.conn_ts = conn_ts, .stream_id = stream_id, .dir = dir};
    __u32 *v = bpf_map_lookup_elem(&http2_stream_budget, &k);
    return v ? *v : 0;
}

/* Bytes this stream may still capture before hitting HTTP2_STREAM_CAPTURE_MAX. */
static __attribute__((noinline))
__u32 http2_stream_remaining(__u64 conn_ts, __u32 stream_id, __u8 dir) {
    __u32 used = http2_stream_used(conn_ts, stream_id, dir);
    if (used >= HTTP2_STREAM_CAPTURE_MAX) {
        return 0;
    }
    return HTTP2_STREAM_CAPTURE_MAX - used;
}

static __attribute__((noinline))
void http2_stream_add(__u64 conn_ts, __u32 stream_id, __u8 dir, __u32 n) {
    struct http2_stream_key k = {.conn_ts = conn_ts, .stream_id = stream_id, .dir = dir};
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
   pending skip resume persists (more to skip and the stream can still take
   more) or clears. is_header picks which of the two persisted markers
   (HTTP2_SKIP_HEADER or HTTP2_SKIP_DATA) to stash, so the next resume
   rechecks the same budget this round drew from. Shared for the same
   reason as the above. */
static __always_inline
void http2_skip_topup_next(__u64 conn_ts, __u32 stream_id, __u8 is_req, __u8 is_header, __u32 skip,
                            __u32 *packed_out, __u8 *data_out) {
    if (!skip) {
        *packed_out = 0;
        *data_out = 0;
    } else if (http2_stream_remaining(conn_ts, stream_id, HTTP2_STREAM_DIR(is_req, is_header))) {
        *packed_out = stream_id;
        *data_out = is_header ? HTTP2_SKIP_HEADER : HTTP2_SKIP_DATA;
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
    __u8 is_header;

    length = ((__u32)hdr[0] << 16) | ((__u32)hdr[1] << 8) | hdr[2];
    type = hdr[3];
    stream_id = ((__u32)hdr[5] << 24) | ((__u32)hdr[6] << 16) | ((__u32)hdr[7] << 8) | hdr[8];
    *stream_id_out = stream_id;
    is_header = type == HTTP2_FRAME_HEADERS || type == HTTP2_FRAME_CONTINUATION;

    take = length;
    if (take > remain) {
        take = remain;
    }
    HTTP2_SRC_BOUND(take);
    if (take < length) {
        a->skip = length - take;
        a->skip_stream = stream_id;
        /* Overwritten below for a copyable frame that gets a proper cut-resume
           record (HTTP2_SKIP_CUT) or a header/data topup (HTTP2_SKIP_HEADER /
           HTTP2_SKIP_DATA); this is the value that sticks for everything else
           (non-copyable frames, and copyable frames whose stream is already
           at its capture cap) — a plain byte count with nothing to
           reconstruct. */
        a->skip_data = HTTP2_SKIP_RAW;
    } else {
        a->skip = 0;
        a->skip_data = 0;
    }
    *take_out = take;
    *copied_out = 0;
    if (!http2_copyable(type)) {
        return 0;
    }

    budget = http2_stream_remaining(a->conn_ts, stream_id, HTTP2_STREAM_DIR(a->is_req, is_header));
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
    http2_stream_add(a->conn_ts, stream_id, HTTP2_STREAM_DIR(a->is_req, is_header), copied);
    *copied_out = copied;
    *body_off_out = out + HTTP2_FRAME_HEADER_SIZE;
    return 0;
}

/* writev/readv/sendmsg. The bytes stay in the process. This table is the
   list of pointers. The frame walk switches to the next pointer inside one
   bpf_loop. */

#define HTTP2_TAIL_RESUME 0
#define HTTP2_TAIL_IOV 1
#define HTTP2_TAIL_READV 2
#define HTTP2_TAIL_READ_EXIT 3

/* One writev/readv/sendmsg. 1024 is IOV_MAX. 16 bytes per entry fits in a per-CPU map. */
#define HTTP2_MAX_VECS 1024

struct http2_vec {
    __u64 base;
    __u32 len;
    __u32 pad;
};

struct http2_iovec_table {
    /* Set to bpf_get_current_pid_tgid() by whichever real syscall last
       (re)populated this table, checked by every later stage of that same
       syscall's tail-call chain before trusting the rest of the struct —
       see the comment on http2_tail_state.owner below. */
    __u64 owner;
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

/* http2_tail_state and http2_iovecs are BPF_MAP_TYPE_PERCPU_ARRAY with a
   single slot: scratch space to carry the source (an iovec table — real for
   writev/readv/sendmsg, synthetic single-entry for plain write/read/TLS, see
   http2_tail_emit) across the bpf_tail_call chain that walks one syscall's
   HTTP2 bytes (RESUME -> IOV), since a tail call replaces the running
   program with no stack/register state surviving the jump. One slot per
   CPU, not per connection, is normally fine: the whole chain runs
   synchronously within the one task whose syscall triggered it, with no
   scheduling point in between for another task's syscall to intervene on
   the same core. "Normally" is doing real work in that sentence, though —
   under load this scratch slot has been observed to read back a completely
   different connection's leftover state (a skip count 10x too large to have
   come from the connection actually being walked), consistent with the
   kernel occasionally preempting mid-chain and running another
   HTTP2-carrying syscall's own chain (from an unrelated connection,
   possibly on a different core migrating in) in between. owner pins down
   which task's chain most recently claimed this slot; every stage after the
   one that sets it re-checks bpf_get_current_pid_tgid() against it and
   bails out cleanly (dropping just this one capture round) on a mismatch,
   rather than reading/writing a stream that was never this task's to
   touch. */
struct http2_tail_state {
    __u64 owner;
    struct connection_id cid;
    __u64 size;
    __u8 method;
    __u8 is_req;
};

/* True once, at the top of every SEC() program that resumes a chain another
   program's http2_tail_emit/http2_load_iovecs started (i.e. every stage
   except those two themselves): is this scratch slot still actually mine? */
static __always_inline
int http2_owner_mismatch(__u64 owner) {
    return owner != bpf_get_current_pid_tgid();
}

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
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} http2_tail_progs SEC(".maps");

/* Same programs, loaded as kprobe so an uprobe can tail-call them.
   A PROG_ARRAY holds one program type. Slots 2 and 3 stay empty:
   readv dispatch is tracepoint-only. */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 4);
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
    t->owner = bpf_get_current_pid_tgid();
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
    /* Generic (not _user): a vector's base can be a real userspace iovec
       base (writev/readv), or the kernel-side iovec_buf_heap scratch
       buffer standing in for one (see http2_tail_emit's synthetic
       single-vector table for the plain write/read/TLS path). */
    if (bpf_probe_read(out, 1, (void *)addr)) {
        return -1;
    }
    t->off = off + 1;
    t->consumed++;
    return 0;
}

/* Fast path for the overwhelmingly common case: the 9-byte frame header
   fits entirely within the iovec segment currently under the cursor, so it
   reads in one bpf_probe_read_user instead of nine separate
   map-lookup-plus-probe_read_user round trips (each with its own
   fault-safe user-copy overhead — see http2_iov_pull). Touches nothing and
   returns -1 if the header doesn't fit the current segment — callers fall
   back to pulling it a byte at a time. */
static __attribute__((noinline))
int http2_iov_pull_header_fast(unsigned char hdr[HTTP2_FRAME_HEADER_SIZE]) {
    struct http2_iovec_table *t;
    __u32 zero = 0;
    __u32 idx;
    __u32 off;
    __u32 len;
    __u64 addr;

    t = bpf_map_lookup_elem(&http2_iovecs, &zero);
    if (!t) {
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
    if (off < len && len - off >= HTTP2_FRAME_HEADER_SIZE) {
        addr = t->v[idx].base + off;
        /* Generic, same reasoning as http2_iov_pull. */
        if (bpf_probe_read(hdr, HTTP2_FRAME_HEADER_SIZE, (void *)addr)) {
            return -1;
        }
        t->off = off + HTTP2_FRAME_HEADER_SIZE;
        t->consumed += HTTP2_FRAME_HEADER_SIZE;
        return 0;
    }
    return -1;
}

/* http2_iov_pull_header_fast, falling back to a byte-at-a-time pull when the
   header doesn't fit the current iovec segment — a writev() CAN split a
   header across vectors within the one syscall
   (TestHttp2WritevHeaderSplitAcrossVectors exercises exactly that) — and
   resumable across syscalls: if a previous http2_tail_emit call for this
   connection+direction ran out of source bytes partway through these same 9
   header bytes, picks up where it left off (http2_partial_hdr) instead of
   misreading this buffer's leading bytes as a fresh header. Returns 0 with
   a complete header in `hdr`, or 1 if the source ran out again — in which
   case whatever was pulled this call (which may be nothing) has been
   folded into the saved partial record. */
static __always_inline
int http2_iov_pull_header_resumable(__u64 conn_ts, __u8 is_req, unsigned char hdr[HTTP2_FRAME_HEADER_SIZE]) {
    struct http2_partial_hdr_key key = {.conn_ts = conn_ts, .is_req = is_req};
    struct http2_partial_hdr_val *ph;
    struct http2_partial_hdr_val save;
    __u8 have = 0;
    int i;

    ph = bpf_map_lookup_elem(&http2_partial_hdr, &key);
    if (ph && ph->len && ph->len < HTTP2_FRAME_HEADER_SIZE) {
        /* Already bounded to 0..8 by the check above — have is only ever
           compared against the unrolled loop's compile-time index below,
           never used to index memory, so it needs no verifier-facing mask
           (unlike idx/off elsewhere in this file, which do). */
        have = ph->len;
        __builtin_memcpy(hdr, ph->hdr, sizeof(ph->hdr));
    }
    if (!have && !http2_iov_pull_header_fast(hdr)) {
        return 0;
    }
#pragma unroll
    for (i = 0; i < HTTP2_FRAME_HEADER_SIZE; i++) {
        if (i < have) {
            continue;
        }
        if (http2_iov_pull(&hdr[i])) {
            __builtin_memset(&save, 0, sizeof(save));
            __builtin_memcpy(save.hdr, hdr, sizeof(save.hdr));
            save.len = i;
            bpf_map_update_elem(&http2_partial_hdr, &key, &save, BPF_ANY);
            return 1;
        }
    }
    bpf_map_delete_elem(&http2_partial_hdr, &key);
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
    if (http2_iov_pull_header_resumable(a->conn_ts, a->is_req, hdr)) {
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
    __u8 is_header;
    __u8 data;
    (void)ctx;

    s = bpf_map_lookup_elem(&http2_tail_state, &zero);
    if (!s || http2_owner_mismatch(s->owner) || !s->size) {
        return 0;
    }
    cid = s->cid;
    is_req = s->is_req;
    iovs = bpf_map_lookup_elem(&http2_iovecs, &zero);
    if (!iovs || http2_owner_mismatch(iovs->owner) || !iovs->n) {
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
    if ((data == HTTP2_SKIP_HEADER || data == HTTP2_SKIP_DATA) && skip) {
        stream_id = packed;
        is_header = data == HTTP2_SKIP_HEADER;
        budget = http2_stream_remaining(conn_ts, stream_id, HTTP2_STREAM_DIR(is_req, is_header));
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
                http2_stream_add(conn_ts, stream_id, HTTP2_STREAM_DIR(is_req, is_header), need);
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
            http2_skip_topup_next(conn_ts, stream_id, is_req, is_header, skip, &packed, &data);
            iovs = bpf_map_lookup_elem(&http2_iovecs, &zero);
            if (!iovs) {
                return 0;
            }
            if (iovs->consumed >= iovs->total || data == HTTP2_SKIP_HEADER || data == HTTP2_SKIP_DATA) {
                conn = bpf_map_lookup_elem(&active_connections, &cid);
                http2_skip_save(conn, is_req, skip, packed, data);
                return 0;
            }
            skip = 0;
            packed = 0;
            data = 0;
        }
    } else if (data == HTTP2_SKIP_RAW && skip) {
        /* Tail of a frame this walker never captures (or a capped stream's
           frame), cut short by the previous buffer's end. No header/body to
           reconstruct, no budget to track — just walk past however many of
           the `skip` remaining bytes this buffer has. */
        left = 0;
        if (iovs->consumed < iovs->total) {
            left = iovs->total - iovs->consumed;
        }
        if (left > skip) {
            left = skip;
        }
        if (left) {
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
        if (skip) {
            conn = bpf_map_lookup_elem(&active_connections, &cid);
            http2_skip_save(conn, is_req, skip, 0, HTTP2_SKIP_RAW);
            return 0;
        }
        packed = 0;
        data = 0;
    }
    conn = bpf_map_lookup_elem(&active_connections, &cid);
    http2_skip_save(conn, is_req, skip, packed, data);
    iovs = bpf_map_lookup_elem(&http2_iovecs, &zero);
    if (iovs && iovs->n && iovs->v[0].len >= HTTP2_PREFACE_SIZE && iovs->idx == 0 && iovs->off == 0) {
        char p[6];
        if (!bpf_probe_read(p, sizeof(p), (void *)iovs->v[0].base) &&
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
        is_header = iovs->cut_hdr[3] == HTTP2_FRAME_HEADERS || iovs->cut_hdr[3] == HTTP2_FRAME_CONTINUATION;
        budget = http2_stream_remaining(conn_ts, stream_id, HTTP2_STREAM_DIR(is_req, is_header));
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
        http2_stream_add(conn_ts, stream_id, HTTP2_STREAM_DIR(is_req, is_header), n);
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
        if (http2_stream_remaining(conn_ts, stream_id, HTTP2_STREAM_DIR(is_req, is_header))) {
            http2_skip_save(conn, is_req, skip, stream_id, is_header ? HTTP2_SKIP_HEADER : HTTP2_SKIP_DATA);
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

/* Inline: bpf_tail_call must see the caller's ctx, and tail_progs must be a
   constant map of the same program type. Every plaintext HTTP/2 buffer
   enters http2_resume, which tail-calls straight into the iovec walker. */
static __always_inline
int http2_tail_emit(void *ctx, struct connection_id cid, struct connection *conn,
                    char *buf, __u64 size, __u8 is_req, __u8 from_heap, void *tail_progs) {
    __u32 zero = 0;
    struct http2_tail_state *s;
    struct http2_iovec_table *iovs;
    if (!conn) {
        return 0;
    }
    if (conn->protocol != PROTOCOL_HTTP2) {
        return 0;
    }
    iovs = bpf_map_lookup_elem(&http2_iovecs, &zero);
    /* A ready iovec table this task didn't itself just load (see
       http2_load_iovecs) belongs to whatever unrelated syscall last won the
       race for this CPU's scratch slot — not usable here. */
    if (iovs && iovs->ready && http2_owner_mismatch(iovs->owner)) {
        iovs = 0;
    }
    if (!(iovs && iovs->ready && iovs->total) && (!size || (!from_heap && !buf))) {
        return 0;
    }
    s = bpf_map_lookup_elem(&http2_tail_state, &zero);
    if (!s) {
        return 0;
    }
    s->owner = bpf_get_current_pid_tgid();
    s->cid = cid;
    s->is_req = is_req;
    s->method = is_req ? METHOD_HTTP2_CLIENT_FRAMES : METHOD_HTTP2_SERVER_FRAMES;
    if (iovs && iovs->ready && iovs->total) {
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
        /* No real (writev/readv/sendmsg) vector list: adapt the single
           contiguous buffer (a real userspace pointer for plain
           write/read/TLS-decrypted data, or the kernel-side
           iovec_buf_heap scratch standing in for one when from_heap) into
           a synthetic one-entry vector table, so every source funnels
           through the one walker (http2_iov_impl) instead of keeping a
           second, source-specific one just for this case. */
        char *src = buf;
        if (from_heap) {
            src = bpf_map_lookup_elem(&iovec_buf_heap, &zero);
            if (!src) {
                return 0;
            }
        }
        iovs = bpf_map_lookup_elem(&http2_iovecs, &zero);
        if (!iovs) {
            return 0;
        }
        iovs->owner = s->owner;
        iovs->n = 1;
        iovs->idx = 0;
        iovs->off = 0;
        iovs->v[0].base = (__u64)src;
        iovs->v[0].len = size;
        if (iovs->v[0].len > HTTP2_SRC_MAX) {
            iovs->v[0].len = HTTP2_SRC_MAX;
        }
        iovs->total = iovs->v[0].len;
        iovs->consumed = 0;
        iovs->skip_left = 0;
        iovs->cut_body = 0;
        iovs->cut_length = 0;
        iovs->ready = 0;

        s->size = iovs->total;
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

/* Not attached. Every source (writev/readv/sendmsg's real vector list, or
   http2_tail_emit's synthetic single-entry one for plain write/read/TLS)
   tail-calls here on its way to the iovec walker, so that walk gets its own
   verifier budget. tail_progs is the caller's prog array (tracepoint or
   kprobe). */
static __always_inline
int http2_resume_impl(void *ctx, void *tail_progs) {
    __u32 zero = 0;
    struct http2_tail_state *s;

    s = bpf_map_lookup_elem(&http2_tail_state, &zero);
    if (!s || http2_owner_mismatch(s->owner) || !s->size) {
        return 0;
    }
    bpf_tail_call(ctx, tail_progs, HTTP2_TAIL_IOV);
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

