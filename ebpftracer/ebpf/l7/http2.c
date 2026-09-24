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
/* h2_skip_*_data value: skip_stream holds (expect << 16) | have. */
#define HTTP2_SKIP_HEADER 2
/* Walk stopped on a cut HEADERS, CONTINUATION or DATA frame. pos is the
   frame start. Not stored on the connection — http2_cut handles it. */
#define HTTP2_SKIP_CUT 3

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
    __u32 pos;
    __u32 out_len;
    __u32 first_stream;
    __u32 skip;
    __u32 skip_stream;
    __u8 is_req;
    __u8 skip_data;
    __u8 method;
};

/* Defined in l7.c, after send_event. One message is at most MAX_PAYLOAD_SIZE. */
static __attribute__((noinline))
void http2_flush(struct http2_trim_args *a);

static __always_inline
int http2_copyable(__u8 type) {
    return type == HTTP2_FRAME_DATA || type == HTTP2_FRAME_HEADERS || type == HTTP2_FRAME_CONTINUATION;
}

/* Frame walk for the tail-call path. A HEADERS, CONTINUATION or DATA frame
   cut before 1KB is captured stops the loop (HTTP2_SKIP_CUT) so http2_cut
   can promise the length without growing this callback. */
static long http2_topup_cb(__u32 i, void *ctx) {
    struct http2_trim_args *a = ctx;
    unsigned char hdr[HTTP2_FRAME_HEADER_SIZE];
    unsigned char nh[HTTP2_FRAME_HEADER_SIZE];
    __u32 pos;
    __u32 remain;
    __u32 length;
    __u32 stream_id;
    __u32 take;
    __u32 start;
    __u32 copied;
    __u32 out;
    __u32 expect;
    __u8 type;
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
    length = ((__u32)hdr[0] << 16) | ((__u32)hdr[1] << 8) | hdr[2];
    type = hdr[3];
    stream_id = ((__u32)hdr[5] << 24) | ((__u32)hdr[6] << 16) | ((__u32)hdr[7] << 8) | hdr[8];
    remain = 0;
    if (pos < a->src_size && pos < HTTP2_SRC_MAX) {
        remain = a->src_size - pos;
        if (remain > HTTP2_SRC_MAX) {
            remain = HTTP2_SRC_MAX;
        }
    }
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
    if (http2_copyable(type)) {
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
        if (out + HTTP2_FRAME_HEADER_SIZE + copied > MAX_PAYLOAD_SIZE) {
            copied = MAX_PAYLOAD_SIZE - out - HTTP2_FRAME_HEADER_SIZE;
        }
        copied = http2_bound_body(copied);
        if (take < length && copied == take) {
            expect = length;
            if (expect > HTTP2_CAPTURE_MAX) {
                expect = HTTP2_CAPTURE_MAX;
            }
            if (copied < expect) {
                a->pos = start;
                a->skip_data = HTTP2_SKIP_CUT;
                return 1;
            }
        }
        nh[0] = copied >> 16;
        nh[1] = copied >> 8;
        nh[2] = copied;
        nh[3] = hdr[3];
        nh[4] = hdr[4];
        nh[5] = hdr[5];
        nh[6] = hdr[6];
        nh[7] = hdr[7];
        nh[8] = hdr[8];
        if (copy_to_payload(a->dst, out, HTTP2_FRAME_HEADER_SIZE, nh) ||
            copy_to_payload(a->dst, out + HTTP2_FRAME_HEADER_SIZE, copied, a->src + pos)) {
            return 1;
        }
        a->out_len = out + HTTP2_FRAME_HEADER_SIZE + copied;
        if (!a->first_stream) {
            a->first_stream = stream_id;
        }
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
