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

// noinline + bpf_loop: the sniffer is a separate BPF subprog so sendmmsg
// does not pay 8-frame tiling against its own 1M-insn budget.
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
