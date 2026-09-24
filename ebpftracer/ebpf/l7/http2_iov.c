/* writev/readv/sendmsg. The bytes stay in the process. This table is the list of
   pointers. The frame walk switches to the next pointer inside one bpf_loop. */

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

    rc = http2_classify_frame(a, hdr, remain, &take, &copied, &body_off);
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
       whole body, or a copyable frame's tail beyond the capture cap — is
       still sitting in the iovec cursor and must be walked past for real. */
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
    __u32 expect;
    __u32 need;
    __u32 left;
    __u32 rest;
    __u32 n;
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
    http2_skip_load(conn, is_req, &skip, &packed, &data);
    dst = bpf_map_lookup_elem(&http2_emit_heap, &zero);
    if (!dst) {
        return 0;
    }
    if (data == HTTP2_SKIP_HEADER && skip) {
        have = packed & 0xffffu;
        expect = packed >> 16;
        if (!expect || have >= expect || expect > HTTP2_CAPTURE_MAX) {
            data = 0;
            packed = 0;
        } else {
            need = expect - have;
            if (need > skip) {
                need = skip;
            }
            if (need > s->size) {
                need = s->size;
            }
            PAYLOAD_BOUND(need);
            if (need) {
                if (http2_iov_copy(dst, 0, need)) {
                    return 0;
                }
                t.cid = cid;
                t.dst = dst;
                t.out_len = need;
                t.method = s->method;
                http2_flush(&t);
                have += need;
                skip -= need;
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
            if (have >= expect || !skip) {
                data = 0;
                packed = 0;
            } else {
                data = HTTP2_SKIP_HEADER;
                packed = (expect << 16) | (have & 0xffffu);
            }
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
        expect = iovs->cut_length;
        if (expect > HTTP2_CAPTURE_MAX) {
            expect = HTTP2_CAPTURE_MAX;
        }
        n = iovs->cut_body;
        if (n > expect) {
            n = expect;
        }
        PAYLOAD_BOUND(n);
        http2_encode_frame_header(nh, expect, iovs->cut_hdr);
        if (copy_to_payload(dst, 0, HTTP2_FRAME_HEADER_SIZE, nh)) {
            return 0;
        }
        if (n && http2_iov_copy(dst, HTTP2_FRAME_HEADER_SIZE, n)) {
            return 0;
        }
        t.out_len = HTTP2_FRAME_HEADER_SIZE + n;
        t.first_stream = ((__u32)iovs->cut_hdr[5] << 24) | ((__u32)iovs->cut_hdr[6] << 16) |
                         ((__u32)iovs->cut_hdr[7] << 8) | iovs->cut_hdr[8];
        t.method = s->method;
        http2_flush(&t);
        conn = bpf_map_lookup_elem(&active_connections, &cid);
        if (iovs->cut_length >= iovs->cut_body) {
            skip = iovs->cut_length - iovs->cut_body;
        } else {
            skip = 0;
        }
        http2_skip_save(conn, is_req, skip, (expect << 16) | (n & 0xffffu), HTTP2_SKIP_HEADER);
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
