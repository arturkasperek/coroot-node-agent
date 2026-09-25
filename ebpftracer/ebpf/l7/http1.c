/* HTTP/1.x HEADERS/DATA capture, modeled on http2.c's per-direction budgets
   but for a text-delimited protocol: headers run until "\r\n\r\n" (not a
   fixed 9-byte length prefix), and the body's real length comes from either
   a Content-Length header or Transfer-Encoding: chunked's own chunk-size
   lines, both parsed out of the byte stream itself (see http1_hdr_scan_cb
   and http1_chunk_size_scan_cb), not a frame prefix. A body with neither
   (allowed for a response closed by the peer instead of framed) is still
   not handled — HTTP1_LEN_UNKNOWN sticks and every byte after the headers
   is (capped) DATA forever, same as Etap 1's behavior for that one case.

   Reuses http2.c's iovec-table plumbing (http2_iovecs, http2_iov_pull,
   http2_iov_copy, http2_iov_skip, http2_iov_adopt, http2_owner_mismatch)
   and http2_emit_heap as scratch: none of that is actually HTTP2-specific,
   it is a generic "walk a byte source, real iovec[] or a single contiguous
   buffer" abstraction that both protocols funnel through. */

#define HTTP1_CAPTURE_MAX 4096

/* Content-Length not seen (or not yet known) for the request/response whose
   body is being walked — sticks until Etap 3 adds chunked support (or a
   future change adds a close-delimited-body fallback for responses). While
   set, http1_capture_data never signals "body done", so no later pipelined
   request on the same connection is recognized — see the file comment. */
#define HTTP1_LEN_UNKNOWN (~0ULL)

/* How many phase transitions (HEADERS, DATA, or one chunk's worth of
   CHUNK_SIZE/CHUNK_DATA/CHUNK_CRLF) http1_walk_impl's self-tail-call chases
   in one buffer. Unlike a genuine cross-syscall resume (state saved,
   picked back up when the next syscall's buffer arrives), running out of
   rounds mid-buffer has no "next buffer" to resume into — this exact
   buffer's remaining bytes are simply never looked at again once its
   iovec table is replaced by the next call's. That only matters for
   pipelining (rare) or a chunked body with many chunks landing in one
   buffer (also rare — most either arrive one chunk at a time or coalesce
   into far fewer, larger reads); a generous bound keeps it rare in
   practice while staying well under the kernel's 33-tail-call-per-chain
   hard cap (this chain's other call — http1_tail_emit's own tail-call
   into the first round — takes one of those 33). */
#define HTTP1_MAX_ROUNDS 24

/* Bound for the header-scanning bpf_loop — NOT the same as HTTP1_CAPTURE_MAX:
   the walker must keep scanning (uncounted) for "\r\n\r\n" past the capture
   cap too, or headers longer than 4KB would never be recognized as ended,
   and everything after them (the real body) would be misread as more
   headers on the next call. Bounds the scan, not "how much to capture" —
   generously sized like http2.c's HTTP2_TRIM_MAX_FRAMES; the real per-call
   cost is however many bytes this buffer actually has, checked by
   http2_iov_pull returning -1 once the source runs dry. */
#define HTTP1_HDR_SCAN_MAX (1 << 20)

#define HTTP1_PHASE_HEADERS 0
#define HTTP1_PHASE_DATA 1
/* Transfer-Encoding: chunked's own framing (RFC 7230 4.1): a hex chunk-size
   line ended by "\r\n", that many bytes of chunk data, another "\r\n", then
   either another chunk-size line or (chunk-size 0) a trailer header block
   ended by "\r\n\r\n" — CHUNK_TRAILER reuses http1_hdr_scan_cb since a
   trailer block is exactly that shape, just discarding any Content-Length
   it finds (chunked bodies don't have one) instead of acting on it. */
#define HTTP1_PHASE_CHUNK_SIZE 2
#define HTTP1_PHASE_CHUNK_DATA 3
#define HTTP1_PHASE_CHUNK_CRLF 4
#define HTTP1_PHASE_CHUNK_TRAILER 5

/* Keyed like http2_stream_budget/http2_partial_hdr (conn_ts, not fd/pid) for
   the same fd-reuse reason. Unlike HTTP2, HTTP/1 has no stream ID, so this
   is the whole per-direction cross-syscall state: how much of the 4KB
   headers/data budgets is spent, which phase we're in, and the last <=3
   scanned bytes so a "\r\n\r\n" split across a syscall boundary is still
   found. */
struct http1_state_key {
    __u64 conn_ts;
    __u8 is_req;
    __u8 pad[7];
};

struct http1_state_val {
    __u64 content_length;    /* accumulated so far this Content-Length header */
    /* Real bytes not yet accounted for in the current body-like phase:
       the overall Content-Length body in HTTP1_PHASE_DATA, or the current
       chunk's size in HTTP1_PHASE_CHUNK_DATA (and the chunk size itself
       being accumulated, in hex, while in HTTP1_PHASE_CHUNK_SIZE — see
       http1_chunk_size_scan_cb). HTTP1_LEN_UNKNOWN if no Content-Length
       and not chunked. */
    __u64 body_remaining;
    __u32 hdr_captured;
    __u32 data_captured;
    __u8 phase;
    __u8 tail[3];
    __u8 tail_len;
    /* Content-Length: name-matching state, carried across syscalls the same
       way tail[] carries the "\r\n\r\n" match — see http1_hdr_scan_cb. */
    __u8 line_pos;
    __u8 line_mismatch;
    __u8 in_value;
    __u8 have_content_length;
    /* Transfer-Encoding: chunked detection — same shape as the
       Content-Length matcher above, plus value_pos to match "chunked"
       itself once the header name matches. */
    __u8 te_line_pos;
    __u8 te_line_mismatch;
    __u8 te_in_value;
    __u8 te_value_pos;
    __u8 chunked;
    /* HTTP1_PHASE_CHUNK_SIZE's own "\r\n" search state (a plain 2-byte
       terminator, not "\r\n\r\n") and whether a ';' chunk-extension is
       being skipped. HTTP1_PHASE_CHUNK_CRLF's post-chunk-data "\r\n" just
       counts bytes consumed (0, 1, then done at 2) in chunk_crlf_consumed. */
    __u8 chunk_saw_cr;
    __u8 chunk_in_ext;
    __u8 chunk_crlf_consumed;
    __u8 pad[1];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct http1_state_key));
    __uint(value_size, sizeof(struct http1_state_val));
    __uint(max_entries, 4096);
} http1_state SEC(".maps");

struct http1_flush_args {
    struct connection_id cid;
    char *dst;
    __u32 out_len;
    __u8 method;
};

/* Same ring-emission shape as http2_flush, but protocol is always
   PROTOCOL_HTTP and there is no stream id (statement_id left 0) — kept
   separate rather than parameterizing http2_flush, since that function is
   freshly stabilized and its struct/call sites are HTTP2-frame-specific
   (first_stream) in ways not worth entangling with a second protocol. */
static __attribute__((noinline))
void http1_flush(struct http1_flush_args *a) {
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
        return;
    }
    e = bpf_map_lookup_elem(&l7_event_heap, &zero);
    if (!e) {
        a->out_len = 0;
        return;
    }
    n = a->out_len;
    if (n > MAX_PAYLOAD_SIZE) {
        n = MAX_PAYLOAD_SIZE;
    }
    PAYLOAD_BOUND(n);
    e->protocol = PROTOCOL_HTTP;
    e->method = a->method;
    e->is_inbound = conn->is_inbound;
    e->status = STATUS_UNKNOWN;
    e->statement_id = 0;
    e->duration = bpf_ktime_get_ns();
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
}

struct http1_hdr_scan_ctx {
    struct connection_id cid;
    char *dst;
    __u32 out_len;
    __u32 hdr_captured;
    __u64 content_length;
    __u8 tail[3];
    __u8 tail_len;
    __u8 line_pos;
    __u8 line_mismatch;
    __u8 in_value;
    __u8 have_content_length;
    __u8 te_line_pos;
    __u8 te_line_mismatch;
    __u8 te_in_value;
    __u8 te_value_pos;
    __u8 chunked;
    __u8 done;
    __u8 method;
    /* Set for a chunked trailer block (HTTP1_PHASE_CHUNK_TRAILER): still
       scans Content-Length/Transfer-Encoding (harmless — trailers don't
       carry a body of their own either way), but the caller ignores the
       results and always goes to HTTP1_PHASE_HEADERS on done, never to a
       body phase. */
    __u8 is_trailer;
};

/* "content-length:" lowercased, matched byte-by-byte case-insensitively
   against each header line's start — mirrors http2's "\r\n\r\n" tail match:
   line_pos/line_mismatch/in_value/have_content_length/content_length all
   persist across syscalls in http1_state exactly like tail[]/tail_len do,
   so a header split mid-name (or mid-digit) is still parsed correctly. */
static const char http1_content_length_name[] = "content-length:";
#define HTTP1_CONTENT_LENGTH_NAME_LEN 15

/* Same idea for "transfer-encoding:", then matching "chunked" itself
   (case-insensitively) as the value — a value list like "gzip, chunked" is
   not recognized (chunked must be the whole value here), which covers the
   overwhelming majority of real Transfer-Encoding headers. */
static const char http1_transfer_encoding_name[] = "transfer-encoding:";
#define HTTP1_TRANSFER_ENCODING_NAME_LEN 18
static const char http1_chunked_value[] = "chunked";
#define HTTP1_CHUNKED_VALUE_LEN 7

/* One byte per bpf_loop iteration: unlike a DATA chunk (a flat byte count),
   where the headers end is data-dependent (the "\r\n\r\n" delimiter), so
   there is no way to bulk-copy ahead of knowing where to stop. Byte-at-a-
   time is the same tradeoff http2_iov_pull_header's byte fallback makes,
   just for the whole header block instead of 9 fixed bytes — headers are
   typically a few hundred bytes in real traffic, not the full 4KB cap. */
static long http1_hdr_scan_cb(__u32 i, void *ctx) {
    struct http1_hdr_scan_ctx *a = ctx;
    struct http1_flush_args f;
    __u8 b;
    __u8 lb;
    __u8 match;
    (void)i;

    if (!a) {
        return 1;
    }
    if (http2_iov_pull(&b)) {
        return 1;
    }
    match = a->tail_len >= 3 && a->tail[0] == '\r' && a->tail[1] == '\n' &&
            a->tail[2] == '\r' && b == '\n';

    /* Content-Length: name/value scan. Runs on every byte regardless of the
       capture cap — this is metadata, not captured payload. */
    if (!a->have_content_length) {
        if (!a->line_mismatch && a->line_pos < HTTP1_CONTENT_LENGTH_NAME_LEN) {
            lb = b;
            if (lb >= 'A' && lb <= 'Z') {
                lb = lb - 'A' + 'a';
            }
            if (lb == http1_content_length_name[a->line_pos]) {
                a->line_pos += 1;
                if (a->line_pos == HTTP1_CONTENT_LENGTH_NAME_LEN) {
                    a->in_value = 1;
                }
            } else {
                a->line_mismatch = 1;
            }
        } else if (a->in_value) {
            if (b == ' ' || b == '\t') {
                /* skip leading whitespace before the digits */
            } else if (b >= '0' && b <= '9') {
                if (a->content_length < (HTTP1_LEN_UNKNOWN - 9) / 10) {
                    a->content_length = a->content_length * 10 + (b - '0');
                }
            } else {
                a->have_content_length = 1;
                a->in_value = 0;
            }
        }
    }
    if (!a->chunked) {
        if (!a->te_line_mismatch && a->te_line_pos < HTTP1_TRANSFER_ENCODING_NAME_LEN) {
            lb = b;
            if (lb >= 'A' && lb <= 'Z') {
                lb = lb - 'A' + 'a';
            }
            if (lb == http1_transfer_encoding_name[a->te_line_pos]) {
                a->te_line_pos += 1;
                if (a->te_line_pos == HTTP1_TRANSFER_ENCODING_NAME_LEN) {
                    a->te_in_value = 1;
                }
            } else {
                a->te_line_mismatch = 1;
            }
        } else if (a->te_in_value) {
            if (b == ' ' || b == '\t') {
                /* skip leading whitespace before the value */
            } else {
                lb = b;
                if (lb >= 'A' && lb <= 'Z') {
                    lb = lb - 'A' + 'a';
                }
                if (a->te_value_pos < HTTP1_CHUNKED_VALUE_LEN && lb == http1_chunked_value[a->te_value_pos]) {
                    a->te_value_pos += 1;
                    if (a->te_value_pos == HTTP1_CHUNKED_VALUE_LEN) {
                        a->chunked = 1;
                        a->te_in_value = 0;
                    }
                } else {
                    a->te_in_value = 0;
                }
            }
        }
    }
    if (b == '\n') {
        a->line_pos = 0;
        a->line_mismatch = 0;
        a->te_line_pos = 0;
        a->te_line_mismatch = 0;
        a->te_value_pos = 0;
    }

    if (a->hdr_captured < HTTP1_CAPTURE_MAX) {
        if (a->out_len >= MAX_PAYLOAD_SIZE) {
            f.cid = a->cid;
            f.dst = a->dst;
            f.out_len = a->out_len;
            f.method = a->method;
            http1_flush(&f);
            a->out_len = f.out_len;
        }
        if (copy_to_payload(a->dst, a->out_len, 1, &b)) {
            return 1;
        }
        a->out_len += 1;
        a->hdr_captured += 1;
    }
    a->tail[0] = a->tail[1];
    a->tail[1] = a->tail[2];
    a->tail[2] = b;
    if (a->tail_len < 3) {
        a->tail_len += 1;
    }
    if (match) {
        a->done = 1;
        return 1;
    }
    return 0;
}

/* Flat cap, no framing: copies whatever's left in the iovec source, up to
   both HTTP1_CAPTURE_MAX total for this (connection, direction) and
   *body_remaining (the real body length from Content-Length, if known —
   see http1_hdr_scan_cb), in MAX_PAYLOAD_SIZE-sized ring records
   (http2_flush's per-slot ceiling applies here too). Skips whatever of the
   real body wasn't captured (over budget) so the source cursor lands
   exactly at the end of this body — the start of the next pipelined
   request's headers, if there is one, rather than partway into it.
   Returns 1 once *body_remaining reaches 0 (the whole real body has been
   accounted for, whether or not all of it was captured), 0 otherwise —
   either the source ran out first, or the length is unknown and there is
   no "done" to reach (see HTTP1_LEN_UNKNOWN). */
static __always_inline
int http1_capture_data(struct connection_id cid, __u32 *data_captured, __u64 *body_remaining, char *dst, __u8 method) {
    struct http2_iovec_table *iovs;
    struct http1_flush_args f;
    __u32 zero = 0;
    __u32 remain;
    __u32 avail;
    __u32 want;
    __u32 captured_now = 0;
    __u32 chunk;
    int i;

    iovs = bpf_map_lookup_elem(&http2_iovecs, &zero);
    if (!iovs) {
        return 0;
    }
    remain = 0;
    if (iovs->consumed < iovs->total) {
        remain = iovs->total - iovs->consumed;
    }
    if (!remain) {
        return 0;
    }
    avail = remain;
    if (*body_remaining != HTTP1_LEN_UNKNOWN && *body_remaining < (__u64)avail) {
        avail = (__u32)*body_remaining;
    }
    want = 0;
    if (*data_captured < HTTP1_CAPTURE_MAX) {
        want = HTTP1_CAPTURE_MAX - *data_captured;
    }
    if (want > avail) {
        want = avail;
    }
#pragma unroll
    for (i = 0; i < (HTTP1_CAPTURE_MAX / MAX_PAYLOAD_SIZE); i++) {
        if (!want) {
            continue;
        }
        chunk = want;
        if (chunk > MAX_PAYLOAD_SIZE) {
            chunk = MAX_PAYLOAD_SIZE;
        }
        if (http2_iov_copy(dst, 0, chunk)) {
            return 0;
        }
        f.cid = cid;
        f.dst = dst;
        f.out_len = chunk;
        f.method = method;
        http1_flush(&f);
        *data_captured += chunk;
        captured_now += chunk;
        want -= chunk;
    }
    if (avail > captured_now) {
        http2_iov_skip(avail - captured_now);
    }
    if (*body_remaining == HTTP1_LEN_UNKNOWN) {
        return 0;
    }
    *body_remaining -= avail;
    return *body_remaining == 0;
}

struct http1_chunk_size_scan_ctx {
    __u64 chunk_size;
    __u8 saw_cr;
    __u8 in_ext;
    __u8 done;
};

/* A chunk-size line: hex digits, an optional ";extension" (skipped, not
   parsed), terminated by a plain "\r\n" (not "\r\n\r\n" — a chunk-size line
   is exactly one line). Same byte-at-a-time/resumable shape as
   http1_hdr_scan_cb's "\r\n\r\n" search, just a 2-byte terminator and hex
   instead of decimal. */
static long http1_chunk_size_scan_cb(__u32 i, void *ctx) {
    struct http1_chunk_size_scan_ctx *a = ctx;
    __u8 b;
    __u8 v;
    (void)i;

    if (!a) {
        return 1;
    }
    if (http2_iov_pull(&b)) {
        return 1;
    }
    if (a->saw_cr && b == '\n') {
        a->done = 1;
        return 1;
    }
    a->saw_cr = (b == '\r');
    if (!a->saw_cr && !a->in_ext) {
        v = 0xff;
        if (b >= '0' && b <= '9') {
            v = b - '0';
        } else if (b >= 'a' && b <= 'f') {
            v = b - 'a' + 10;
        } else if (b >= 'A' && b <= 'F') {
            v = b - 'A' + 10;
        }
        if (v != 0xff) {
            if (a->chunk_size < (HTTP1_LEN_UNKNOWN >> 4)) {
                a->chunk_size = (a->chunk_size << 4) | v;
            }
        } else if (b == ';') {
            a->in_ext = 1;
        }
        /* Anything else on the line (stray whitespace, ...) is tolerated:
           neither a hex digit nor ';', so just ignored until the "\r\n". */
    }
    return 0;
}

/* The mandatory "\r\n" after a chunk's data, before the next chunk-size
   line. Always exactly 2 bytes with no content to interpret, but still
   needs to resume correctly if a syscall boundary lands between them —
   *consumed persists across calls the same way every other partial-scan
   counter in this file does. Returns 1 once both bytes are in. */
static __always_inline
int http1_chunk_crlf_step(__u8 *consumed) {
    __u8 b;
    int i;

#pragma unroll
    for (i = 0; i < 2; i++) {
        if (*consumed < 2) {
            if (http2_iov_pull(&b)) {
                return 0;
            }
            *consumed += 1;
        }
    }
    return *consumed >= 2;
}

/* Percpu scratch carrying http1_tail_emit's arguments across the
   bpf_tail_call to http1_walk_impl — same reasoning as http2_tail_state:
   a tail call replaces the running program, nothing survives on the
   stack/in registers. owner guards against another task's syscall winning
   this CPU's slot in between (see http2_owner_mismatch). round counts how
   many times http1_walk_impl has tail-called itself for this buffer (see
   below), bounding HTTP1_MAX_ROUNDS independent of any one call's own
   verifier budget. */
struct http1_tail_state {
    __u64 owner;
    struct connection_id cid;
    __u64 conn_ts;
    __u8 is_req;
    __u8 round;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct http1_tail_state);
} http1_tail_state SEC(".maps");

/* Not attached: tail-called only, so the bpf_loop-heavy header/chunk scan
   gets its own verifier budget separate from whichever real hook
   (sys_enter_write, sys_exit_read, a TLS uprobe, ...) triggered it — the
   same reason HTTP2's frame walk is a separate stage. Processes exactly one
   phase transition (HEADERS, DATA, or one of the chunked sub-phases — see
   the HTTP1_PHASE_* comments); reaching the end of one with more of this
   buffer still unconsumed tail-calls itself again for the next phase,
   bounded by http1_tail_state.round rather than unrolling a loop over
   phases in one call — an earlier version did that and blew the same
   1M-instruction verifier budget HTTP2's own frame walk needs its own
   stage to avoid. A single chunked body with many small chunks can need
   more rounds than one buffer's worth of tail-calls provides; it simply
   keeps resuming (via http1_state) across as many later buffers as it
   takes, same as a slow trickle of any other kind. */
static __always_inline
int http1_walk_impl(void *ctx, void *tail_progs) {
    __u32 zero = 0;
    struct http1_tail_state *s;
    struct http1_state_key key = {};
    struct http1_state_val sv = {};
    struct http1_state_val *st;
    struct http1_hdr_scan_ctx sc;
    struct http1_chunk_size_scan_ctx cs;
    struct http1_flush_args f;
    struct http2_iovec_table *iovs;
    char *dst;
    __u32 source_left;
    __u8 method;

    s = bpf_map_lookup_elem(&http1_tail_state, &zero);
    if (!s || http2_owner_mismatch(s->owner)) {
        return 0;
    }
    key.conn_ts = s->conn_ts;
    key.is_req = s->is_req;
    st = bpf_map_lookup_elem(&http1_state, &key);
    if (st) {
        __builtin_memcpy(&sv, st, sizeof(sv));
    } else {
        sv.body_remaining = HTTP1_LEN_UNKNOWN;
    }
    dst = bpf_map_lookup_elem(&http2_emit_heap, &zero);
    if (!dst) {
        return 0;
    }

    if (sv.phase == HTTP1_PHASE_HEADERS || sv.phase == HTTP1_PHASE_CHUNK_TRAILER) {
        __builtin_memset(&sc, 0, sizeof(sc));
        sc.cid = s->cid;
        sc.dst = dst;
        sc.is_trailer = (sv.phase == HTTP1_PHASE_CHUNK_TRAILER);
        sc.hdr_captured = sv.hdr_captured;
        sc.content_length = sv.content_length;
        sc.tail[0] = sv.tail[0];
        sc.tail[1] = sv.tail[1];
        sc.tail[2] = sv.tail[2];
        sc.tail_len = sv.tail_len;
        sc.line_pos = sv.line_pos;
        sc.line_mismatch = sv.line_mismatch;
        sc.in_value = sv.in_value;
        sc.have_content_length = sv.have_content_length;
        sc.te_line_pos = sv.te_line_pos;
        sc.te_line_mismatch = sv.te_line_mismatch;
        sc.te_in_value = sv.te_in_value;
        sc.te_value_pos = sv.te_value_pos;
        sc.chunked = sv.chunked;
        sc.method = s->is_req ? METHOD_HTTP_CLIENT_HEADERS : METHOD_HTTP_SERVER_HEADERS;

        bpf_loop(HTTP1_HDR_SCAN_MAX, http1_hdr_scan_cb, &sc, 0);

        if (sc.out_len) {
            f.cid = s->cid;
            f.dst = dst;
            f.out_len = sc.out_len;
            f.method = sc.method;
            http1_flush(&f);
        }
        sv.hdr_captured = sc.hdr_captured;
        sv.content_length = sc.content_length;
        sv.tail[0] = sc.tail[0];
        sv.tail[1] = sc.tail[1];
        sv.tail[2] = sc.tail[2];
        sv.tail_len = sc.tail_len;
        sv.line_pos = sc.line_pos;
        sv.line_mismatch = sc.line_mismatch;
        sv.in_value = sc.in_value;
        sv.have_content_length = sc.have_content_length;
        sv.te_line_pos = sc.te_line_pos;
        sv.te_line_mismatch = sc.te_line_mismatch;
        sv.te_in_value = sc.te_in_value;
        sv.te_value_pos = sc.te_value_pos;
        sv.chunked = sc.chunked;
        if (!sc.done) {
            bpf_map_update_elem(&http1_state, &key, &sv, BPF_ANY);
            return 0;
        }
        sv.hdr_captured = 0;
        sv.line_pos = 0;
        sv.line_mismatch = 0;
        sv.in_value = 0;
        sv.have_content_length = 0;
        sv.te_line_pos = 0;
        sv.te_line_mismatch = 0;
        sv.te_in_value = 0;
        sv.te_value_pos = 0;
        if (sc.is_trailer) {
            sv.phase = HTTP1_PHASE_HEADERS;
            sv.chunked = 0;
            sv.content_length = 0;
            sv.data_captured = 0;
        } else if (sc.chunked) {
            sv.phase = HTTP1_PHASE_CHUNK_SIZE;
            sv.body_remaining = 0;
            sv.chunk_saw_cr = 0;
            sv.chunk_in_ext = 0;
            sv.content_length = 0;
            sv.data_captured = 0;
        } else {
            sv.phase = HTTP1_PHASE_DATA;
            sv.body_remaining = sc.have_content_length ? sc.content_length : HTTP1_LEN_UNKNOWN;
            sv.content_length = 0;
            sv.chunked = 0;
            sv.data_captured = 0;
        }
    } else if (sv.phase == HTTP1_PHASE_CHUNK_SIZE) {
        cs.chunk_size = sv.body_remaining;
        cs.saw_cr = sv.chunk_saw_cr;
        cs.in_ext = sv.chunk_in_ext;
        cs.done = 0;

        bpf_loop(HTTP1_HDR_SCAN_MAX, http1_chunk_size_scan_cb, &cs, 0);

        sv.body_remaining = cs.chunk_size;
        sv.chunk_saw_cr = cs.saw_cr;
        sv.chunk_in_ext = cs.in_ext;
        if (!cs.done) {
            bpf_map_update_elem(&http1_state, &key, &sv, BPF_ANY);
            return 0;
        }
        sv.phase = sv.body_remaining ? HTTP1_PHASE_CHUNK_DATA : HTTP1_PHASE_CHUNK_TRAILER;
    } else if (sv.phase == HTTP1_PHASE_CHUNK_DATA) {
        method = s->is_req ? METHOD_HTTP_CLIENT_DATA : METHOD_HTTP_SERVER_DATA;
        if (!http1_capture_data(s->cid, &sv.data_captured, &sv.body_remaining, dst, method)) {
            bpf_map_update_elem(&http1_state, &key, &sv, BPF_ANY);
            return 0;
        }
        sv.phase = HTTP1_PHASE_CHUNK_CRLF;
        sv.chunk_crlf_consumed = 0;
    } else if (sv.phase == HTTP1_PHASE_CHUNK_CRLF) {
        if (!http1_chunk_crlf_step(&sv.chunk_crlf_consumed)) {
            bpf_map_update_elem(&http1_state, &key, &sv, BPF_ANY);
            return 0;
        }
        sv.phase = HTTP1_PHASE_CHUNK_SIZE;
        sv.body_remaining = 0;
        sv.chunk_saw_cr = 0;
        sv.chunk_in_ext = 0;
    } else {
        method = s->is_req ? METHOD_HTTP_CLIENT_DATA : METHOD_HTTP_SERVER_DATA;
        if (!http1_capture_data(s->cid, &sv.data_captured, &sv.body_remaining, dst, method)) {
            bpf_map_update_elem(&http1_state, &key, &sv, BPF_ANY);
            return 0;
        }
        sv.phase = HTTP1_PHASE_HEADERS;
        sv.data_captured = 0;
    }

    bpf_map_update_elem(&http1_state, &key, &sv, BPF_ANY);

    iovs = bpf_map_lookup_elem(&http2_iovecs, &zero);
    if (!iovs) {
        return 0;
    }
    source_left = 0;
    if (iovs->consumed < iovs->total) {
        source_left = iovs->total - iovs->consumed;
    }
    if (!source_left || s->round >= HTTP1_MAX_ROUNDS) {
        return 0;
    }
    s->round += 1;
    bpf_tail_call(ctx, tail_progs, HTTP1_TAIL_WALK);
    return 0;
}

SEC("tracepoint/http1/walk")
int http1_walk(void *ctx) {
    return http1_walk_impl(ctx, &http2_tail_progs);
}

SEC("uprobe/http1_walk")
int http1_walk_kp(void *ctx) {
    return http1_walk_impl(ctx, &http2_tail_progs_kprobe);
}

/* Entry point: mirrors http2_tail_emit's shape (called for every buffer on
   an established connection, plus once more to process the very first one
   right after protocol detection sets conn->protocol). Cheap — no bpf_loop
   here — so it runs inline from trace_enter_write/trace_exit_read/the TLS
   hooks, then tail-calls http1_walk for the actual scan (see above). Reuses
   the caller's http2_tail_progs(_kprobe) array (HTTP1_TAIL_WALK slot):
   both protocols' tail-call chains are plain program-type-keyed jump
   tables, nothing HTTP2-specific about sharing one. */
static __always_inline
int http1_tail_emit(void *ctx, struct connection_id cid, struct connection *conn,
                    char *buf, __u64 size, __u8 is_req, __u8 from_heap, void *tail_progs) {
    __u32 zero = 0;
    struct http2_iovec_table *iovs;
    struct http1_tail_state *s;

    if (!conn || conn->protocol != PROTOCOL_HTTP) {
        return 0;
    }
    iovs = http2_iov_adopt(buf, size, from_heap);
    if (!iovs) {
        return 0;
    }
    s = bpf_map_lookup_elem(&http1_tail_state, &zero);
    if (!s) {
        return 0;
    }
    s->owner = bpf_get_current_pid_tgid();
    s->cid = cid;
    s->conn_ts = conn->timestamp;
    s->is_req = is_req;
    s->round = 0;
    bpf_tail_call(ctx, tail_progs, HTTP1_TAIL_WALK);
    return 1;
}
