/* HTTP/1.x HEADERS/DATA capture, modeled on http2.c's per-direction budgets
   but for a text-delimited protocol: headers run until "\r\n\r\n" (not a
   fixed 9-byte length prefix), and the body's real length comes from either
   a Content-Length header or Transfer-Encoding: chunked's own chunk-size
   lines, both parsed out of the byte stream itself (see http1_hdr_scan_cb
   and http1_chunks_walk_cb), not a frame prefix. A body with neither
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
   set, http1_body_step never brings the body to its end, so no later message
   on the same connection is recognized — see the file comment. */
#define HTTP1_LEN_UNKNOWN (~0ULL)

/* How many phases (HEADERS, DATA, a chunked body's framing, its trailer)
   http1_walk_impl's self-tail-call chases in one buffer. Unlike a genuine
   cross-syscall resume (state saved, picked back up when the next syscall's
   buffer arrives), running out of rounds mid-buffer has no "next buffer" to
   resume into — this exact buffer's remaining bytes are simply never looked
   at again once its iovec table is replaced by the next call's. A message
   takes at most three phases, so it only matters for many messages in one
   buffer (pipelining, which the agent does not follow anyway); a generous
   bound stays well under the kernel's 33-tail-call-per-chain hard cap (this
   chain's other call — http1_tail_emit's own tail-call into the first
   round — takes one of those 33). */
#define HTTP1_MAX_ROUNDS 30

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
       http1_chunks_walk_cb). HTTP1_LEN_UNKNOWN if no Content-Length
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
    /* The status code of a response, read off its first line ("HTTP/1.1 304
       ..."): the digits after the first space. Carried across syscalls like
       the matchers above. A request's first line goes through the same scan
       and its "status" is ignored. */
    __u8 status_line_done;
    __u8 status_space_seen;
    __u8 status_digits;
    __u16 status_code;
    /* The first word of a request line, matched against "HEAD": how many of
       its bytes were seen, and whether one did not match. */
    __u8 first_word_len;
    __u8 not_head;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct http1_state_key));
    __uint(value_size, sizeof(struct http1_state_val));
    __uint(max_entries, 4096);
} http1_state SEC(".maps");

/* Connections (by conn_ts) whose request waiting for a response is a HEAD: its
   response carries the Content-Length of the resource but no body (RFC 9110
   9.3.2). Set by the request direction, taken by the response direction — a map
   of its own because each direction rewrites its http1_state entry whole. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);
    __type(value, __u8);
    __uint(max_entries, 4096);
} http1_head_requests SEC(".maps");

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
    /* the connection's direction as seen when the chain started (see
       http1_flush for why it is not looked up again there) */
    __u8 is_inbound;
    /* its bodies are captured by the client's agent (connection.skip_bodies):
       the body steps skip them as if the capture budget were spent */
    __u8 skip_bodies;
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct http1_tail_state);
} http1_tail_state SEC(".maps");

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
    struct http1_tail_state *ts;
    __u64 conn_ts;
    __u8 inbound;
    __u32 n;
    if (!a || !a->out_len || !a->dst) {
        return;
    }
    /* Stamp the event with the connection identity the chain started with
       (http1_tail_emit's), not with whatever active_connections holds for
       this (pid, fd) by now: every request here is a fresh connection and
       fds are recycled within microseconds, so by the time a slow walk got
       to emit, the fd could already belong to the NEXT connection — the
       event then reached the agent under that connection's timestamp, and
       was worse than lost (it was somebody else's data). If the connection
       has already been closed, emit anyway: the agent keeps recently closed
       connections around, and matches by (pid, fd, timestamp). */
    ts = scratch_lookup(&http1_tail_state);
    if (ts && ts->owner == bpf_get_current_pid_tgid() &&
        ts->cid.pid == a->cid.pid && ts->cid.fd == a->cid.fd) {
        conn_ts = ts->conn_ts;
        inbound = ts->is_inbound;
    } else {
        conn = bpf_map_lookup_elem(&active_connections, &a->cid);
        if (!conn) {
            a->out_len = 0;
            return;
        }
        conn_ts = conn->timestamp;
        inbound = conn->is_inbound;
    }
    e = scratch_lookup(&l7_event_heap);
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
    e->is_inbound = inbound;
    e->status = STATUS_UNKNOWN;
    e->statement_id = 0;
    e->duration = bpf_ktime_get_ns();
    {
        struct bpf_dynptr d = {};
        __u32 pn = payload_copy_len(n);
        __u32 rec = sizeof(*e) + pn;
        e->connection_timestamp = conn_ts;
        e->fd = a->cid.fd;
        e->pid = a->cid.pid;
        e->payload_size = n;
        e->ts = bpf_ktime_get_ns();
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
    __u8 status_line_done;
    __u8 status_space_seen;
    __u8 status_digits;
    __u16 status_code;
    __u8 first_word_len;
    __u8 not_head;
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
static const char http1_head_method[] = "HEAD";
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
    if (!a->status_line_done) {
        if (b == '\n') {
            a->status_line_done = 1;
        } else if (!a->status_space_seen) {
            if (b == ' ') {
                a->status_space_seen = 1;
            } else {
                if (a->first_word_len >= 4 || b != http1_head_method[a->first_word_len]) {
                    a->not_head = 1;
                }
                if (a->first_word_len < 0xff) {
                    a->first_word_len += 1;
                }
            }
        } else if (a->status_digits < 3 && b >= '0' && b <= '9') {
            a->status_code = a->status_code * 10 + (b - '0');
            a->status_digits += 1;
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

/* One step through a body: up to MAX_PAYLOAD_SIZE bytes of it captured while
   the message's HTTP1_CAPTURE_MAX budget lasts, or all that this buffer holds
   of it skipped once the budget is spent, so the source cursor lands exactly at
   the end of the body when it is in the buffer. *remaining is what is left of
   the body (or of the current chunk), HTTP1_LEN_UNKNOWN for a body that ends
   with the connection. Returns the bytes stepped over, 0 once the buffer is
   out. Small on purpose: it runs inside bpf_loop callbacks, and the 4 KB of a
   capture take four iterations rather than an unrolled copy loop. */
static __always_inline
__u32 http1_body_step(struct connection_id cid, char *dst, __u8 method, __u32 *data_captured, __u64 *remaining) {
    struct http2_iovec_table *iovs;
    struct http1_flush_args f;
    __u32 zero = 0;
    __u32 n;

    iovs = scratch_lookup(&http2_iovecs);
    if (!iovs || iovs->consumed >= iovs->total) {
        return 0;
    }
    n = iovs->total - iovs->consumed;
    if (*remaining != HTTP1_LEN_UNKNOWN && *remaining < (__u64)n) {
        n = (__u32)*remaining;
    }
    if (!n) {
        return 0;
    }
    if (*data_captured < HTTP1_CAPTURE_MAX) {
        if (n > HTTP1_CAPTURE_MAX - *data_captured) {
            n = HTTP1_CAPTURE_MAX - *data_captured;
        }
        if (n > MAX_PAYLOAD_SIZE) {
            n = MAX_PAYLOAD_SIZE;
        }
        if (http2_iov_copy(dst, 0, n)) {
            return 0;
        }
        f.cid = cid;
        f.dst = dst;
        f.out_len = n;
        f.method = method;
        http1_flush(&f);
        *data_captured += n;
    } else {
        http2_iov_skip(n);
    }
    if (*remaining != HTTP1_LEN_UNKNOWN) {
        *remaining -= n;
    }
    return n;
}

/* A body framed by Content-Length (or ending with the connection), walked in
   steps of http1_body_step until it ends or the buffer runs out. */
struct http1_body_walk {
    struct connection_id cid;
    char *dst;
    __u64 remaining;
    __u32 data_captured;
    __u8 method;
};

static long http1_body_walk_cb(__u32 i, void *ctx) {
    struct http1_body_walk *w = ctx;
    (void)i;

    if (!http1_body_step(w->cid, w->dst, w->method, &w->data_captured, &w->remaining)) {
        return 1;
    }
    return w->remaining == 0;
}

/* A chunked body (RFC 9112 7.1): a hex size line ended by "\r\n" (an optional
   ";extension" is skipped), that many bytes of data, "\r\n", and again, until a
   size of 0, after which a trailer block ends the body. A buffer can hold many
   chunks (ClickHouse replication reads a dozen small ones at once), so the whole
   framing is walked in one bpf_loop, one step per iteration, instead of one
   tail-call round per chunk phase: rounds are bounded by the kernel's 33 tail
   calls, and a buffer with more chunks than that left the walk out of step with
   the stream, swallowing every later message on the connection as chunk data. */
struct http1_chunks_walk {
    struct connection_id cid;
    char *dst;
    /* data bytes left of the current chunk; while its size line is read, the
       size accumulated so far */
    __u64 chunk_remaining;
    __u32 data_captured;
    __u8 phase;
    __u8 saw_cr;
    __u8 in_ext;
    __u8 crlf_consumed;
    __u8 method;
};

/* One step: a step through the current chunk's data (see http1_body_step), or
   one byte of a size line or of the "\r\n" after the data. Stops at the last chunk (the trailer is
   walked as a header block) or when the buffer runs out. */
static long http1_chunks_walk_cb(__u32 i, void *ctx) {
    struct http1_chunks_walk *w = ctx;
    __u8 b;
    __u8 v;
    (void)i;

    if (w->phase == HTTP1_PHASE_CHUNK_DATA) {
        if (!http1_body_step(w->cid, w->dst, w->method, &w->data_captured, &w->chunk_remaining)) {
            return 1;
        }
        if (!w->chunk_remaining) {
            w->phase = HTTP1_PHASE_CHUNK_CRLF;
            w->crlf_consumed = 0;
        }
        return 0;
    }
    if (http2_iov_pull(&b)) {
        return 1;
    }
    if (w->phase == HTTP1_PHASE_CHUNK_CRLF) {
        w->crlf_consumed += 1;
        if (w->crlf_consumed == 2) {
            w->phase = HTTP1_PHASE_CHUNK_SIZE;
            w->chunk_remaining = 0;
            w->saw_cr = 0;
            w->in_ext = 0;
        }
        return 0;
    }
    if (w->saw_cr && b == '\n') {
        if (!w->chunk_remaining) {
            w->phase = HTTP1_PHASE_CHUNK_TRAILER;
            return 1;
        }
        w->phase = HTTP1_PHASE_CHUNK_DATA;
        return 0;
    }
    w->saw_cr = (b == '\r');
    if (!w->saw_cr && !w->in_ext) {
        v = 0xff;
        if (b >= '0' && b <= '9') {
            v = b - '0';
        } else if (b >= 'a' && b <= 'f') {
            v = b - 'a' + 10;
        } else if (b >= 'A' && b <= 'F') {
            v = b - 'A' + 10;
        }
        if (v != 0xff) {
            if (w->chunk_remaining < (HTTP1_LEN_UNKNOWN >> 4)) {
                w->chunk_remaining = (w->chunk_remaining << 4) | v;
            }
        } else if (b == ';') {
            w->in_ext = 1;
        }
        /* Anything else on the line (stray whitespace, ...) is tolerated:
           neither a hex digit nor ';', so just ignored until the "\r\n". */
    }
    return 0;
}

static __always_inline
int http1_status_has_no_body(__u16 status) {
    return (status >= 100 && status < 200) || status == 204 || status == 304;
}

/* Not attached: tail-called only, so the bpf_loop-heavy header/chunk scan
   gets its own verifier budget separate from whichever real hook
   (sys_enter_write, sys_exit_read, a TLS uprobe, ...) triggered it — the
   same reason HTTP2's frame walk is a separate stage. Processes exactly one
   phase (HEADERS, DATA, or a chunked body's framing — see the HTTP1_PHASE_*
   comments); reaching the end of one with more of this
   buffer still unconsumed tail-calls itself again for the next phase,
   bounded by http1_tail_state.round rather than unrolling a loop over
   phases in one call — an earlier version did that and blew the same
   1M-instruction verifier budget HTTP2's own frame walk needs its own
   stage to avoid. A chunked body's framing takes a single phase, however many
   chunks the buffer holds (see http1_chunks_walk). */
static __always_inline
int http1_walk_impl(void *ctx, void *tail_progs) {
    __u32 zero = 0;
    struct http1_tail_state *s;
    struct http1_state_key key = {};
    struct http1_state_val sv = {};
    struct http1_state_val *st;
    struct http1_hdr_scan_ctx sc;
    struct http1_chunks_walk cw;
    struct http1_body_walk bw;
    struct http1_flush_args f;
    struct http2_iovec_table *iovs;
    char *dst;
    __u32 source_left;
    __u8 head_response;
    __u8 one = 1;

    s = scratch_lookup(&http1_tail_state);
    if (!s) {
        return 0;
    }
    if (http2_owner_mismatch(s->owner)) {
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
    dst = scratch_lookup(&http2_emit_heap);
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
        sc.status_line_done = sv.status_line_done;
        sc.status_space_seen = sv.status_space_seen;
        sc.status_digits = sv.status_digits;
        sc.status_code = sv.status_code;
        sc.first_word_len = sv.first_word_len;
        sc.not_head = sv.not_head;
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
        sv.status_line_done = sc.status_line_done;
        sv.status_space_seen = sc.status_space_seen;
        sv.status_digits = sc.status_digits;
        sv.status_code = sc.status_code;
        sv.first_word_len = sc.first_word_len;
        sv.not_head = sc.not_head;
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
        sv.status_line_done = 0;
        sv.status_space_seen = 0;
        sv.status_digits = 0;
        sv.status_code = 0;
        sv.first_word_len = 0;
        sv.not_head = 0;
        head_response = 0;
        if (!sc.is_trailer) {
            if (s->is_req) {
                if (sc.first_word_len == 4 && !sc.not_head) {
                    bpf_map_update_elem(&http1_head_requests, &key.conn_ts, &one, BPF_ANY);
                } else {
                    bpf_map_delete_elem(&http1_head_requests, &key.conn_ts);
                }
            } else if (bpf_map_lookup_elem(&http1_head_requests, &key.conn_ts)) {
                head_response = 1;
                bpf_map_delete_elem(&http1_head_requests, &key.conn_ts);
            }
        }
        if (sc.is_trailer) {
            sv.phase = HTTP1_PHASE_HEADERS;
            sv.chunked = 0;
            sv.content_length = 0;
            sv.data_captured = 0;
        } else if (!s->is_req && (head_response || http1_status_has_no_body(sc.status_code))) {
            /* 1xx, 204 and 304 responses, and responses to HEAD, end with
               their headers whatever Content-Length or Transfer-Encoding they
               carry (RFC 9110 6.4.1); without this a 304 (no Content-Length)
               would read as a close-delimited body and swallow every later
               response on the connection, and a HEAD response would take the
               start of the next one for its body. */
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
            /* No Content-Length and not chunked: for a REQUEST this always
               means a zero-length body (RFC 7230 3.3.2 — a request without
               either header has no body, full stop; GET/HEAD/DELETE never
               carry one). Getting this wrong is not just "one unknown
               body's bytes are misread" — on a reused (keep-alive)
               connection it is fatal: HTTP1_LEN_UNKNOWN never reaches 0
               (see http1_body_step), so the phase never returns to
               HEADERS and every later request on the same connection is
               parsed as more of this "body" forever. A RESPONSE genuinely
               can be close-delimited instead of framed (rare, legacy), so
               HTTP1_LEN_UNKNOWN stays correct there — see the file
               comment and http1_body_step's own doc comment. */
            sv.body_remaining = sc.have_content_length ? sc.content_length : (s->is_req ? 0 : HTTP1_LEN_UNKNOWN);
            if (!sv.body_remaining) {
                /* Known empty body: nothing for a DATA round to do, and each
                   round costs one of the kernel's 33 tail calls, which is
                   what bounds how many pipelined requests one buffer can
                   hold. */
                sv.phase = HTTP1_PHASE_HEADERS;
            }
            sv.content_length = 0;
            sv.chunked = 0;
            sv.data_captured = 0;
        }
    } else if (sv.phase == HTTP1_PHASE_CHUNK_SIZE || sv.phase == HTTP1_PHASE_CHUNK_DATA ||
               sv.phase == HTTP1_PHASE_CHUNK_CRLF) {
        cw.cid = s->cid;
        cw.dst = dst;
        cw.chunk_remaining = sv.body_remaining;
        cw.data_captured = s->skip_bodies ? HTTP1_CAPTURE_MAX : sv.data_captured;
        cw.phase = sv.phase;
        cw.saw_cr = sv.chunk_saw_cr;
        cw.in_ext = sv.chunk_in_ext;
        cw.crlf_consumed = sv.chunk_crlf_consumed;
        cw.method = s->is_req ? METHOD_HTTP_CLIENT_DATA : METHOD_HTTP_SERVER_DATA;

        bpf_loop(HTTP1_HDR_SCAN_MAX, http1_chunks_walk_cb, &cw, 0);

        sv.body_remaining = cw.chunk_remaining;
        sv.data_captured = cw.data_captured;
        sv.phase = cw.phase;
        sv.chunk_saw_cr = cw.saw_cr;
        sv.chunk_in_ext = cw.in_ext;
        sv.chunk_crlf_consumed = cw.crlf_consumed;
        if (sv.phase != HTTP1_PHASE_CHUNK_TRAILER) {
            /* the buffer ran out mid-body */
            bpf_map_update_elem(&http1_state, &key, &sv, BPF_ANY);
            return 0;
        }
    } else {
        bw.cid = s->cid;
        bw.dst = dst;
        bw.remaining = sv.body_remaining;
        bw.data_captured = s->skip_bodies ? HTTP1_CAPTURE_MAX : sv.data_captured;
        bw.method = s->is_req ? METHOD_HTTP_CLIENT_DATA : METHOD_HTTP_SERVER_DATA;

        bpf_loop(HTTP1_HDR_SCAN_MAX, http1_body_walk_cb, &bw, 0);

        sv.body_remaining = bw.remaining;
        sv.data_captured = bw.data_captured;
        if (sv.body_remaining) {
            /* the buffer ran out mid-body, or the body ends with the connection */
            bpf_map_update_elem(&http1_state, &key, &sv, BPF_ANY);
            return 0;
        }
        sv.phase = HTTP1_PHASE_HEADERS;
        sv.data_captured = 0;
    }

    bpf_map_update_elem(&http1_state, &key, &sv, BPF_ANY);

    iovs = scratch_lookup(&http2_iovecs);
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
    s = scratch_lookup(&http1_tail_state);
    if (!s) {
        return 0;
    }
    s->owner = bpf_get_current_pid_tgid();
    s->cid = cid;
    s->conn_ts = conn->timestamp;
    s->is_inbound = conn->is_inbound;
    s->skip_bodies = conn->skip_bodies;
    s->is_req = is_req;
    s->round = 0;
    bpf_tail_call(ctx, tail_progs, HTTP1_TAIL_WALK);
    return 1;
}
