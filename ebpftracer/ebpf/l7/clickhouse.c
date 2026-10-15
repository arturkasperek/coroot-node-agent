// A query id is a UUID unless the client chose its own (clickhouse-client
// --query_id, most drivers): any short printable string.
#define CLICKHOUSE_MAX_QUERY_ID_SIZE 64

#define CLICKHOUSE_QUERY_KIND_INITIAL 1
#define CLICKHOUSE_QUERY_KIND_SECONDARY 2

#define CLICKHOUSE_CLIENT_CODE_QUERY 1

#define CLICKHOUSE_SERVER_CODE_DATA 1
#define CLICKHOUSE_SERVER_CODE_EXCEPTION 2
#define CLICKHOUSE_SERVER_CODE_PROGRESS 3
#define CLICKHOUSE_SERVER_CODE_END_OF_STREAM 5
#define CLICKHOUSE_SERVER_CODE_LOG 10
#define CLICKHOUSE_SERVER_CODE_TABLE_COLUMNS 11
#define CLICKHOUSE_SERVER_CODE_PROFILE_EVENTS 14

// rows, bytes, total rows, total bytes, written rows, written bytes, elapsed ns
#define CLICKHOUSE_PROGRESS_FIELDS 7
#define CLICKHOUSE_PROGRESS_MAX_SIZE (1 + CLICKHOUSE_PROGRESS_FIELDS * 10)

#define CLICKHOUSE_COMPRESSION_NONE 0x02
#define CLICKHOUSE_COMPRESSION_LZ4  0x82
#define CLICKHOUSE_COMPRESSION_ZSTD 0x90

#define CLICKHOUSE_MIN_QUERY_SIZE 40
#define CLICKHOUSE_MAX_USER_SIZE 63
#define CLICKHOUSE_MAX_ADDRESS_SIZE 48

// the max legitimate offset within the query header is 253 (2+64+1+1+63+1+64+1+48+8)
#define CLICKHOUSE_MAX_OFFSET 256 // checking this fixes the program load on 5.4

// A query id of len bytes at buf: empty, or printable at both ends.
static __always_inline
int is_clickhouse_query_id(char *buf, __u8 len) {
    __u8 first = 0;
    __u8 last = 0;
    if (len == 0) {
        return 1;
    }
    if (len > CLICKHOUSE_MAX_QUERY_ID_SIZE) {
        return 0;
    }
    bpf_read(buf, first);
    bpf_read(buf+len-1, last);
    return first >= 0x20 && first <= 0x7e && last >= 0x20 && last <= 0x7e;
}

static __always_inline
int is_clickhouse_query(char *buf, __u64 buf_size) {
    if (buf_size < CLICKHOUSE_MIN_QUERY_SIZE) {
        return 0;
    }
    __u8 b[2];
    bpf_read(buf, b);
    if (b[0] != CLICKHOUSE_CLIENT_CODE_QUERY) {
        return 0;
    }
    if (!is_clickhouse_query_id(buf+2, b[1])) {
        return 0;
    }
    __u64 offset = 2 + b[1];
    __u8 kind = 0;
    bpf_read(buf+offset, kind);
    if (kind != CLICKHOUSE_QUERY_KIND_INITIAL && kind != CLICKHOUSE_QUERY_KIND_SECONDARY) {
        return 0;
    }
    offset += 1;
    __u8 len = 0;
    bpf_read(buf+offset, len); // initial_user
    if (len > CLICKHOUSE_MAX_USER_SIZE) {
        return 0;
    }
    offset += 1 + len;
    if (offset > CLICKHOUSE_MAX_OFFSET) {
        return 0;
    }
    bpf_read(buf+offset, len); // initial_query_id
    if (!is_clickhouse_query_id(buf+offset+1, len)) {
        return 0;
    }
    offset += 1 + len;
    if (offset > CLICKHOUSE_MAX_OFFSET) {
        return 0;
    }
    bpf_read(buf+offset, len); // initial_address
    if (len > CLICKHOUSE_MAX_ADDRESS_SIZE) {
        return 0;
    }
    if (len > 0) {
        __u8 c = 0;
        bpf_read(buf+offset+1, c);
        if (!((c >= '0' && c <= '9') || c == '[' || c == ':')) {
            return 0;
        }
    }
    offset += 1 + len + 8; // interface follows the 8-byte initial_query_start_time_microseconds
    if (offset > CLICKHOUSE_MAX_OFFSET || offset >= buf_size) {
        return 0;
    }
    __u8 iface = 0;
    // TCP, HTTP, GRPC, MYSQL, POSTGRESQL, LOCAL, TCP_INTERSERVER, PROMETHEUS, BACKGROUND,
    // ARROW_FLIGHT, ICEBERG_REST_CATALOG
    bpf_read(buf+offset, iface);
    if (iface < 1 || iface > 11) {
        return 0;
    }
    return 1;
}

static __always_inline
int is_clickhouse_compression_method(char *buf) {
    __u8 method = 0;
    bpf_read(buf, method);
    return method == CLICKHOUSE_COMPRESSION_LZ4 || method == CLICKHOUSE_COMPRESSION_ZSTD || method == CLICKHOUSE_COMPRESSION_NONE;
}

struct clickhouse_progress_scan {
    char *buf;
    __u64 buf_size;
    __u8 fields;
};

// One byte of a Progress packet's varints per iteration: a bpf_loop, because an
// unrolled scan of up to 70 bytes is too much for the programs this is inlined in.
static long clickhouse_progress_scan_cb(__u32 i, void *ctx) {
    struct clickhouse_progress_scan *scan = ctx;
    __u8 b = 0;

    if (i + 1 >= scan->buf_size || bpf_probe_read(&b, sizeof(b), scan->buf + i + 1)) {
        return 1;
    }
    if (!(b & 0x80)) {
        scan->fields++;
    }
    return scan->fields == CLICKHOUSE_PROGRESS_FIELDS;
}

// Progress: CLICKHOUSE_PROGRESS_FIELDS varints after the packet code.
static __always_inline
int is_clickhouse_progress(char *buf, __u64 buf_size) {
    struct clickhouse_progress_scan scan = {.buf = buf, .buf_size = buf_size};
    bpf_loop(CLICKHOUSE_PROGRESS_MAX_SIZE - 1, clickhouse_progress_scan_cb, &scan, 0);
    return scan.fields == CLICKHOUSE_PROGRESS_FIELDS;
}

// The first packet of the server's answer to a query: Data or Exception; for an
// INSERT TableColumns (newer servers send it before anything else); Log or
// ProfileEvents for a client that asked for them; or Progress for a query that
// has no rows to send yet.
static __always_inline
int is_clickhouse_response(char *buf, __u64 buf_size, __s32 *status) {
    __u8 b[3];
    bpf_read(buf, b);
    if (b[0] == CLICKHOUSE_SERVER_CODE_DATA || b[0] == CLICKHOUSE_SERVER_CODE_LOG ||
        b[0] == CLICKHOUSE_SERVER_CODE_PROFILE_EVENTS) {
        // a block packet: an empty name (of a temporary table, of the logs),
        // then the block
        if (b[1] != 0) {
            return 0;
        }
        if (b[2] == 1) { // uncompressed block: BlockInfo field number 1
            *status = STATUS_OK;
            return 1;
        }
        // compressed block: compression method follows the 16-byte checksum
        if (is_clickhouse_compression_method(buf+2+16)) {
            *status = STATUS_OK;
            return 1;
        }
        return 0;
    }
    if (b[0] == CLICKHOUSE_SERVER_CODE_TABLE_COLUMNS) {
        if (b[1] == 0) { // uncompressed: an empty table name, then "columns format version: ..."
            __u8 c[3];
            bpf_read(buf+2, c);
            if ((c[0] & 0x80 ? c[2] : c[1]) != 'c') {
                return 0;
            }
            *status = STATUS_OK;
            return 1;
        }
        // compressed: the whole packet body is one compressed frame
        if (is_clickhouse_compression_method(buf+1+16)) {
            *status = STATUS_OK;
            return 1;
        }
        return 0;
    }
    if (b[0] == CLICKHOUSE_SERVER_CODE_PROGRESS) {
        if (!is_clickhouse_progress(buf, buf_size)) {
            return 0;
        }
        *status = STATUS_OK;
        return 1;
    }
    if (b[0] == CLICKHOUSE_SERVER_CODE_EXCEPTION) {
        __s32 code = 0;
        bpf_read(buf+1, code);
        if (code <= 0 || code > 4096) {
            return 0;
        }
        *status = STATUS_FAILED;
        return 1;
    }
    if (b[0] == CLICKHOUSE_SERVER_CODE_END_OF_STREAM && buf_size == 1) {
        *status = STATUS_OK;
        return 1;
    }
    return 0;
}
