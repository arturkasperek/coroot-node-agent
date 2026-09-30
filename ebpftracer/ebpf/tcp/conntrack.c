#define IPPROTO_TCP 6
#define AF_INET     2
#define AF_INET6    10

struct inet_addr {
    __be32 ip[4];
};

struct nf_conntrack_man {
    struct inet_addr addr;
    __be16 port;
    __be16 l3num;           // Layer 3 protocol (e.g., AF_INET, AF_INET6)
};

struct nf_conntrack_tuple {
    struct nf_conntrack_man src;
    struct {
        struct inet_addr addr;
        __be16 port;
        __u8 protonum;         // Protocol number (TCP, UDP, ICMP, etc.)
        __u8 dir;              // Direction
    } dst;
};

struct nf_conntrack_tuple_hash {
    __u8 __pad[16];
    struct nf_conntrack_tuple tuple;
};

struct nf_conn {
    __u8 __pad[16];
    struct nf_conntrack_tuple_hash tuplehash[2];
};

struct ipPort {
    __u8 ip[16];
    __u16 port;
};

/* Keyed by the connection's source AND the destination it was aimed at (the
   pre-NAT one), not by the source alone: the kernel happily hands out the
   same ephemeral source port for connections to different destinations, so
   a source-only key let one connection's entry overwrite another's, and a
   connection was then reported (and its requests attributed) with someone
   else's actual destination. */
struct connPair {
    __u8 src_ip[16];
    __u8 dst_ip[16];
    __u16 src_port;
    __u16 dst_port;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct connPair));
    __uint(value_size, sizeof(struct ipPort));
    __uint(max_entries, 10240);
} actual_destinations SEC(".maps");

static __always_inline
int handle_ct(struct pt_regs *ctx, struct nf_conn conn)
{
    struct nf_conntrack_tuple orig = conn.tuplehash[0].tuple;
    struct nf_conntrack_tuple repl = conn.tuplehash[1].tuple;

    if (repl.dst.protonum != IPPROTO_TCP) {
        return 0;
    }
    struct connPair src = {};
    struct ipPort actualDst = {};
    if (repl.src.l3num == AF_INET) {
        src.src_ip[10] = 0xff;
        src.src_ip[11] = 0xff;
        __builtin_memcpy(&src.src_ip[12], &repl.dst.addr.ip, 4);
        src.dst_ip[10] = 0xff;
        src.dst_ip[11] = 0xff;
        __builtin_memcpy(&src.dst_ip[12], &orig.dst.addr.ip, 4);

        actualDst.ip[10] = 0xff;
        actualDst.ip[11] = 0xff;
        __builtin_memcpy(&actualDst.ip[12], &repl.src.addr.ip, 4);
    } else if (repl.src.l3num == AF_INET6) {
        __builtin_memcpy(&src.src_ip, &repl.dst.addr.ip, 16);
        __builtin_memcpy(&src.dst_ip, &orig.dst.addr.ip, 16);
        __builtin_memcpy(&actualDst.ip, &repl.src.addr.ip, 16);
    }
    src.src_port = bpf_ntohs(repl.dst.port);
    src.dst_port = bpf_ntohs(orig.dst.port);
    actualDst.port = bpf_ntohs(repl.src.port);
    bpf_map_update_elem(&actual_destinations, &src, &actualDst, BPF_ANY);
    return 0;
}

SEC("kprobe/nf_ct_deliver_cached_events")
int nf_ct_deliver_cached_events(struct pt_regs *ctx) {
    struct nf_conn conn;
    if (bpf_probe_read(&conn, sizeof(conn), (void *)PT_REGS_PARM1(ctx)) != 0) {
        return 0;
    }
    return handle_ct(ctx, conn);
}
