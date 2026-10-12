#define IPPROTO_TCP 6
#define AF_INET     2
#define AF_INET6    10

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

SEC("kprobe/nf_ct_deliver_cached_events")
int nf_ct_deliver_cached_events(struct pt_regs *ctx) {
    struct nf_conn *ct = (struct nf_conn *)PT_REGS_PARM1(ctx);
    if (BPF_CORE_READ(ct, tuplehash[1].tuple.dst.protonum) != IPPROTO_TCP) {
        return 0;
    }
    struct connPair src = {};
    struct ipPort actualDst = {};
    __u16 family = BPF_CORE_READ(ct, tuplehash[1].tuple.src.l3num);
    if (family == AF_INET) {
        src.src_ip[10] = 0xff;
        src.src_ip[11] = 0xff;
        BPF_CORE_READ_INTO((__be32 *)&src.src_ip[12], ct, tuplehash[1].tuple.dst.u3.ip6[0]);
        src.dst_ip[10] = 0xff;
        src.dst_ip[11] = 0xff;
        BPF_CORE_READ_INTO((__be32 *)&src.dst_ip[12], ct, tuplehash[0].tuple.dst.u3.ip6[0]);

        actualDst.ip[10] = 0xff;
        actualDst.ip[11] = 0xff;
        BPF_CORE_READ_INTO((__be32 *)&actualDst.ip[12], ct, tuplehash[1].tuple.src.u3.ip6[0]);
    } else if (family == AF_INET6) {
        BPF_CORE_READ_INTO((union nf_inet_addr *)&src.src_ip, ct, tuplehash[1].tuple.dst.u3);
        BPF_CORE_READ_INTO((union nf_inet_addr *)&src.dst_ip, ct, tuplehash[0].tuple.dst.u3);
        BPF_CORE_READ_INTO((union nf_inet_addr *)&actualDst.ip, ct, tuplehash[1].tuple.src.u3);
    }
    src.src_port = bpf_ntohs(BPF_CORE_READ(ct, tuplehash[1].tuple.dst.u.all));
    src.dst_port = bpf_ntohs(BPF_CORE_READ(ct, tuplehash[0].tuple.dst.u.all));
    actualDst.port = bpf_ntohs(BPF_CORE_READ(ct, tuplehash[1].tuple.src.u.all));
    bpf_map_update_elem(&actual_destinations, &src, &actualDst, BPF_ANY);
    return 0;
}
