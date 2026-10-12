struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} tcp_retransmit_events SEC(".maps");

SEC("tracepoint/tcp/tcp_retransmit_skb")
int tcp_retransmit_skb(struct trace_event_raw_tcp_retransmit_skb *args)
{
    struct tcp_event e = {
        .type = EVENT_TYPE_TCP_RETRANSMIT,
        .sport = args->sport,
        .dport = args->dport,
    };
    BPF_CORE_READ_INTO(&e.saddr, args, saddr_v6);
    BPF_CORE_READ_INTO(&e.daddr, args, daddr_v6);

    bpf_perf_event_output(args, &tcp_retransmit_events, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}
