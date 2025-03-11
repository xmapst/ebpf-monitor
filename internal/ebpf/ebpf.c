//go:build ignore
#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2
#define AF_INET6 10

struct ip_key {
    __u32 family;
    __u8 addr[16];
};

struct packet_info {
    __be32 src_ip;
    __be32 dst_ip;
    __be32 src_ipv6[4];
    __be32 dst_ipv6[4];
    __be16 src_port;
    __be16 dst_port;
    unsigned char src_mac[ETH_ALEN];
    unsigned char dst_mac[ETH_ALEN];
    __u16 eth_proto;
    __u16 ip_proto;
    __u32 pkt_size;
    __u8 direction;
} __attribute__((packed));

struct token_bucket {
    __u64 tokens;
    __u64 last_update;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 128);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct ip_key));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 2048);
} rate_limit_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct ip_key));
    __uint(value_size, sizeof(struct token_bucket));
    __uint(max_entries, 8192);
} token_map SEC(".maps");

/* 内联解析传输层头部，减少分支调用 */
static __always_inline void parse_transport(struct packet_info *pkt_info, void *data, void *data_end, __u8 proto) {
    pkt_info->ip_proto = proto;
    pkt_info->src_port = 0;
    pkt_info->dst_port = 0;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = data;
        if ((void*)(tcp + 1) <= data_end) {
            pkt_info->src_port = bpf_ntohs(tcp->source);
            pkt_info->dst_port = bpf_ntohs(tcp->dest);
        }
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = data;
        if ((void*)(udp + 1) <= data_end) {
            pkt_info->src_port = bpf_ntohs(udp->source);
            pkt_info->dst_port = bpf_ntohs(udp->dest);
        }
    }
}

/* 内联 token bucket 检查，减少重复 map 查找和计算 */
static __always_inline bool rate_limit_check(struct ip_key *key, __u32 rate_limit) {
    struct token_bucket *tb;
    __u64 now = bpf_ktime_get_ns();

    tb = bpf_map_lookup_elem(&token_map, key);
    if (!tb) {
        struct token_bucket new_tb = {
            .tokens = rate_limit,
            .last_update = now,
        };
        bpf_map_update_elem(&token_map, key, &new_tb, BPF_NOEXIST);
        return true;
    }
    __u64 elapsed = now - tb->last_update;
    __u64 tokens_to_add = (elapsed * rate_limit) / 1000000000ULL;

    if (tokens_to_add > 0) {
        tb->tokens = (tb->tokens + tokens_to_add > rate_limit) ? rate_limit : tb->tokens + tokens_to_add;
        tb->last_update = now;
    }
    if (tb->tokens >= 1) {
        tb->tokens--;
        return true;
    }
    return false;
}

/* 处理数据包主逻辑 */
static __always_inline int process_packet(struct __sk_buff *skb, __u8 direction) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct packet_info pkt_info = {};
    struct ethhdr *eth = data;  // 直接取数据指针（需保证数据连续）
    struct ip_key rate_key = {};

    if ((void*)(eth + 1) > data_end)
        return TC_ACT_OK;

    __builtin_memcpy(pkt_info.src_mac, eth->h_source, ETH_ALEN);
    __builtin_memcpy(pkt_info.dst_mac, eth->h_dest, ETH_ALEN);
    pkt_info.eth_proto = bpf_ntohs(eth->h_proto);
    pkt_info.pkt_size = (__u32)(data_end - data);
    pkt_info.direction = direction;

    int offset = sizeof(*eth);

    if (pkt_info.eth_proto == ETH_P_IP) {
        struct iphdr *ip = data + offset;
        if ((void*)(ip + 1) > data_end)
            goto submit;
        rate_key.family = AF_INET;
        __builtin_memcpy(rate_key.addr, &ip->saddr, 4);
        pkt_info.src_ip = ip->saddr;
        pkt_info.dst_ip = ip->daddr;
        offset += ip->ihl * 4;
        parse_transport(&pkt_info, data + offset, data_end, ip->protocol);
    } else if (pkt_info.eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = data + offset;
        if ((void*)(ip6 + 1) > data_end)
            goto submit;
        rate_key.family = AF_INET6;
        __builtin_memcpy(rate_key.addr, ip6->saddr.s6_addr32, 16);
        __builtin_memcpy(pkt_info.src_ipv6, ip6->saddr.s6_addr32, 16);
        __builtin_memcpy(pkt_info.dst_ipv6, ip6->daddr.s6_addr32, 16);
        offset += sizeof(*ip6);
        parse_transport(&pkt_info, data + offset, data_end, ip6->nexthdr);
    } else {
        goto submit;
    }

    /* ingress 模式下执行速率限制 */
    if (direction == 1) {
        __u32 *rate_limit = bpf_map_lookup_elem(&rate_limit_map, &rate_key);
        if (rate_limit && *rate_limit > 0) {
            if (!rate_limit_check(&rate_key, *rate_limit))
                return TC_ACT_SHOT;
        }
    }

submit:
    bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &pkt_info, sizeof(pkt_info));
    return TC_ACT_OK;
}

SEC("tcx/ingress")
int ingress_prog(struct __sk_buff *skb) {
    return process_packet(skb, 1);
}

SEC("tcx/egress")
int egress_prog(struct __sk_buff *skb) {
    return process_packet(skb, 2);
}

char _license[] SEC("license") = "GPL";
