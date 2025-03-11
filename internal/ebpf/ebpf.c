//go:build ignore
/*
 * 基于 TCX 监控程序
 * 功能:
 * - TCP/UDP 协议解析，上报事件
 */
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

/* 数据包信息结构，总大小：65 字节 */
struct packet_info {
    // 网络层 - IPv4 地址
    __be32 src_ip;                   // 源 IPv4 地址
    __be32 dst_ip;                   // 目的 IPv4 地址

    // 网络层 - IPv6 地址
    __be32 src_ipv6[4];              // 源 IPv6 地址 (128 位)
    __be32 dst_ipv6[4];              // 目的 IPv6 地址 (128 位)

    // 传输层
    __be16 src_port;                 // 源端口 (TCP/UDP)
    __be16 dst_port;                 // 目的端口 (TCP/UDP)

    // 链路层
    unsigned char src_mac[ETH_ALEN]; // 源 MAC 地址
    unsigned char dst_mac[ETH_ALEN]; // 目的 MAC 地址

    // 协议相关信息
    __u16 eth_proto;                 // 以太网协议类型
    __u16 ip_proto;                  // IP 协议号

    // 元数据
    __u32 pkt_size;                  // 数据包总大小
    __u8 direction;                  // 数据包方向，1: ingress, 2: egress
} __attribute__((packed));           // 65 字节

/* 上报数据包事件的 perf event map */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 128);
} events SEC(".maps");

/* 解析 TCP/UDP 头部信息 */
static __always_inline void parse_transport(struct packet_info *pkt_info, void *data, void *data_end, __u8 proto)
{
    pkt_info->ip_proto = proto;
    pkt_info->src_port = 0;
    pkt_info->dst_port = 0;

    switch (proto) {
    case IPPROTO_TCP: {
        if (data + sizeof(struct tcphdr) > data_end)
            return;
        struct tcphdr *tcp = data;
        pkt_info->src_port = bpf_ntohs(tcp->source);
        pkt_info->dst_port = bpf_ntohs(tcp->dest);
        break;
    }
    case IPPROTO_UDP: {
        if (data + sizeof(struct udphdr) > data_end)
            return;
        struct udphdr *udp = data;
        pkt_info->src_port = bpf_ntohs(udp->source);
        pkt_info->dst_port = bpf_ntohs(udp->dest);
        break;
    }
    default:
        break;
    }
}

/* 处理 ingress/egress 链路数据 */
static __always_inline int process_packet(struct __sk_buff *skb, __u8 direction)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct packet_info pkt_info = {0};
    struct ethhdr eth_hdr = {0};
    int offset = 0;

    /* 检查数据包边界 */
    if (data + sizeof(eth_hdr) > data_end)
        return TC_ACT_OK;

    if (bpf_skb_load_bytes(skb, 0, &eth_hdr, sizeof(eth_hdr)) < 0)
        return TC_ACT_OK;

    __builtin_memcpy(pkt_info.src_mac, eth_hdr.h_source, ETH_ALEN);
    __builtin_memcpy(pkt_info.dst_mac, eth_hdr.h_dest, ETH_ALEN);
    pkt_info.eth_proto = bpf_ntohs(eth_hdr.h_proto);
    pkt_info.pkt_size = data_end - data;
    pkt_info.direction = direction;

    offset = sizeof(eth_hdr);

    if (pkt_info.eth_proto == ETH_P_IP) {
        struct iphdr ip = {0};
        if (bpf_skb_load_bytes(skb, offset, &ip, sizeof(ip)) < 0)
            goto submit;
        pkt_info.src_ip = ip.saddr;
        pkt_info.dst_ip = ip.daddr;
        offset += sizeof(ip);
        parse_transport(&pkt_info, data + sizeof(eth_hdr) + sizeof(ip), data_end, ip.protocol);
    } else if (pkt_info.eth_proto == ETH_P_IPV6) {
        struct ipv6hdr ip6 = {0};
        if (bpf_skb_load_bytes(skb, offset, &ip6, sizeof(ip6)) < 0)
            goto submit;
        __builtin_memcpy(pkt_info.src_ipv6, &ip6.saddr, sizeof(ip6.saddr));
        __builtin_memcpy(pkt_info.dst_ipv6, &ip6.daddr, sizeof(ip6.daddr));
        offset += sizeof(ip6);
        parse_transport(&pkt_info, data + sizeof(eth_hdr) + sizeof(ip6), data_end, ip6.nexthdr);
    }

submit:
    bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &pkt_info, sizeof(pkt_info));
    return TC_ACT_OK;
}

/* TCX ingress 程序入口点 */
SEC("tcx/ingress")
int ingress_prog(struct __sk_buff *skb)
{
    return process_packet(skb, 1);
}

/* TCX egress 程序入口点 */
SEC("tcx/egress")
int egress_prog(struct __sk_buff *skb)
{
    return process_packet(skb, 2);
}

char _license[] SEC("license") = "GPL";
