//go:build ignore
/*
 * 优化后的 XDP 监控程序
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

/* 数据包信息结构，总大小：64 字节 */
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
} __attribute__((packed));           // 64 字节

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

/* XDP 程序入口点 */
SEC("xdp")
int xdp_program(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct packet_info pkt_info = {0};
    struct ethhdr eth_hdr = {0};

    if (data + sizeof(eth_hdr) > data_end)
        return XDP_PASS;

    /* 一次性加载整个以太网头部 */
    if (bpf_probe_read_kernel(&eth_hdr, sizeof(eth_hdr), data) != 0)
        return XDP_PASS;

    __builtin_memcpy(pkt_info.src_mac, eth_hdr.h_source, ETH_ALEN);
    __builtin_memcpy(pkt_info.dst_mac, eth_hdr.h_dest, ETH_ALEN);
    pkt_info.eth_proto = bpf_ntohs(eth_hdr.h_proto);
    pkt_info.pkt_size = data_end - data;

    /* 根据以太网协议解析 IP 数据包 */
    if (pkt_info.eth_proto == ETH_P_IP) {
        struct iphdr *ip = data + sizeof(eth_hdr);
        if ((void *)(ip + 1) > data_end)
            goto submit;

        bpf_probe_read_kernel(&pkt_info.src_ip, sizeof(ip->saddr), &ip->saddr);
        bpf_probe_read_kernel(&pkt_info.dst_ip, sizeof(ip->daddr), &ip->daddr);
        parse_transport(&pkt_info, (void *)(ip + 1), data_end, ip->protocol);
    } else if (pkt_info.eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = data + sizeof(eth_hdr);
        if ((void *)(ip6 + 1) > data_end)
            goto submit;

        bpf_probe_read_kernel(pkt_info.src_ipv6, sizeof(ip6->saddr), &ip6->saddr);
        bpf_probe_read_kernel(pkt_info.dst_ipv6, sizeof(ip6->daddr), &ip6->daddr);
        parse_transport(&pkt_info, (void *)(ip6 + 1), data_end, ip6->nexthdr);
    }

submit:
    /* 上报数据包事件 */
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &pkt_info, sizeof(pkt_info));
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
