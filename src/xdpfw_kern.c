// SPDX-License-Identifier: GPL-2.0

#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdpfw_common.h"

#include "xdp/xdp_stats_kern.h"
#include "xdpfw_filter_kern.h"

#define DEFAULT_ACTION XDP_PASS

#define XDPFW_PARSE_HDR_UNSUPPORTED -2
#define XDPFW_PARSE_HDR_BAD_HDR -1
#define XDPFW_PARSE_HDR_OK 0

struct hdr_cursor {
    void *pos;
};

static __always_inline int parse_ethhdr(struct hdr_cursor *hc, void *data_end,
                                        struct ethhdr **ethhdr)
{
    struct ethhdr *eth = hc->pos;
    int hdrsize = sizeof(struct ethhdr);

    if (hc->pos + hdrsize > data_end) {
        return -1;
    }

    hc->pos = eth + 1;
    *ethhdr = eth;

    return eth->h_proto;
}

static __always_inline int parse_iphdr(struct hdr_cursor *hc, void *data_end,
                                       struct iphdr **iphdr)
{
    struct iphdr *ip = hc->pos;
    int hdrsize;

    if (hc->pos + sizeof(struct iphdr) > data_end) {
        return -1;
    }

    hdrsize = ip->ihl * 4;

    if (hc->pos + hdrsize > data_end) {
        return -1;
    }

    hc->pos += hdrsize;
    *iphdr = ip;

    return ip->protocol;
}

static __always_inline int parse_icmphdr(struct hdr_cursor *hc, void *data_end,
                                         struct icmphdr **icmphdr)
{
    struct icmphdr *icmp = hc->pos;
    int hdrsize = sizeof(struct icmphdr);

    if (hc->pos + hdrsize > data_end) {
        return -1;
    }

    hc->pos = icmp + 1;
    *icmphdr = icmp;

    return icmp->type;
}

static __always_inline int parse_tcphdr(struct hdr_cursor *hc, void *data_end,
                                        struct tcphdr **tcphdr)
{
    struct tcphdr *tcp = hc->pos;
    int hdrsize = sizeof(struct tcphdr);
    int len;

    if (hc->pos + hdrsize > data_end) {
        return -1;
    }

    len = tcp->doff * 4;
    if (hc->pos + len > data_end) {
        return -1;
    }

    hc->pos += hdrsize;
    *tcphdr = tcp;

    return len;
}

static __always_inline int parse_udphdr(struct hdr_cursor *hc, void *data_end,
                                        struct udphdr **udphdr)
{
    struct udphdr *udp = hc->pos;
    int hdrsize = sizeof(struct udphdr);
    int len;

    if (hc->pos + hdrsize > data_end) {
        return -1;
    }

    hc->pos = udp + 1;
    *udphdr = udp;

    len = bpf_ntohs(udp->len) - hdrsize;
    if (len < 0) {
        return -1;
    }

    return len;
}

static __always_inline int parse_hdr(void *hdr_ptr, void *data_end,
                                     struct ethhdr **eth, struct iphdr **ip,
                                     struct upperhdr *upper)
{
    int ret;
    struct hdr_cursor hc = { .pos = hdr_ptr };

    ret = parse_ethhdr(&hc, data_end, eth);
    if (ret < 0) {
        return XDPFW_PARSE_HDR_BAD_HDR;
    }

    if (ret != bpf_htons(ETH_P_IP)) {
        return XDPFW_PARSE_HDR_UNSUPPORTED;
    }

    ret = parse_iphdr(&hc, data_end, ip);
    if (ret < 0) {
        return XDPFW_PARSE_HDR_BAD_HDR;
    }

    switch ((enum upper_proto)ret) {
    case ICMP:
        upper->protocol = ret;
        ret = parse_icmphdr(&hc, data_end, &upper->hdr.icmp);
        break;
    case TCP:
        upper->protocol = ret;
        ret = parse_tcphdr(&hc, data_end, &upper->hdr.tcp);
        break;
    case UDP:
        upper->protocol = ret;
        ret = parse_udphdr(&hc, data_end, &upper->hdr.udp);
        break;
    default:
        ret = XDPFW_PARSE_HDR_UNSUPPORTED;
    }

    return (ret > 0) ? XDPFW_PARSE_HDR_OK : ret;
}

SEC(XDPOBJ_PROGSEC)
int XDP_FUNCTION(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct upperhdr upper;
    filter_type_t filter_verdict;
    __u32 action;
    int ret;

    ret = parse_hdr(data, data_end, &eth, &ip, &upper);
    if (ret == XDPFW_PARSE_HDR_BAD_HDR) {
        action = XDP_ABORTED;
        goto out;
    } else if (ret == XDPFW_PARSE_HDR_UNSUPPORTED) {
        action = DEFAULT_ACTION;
        goto out;
    }

    filter_verdict = get_filter_verdict(ip, &upper);
    action =
        filter_type_is_action(filter_verdict) ? filter_verdict : DEFAULT_ACTION;

out:
    return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";
