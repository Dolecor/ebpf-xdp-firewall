/* SPDX-License-Identifier: GPL-2.0 */

#ifndef XDPFW_FILTER_KERN_H
#define XDPFW_FILTER_KERN_H

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>

#include "xdpfw_filter_kern_user.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, XDPFW_FILTER_MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct filterrec);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} XDPFW_FILTER_MAP_NAME SEC(".maps");

struct upperhdr {
    enum upper_proto protocol;
    union {
        struct icmphdr *icmp;
        union {
            struct tcphdr *tcp;
            struct udphdr *udp;
            struct {
                __be16 source;
                __be16 dest;
            } * ports;
        };
    } hdr;
};

static filter_type_t __always_inline
__get_filter_verdict(const struct filterrec *filter, const struct iphdr *ip,
                     const struct upperhdr *upper)
{
    filter_type_t verdict = FILTER_TYPE_NO_MATCH;

    if (filter->type == FILTER_TYPE_END_OF_LIST) {
        verdict = filter->type;
        goto out;
    }

    if (upper->protocol != filter->protocol) {
        goto out;
    }

    if (upper->protocol != ICMP) {
        if (!((upper->hdr.ports->source == XDPFW_PORT_ANY)
              || ((upper->hdr.ports->source >= filter->src_port)
                  && (upper->hdr.ports->source <= filter->src_port_end)))) {
            goto out;
        }

        if (!((upper->hdr.ports->dest == XDPFW_PORT_ANY)
              || ((upper->hdr.ports->dest >= filter->dst_port)
                  && (upper->hdr.ports->dest <= filter->dst_port_end)))) {
            goto out;
        }
    }

    if (!((ip->saddr & ~filter->src_wcard) == filter->src_ip)) {
        goto out;
    }

    if (!((ip->daddr & ~filter->dst_wcard) == filter->dst_ip)) {
        goto out;
    }

    verdict = filter->type;

out:
    return verdict;
}

static filter_type_t __always_inline
get_filter_verdict(const struct iphdr *ip, const struct upperhdr *upper)
{
    struct filterrec *filter;
    filter_type_t verdict = FILTER_TYPE_NO_MATCH;

#pragma unroll(XDPFW_FILTER_MAX_ENTRIES)
    for (__u32 i = 0; i < XDPFW_FILTER_MAX_ENTRIES; ++i) {
        __u32 key = i;
        filter = bpf_map_lookup_elem(&XDPFW_FILTER_MAP_NAME, &key);
        if (!filter || (filter->type == FILTER_TYPE_EMPTY_CELL)) {
            continue;
        }

        verdict = __get_filter_verdict(filter, ip, upper);
        if ((verdict == FILTER_TYPE_END_OF_LIST)
            || filter_type_is_action(verdict)) {
            break;
        }
    }

    return verdict;
}

#endif /* XDPFW_FILTER_KERN_H */
