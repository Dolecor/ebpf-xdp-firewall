/* SPDX-License-Identifier: GPL-2.0 */

#ifndef XDPFW_FILTER_KERN_USER_H
#define XDPFW_FILTER_KERN_USER_H

#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_endian.h>

enum filter_action {
    ACTION_DENY = 1, /* XDP_DROP */
    ACTION_PERMIT,   /* XDP_PASS */
};

typedef __u8 filter_action_t;

/* TODO: add wildcard to IPs and range to ports */

#pragma pack(push)
#pragma pack(1) /* or padding fields? */
struct filterrec {
    struct in_addr src_ip;
    struct in_addr dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    filter_action_t action;
};
#pragma pack(pop)

#define FILTERREC_MAX_ENTRIES 128
#define XDPFW_FILTER_MAP_NAME xdpfw_filter_map

#endif /* XDPFW_FILTER_KERN_USER_H */
