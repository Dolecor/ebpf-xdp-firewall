/* SPDX-License-Identifier: GPL-2.0 */

#ifndef XDPFW_FILTER_KERN_USER_H
#define XDPFW_FILTER_KERN_USER_H

#include <linux/in.h>

#define FILTER_TYPE_MAX  ((__u8)~0U) /* U8_MAX */
#define FILTER_TYPE_END_OF_LIST     0 /* must be 0 */
#define FILTER_TYPE_DENY            XDP_DROP  /* 1 */
#define FILTER_TYPE_PERMIT          XDP_PASS  /* 2 */
#define FILTER_TYPE_EMPTY_CELL      (FILTER_TYPE_MAX - 1)
#define FILTER_TYPE_NO_MATCH        FILTER_TYPE_MAX

#define filter_type_is_action(type) \
    ((type == FILTER_TYPE_DENY) || (type == FILTER_TYPE_PERMIT))

#define XDPFW_IP_ANY INADDR_ANY
#define XDPFW_PORT_ANY (__u16)0

#define XDPFW_IP_WILDCARD_ANY 0xFFFFFFFF    /* 255.255.255.255 */
#define XDPFW_IP_WILDCARD_HOST 0            /* 0.0.0.0 */

typedef __u8 filter_type_t;

#pragma pack(push)
#pragma pack(1)
struct filterrec {
    __be32 src_ip;
    __be32 src_wcard;
    __be32 dst_ip;
    __be32 dst_wcard;
    __u16 src_port;
    __u16 src_port_end;
    __u16 dst_port;
    __u16 dst_port_end;
    __u8 protocol;
    filter_type_t type;
};
#pragma pack(pop)

enum upper_proto {
    ICMP = IPPROTO_ICMP, /* 1 */
    TCP = IPPROTO_TCP,   /* 6 */
    UDP = IPPROTO_UDP,   /* 17 */
};

#define XDPFW_FILTER_MAX_ENTRIES (128 + 1) /* 1 for FILTER_TYPE_END_OF_LIST */
#define XDPFW_FILTER_MAP_NAME xdpfw_filter_map

#endif /* XDPFW_FILTER_KERN_USER_H */
