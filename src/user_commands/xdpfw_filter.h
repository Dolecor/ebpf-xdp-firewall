/* SPDX-License-Identifier: GPL-2.0 */

#ifndef XDPFW_FILTER_H
#define XDPFW_FILTER_H

#include "params.h"
#include "../xdpfw_filter_kern_user.h"

struct filterlistopt {
    struct iface iface;
};

#define INSERT_AT_NO_SET 0xFFFFFFFF

struct filteraddopt {
    struct iface iface;
    filter_type_t action;
    enum upper_proto protocol;
    struct ip_addr src_ip;
    struct ip_addr dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t insert_at;
};

struct filterrmopt {
    struct iface iface;
    uint32_t filter_id;
};

int xdpfw_filter_list(const struct filterlistopt *, const char *);
int xdpfw_filter_add(const struct filteraddopt *, const char *);
int xdpfw_filter_remove(const struct filterrmopt *, const char *);

#endif /* XDPFW_FILTER_H */
