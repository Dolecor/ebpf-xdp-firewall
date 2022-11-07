/* SPDX-License-Identifier: GPL-2.0 */

#ifndef XDPFW_FILTER_KERN_H
#define XDPFW_FILTER_KERN_H

#include "xdpfw_filter_kern_user.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, FILTERREC_MAX_ENTRIES);
    __type(key, int);
    __type(value, struct filterrec);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} XDPFW_FILTER_MAP_NAME SEC(".maps");

#endif /* XDPFW_FILTER_KERN_H */