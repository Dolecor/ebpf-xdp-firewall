// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "xdpfw_common.h"

SEC(XDPOBJ_PROGSEC)
int XDP_FUNCTION(struct xdp_md *ctx)
{
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
