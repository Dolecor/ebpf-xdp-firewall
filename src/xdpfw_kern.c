// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "xdpfw_common.h"

#include "xdp/xdp_stats_kern.h"
#include "xdpfw_filter_kern.h"

#define DEFAULT_ACTION XDP_PASS

SEC(XDPOBJ_PROGSEC)
int XDP_FUNCTION(struct xdp_md *ctx)
{
    __u32 action = DEFAULT_ACTION;
    return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";
