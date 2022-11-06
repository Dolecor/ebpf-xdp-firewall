// SPDX-License-Identifier: GPL-2.0

#include <linux/err.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include "logging.h"

#include "../xdpfw_common.h"

static int is_xdpfw_program(const struct xdp_program *xdp_prog)
{
    return !strcmp(xdp_program__name(xdp_prog), textify(XDP_FUNCTION));
}

struct xdp_program *
xdpfw__from_xdp_multiprog_from_iface(int ifindex, struct xdp_multiprog **xdp_mp,
                                     enum xdp_attach_mode *mode)
{
    struct xdp_program *xdp_prog = NULL;
    *mode = XDP_MODE_UNSPEC;

    *xdp_mp = xdp_multiprog__get_from_ifindex(ifindex);
    if (IS_ERR_OR_NULL(*xdp_mp)) {
        pr_warn("No XDP program loaded on device\n");
        xdp_prog = ERR_CAST(*xdp_mp);
        *xdp_mp = NULL;
        goto out;
    }

    if (xdp_multiprog__is_legacy(*xdp_mp)) {
        xdp_prog = xdp_multiprog__main_prog(*xdp_mp);
        if (is_xdpfw_program(xdp_prog)) {
            pr_debug("legacy\n");
            *mode = xdp_multiprog__attach_mode(*xdp_mp);
            goto out;
        }
    }

    while ((xdp_prog = xdp_multiprog__next_prog(xdp_prog, *xdp_mp))) {
        if (is_xdpfw_program(xdp_prog)) {
            pr_debug("dispatcher\n");
            *mode = xdp_multiprog__attach_mode(*xdp_mp);
            goto out;
        }
    }

    pr_debug(
        "XDP loaded on device, but it is "
        "nor xdp-dispatcher with %s, not either %s itself in legacy mode\n",
        COMMON_PROG_NAME, COMMON_PROG_NAME);

    xdp_prog = ERR_PTR(-ENOENT);

out:
    return xdp_prog;
}
