// SPDX-License-Identifier: GPL-2.0

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

/* xdp-tools utils */
#include "util.h"
#include "params.h"
#include "logging.h"

#include "../xdpfw_common.h"
#include "xdpfw_helpers.h"
#include "xdpfw_stop.h"

int unload_xdp_program(const struct stopopt *opt)
{
    struct xdp_program *xdp_prog;
    struct xdp_multiprog *xdp_mp;
    enum xdp_attach_mode mode;
    __unused LIBBPF_OPTS(bpf_object_open_opts, opts);
    char errmsg[STRERR_BUFSIZE];
    int err = EXIT_SUCCESS;

    xdp_prog = xdpfw__from_xdp_multiprog_from_iface(opt->iface.ifindex, &xdp_mp,
                                                    &mode);
    err = libxdp_get_error(xdp_prog);
    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        pr_warn("Could not get XDP program from interface '%s'\n",
                opt->iface.ifname);
        xdp_prog = NULL;
        goto out;
    }

    pr_debug("%s found on device %s (id: %u). Detaching...\n", PROGCTL_NAME,
             opt->iface.ifname, xdp_program__id(xdp_prog));

    err = xdp_program__detach(xdp_prog, opt->iface.ifindex, mode, 0);
    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        pr_warn("Could not detach XDP program on interface '%s': %s(%d)\n",
                opt->iface.ifname, errmsg, err);
        goto out;
    }

    pr_info("%s stopped on interface '%s'\n", COMMON_PROG_NAME,
            opt->iface.ifname);

out:
    xdp_multiprog__close(xdp_mp);
    return err;
}

int xdpfw_stop(const struct stopopt *opt)
{
    return unload_xdp_program(opt);
}
