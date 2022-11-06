// SPDX-License-Identifier: GPL-2.0

#include <stdbool.h>
#include <linux/err.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

/* xdp-tools utils */
#include "util.h"
#include "params.h"
#include "logging.h"

#include "../xdpfw_common.h"
#include "xdpfw_helpers.h"
#include "xdpfw_start.h"

bool xdpfw_is_loaded(int ifindex)
{
    struct xdp_program *xdp_prog;
    struct xdp_multiprog *xdp_mp;
    enum xdp_attach_mode mode;

    xdp_prog = xdpfw__from_xdp_multiprog_from_iface(ifindex, &xdp_mp, &mode);
    xdp_multiprog__close(xdp_mp);

    return IS_ERR(xdp_prog);
}

int load_xdp_program(const struct startopt *opt)
{
    struct xdp_program *xdp_prog = NULL;
    LIBBPF_OPTS(bpf_object_open_opts, opts);
    char errmsg[STRERR_BUFSIZE];
    int err = EXIT_SUCCESS;

    if (!xdpfw_is_loaded(opt->iface.ifindex)) {
        pr_warn("%s is already loaded on device\n", PROGCTL_NAME);
        err = EXIT_FAILURE;
        goto out;
    }

    xdp_prog = xdp_program__open_file(XDPOBJ_FILENAME, XDPOBJ_PROGSEC, &opts);
    err = libxdp_get_error(xdp_prog);
    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        pr_warn("Could not load BPF program: %s(%d)\n", errmsg, err);
        xdp_prog = NULL;
        goto out;
    }

    err = xdp_program__attach(xdp_prog, opt->iface.ifindex, opt->mode, 0);
    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        pr_warn("Could not attach XDP program on interface '%s': %s(%d)\n",
                opt->iface.ifname, errmsg, err);
        goto out;
    }

    pr_info("%s started on interface '%s' with prog id %d\n", COMMON_PROG_NAME,
            opt->iface.ifname, xdp_program__id(xdp_prog));

out:
    if (xdp_prog != NULL) {
        xdp_program__close(xdp_prog);
    }

    return err;
}

int xdpfw_start(const struct startopt *opt)
{
    return load_xdp_program(opt);
}
