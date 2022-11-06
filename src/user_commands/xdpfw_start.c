// SPDX-License-Identifier: GPL-2.0

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

/* xdp-tools utils */
#include "util.h"
#include "params.h"
#include "logging.h"

#include "../xdpfw_common.h"
#include "xdpfw_start.h"

int load_xdp_program(const struct startopt *opt)
{
    struct xdp_program *xdp_prog;
    LIBBPF_OPTS(bpf_object_open_opts, opts);
    char errmsg[STRERR_BUFSIZE];
    int err = EXIT_SUCCESS;

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

    pr_info("%s started on interface '%s' with prog id %d\n",
            COMMON_PROG_NAME, opt->iface.ifname, xdp_program__id(xdp_prog));

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
