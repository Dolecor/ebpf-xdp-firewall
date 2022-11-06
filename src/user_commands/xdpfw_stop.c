// SPDX-License-Identifier: GPL-2.0

#include <linux/err.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

/* xdp-tools utils */
#include "util.h"
#include "params.h"
#include "logging.h"

#include "../xdpfw_common.h"
#include "xdpfw_stop.h"

struct xdp_program *xdp_program__from_iface(int ifindex)
{
    __u32 prog_id = 0;
    int err = 0;

    err = bpf_xdp_query_id(ifindex, 0, &prog_id);
    if (err) {
        pr_warn("could not get program id from interface: %s\n", strerror(err));
        return ERR_PTR(err);
    }

    if (prog_id == 0) {
        pr_warn("XDP not loaded on device\n");
        return ERR_PTR(-ENOENT);
    }

    return xdp_program__from_id(prog_id);
}

int is_xdpfw_program(const struct xdp_program *xdp_prog)
{
    return !strcmp(xdp_program__name(xdp_prog), textify(XDP_FUNCTION));
}

int unload_xdp_program(const struct stopopt *opt)
{
    struct xdp_program *xdp_prog;
    enum xdp_attach_mode mode = XDP_MODE_UNSPEC;
    __unused LIBBPF_OPTS(bpf_object_open_opts, opts);
    char errmsg[STRERR_BUFSIZE];
    int err = EXIT_SUCCESS;

    xdp_prog = xdp_program__from_iface(opt->iface.ifindex);
    err = libxdp_get_error(xdp_prog);
    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        pr_warn("Could not get BPF program from interface '%s'\n",
                opt->iface.ifname);
        xdp_prog = NULL;
        goto out;
    }

    if (!is_xdpfw_program(xdp_prog)) {
        pr_warn("%s not allow to detach non-xdpfw program. (attached XDP: %s with id %d)\n",
                PROGCTL_NAME, xdp_program__name(xdp_prog), xdp_program__id(xdp_prog));
        goto out;
    }

    err = xdp_program__detach(xdp_prog, opt->iface.ifindex, mode, 0);
    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        pr_warn("Could not detach XDP program on interface '%s': %s(%d)\n",
                opt->iface.ifname, errmsg, err);
        goto out;
    }

    pr_info("%s stopped on interface '%s'\n",
            COMMON_PROG_NAME, opt->iface.ifname);

out:
    if (xdp_prog != NULL) {
        xdp_program__close(xdp_prog);
    }

    return err;
}

int xdpfw_stop(const struct stopopt *opt)
{
    return unload_xdp_program(opt);
}
