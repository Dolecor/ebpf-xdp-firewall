// SPDX-License-Identifier: GPL-2.0

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

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

static int remove_maps(const char *pin_root_path)
{
    int pin_fd;
    int err = 0;

    pin_fd = open(pin_root_path, O_DIRECTORY);
    if (pin_fd < 0) {
		err = -errno;
		pr_warn("Unable to open pin directory %s: %s\n",
			pin_root_path, strerror(-err));
		goto out;
	}

    err = unlink_pinned_map(pin_fd, textify(XDP_STATS_MAP_NAME));
    if (err) {
        goto out;
    }

    err = unlink_pinned_map(pin_fd, textify(XDPFW_FILTER_MAP_NAME));
    if (err) {
        goto out;
    }

out:
    if (pin_fd >= 0) {
        close(pin_fd);
    }

    return err;
}

static int unload_xdp_program(const struct stopopt *opt, const char *pin_root_path)
{
    struct xdp_program *xdp_prog;
    struct xdp_multiprog *xdp_mp;
    enum xdp_attach_mode mode;
    LIBBPF_OPTS(bpf_object_open_opts, opts, .pin_root_path = pin_root_path);
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

    err = remove_maps(pin_root_path);
    if (err) {
        pr_warn("Tried to remove maps but failed (%s).", strerror(-err));
		goto out;
    }

out:
    xdp_multiprog__close(xdp_mp);
    return err;
}

int xdpfw_stop(const struct stopopt *opt, const char *pin_root_path)
{
    return unload_xdp_program(opt, pin_root_path);
}
