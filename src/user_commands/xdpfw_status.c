// SPDX-License-Identifier: GPL-2.0

#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

/* xdp-tools utils */
#include "util.h"
#include "params.h"
#include "logging.h"
#include "stats.h"

#include "../xdpfw_common.h"
#include "xdpfw_helpers.h"
#include "xdpfw_status.h"

int xdpfw_stats_print(const char *pin_root_path)
{
    int map_fd = -1;
    struct bpf_map_info info = {};
    struct stats_record rec = {};
    int err = EXIT_SUCCESS;

    map_fd = get_pinned_map_fd(pin_root_path, textify(XDP_STATS_MAP_NAME), &info);
    if (map_fd < 0) {
        err = map_fd;
        pr_warn("Could not find stats map.\n");
        goto out;
    }

    rec.stats[XDP_DROP].enabled = true;

    err = stats_collect(map_fd, info.type, &rec);
    if (err) {
        goto out;
    }

    printf("Number of denied packets: %lld\n",
           rec.stats[XDP_DROP].total.rx_packets);

out:
    if (map_fd >= 0) {
        close(map_fd);
    }

    return err;
}

static int print_status(const struct statusopt *opt, const char *pin_root_path)
{
    struct xdp_program *xdp_prog;
    struct xdp_multiprog *xdp_mp;
    enum xdp_attach_mode mode;
    char errmsg[STRERR_BUFSIZE];
    int err = EXIT_SUCCESS;

    xdp_prog = xdpfw__from_xdp_multiprog_from_iface(opt->iface.ifindex, &xdp_mp,
                                                    &mode);
    err = libxdp_get_error(xdp_prog);

    printf("\n");
    printf("STATUS:\n");
    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        pr_warn("Could not get status: %s(%d)\n", errmsg, err);
        xdp_prog = NULL;
        goto out;
    } else {
        printf("%s is started on interface '%s' with id %d in %s mode\n",
               PROGCTL_NAME, opt->iface.ifname, xdp_program__id(xdp_prog),
               xdp_multiprog__is_legacy(xdp_mp) ? "legacy" : "multiprog");
    }

    if (opt->stats) {
        printf("\n");
        printf("STATS:\n");
        xdpfw_stats_print(pin_root_path);
    }

out:
    xdp_multiprog__close(xdp_mp);
    return 0;
}

int xdpfw_status(const struct statusopt *opt, const char *pin_root_path)
{
    return print_status(opt, pin_root_path);
}
