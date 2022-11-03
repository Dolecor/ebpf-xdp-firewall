// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/err.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include "../xdp-tools/lib/util/util.h"
#include "../xdp-tools/lib/util/params.h"
#include "../xdp-tools/lib/util/logging.h"

#include "xdpfw_common.h"

#define PROG_NAME (COMMON_PROG_NAME "ctl")

#define DEFAULT_ATTACH_MODE XDP_MODE_SKB

static const struct startopt {
    struct iface iface;
    enum xdp_attach_mode mode;
} defaults_start = {
    .mode = DEFAULT_ATTACH_MODE,
};

static struct prog_option start_options[] = {
    DEFINE_OPTION("dev", OPT_IFNAME, struct startopt, iface, .positional = true,
                  .metavar = "<ifname>", .required = true,
                  .help = "Start xdpfw on device <ifname>"),
    END_OPTIONS
};

int load_xdp_program(const struct startopt *opt)
{
    struct xdp_program *xdp_prog;
    LIBBPF_OPTS(bpf_object_open_opts, opts);
    char errmsg[STRERR_BUFSIZE];
    int err = EXIT_SUCCESS;

    xdp_prog = xdp_program__open_file(XDPOBJ_PROGNAME, XDPOBJ_PROGSEC, &opts);
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

int do_start(const void *cfg, __unused const char *pin_root_path)
{
    const struct startopt *opt = cfg;

    return load_xdp_program(opt);
}

static const struct stopopt {
    struct iface iface;
} defaults_stop = {};

static struct prog_option stop_options[] = {
    DEFINE_OPTION("dev", OPT_IFNAME, struct startopt, iface, .positional = true,
                  .metavar = "<ifname>", .required = true,
                  .help = "Stop xdpfw on device <ifname>"),
    END_OPTIONS
};

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
    enum xdp_attach_mode mode = DEFAULT_ATTACH_MODE;
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
                PROG_NAME, xdp_program__name(xdp_prog), xdp_program__id(xdp_prog));
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

int do_stop(const void *cfg, __unused const char *pin_root_path)
{
    const struct stopopt *opt = cfg;

    return unload_xdp_program(opt);
}

int print_help(__unused const void *cfg, __unused const char *pin_root_path)
{
    fprintf(
        stderr,
        "Usage: %s COMMAND [options]\n"
        "\n"
        "COMMAND can be one of:\n"
        "       start       - start firewall on an interface\n"
        "       stop        - stop firewall on an interface\n"
//TODO: start, stop, status, reset, list-filter, add-filter, remove-filter
        "       help        - show this help message\n"
        "\n"
        "Use '%s COMMAND --help' to see options for specific command\n",
        PROG_NAME, PROG_NAME);

    return EXIT_FAILURE;
}

// TODO: add commands
//       start, stop, status, reset, list-filter, add-filter, remove-filter
static const struct prog_command cmds[] = {
    DEFINE_COMMAND(start, "Start firewall (load XDP program) on an interface"),
    DEFINE_COMMAND(stop, "Stop firewall (unload XDP program) on an interface"),
    { .name = "help", .func = print_help, .no_cfg = true },
    END_COMMANDS
};

union xdpfw_opts {
    struct startopt start;
    struct stopopt stop;
};

int main(int argc, char **argv)
{
    if (argc > 1) {
        return dispatch_commands(argv[1], argc - 1, argv + 1, cmds,
                                 sizeof(union xdpfw_opts), PROG_NAME);
    }

    return print_help(NULL, NULL);
}