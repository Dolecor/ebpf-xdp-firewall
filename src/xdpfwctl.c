// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <linux/err.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

/* xdp-tools utils */
#include "util.h"
#include "params.h"

#include "xdpfw_common.h"
#include "user_commands/xdpfw_start.h"
#include "user_commands/xdpfw_stop.h"
#include "user_commands/xdpfw_status.h"

#define DEFAULT_ATTACH_MODE XDP_MODE_SKB
#define DEFAULT_STATUS_STATS false

static struct prog_option start_options[] = {
    DEFINE_OPTION("dev", OPT_IFNAME, struct startopt, iface,
                  .metavar = "<ifname>",
                  .positional = true,
                  .required = true,
                  .help = "Start xdpfw on device <ifname>"),
    END_OPTIONS
};

static const struct startopt defaults_start = {
    .mode = DEFAULT_ATTACH_MODE,
};

int do_start(const void *cfg, const char *pin_root_path)
{
    const struct startopt *opt = cfg;
    return xdpfw_start(opt, pin_root_path);
}

static struct prog_option stop_options[] = {
    DEFINE_OPTION("dev", OPT_IFNAME, struct stopopt, iface,
                  .metavar = "<ifname>",
                  .positional = true,
                  .required = true,
                  .help = "Stop xdpfw on device <ifname>"),
    END_OPTIONS
};

static const struct startopt defaults_stop = {};

int do_stop(const void *cfg, const char *pin_root_path)
{
    const struct stopopt *opt = cfg;
    return xdpfw_stop(opt, pin_root_path);
}

static struct prog_option status_options[] = {
    DEFINE_OPTION("dev", OPT_IFNAME, struct statusopt, iface,
                  .metavar = "<ifname>",
                  .positional = true,
                  .required = true,
                  .help = "Print status of xdpfw on device <ifname>"),
    DEFINE_OPTION("stats", OPT_BOOL, struct statusopt, stats,
                  .short_opt = 's',
                  .help = "Print number of denied packets"),
    // DEFINE_OPTION("filters", OPT_BOOL, struct statusopt, filters,
    //               .short_opt = 'f',
    //               .help = "Print list of active filters"),
    END_OPTIONS
};

static const struct statusopt defaults_status = {
    .stats = DEFAULT_STATUS_STATS,
};

int do_status(const void *cfg, const char *pin_root_path)
{
    const struct statusopt *opt = cfg;
    return xdpfw_status(opt, pin_root_path);
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
        "       status      - print status of firewall on an interface\n"
        // "       reset       - reset stats and filters of firewall on an interface\n"
        // "       list-filter - list active filters of firewall on an interface\n"
        // "       add-filter  - add filter to firewall on an interface\n"
        // "       del-filter  - delete filter from firewall on an interface\n"
        "       help        - show this help message\n"
        "\n"
        "Use '%s COMMAND --help' to see options for specific command\n",
        PROGCTL_NAME, PROGCTL_NAME);

    return EXIT_FAILURE;
}

// TODO: add commands
//       reset, list-filter, add-filter, remove-filter
static const struct prog_command cmds[] = {
    DEFINE_COMMAND(start, "Start firewall (load XDP program) on an interface"),
    DEFINE_COMMAND(stop, "Stop firewall (unload XDP program) on an interface"),
    DEFINE_COMMAND(status, "Print status and stats of xdpfw on an interface"),
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
                                 sizeof(union xdpfw_opts), PROGCTL_NAME);
    }

    return print_help(NULL, NULL);
}
