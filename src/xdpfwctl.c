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
#include "user_commands/xdpfw_filter.h"
#include "user_commands/xdpfw_reset.h"

#define DEFAULT_ATTACH_MODE XDP_MODE_SKB
#define DEFAULT_STATUS_STATS false

static struct prog_option start_options[] = {
    DEFINE_OPTION("dev", OPT_IFNAME, struct startopt, iface,
                  .metavar = "<ifname>",
                  .positional = true,
                  .required = true,
                  .help = "Start on device <ifname>"),
    END_OPTIONS
};

static const struct startopt defaults_start = {
    .mode = DEFAULT_ATTACH_MODE,
};

int do_start(const void *cfg, const char *pin_root_path)
{
    const struct startopt *opt = cfg;
    char pin_dir[PATH_MAX];

    sprintf(pin_dir, "%s/%s",  pin_root_path, opt->iface.ifname);

    return xdpfw_start(opt, pin_dir);
}

static struct prog_option stop_options[] = {
    DEFINE_OPTION("dev", OPT_IFNAME, struct stopopt, iface,
                  .metavar = "<ifname>",
                  .positional = true,
                  .required = true,
                  .help = "Stop on device <ifname>"),
    END_OPTIONS
};

static const struct stopopt defaults_stop = {};

int do_stop(const void *cfg, const char *pin_root_path)
{
    const struct stopopt *opt = cfg;
    char pin_dir[PATH_MAX];

    sprintf(pin_dir, "%s/%s", pin_root_path, opt->iface.ifname);

    return xdpfw_stop(opt, pin_dir);
}

static struct prog_option status_options[] = {
    DEFINE_OPTION("dev", OPT_IFNAME, struct statusopt, iface,
                  .metavar = "<ifname>",
                  .positional = true,
                  .required = true,
                  .help = "Print status on device <ifname>"),
    DEFINE_OPTION("stats", OPT_BOOL, struct statusopt, stats,
                  .short_opt = 's',
                  .help = "Print number of denied packets"),
    DEFINE_OPTION("filters", OPT_BOOL, struct statusopt, filters,
                  .short_opt = 'f',
                  .help = "Print number of active filters"),
    END_OPTIONS
};

static const struct statusopt defaults_status = {
    .stats = DEFAULT_STATUS_STATS,
};

int do_status(const void *cfg, const char *pin_root_path)
{
    const struct statusopt *opt = cfg;
    char pin_dir[PATH_MAX];

    sprintf(pin_dir, "%s/%s", pin_root_path, opt->iface.ifname);

    return xdpfw_status(opt, pin_dir);
}

static struct prog_option flist_options[] = {
    DEFINE_OPTION("dev", OPT_IFNAME, struct filterlistopt, iface,
                  .metavar = "<ifname>",
                  .positional = true,
                  .required = true,
                  .help = "List on device <ifname>"),
    END_OPTIONS
};

static const struct filterlistopt defaults_flist = { };

int do_flist(const void *cfg, const char *pin_root_path)
{
    const struct filterlistopt *opt = cfg;
    char pin_dir[PATH_MAX];

    sprintf(pin_dir, "%s/%s", pin_root_path, opt->iface.ifname);

    return xdpfw_filter_list(opt, pin_dir);
}

static struct enum_val filter_actions[] = {
    { "deny", FILTER_TYPE_DENY },
    { "permit", FILTER_TYPE_PERMIT },
    { NULL, 0 },
};

static struct enum_val upper_protocols[] = {
    { "icmp", ICMP },
    { "tcp", TCP },
    { "udp", UDP },
    { NULL, 0 },
};

static struct prog_option fadd_options[] = {
    DEFINE_OPTION("dev", OPT_IFNAME, struct filteraddopt, iface,
                  .metavar = "<ifname>",
                  .positional = true,
                  .required = true,
                  .help = "Add on device <ifname>"),
    DEFINE_OPTION("action", OPT_ENUM, struct filteraddopt, action,
                  .metavar = "<action>",
                  .positional = true,
                  .required = true,
                  .typearg = filter_actions,
                  .help = "Specify <action> of filter"),
    DEFINE_OPTION("protocol", OPT_ENUM, struct filteraddopt, protocol,
                  .metavar = "<proto>",
                  .positional = true,
                  .required = true,
                  .typearg = upper_protocols,
                  .help = "Specify <proto> of filter"),
    DEFINE_OPTION("srcip", OPT_IPADDR, struct filteraddopt, src_ip,
                  .metavar = "<ip>",
                  .help = "Specify source ip of filter (default: 0.0.0.0 (any))"),
    DEFINE_OPTION("dstip", OPT_IPADDR, struct filteraddopt, dst_ip,
                  .metavar = "<ip>",
                  .help = "Specify dest ip of filter (default: 0.0.0.0 (any))"),
    DEFINE_OPTION("sport", OPT_U16, struct filteraddopt, src_port,
                  .metavar = "<port>",
                  .help = "Specify source port of filter (default: 0 (any))"),
    DEFINE_OPTION("dport", OPT_U16, struct filteraddopt, dst_port,
                  .metavar = "<port>",
                  .help = "Specify dest port of filter (default: 0 (any))"),
    DEFINE_OPTION("id", OPT_U32, struct filteraddopt, insert_at,
                  .short_opt = 'i',
                  .metavar = "<id>",
                  .help = "Specify <id> to insert at list of filters"),
    END_OPTIONS
};

static const struct filteraddopt defaults_fadd = {
    .src_ip = { .addr.addr4.s_addr = XDPFW_IP_ANY },
    .dst_ip = { .addr.addr4.s_addr = XDPFW_IP_ANY },
    .src_port = XDPFW_PORT_ANY,
    .dst_port = XDPFW_PORT_ANY,
    .insert_at = INSERT_AT_NO_SET,
};

int do_fadd(const void *cfg, const char *pin_root_path)
{
    const struct filteraddopt *opt = cfg;
    char pin_dir[PATH_MAX];

    sprintf(pin_dir, "%s/%s", pin_root_path, opt->iface.ifname);

    return xdpfw_filter_add(opt, pin_dir);
}

static struct prog_option frm_options[] = {
    DEFINE_OPTION("dev", OPT_IFNAME, struct filteraddopt, iface,
                  .metavar = "<ifname>",
                  .positional = true,
                  .required = true,
                  .help = "Remove from device <ifname>"),
    DEFINE_OPTION("id", OPT_U32, struct filterrmopt, filter_id,
                  .metavar = "<id>",
                  .positional = true,
                  .required = true,
                  .help = "Specify <id> of filter"),
    END_OPTIONS
};

static const struct filterrmopt defaults_frm = {};

int do_frm(const void *cfg, const char *pin_root_path)
{
    const struct filterrmopt *opt = cfg;
    char pin_dir[PATH_MAX];

    sprintf(pin_dir, "%s/%s", pin_root_path, opt->iface.ifname);

    return xdpfw_filter_remove(opt, pin_dir);
}

static struct prog_option reset_options[] = {
    DEFINE_OPTION("dev", OPT_IFNAME, struct resetopt, iface,
                  .metavar = "<ifname>",
                  .positional = true,
                  .required = true,
                  .help = "Reset on device <ifname>"),
    DEFINE_OPTION("stats", OPT_BOOL, struct resetopt, stats,
                  .short_opt = 's',
                  .help = "Reset stats"),
    DEFINE_OPTION("filters", OPT_BOOL, struct resetopt, filters,
                  .short_opt = 'f',
                  .help = "Reset filter list"),
    END_OPTIONS
};

static const struct resetopt defaults_reset = {
    .filters = false,
    .stats = false,
};

int do_reset(const void *cfg, const char *pin_root_path)
{
    const struct resetopt *opt = cfg;
    char pin_dir[PATH_MAX];

    sprintf(pin_dir, "%s/%s", pin_root_path, opt->iface.ifname);

    return xdpfw_reset(opt, pin_dir);
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
        "       flist       - list filters of firewall on an interface\n"
        "       fadd        - add filter to firewall on an interface\n"
        "       frm         - remove filter from firewall on an interface\n"
        "       reset       - reset stats and filters of firewall on an interface\n"
        "       help        - show this help message\n"
        "\n"
        "Use '%s COMMAND --help' to see options for specific command\n",
        PROGCTL_NAME, PROGCTL_NAME);

    return EXIT_FAILURE;
}

static const struct prog_command cmds[] = {
    DEFINE_COMMAND(start, "Start xdpfw (load XDP program) on an interface"),
    DEFINE_COMMAND(stop, "Stop xdpfw (unload XDP program) on an interface"),
    DEFINE_COMMAND(status, "Print status and stats of xdpfw on an interface"),
    DEFINE_COMMAND(flist, "List filters of xdpfw on an interface"),
    DEFINE_COMMAND(fadd, "Add filter to xdpfw on an interface"),
    DEFINE_COMMAND(frm, "Remove filter from xdpfw on an interface"),
    DEFINE_COMMAND(reset, "Reset xdpfw on an interface"),
    { .name = "help", .func = print_help, .no_cfg = true },
    END_COMMANDS
};

union xdpfw_opts {
    struct startopt start;
    struct stopopt stop;
    struct statusopt status;
    struct filterlistopt flist;
    struct filteraddopt fadd;
    struct filterrmopt frm;
    struct resetopt reset;
};

int main(int argc, char **argv)
{
    if (argc > 1) {
        return dispatch_commands(argv[1], argc - 1, argv + 1, cmds,
                                 sizeof(union xdpfw_opts), PROGCTL_NAME);
    }

    return print_help(NULL, NULL);
}
