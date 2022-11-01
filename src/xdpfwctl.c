// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <stdlib.h>

///
#include <unistd.h>

#include "../xdp-tools/lib/util/util.h"
#include "../xdp-tools/lib/util/params.h"

#define PROG_NAME "xdpfwctl"

static const struct startopt {
    struct iface iface;
} defaults_start = {};

static struct prog_option start_options[] = {
    DEFINE_OPTION("dev", OPT_IFNAME, struct startopt, iface, .positional = true,
                  .metavar = "<ifname>", .required = true,
                  .help = "Start xdpfw on device <ifname>"),
    END_OPTIONS
};

int do_start(__unused const void *cfg, __unused const char *pin_root_path)
{
    ///
    while(1) {
        printf("doing start...\n");
        sleep(10);
    }

    return EXIT_FAILURE;
}

int print_help(__unused const void *cfg, __unused const char *pin_root_path)
{
    ///
    printf("print_help\n");

    return EXIT_FAILURE;
}

// TODO: add commands
//       start, stop, status, reset, list-filter, add-filter, remove-filter
static const struct prog_command cmds[] = {
    DEFINE_COMMAND(start, "Start (load XDP program) firewall on an interface"),
    { .name = "help", .func = print_help, .no_cfg = true },
    END_COMMANDS
};

union xdpfw_opts {
    struct startopt start;
};

int main(int argc, char **argv)
{
    if (argc > 1)
        return dispatch_commands(argv[1], argc - 1, argv + 1, cmds,
                                 sizeof(union xdpfw_opts), PROG_NAME);

    return print_help(NULL, NULL);
}