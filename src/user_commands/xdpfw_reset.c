// SPDX-License-Identifier: GPL-2.0

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "util.h"
#include "logging.h"

#include "xdp/xdp_stats_kern_user.h"
#include "../xdpfw_filter_kern_user.h"
#include "xdpfw_reset.h"

static int reset_stats(const char *pin_root_path)
{
    int map_fd = -1;
    int nr_cpus;
    struct datarec *values = NULL;
    int err = EXIT_SUCCESS;

    map_fd =
        get_pinned_map_fd(pin_root_path, textify(XDP_STATS_MAP_NAME), NULL);
    if (map_fd < 0) {
        err = map_fd;
        pr_warn("Could not find stats map.\n");
        goto out;
    }

    nr_cpus = libbpf_num_possible_cpus();
    if (nr_cpus < 0) {
        err = nr_cpus;
        goto out;
    }

    values = calloc(nr_cpus, sizeof(*values));
    if (!values) {
        err = -ENOMEM;
        goto out;
    }

    for (uint32_t key = 0; key < XDP_ACTION_MAX; ++key) {
        if (bpf_map_update_elem(map_fd, &key, values, 0)) {
            pr_debug("bpf_map_update_elem failed (key:%u)\n", key);
        }
    }

    printf("Stats reset\n");

out:
    free(values);
    if (map_fd >= 0) {
        close(map_fd);
    }

    return err;
}

static int add_end_of_list(int map_fd, uint32_t end_id)
{
    static const struct filterrec end_filter = {
        .type = FILTER_TYPE_END_OF_LIST,
    };
    return bpf_map_update_elem(map_fd, &end_id, &end_filter, 0);
}

static int reset_filters(const char *pin_root_path)
{
    int map_fd;

    map_fd =
        get_pinned_map_fd(pin_root_path, textify(XDPFW_FILTER_MAP_NAME), NULL);
    if (map_fd < 0) {
        pr_warn("Could not find filter map\n");
        return -1;
    }

    add_end_of_list(map_fd, 0);

    printf("Filters reset\n");

    if (map_fd >= 0) {
        close(map_fd);
    }

    return 0;
}

static int reset(const char *pin_root_path, bool stats, bool filters)
{
    if (!stats && !filters) {
        printf("Options are not specified\n");
        return -1;
    }

    if (stats) {
        reset_stats(pin_root_path);
    }

    if (filters) {
        reset_filters(pin_root_path);
    }

    return 0;
}

int xdpfw_reset(const struct resetopt *opt, const char *pin_root_path)
{
    return reset(pin_root_path, opt->stats, opt->filters);
}
