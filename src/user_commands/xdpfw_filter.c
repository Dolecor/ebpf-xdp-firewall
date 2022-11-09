// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include "util.h"
#include "logging.h"

#include "../xdpfw_filter_kern_user.h"
#include "../xdpfw_common.h"
#include "xdpfw_helpers.h"
#include "xdpfw_filter.h"

#define PRINT_HEADER \
    "| id| type | proto |     srcip     | sport |     dstip     | dport |\n"
#define PRINT_SEP \
    "+---+------+-------+---------------+-------+---------------+-------+\n"
#define FILTER_FMT "|%3u|%-6s| %-5s |%-15s| %-5s |%-15s| %-5s |\n"

static char *str_actions[] = {
    [FILTER_TYPE_END_OF_LIST] = "end",
    [FILTER_TYPE_DENY] = "deny",
    [FILTER_TYPE_PERMIT] = "permit",
};

static char *str_protos[] = {
    [ICMP] = "icmp",
    [TCP] = "tcp",
    [UDP] = "udp",
};

static int print_filter_list(const char *pin_root_path)
{
    int map_fd;
    struct filterrec filter;
    char srcip_str[INET_ADDRSTRLEN];
    char dstip_str[INET_ADDRSTRLEN];
    char sport_str[PORTSTRLEN];
    char dport_str[PORTSTRLEN];

    map_fd =
        get_pinned_map_fd(pin_root_path, textify(XDPFW_FILTER_MAP_NAME), NULL);
    if (map_fd < 0) {
        pr_warn("Could not find filter map\n");
        return -1;
    }

    printf(PRINT_HEADER);
    printf(PRINT_SEP);

    for (size_t i = 0; i < XDPFW_FILTER_MAX_ENTRIES; ++i) {
        if (bpf_map_lookup_elem(map_fd, &i, &filter) != 0) {
            pr_debug("bpf_map_lookup_elem failed (key:%zu\n", i);
        }

        if (filter.type == FILTER_TYPE_EMPTY_CELL) {
            continue;
        }

        if (filter.type == FILTER_TYPE_END_OF_LIST) {
            printf(FILTER_FMT, (uint32_t)i, str_actions[filter.type],
                   "---", "---", "---", "---", "---");
            break;
        }

        printf(FILTER_FMT, (uint32_t)i, str_actions[filter.type],
               str_protos[filter.protocol],
               inaddr_to_str(filter.src_ip, srcip_str),
               port_to_str(filter.src_port, sport_str),
               inaddr_to_str(filter.dst_ip, dstip_str),
               port_to_str(filter.dst_port, dport_str));
    }

    if (map_fd >= 0) {
        close(map_fd);
    }

    return 0;
}

static int add_end_of_list(int map_fd, uint32_t end_id)
{
    static const struct filterrec end_filter = {
        .type = FILTER_TYPE_END_OF_LIST,
    };
    return bpf_map_update_elem(map_fd, &end_id, &end_filter, 0);
}

static int add_empty_list_cell(int map_fd, uint32_t empty_cell_id)
{
    static const struct filterrec empty_filter = {
        .type = FILTER_TYPE_EMPTY_CELL,
    };
    return bpf_map_update_elem(map_fd, &empty_cell_id, &empty_filter, 0);
}

static int add_filter(const char *pin_root_path, const struct filterrec *filter,
                      uint32_t insert_at)
{
    int map_fd;
    struct filterrec lookup_filter;
    uint32_t list_end = 0;
    int err = 0;

    map_fd =
        get_pinned_map_fd(pin_root_path, textify(XDPFW_FILTER_MAP_NAME), NULL);
    if (map_fd < 0) {
        pr_warn("Could not find filter map\n");
        return -1;
    }

    for (list_end = 0; list_end < XDPFW_FILTER_MAX_ENTRIES - 1; ++list_end) {
        if (bpf_map_lookup_elem(map_fd, &list_end, &lookup_filter) != 0) {
            pr_debug("bpf_map_lookup_elem failed (key:%u\n", list_end);
        }

        if (lookup_filter.type == FILTER_TYPE_END_OF_LIST) {
            break;
        }
    }

    if (insert_at != INSERT_AT_NO_SET) {
        if (insert_at > list_end) {
            pr_warn("Could not insert after end of list "
                    "(insert id: %u, end id: %d)\n",
                    insert_at, list_end);
            err = -1;
            goto out;
        }

        if (insert_at >= XDPFW_FILTER_MAX_ENTRIES - 1) {
            pr_warn("Could not insert after max id "
                    "(insert id: %u, max id: %d)\n",
                    insert_at, XDPFW_FILTER_MAX_ENTRIES - 1);
            err = -1;
            goto out;
        }

        bpf_map_update_elem(map_fd, &insert_at, filter, 0);
    } else {
        if (list_end == XDPFW_FILTER_MAX_ENTRIES - 1) {
            pr_warn("Maximum size of list is reached\n");
            err = -1;
            goto out;
        }

        bpf_map_update_elem(map_fd, &list_end, filter, 0);
        add_end_of_list(map_fd, list_end + 1);
    }

out:
    if (map_fd >= 0) {
        close(map_fd);
    }

    return err;
}

static int remove_filter(const char *pin_root_path, uint32_t id)
{
    int map_fd;
    struct filterrec lookup_filter;
    uint32_t list_end = 0;
    int err = 0;

    map_fd =
        get_pinned_map_fd(pin_root_path, textify(XDPFW_FILTER_MAP_NAME), NULL);
    if (map_fd < 0) {
        pr_warn("Could not find filter map\n");
        return -1;
    }

    for (list_end = 0; list_end < XDPFW_FILTER_MAX_ENTRIES - 1; ++list_end) {
        if (bpf_map_lookup_elem(map_fd, &list_end, &lookup_filter) != 0) {
            pr_debug("bpf_map_lookup_elem failed (key:%u\n", list_end);
        }

        if (lookup_filter.type == FILTER_TYPE_END_OF_LIST) {
            break;
        }
    }

    if (id >= list_end) {
        pr_warn("Could not remove at/after end of list "
                "(rm id: %u, end id: %d)\n",
                id, list_end);
        err = -1;
        goto out;
    }

    add_empty_list_cell(map_fd, id);
    if (id == list_end - 1) {
        add_end_of_list(map_fd, list_end - 1);
    }

out:
    if (map_fd >= 0) {
        close(map_fd);
    }

    return err;
}

int xdpfw_filter_list(__unused const struct filterlistopt *opt,
                      const char *pin_root_path)
{
    return print_filter_list(pin_root_path);
}

int xdpfw_filter_add(const struct filteraddopt *opt, const char *pin_root_path)
{
    struct filterrec filter;

    if ((opt->dst_ip.af == AF_INET6) || (opt->src_ip.af == AF_INET6)) {
        pr_warn("IPv6 is not supported\n");
        return -1;
    }

    filter.type = opt->action;
    filter.protocol = opt->protocol;
    filter.src_ip = opt->src_ip.addr.addr4.s_addr;
    filter.dst_ip = opt->dst_ip.addr.addr4.s_addr;
    filter.src_port = htons(opt->src_port);
    filter.dst_port = htons(opt->dst_port);

    return add_filter(pin_root_path, &filter, opt->insert_at);
}

int xdpfw_filter_remove(const struct filterrmopt *opt,
                        __unused const char *pin_root_path)
{
    return remove_filter(pin_root_path, opt->filter_id);
}
