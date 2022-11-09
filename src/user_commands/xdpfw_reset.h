/* SPDX-License-Identifier: GPL-2.0 */

#ifndef XDPFW_HELPERS_H
#define XDPFW_HELPERS_H

#include <stdbool.h>

struct resetopt {
    struct iface iface;
    bool stats;
    bool filters;
};

int xdpfw_reset(const struct resetopt *opt, const char *pin_root_path);

#endif /* XDPFW_HELPERS_H */
