/* SPDX-License-Identifier: GPL-2.0 */

#ifndef XDPFW_STATUS_H
#define XDPFW_STATUS_H

#include <stdbool.h>

#include "params.h"

struct statusopt {
    struct iface iface;
    bool stats;
    bool filters;
};

int xdpfw_status(const struct statusopt *opt, const char *pin_root_path);

#endif /* XDPFW_STATUS_H */
