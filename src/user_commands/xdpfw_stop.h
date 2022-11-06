/* SPDX-License-Identifier: GPL-2.0 */

#ifndef XDPFW_STOP_H
#define XDPFW_STOP_H

#include "params.h"

struct stopopt {
    struct iface iface;
};

int xdpfw_stop(const struct stopopt *opt);

#endif /* XDPFW_STOP_H */
