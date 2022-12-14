/* SPDX-License-Identifier: GPL-2.0 */

#ifndef XDPFW_START_H
#define XDPFW_START_H

#include "params.h"

struct startopt {
    struct iface iface;
    enum xdp_attach_mode mode;
};

int xdpfw_start(const struct startopt *opt, const char *pin_root_path);

#endif /* XDPFW_START_H */
