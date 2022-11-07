/* SPDX-License-Identifier: GPL-2.0 */

#ifndef XDPFW_HELPERS_H
#define XDPFW_HELPERS_H

#include <stdbool.h>
#include <xdp/libxdp.h>

struct xdp_program *
xdpfw__from_xdp_multiprog_from_iface(int ifindex, struct xdp_multiprog **xdp_mp,
                                     enum xdp_attach_mode *mode);
int is_xdpfw_program(const struct xdp_program *xdp_prog);
bool xdpfw_is_loaded(int ifindex);

#endif /* XDPFW_HELPERS_H */
