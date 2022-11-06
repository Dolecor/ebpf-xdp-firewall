/* SPDX-License-Identifier: GPL-2.0 */

#ifndef XDPFW_HELPERS_H
#define XDPFW_HELPERS_H

#include <xdp/libxdp.h>

struct xdp_program *
xdpfw__from_xdp_multiprog_from_iface(int ifindex, struct xdp_multiprog **xdp_mp,
                                     enum xdp_attach_mode *mode);

#endif /* XDPFW_HELPERS_H */
