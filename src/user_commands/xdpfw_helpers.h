/* SPDX-License-Identifier: GPL-2.0 */

#ifndef XDPFW_HELPERS_H
#define XDPFW_HELPERS_H

#include <stdbool.h>
#include <xdp/libxdp.h>

#include "../xdpfw_filter_kern_user.h"

#define PORTSTRLEN 6
#define ANY_IP XDPFW_IP_ANY
#define ANY_PORT XDPFW_PORT_ANY
#define WILDCARD_HOST XDPFW_IP_WILDCARD_HOST
#define WILDCARD_ANY XDPFW_IP_WILDCARD_ANY
#define HOST_STR "host"
#define ANY_STR "any"

struct xdp_program *
xdpfw__from_xdp_multiprog_from_iface(int ifindex, struct xdp_multiprog **xdp_mp,
                                     enum xdp_attach_mode *mode);
int is_xdpfw_program(const struct xdp_program *xdp_prog);
bool xdpfw_is_loaded(int ifindex);

char *inaddr_to_str(uint32_t ip, char *buf);
char *port_to_str(uint16_t port, char *buf);

#endif /* XDPFW_HELPERS_H */
