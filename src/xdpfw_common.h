/* SPDX-License-Identifier: GPL-2.0 */

#ifndef XDPFW_COMMON_H
#define XDPFW_COMMON_H

#define _textify(x) #x
#define textify(x) _textify(x)

#define concat(a, b) a ## b
#define _concat(a, b) concat(a, b)

#define _COMMON_PROG_NAME xdpfw
#define COMMON_PROG_NAME textify(_COMMON_PROG_NAME)

#define XDPOBJ_FILENAME "xdpfw_kern.o"
#define XDPOBJ_PROGSEC COMMON_PROG_NAME
#define XDP_FUNCTION _concat(_COMMON_PROG_NAME, _prog)

#define PROGCTL_NAME (COMMON_PROG_NAME "ctl")

#include "xdp/xdp_stats_kern_user.h"
#include "xdpfw_filter_kern_user.h"

#endif /* XDPFW_COMMON_H */
