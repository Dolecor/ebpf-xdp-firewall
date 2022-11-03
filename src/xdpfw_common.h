/* SPDX-License-Identifier: GPL-2.0 */

#ifndef XDPFW_COMMON_H
#define XDPFW_COMMON_H

#define _textify(x) #x
#define textify(x) _textify(x)

#define concat(a, b) a ## b
#define _concat(a, b) concat(a, b)

#define _COMMON_PROG_NAME xdpfw
#define COMMON_PROG_NAME textify(_COMMON_PROG_NAME)

#define XDPOBJ_PROGNAME "xdpfw_kern.o"
#define XDPOBJ_PROGSEC COMMON_PROG_NAME
#define XDP_FUNCTION _concat(_COMMON_PROG_NAME, _prog)

#endif /* XDPFW_COMMON_H */