# SPDX-License-Identifier: GPL-2.0

XDP_TARGETS := xdpfw_kern
EXTRA_KERN_DEPS := xdpfw_filter_kern.h

USER_TARGETS := xdpfwctl

XDPFWCTL_CMDS_PREFIX := user_commands/
XDPFWCTL_CMDS := xdpfw_helpers xdpfw_start xdpfw_stop xdpfw_status xdpfw_filter
USER_TARGETS_OBJS := $(addprefix $(XDPFWCTL_CMDS_PREFIX), \
						$(addsuffix .o, $(XDPFWCTL_CMDS)))
#USER_TARGETS_OBJS_DEPS := $(addprefix $(XDPFWCTL_COMMANDS), )

KERN_USER_H := xdpfw_common.h xdpfw_filter_kern_user.h

LIB_DIR = ../xdp-tools/lib/
include $(LIB_DIR)/common.mk
