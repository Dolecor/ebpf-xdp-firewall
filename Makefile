# SPDX-License-Identifier: GPL-2.0

all: xdpfw

xdpfw:
	$(MAKE) -C ./src

xdpfw-clean:
	$(MAKE) -C ./src clean

.PHONY: xdpfw xdpfw-clean
