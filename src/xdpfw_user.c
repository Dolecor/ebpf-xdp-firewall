// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>

#include <bpf/libbpf.h>

int main(/* int argc, char **argv */)
{
    printf("libbpf version: %s\n", libbpf_version_string());
    return 0;
}
