// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#ifndef __BPFSNOOP_ARG_OUTPUT_H_
#define __BPFSNOOP_ARG_OUTPUT_H_

#include "vmlinux.h"

#include "bpf_helpers.h"

static __noinline void
output_arg(__u64 *args, void *buff)
{
    /* This function will be rewrote by Go totally. */
    /* Keeping one line is to show in `bpfsnoop -d -p`. */
    bpf_printk("bpfsnoop: output_arg: args=%llx buff=%llx\n", args, buff);
}

#endif // __BPFSNOOP_ARG_OUTPUT_H_
