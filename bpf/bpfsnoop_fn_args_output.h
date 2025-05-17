// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#ifndef __BPFSNOOP_FN_ARGS_OUTPUT_H_
#define __BPFSNOOP_FN_ARGS_OUTPUT_H_

#include "vmlinux.h"

#include "bpf_helpers.h"

static __noinline void
output_fn_args(__u64 *args, void *buff, __u64 retval)
{
    /* This function will be rewrote by Go totally. */
    bpf_printk("bpfsnoop: output_fn_args: args %p, retval %llu, buff %p\n", args, retval, buff);
}

#endif // __BPFSNOOP_FN_ARGS_OUTPUT_H_
