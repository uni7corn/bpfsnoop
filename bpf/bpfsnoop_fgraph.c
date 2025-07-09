// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_map_helpers.h"

#include "bpfsnoop_event.h"
#include "bpfsnoop_fn_args_output.h"
#include "bpfsnoop_sess.h"

struct bpfsnoop_fn_args {
    __u32 args_nr;
    bool with_retval;
    __u8 pad[3];
    __u32 buf_size;
} __attribute__((packed));

struct bpfsnoop_fgraph_configs {
    __u64 func_ip;
    __u32 max_depth;
    __u32 entry; // 1 for entry, 0 for exit
    __u32 mypid;
    struct bpfsnoop_fn_args fn_args;
} __attribute__((packed));

volatile const struct bpfsnoop_fgraph_configs BSN_FGRAPH_CFG;
#define cfg (&BSN_FGRAPH_CFG)

__u32 ready SEC(".data.ready") = 0;

struct bpfsnoop_fgraph_event {
    __u16 type;
    __u16 length;
    __u32 kernel_ts;
    __u64 session_id;
    __u64 func_ip;
    __u32 cpu;
    __u32 depth;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, 1024 * 1024); // 1Mi entries
} bpfsnoop_fgraph_tracee_ips SEC(".maps");

/* Check the tracee ip in the following stack layout:
 * +----+ tracee caller fp
 * | .. |
 * | ip | tracee caller ip
 * | ip | tracee ip        <-- check this ip
 * | fp | tracee caller fp
 * +----+ tramp fp
 * | .. |
 * | ip | tramp ip
 * | fp | tramp fp
 * +----+ fgraph prog fp
 * | .. |
 *
 */
static __always_inline bool
is_tramp_fp(__u64 ip)
{
    __u32 *val;

    val = bpf_map_lookup_elem(&bpfsnoop_fgraph_tracee_ips, &ip);
    return val != NULL;
}

static __always_inline struct bpfsnoop_sess *
try_get_session(int *depth)
{
    struct bpfsnoop_sess *sess;
    __u32 max_depth;
    __u64 buff[2]; /* [FP|IP] */
    __u64 fp;
    int i;

    /* get frame pointer */
    asm volatile ("%[fp] = r10" : [fp] "+r"(fp) :); /* read prog fp */
    (void) bpf_probe_read_kernel(&fp, sizeof(fp), (void *) fp); /* read tramp fp */
    (void) bpf_probe_read_kernel(&fp, sizeof(fp), (void *) fp); /* read caller fp */

    *depth = 0;
    max_depth = cfg->max_depth;
    int max_tries = max_depth * 2;
    for (i = 0; i < max_tries; i++) {
        (void) bpf_probe_read_kernel(&buff, sizeof(buff), (void *) fp); /* read both fp&ip at same time */
        sess = get_session(buff[0]);
        if (sess)
            return sess;

        if (!is_tramp_fp(buff[1]))
            (*depth)++;
        if (*depth > max_depth)
            break;
        fp = buff[0]; /* next frame pointer */
    }

    return NULL;
}

SEC("fexit")
int BPF_PROG(bpfsnoop_fgraph)
{
    struct bpfsnoop_fgraph_event *evt;
    struct bpfsnoop_sess *sess;
    __u64 args[MAX_FN_ARGS];
    __u64 retval = 0;
    size_t buffer_sz;
    int depth = 0;
    void *buffer;

    if (!ready)
        return BPF_OK;

    if (cfg->mypid == (bpf_get_current_pid_tgid() >> 32))
        return BPF_OK;

    sess = try_get_session(&depth);
    if (!sess)
        return BPF_OK;

    buffer_sz = sizeof(*evt) + cfg->fn_args.buf_size;
    buffer = bpf_ringbuf_reserve(&bpfsnoop_events, buffer_sz, 0);
    if (!buffer)
        return BPF_OK;

    (void) bpf_probe_read_kernel(args, 8*cfg->fn_args.args_nr, ctx);
    if (cfg->fn_args.with_retval)
        (void) bpf_probe_read_kernel(&retval, sizeof(retval), ctx + 8*cfg->fn_args.args_nr);

    evt = (typeof(evt)) buffer;
    evt->type = cfg->entry ? BPFSNOOP_EVENT_TYPE_GRAPH_ENTRY
                           : BPFSNOOP_EVENT_TYPE_GRAPH_EXIT;
    evt->length = buffer_sz;
    evt->kernel_ts = (__u32) bpf_ktime_get_ns();
    evt->session_id = sess->session_id;
    evt->func_ip = cfg->func_ip;
    evt->cpu = bpf_get_smp_processor_id();
    evt->depth = depth;

    buffer += sizeof(*evt);
    output_fn_args(args, buffer, retval);

    bpf_ringbuf_submit(evt, 0);

    return BPF_OK;
}

char __license[] SEC("license") = "GPL";
