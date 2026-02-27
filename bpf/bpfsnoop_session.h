// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2026 Leon Hwang */

#ifndef __BPFSNOOP_SESSION_H_
#define __BPFSNOOP_SESSION_H_

#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"

#include "bpfsnoop_sess.h"
#include "bpfsnoop_tracing.h"

static __always_inline bool
bpfsnoop_session_enter(void *ctx, __u64 pid_tgid, __u64 func_ip, __u64 sid, bool pass,
                       __u64 *session_id, bool is_session)
{
    if (!pass)
        return false;

    if (is_session) {
        __u64 *cookie = bpfsnoop_session_cookie(ctx);
        *cookie = sid;
    } else {
        add_session(pid_tgid, func_ip, sid);
    }

    *session_id = sid;
    return true;
}

static __always_inline bool
bpfsnoop_session_exit(void *ctx, __u64 pid_tgid, __u64 func_ip, __u64 *session_id, bool is_session)
{
    if (is_session) {
        __u64 *cookie = bpfsnoop_session_cookie(ctx);
        __u64 sid = *cookie;

        if (!sid)
            return false;

        *session_id = sid - 1;
    } else {
        __u64 sid = get_and_del_session(pid_tgid, func_ip);

        if (!sid)
            return false;

        *session_id = sid - 1;
    }

    return true;
}

#endif // __BPFSNOOP_SESSION_H_
