// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#ifndef __BPFSNOOP_SESS_H_
#define __BPFSNOOP_SESS_H_

#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_map_helpers.h"

#include "bpfsnoop.h"

#define MAX_RECUR_DEPTH 64
#define MASK_RECUR_DEPTH (MAX_RECUR_DEPTH-1)

struct bpfsnoop_sess_key {
    __u64 pid_tgid;
    __u64 func_ip;
};

struct bpfsnoop_sess {
    __u32 depth;
    __u64 session_ids[MAX_RECUR_DEPTH];
};

#define SESS_ID(s, d) (s->session_ids[d&MASK_RECUR_DEPTH])

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct bpfsnoop_sess);
} bpfsnoop_session_buff SEC(".maps");

static __always_inline struct bpfsnoop_sess *
__get_sess_buff(void)
{
    __u32 key = 0;

    return bpf_map_lookup_elem(&bpfsnoop_session_buff, &key);
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BPFSNOOP_MAX_ENTRIES);
    __type(key, struct bpfsnoop_sess_key);
    __type(value, struct bpfsnoop_sess);
} bpfsnoop_sessions SEC(".maps");

static __always_inline void
add_session(__u64 pid_tgid, __u64 func_ip, __u64 session_id)
{
    struct bpfsnoop_sess *init, *sess;
    struct bpfsnoop_sess_key key;

    key.pid_tgid = pid_tgid;
    key.func_ip = func_ip;
    sess = bpf_map_lookup_elem(&bpfsnoop_sessions, &key);
    if (sess) {
        sess->depth++;
        SESS_ID(sess, sess->depth) = session_id;
    } else {
        init = __get_sess_buff();
        if (init) {
            init->depth = 0;
            SESS_ID(init, 0) = session_id;
            (void) bpf_map_update_elem(&bpfsnoop_sessions, &key, init, BPF_ANY);
        }
    }
}

static __always_inline __u64
get_session(__u64 pid_tgid, __u64 func_ip)
{
    struct bpfsnoop_sess_key key;
    struct bpfsnoop_sess *sess;

    key.pid_tgid = pid_tgid;
    key.func_ip = func_ip;
    sess = (typeof(sess)) bpf_map_lookup_elem(&bpfsnoop_sessions, &key);
    return sess ? SESS_ID(sess, sess->depth) : 0;
}

static __always_inline __u64
get_and_del_session(__u64 pid_tgid, __u64 func_ip)
{
    struct bpfsnoop_sess_key key;
    struct bpfsnoop_sess *sess;
    __u64 session_id = 0;

    key.pid_tgid = pid_tgid;
    key.func_ip = func_ip;
    sess = (typeof(sess)) bpf_map_lookup_elem(&bpfsnoop_sessions, &key);
    if (sess) {
        session_id = SESS_ID(sess, sess->depth);
        if (sess->depth)
            sess->depth--;
        else
            (void) bpf_map_delete_elem(&bpfsnoop_sessions, &key);
    }

    return session_id;
}

#endif // __BPFSNOOP_SESS_H_
