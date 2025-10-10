// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#ifndef __BPFSNOOP_PKT_H_
#define __BPFSNOOP_PKT_H_

#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_endian.h"

#include "if_ether.h"

#define VXLAN_PORT      4789
/* ETH(14) + IP(20) + UDP(8) + VXLAN(8) */
#define VXLAN_HDR_LEN   50

volatile const u32 SKIP_TUNNEL;

static __always_inline bool
is_ip_vxlan_pkt(void *data)
{
    struct udphdr *udp;
    struct iphdr *ip;
    u8 b;

    ip = (typeof(ip)) data;
    if (BPF_CORE_READ(ip, protocol) != IPPROTO_UDP)
        return false;

    bpf_probe_read_kernel(&b, sizeof(b), ip);
    udp = (typeof(udp)) ((void *) ip + ((b & 0xF) << 2));
    return BPF_CORE_READ(udp, dest) == bpf_htons(VXLAN_PORT);
}

static __always_inline bool
is_vxlan_pkt(void *data)
{
    struct ethhdr *eth = (typeof(eth)) data;

    if (BPF_CORE_READ(eth, h_proto) != bpf_htons(ETH_P_IP))
        return false;

    return is_ip_vxlan_pkt((void *) (eth + 1));
}

static __always_inline void *
__skip_tunnel(void *data, bool iphdr)
{
    if (!SKIP_TUNNEL)
        return data;

    if (iphdr && is_ip_vxlan_pkt(data))
        return data + VXLAN_HDR_LEN;

    if (!iphdr && is_vxlan_pkt(data))
        return data + VXLAN_HDR_LEN;

    return data;
}

static __always_inline void *
skip_tunnel(void *data)
{
    return __skip_tunnel(data, false);
}

static __always_inline void *
skip_tunnel_iph(void *iph)
{
    return __skip_tunnel(iph, true);
}

#endif // __BPFSNOOP_PKT_H_
