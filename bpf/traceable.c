// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#define ADDR_CAP 1024

volatile const u64 addrs[ADDR_CAP];
volatile const u32 nr_addrs SEC(".rodata.nr_addrs");
volatile const u32 has_endbr SEC(".rodata.endbr") = 0;
volatile const u32 tramp_jmp;
u64 tramps[ADDR_CAP] SEC(".data.tramps");
bool traceables[ADDR_CAP];
bool run SEC(".data.run");

static __noinline void
probe_addr_info(int i)
{
    u64 addr = addrs[i];
    u8 buff[16], *ptr;
    bool traceable;

    if (bpf_probe_read_kernel(&buff, 16, (void *) addr))
        return;

#if defined(bpf_target_x86)
    static const u64 nop5 = 0x0000441F0F;
    u64 a, b;

    ptr = has_endbr ? buff + 4 : buff;
    if (tramp_jmp && ptr[0] == 0xE9 /* jmp */)
        tramps[i] = addr + (has_endbr ? 4 : 0) + 5 + (__s32) (((*(u64 *) ptr) >> 8) & 0xFFFFFFFF);
    /* Avoid 'misaligned stack access off 0+-12+0 size 8' */
    a = *(u32 *) ptr;
    b = *(u8 *) (ptr + 4);
    traceable = (b<<32 | a) == nop5 /* nop5 */ || ptr[0] == 0xE8 /* callq */ ||
           /* 373f2f44c300 ("bpf,x86: adjust the "jmp" mode for bpf trampoline")
            * since 6.19 kernel.
            */
           ptr[0] == 0xE9 /* jmp */;

#elif defined(bpf_target_arm64)
    ptr = buff + 4;
    u32 insn = *(u32 *) ptr;

    traceable = insn == 0xD503201F /* nop */ || ptr[3] == 0x97 /* bl */ ||
           ptr[3] == 0x94 /* blr */;

#else
# error "Unsupported architecture"
#endif

    traceables[i] = traceable;
}

SEC("fentry/__x64_sys_nanosleep")
int BPF_PROG(detect, struct pt_regs *regs)
{
    if (run)
        return BPF_OK;
    run = true;

    for (int i = 0; i < ADDR_CAP; i++) {
        if (i >= nr_addrs)
            break;
        probe_addr_info(i);
    }

    return BPF_OK;
}

char __license[] SEC("license") = "GPL";
