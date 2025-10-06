// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#ifndef __BPFSNOOP_STACK_H_
#define __BPFSNOOP_STACK_H_

#include "vmlinux.h"
#include "bpf_helpers.h"

/* Stack layout on x86:
 * +-----+ FP of tracee's caller
 * | ... |
 * | rip | IP of tracee's caller
 * | rip | IP of tracee
 * | rbp | FP of tracee's caller
 * +-----+ FP of trampoline
 * | ret | retval on stack
 * | arg | args[...]
 * +-----+ ctx of current prog
 * | ... |
 * | rip | IP of trampoline
 * | rbp | FP of trampoline
 * +-----+ FP of current prog
 * | ... |
 * +-----+ SP of current prog
 *
 * Stack layout on arm64:
 * |  r9  |
 * |  fp  | FP of tracee's caller
 * |  lr  | IP of tracee
 * |  fp  | FP of tracee
 * +------+ FP of trampoline  <-------+
 * |  ..  | padding                   |
 * |  ..  | callee saved regs         |
 * | retv | retval of tracee          |
 * | regs | regs of tracee            |
 * | nreg | number of regs            |
 * |  ip  | IP of tracee if needed    | possible range of
 * | rctx | bpf_tramp_run_ctx         | detection
 * |  lr  | IP of trampoline          |
 * |  fp  | FP of trampoline  <--------- detect it
 * +------+ FP of current prog        |
 * | regs | callee saved regs         |
 * +------+ R10 of bpf prog   <-------+
 * |  ..  |
 * +------+ SP of current prog
 */

static __always_inline u64
get_tracing_fp(void)
{
	u64 fp;

	/* get frame pointer */
	asm volatile ("%[fp] = r10" : [fp] "+r"(fp) :);
	return fp;
}

static __always_inline u64
__get_ptr(void *ctx, __u32 args_nr, bool retval)
{
	int offset;

	offset = (args_nr & 0xF) * 8; /* each arg is 8 bytes */
	offset += retval ? 8 : 0; /* retval */
	return (__u64) ctx + offset;
}

#if defined(bpf_target_x86)
static __always_inline u64
get_tramp_fp(void *ctx, __u32 args_nr, bool retval)
{
	return __get_ptr(ctx, args_nr, retval);
}

#elif defined(bpf_target_arm64)

/* This offset is different for each tracee because of the number of tracee's
 * arguments.
 */
u32 tramp_fp_offset;

/* As R10 of bpf is not A64_FP, we need to detect the FP of trampoline
 * by scanning the stacks of current bpf prog and the trampoline.
 *
 * Since commit 5d4fa9ec5643 ("bpf, arm64: Avoid blindly saving/restoring all callee-saved registers"),
 * the number of callee-saved registers saved in the bpf prog prologue is
 * dynamic, not fixed anymore.
 */
static __always_inline u64
detect_tramp_fp_offset(u64 r10)
{
	static const int range_of_detection = 256;
	u64 fp;

	for (int i = 6; i >= 0; i--) {
		bpf_probe_read_kernel(&fp, sizeof(fp), (void *) (r10 + i * 16));
		if (r10 < fp && fp < r10 + range_of_detection) {
			tramp_fp_offset = i * 16;
			return fp;
		}
	}

	return r10;
}

static __always_inline u64
get_tramp_fp(void *ctx, __u32 args_nr, bool retval)
{
	u64 fp = get_tracing_fp();

	if (tramp_fp_offset) {
		(void) bpf_probe_read_kernel(&fp, sizeof(fp), (void *) (fp + tramp_fp_offset));
		return fp;
	}

	fp = detect_tramp_fp_offset(fp);
	return fp;
}
#else
# error "Unsupported architecture for bpfsnoop"
#endif

#endif // __BPFSNOOP_STACK_H_
