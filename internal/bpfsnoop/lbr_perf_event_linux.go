// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package bpfsnoop

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

func openLbrPerfEvent(cpu int, branchTypes []string) (int, error) {
	var attr unix.PerfEventAttr
	attr.Size = uint32(unsafe.Sizeof(attr))
	attr.Type = unix.PERF_TYPE_HARDWARE
	attr.Config = unix.PERF_COUNT_HW_CPU_CYCLES
	attr.Sample = 4000
	attr.Bits |= unix.PerfBitFreq
	attr.Sample_type = unix.PERF_SAMPLE_BRANCH_STACK
	attr.Branch_sample_type = unix.PERF_SAMPLE_BRANCH_KERNEL

	for _, branchType := range branchTypes {
		switch branchType {
		case "any":
			attr.Branch_sample_type |= unix.PERF_SAMPLE_BRANCH_ANY
			break
		case "any_call":
			attr.Branch_sample_type |= unix.PERF_SAMPLE_BRANCH_ANY_CALL
			break
		case "any_return":
			attr.Branch_sample_type |= unix.PERF_SAMPLE_BRANCH_ANY_RETURN
			break
		case "ind_call":
			attr.Branch_sample_type |= unix.PERF_SAMPLE_BRANCH_IND_CALL
			break
		case "abort_tx":
			attr.Branch_sample_type |= unix.PERF_SAMPLE_BRANCH_ABORT_TX
			break
		case "in_tx":
			attr.Branch_sample_type |= unix.PERF_SAMPLE_BRANCH_IN_TX
			break
		case "no_tx":
			attr.Branch_sample_type |= unix.PERF_SAMPLE_BRANCH_NO_TX
			break
		case "cond":
			attr.Branch_sample_type |= unix.PERF_SAMPLE_BRANCH_COND
			break
		case "call_stack":
			attr.Branch_sample_type |= unix.PERF_SAMPLE_BRANCH_CALL_STACK
			break
		case "ind_jump":
			attr.Branch_sample_type |= unix.PERF_SAMPLE_BRANCH_IND_JUMP
			break
		case "call":
			attr.Branch_sample_type |= unix.PERF_SAMPLE_BRANCH_CALL
			break
		default:
			return -1, fmt.Errorf("unknown branch type: %s", branchType)
		}
	}

	return unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
}
