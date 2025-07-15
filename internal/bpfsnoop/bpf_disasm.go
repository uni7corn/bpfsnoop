// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"

	"github.com/bpfsnoop/gapstone"
)

func disasmKfuncAt(kaddr uint64, bytes uint, ksyms *Kallsyms, engine *gapstone.Engine) ([]gapstone.Instruction, error) {
	bytes = guessBytes(uintptr(kaddr), ksyms, bytes)
	data, err := readKernel(kaddr, uint32(bytes))
	if err != nil {
		return nil, fmt.Errorf("failed to read %d bytes kernel memory from %#x: %w", bytes, kaddr, err)
	}

	data = trimTailingInsns(data)
	insns, err := engine.Disasm(data, kaddr, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to disassemble insns: %w", err)
	}

	return insns, nil
}
