// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import "github.com/cilium/ebpf/asm"

// emitDirectRead emits offset chain using direct memory access.
func (c *compiler) emitDirectRead(offsets []pendingOffset, reg asm.Register) {
	lastIdx := len(offsets) - 1
	for i, offset := range offsets {
		if !offset.deref {
			// Address-only
			if offset.offset != 0 {
				c.emit(asm.Add.Imm(reg, int32(offset.offset)))
			}
		} else {
			// Dereference
			c.emit(
				asm.LoadMem(reg, reg, int16(offset.offset), asm.DWord),
			)
			if i != lastIdx {
				c.labelExitUsed = true
				c.emit(
					asm.JEq.Imm(reg, 0, c.labelExit),
				)
			}
		}
	}
}
