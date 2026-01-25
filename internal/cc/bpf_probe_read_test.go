// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"testing"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
	"github.com/cilium/ebpf/asm"
)

func TestEmitProbeRead(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("addr only", func(t *testing.T) {
		defer c.reset()

		offsets := []pendingOffset{
			{offset: 16, deref: true}, // skb->dev
			{offset: 1464},            // skb->dev.dev
			{offset: 0},               // skb->dev.dev.kobj
			{offset: 24},              // dev->dev.dev.kobj.parent
		}

		c.emitProbeRead(offsets, r8)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mov.Reg(r3, r8),
			asm.Add.Imm(r3, 16),
			asm.Mov.Imm(r2, 8),
			asm.Mov.Reg(r1, rfp),
			asm.Add.Imm(r1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(r3, rfp, -8, dword),
			asm.JEq.Imm(r3, 0, c.labelExit),
			asm.Add.Imm(r3, 1464),
			asm.Add.Imm(r3, 24),
			asm.Mov.Reg(r8, r3),
		})
	})

	t.Run("offsets", func(t *testing.T) {
		defer c.reset()

		val := prepareExprVal(t, c, "skb->dev->dev.kobj.parent->name")
		offsets := val.offsets

		c.emitProbeRead(offsets, r8)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mov.Reg(r3, r8),
			asm.Add.Imm(r3, 16),
			asm.Mov.Imm(r2, 8),
			asm.Mov.Reg(r1, rfp),
			asm.Add.Imm(r1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(r3, rfp, -8, dword),
			asm.JEq.Imm(r3, 0, c.labelExit),
			asm.Add.Imm(r3, 1488),
			asm.Mov.Imm(r2, 8),
			asm.Mov.Reg(r1, rfp),
			asm.Add.Imm(r1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(r3, rfp, -8, dword),
			asm.JEq.Imm(r3, 0, c.labelExit),
			asm.Mov.Imm(r2, 8),
			asm.Mov.Reg(r1, rfp),
			asm.Add.Imm(r1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(r8, rfp, -8, dword),
		})
	})
}
