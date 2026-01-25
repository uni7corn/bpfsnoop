// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"fmt"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

func canRdonlyCast(spec btfSpecer, t btf.Type) (bool, btf.TypeID, error) {
	t = mybtf.UnderlyingType(t)
	ptr, ok := t.(*btf.Pointer)
	if !ok {
		return false, 0, nil
	}

	t = mybtf.UnderlyingType(ptr.Target)
	_, isStruct := t.(*btf.Struct)
	_, isUnion := t.(*btf.Union)
	if !isStruct && !isUnion {
		return false, 0, nil
	}

	typID, err := getPointerTypeID(spec, t, isStruct, isUnion)
	return err == nil, typID, err
}

func canReadByRdonlyCast(t btf.Type) bool {
	switch mybtf.UnderlyingType(t).(type) {
	case *btf.Pointer, *btf.Int, *btf.Enum:
		return true
	default:
		return false
	}
}

func bpfKfuncCall(id btf.TypeID) asm.Instruction {
	return asm.Instruction{
		OpCode:   asm.Call.Op(asm.ImmSource),
		Src:      asm.PseudoKfuncCall,
		Constant: int64(id),
	}
}

func (c *compiler) coreReadByProbeRead(reg asm.Register, lastIdx bool) {
	immReg := asm.R1
	resReg := immReg
	if lastIdx && reg != immReg {
		resReg = reg
	}
	c.emit(
		asm.Mov.Reg(asm.R3, immReg),  // r3 = r1
		asm.Mov.Imm(asm.R2, 8),       // r2 = 8
		asm.Mov.Reg(asm.R1, asm.RFP), // r1 = rfp
		asm.Add.Imm(asm.R1, -8),      // r1 -= 8
		asm.FnProbeReadKernel.Call(),
		asm.LoadMem(resReg, asm.RFP, -8, asm.DWord), // immReg = *(u64 *)(rfp - 8)
	)
}

// emitCoreRead emits offset chain using CO-RE (bpf_rdonly_cast).
func (c *compiler) emitCoreRead(offsets []pendingOffset, reg asm.Register) error {
	regsNr := 5
	if c.rdonlyCastFastcall {
		regsNr = 2
	}
	c.pushUsedCallerSavedRegsN(regsNr)
	defer c.popUsedCallerSavedRegsN(regsNr)

	immReg := asm.R1
	if reg != immReg {
		c.emit(asm.Mov.Reg(immReg, reg))
	}

	lastIdx := len(offsets) - 1
	for i, offset := range offsets {
		if !offset.deref {
			// Address-only
			if offset.offset != 0 {
				c.emit(asm.Add.Imm(immReg, int32(offset.offset)))
			}
			if i == lastIdx && reg != immReg {
				c.emit(asm.Mov.Reg(reg, immReg))
			}
			continue
		}

		canCast, typID, err := canRdonlyCast(c.btfSpec, offset.prevBtf)
		if err != nil {
			return fmt.Errorf("failed to check if %v can be bpf_rdonly_cast: %w", offset.prevBtf, err)
		}
		if !canCast {
			c.coreReadByProbeRead(reg, i == lastIdx)
			continue
		}

		size, err := sizeof(offset.btf)
		if err != nil {
			return fmt.Errorf("failed to get size of %v: %w", offset.btf, err)
		}

		if !canReadByRdonlyCast(offset.btf) {
			c.coreReadByProbeRead(reg, i == lastIdx)
			continue
		}

		// bpf_rdonly_cast(r1, btf_id)
		c.emit(asm.Mov.Imm(asm.R2, int32(typID)))
		c.emit(bpfKfuncCall(c.rdonlyCastTypeID))
		// r0 is the result of bpf_rdonly_cast

		if i != lastIdx {
			c.labelExitUsed = true
			c.emit(asm.LoadMem(immReg, asm.R0, int16(offset.offset), size))
			c.emit(asm.JEq.Imm(immReg, 0, c.labelExit))
		} else if reg != immReg {
			c.emit(asm.LoadMem(reg, asm.R0, int16(offset.offset), size))
		}
	}

	return nil
}
