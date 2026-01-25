// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"testing"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

func TestExprValueKindString(t *testing.T) {
	tests := []struct {
		kind     exprValueKind
		expected string
	}{
		{exprValueKindConstant, "Constant"},
		{exprValueKindPending, "Pending"},
		{exprValueKindMaterialized, "Materialized"},
		{exprValueKindEnumMaybe, "EnumMaybe"},
		{exprValueKind(999), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			test.AssertEqual(t, tt.kind.String(), tt.expected)
		})
	}
}

func TestExprValueString(t *testing.T) {
	t.Run("Constant", func(t *testing.T) {
		v := newConstant(42)
		test.AssertEqual(t, v.String(), "Constant(42)")
	})

	t.Run("Pending with varIndex", func(t *testing.T) {
		v := newPendingVar(0, &btf.Int{})
		test.AssertStrPrefix(t, v.String(), "Pending(var[0]")
	})

	t.Run("Pending with uptr", func(t *testing.T) {
		v := newPendingUptr(0x1234, &btf.Int{})
		test.AssertStrPrefix(t, v.String(), "Pending(uptr=0x1234")
	})

	t.Run("Pending with reg", func(t *testing.T) {
		v := newPendingReg(asm.R8, &btf.Int{})
		test.AssertStrPrefix(t, v.String(), "Pending(reg=R8")
	})

	t.Run("Materialized", func(t *testing.T) {
		v := newMaterialized(asm.R5, &btf.Int{})
		test.AssertStrPrefix(t, v.String(), "Materialized(R5")
	})

	t.Run("EnumMaybe", func(t *testing.T) {
		v := newEnumMaybe("TEST_ENUM")
		test.AssertEqual(t, v.String(), "EnumMaybe(TEST_ENUM)")
	})

	t.Run("Unknown", func(t *testing.T) {
		v := exprValue{kind: exprValueKind(999)}
		test.AssertEqual(t, v.String(), "Unknown")
	})
}

func TestExprValueStateCheckers(t *testing.T) {
	t.Run("isConstant", func(t *testing.T) {
		v := newConstant(1)
		test.AssertTrue(t, v.isConstant())
		test.AssertFalse(t, v.isPending())
		test.AssertFalse(t, v.isMaterialized())
		test.AssertFalse(t, v.isEnumMaybe())
	})

	t.Run("isPending", func(t *testing.T) {
		v := newPendingVar(0, &btf.Int{})
		test.AssertFalse(t, v.isConstant())
		test.AssertTrue(t, v.isPending())
		test.AssertFalse(t, v.isMaterialized())
		test.AssertFalse(t, v.isEnumMaybe())
	})

	t.Run("isMaterialized", func(t *testing.T) {
		v := newMaterialized(asm.R0, &btf.Int{})
		test.AssertFalse(t, v.isConstant())
		test.AssertFalse(t, v.isPending())
		test.AssertTrue(t, v.isMaterialized())
		test.AssertFalse(t, v.isEnumMaybe())
	})

	t.Run("isEnumMaybe", func(t *testing.T) {
		v := newEnumMaybe("TEST")
		test.AssertFalse(t, v.isConstant())
		test.AssertFalse(t, v.isPending())
		test.AssertFalse(t, v.isMaterialized())
		test.AssertTrue(t, v.isEnumMaybe())
	})
}

func TestExprValueAddOffset(t *testing.T) {
	v := newPendingVar(0, &btf.Pointer{Target: &btf.Int{}})

	test.AssertEqual(t, len(v.offsets), 0)

	v.addOffset(pendingOffset{
		offset: 8,
		deref:  true,
		btf:    &btf.Int{},
	})

	test.AssertEqual(t, len(v.offsets), 1)
	test.AssertEqual(t, v.offsets[0].offset, int64(8))
	test.AssertTrue(t, v.offsets[0].deref)

	v.addOffset(pendingOffset{
		offset: 16,
		deref:  false,
		btf:    &btf.Int{},
	})

	test.AssertEqual(t, len(v.offsets), 2)
	test.AssertEqual(t, v.offsets[1].offset, int64(16))
	test.AssertFalse(t, v.offsets[1].deref)
}

func TestExprValueLastOffset(t *testing.T) {
	t.Run("empty offsets", func(t *testing.T) {
		v := newPendingVar(0, &btf.Int{})
		test.AssertTrue(t, v.lastOffset() == nil)
	})

	t.Run("with offsets", func(t *testing.T) {
		v := newPendingVar(0, &btf.Int{})
		v.addOffset(pendingOffset{offset: 8})
		v.addOffset(pendingOffset{offset: 16})

		last := v.lastOffset()
		test.AssertTrue(t, last != nil)
		test.AssertEqual(t, last.offset, int64(16))
	})
}

func TestExprValuePrevBtf(t *testing.T) {
	t.Run("empty offsets", func(t *testing.T) {
		v := newPendingVar(0, &btf.Int{})
		test.AssertTrue(t, v.prevBtf() == nil)
	})

	t.Run("with offsets", func(t *testing.T) {
		intType := &btf.Int{}
		ptrType := &btf.Pointer{Target: intType}
		v := newPendingVar(0, ptrType)
		v.addOffset(pendingOffset{
			offset:  8,
			prevBtf: ptrType,
			btf:     intType,
		})

		prev := v.prevBtf()
		test.AssertTrue(t, prev != nil)
		// Compare directly since types are btf.Type interface
		if prev != btf.Type(ptrType) {
			t.Errorf("expected prevBtf to be ptrType")
		}
	})
}

func TestNewConstant(t *testing.T) {
	v := newConstant(42)
	test.AssertEqual(t, v.kind, exprValueKindConstant)
	test.AssertEqual(t, v.num, int64(42))
}

func TestNewPendingVar(t *testing.T) {
	intType := &btf.Int{}
	v := newPendingVar(5, intType)
	test.AssertEqual(t, v.kind, exprValueKindPending)
	test.AssertEqual(t, v.varIndex, 5)
	if v.btf != btf.Type(intType) {
		t.Errorf("expected btf to be intType")
	}
}

func TestNewPendingReg(t *testing.T) {
	intType := &btf.Int{}
	v := newPendingReg(asm.R7, intType)
	test.AssertEqual(t, v.kind, exprValueKindPending)
	test.AssertEqual(t, v.varIndex, -1)
	test.AssertEqual(t, v.baseReg, asm.R7)
	if v.btf != btf.Type(intType) {
		t.Errorf("expected btf to be intType")
	}
}

func TestNewPendingUptr(t *testing.T) {
	intType := &btf.Int{}
	v := newPendingUptr(0xDEADBEEF, intType)
	test.AssertEqual(t, v.kind, exprValueKindPending)
	test.AssertEqual(t, v.varIndex, -1)
	test.AssertEqual(t, v.uptr, uint64(0xDEADBEEF))
	if v.btf != btf.Type(intType) {
		t.Errorf("expected btf to be intType")
	}
}

func TestNewMaterialized(t *testing.T) {
	intType := &btf.Int{}
	v := newMaterialized(asm.R3, intType)
	test.AssertEqual(t, v.kind, exprValueKindMaterialized)
	test.AssertEqual(t, v.reg, asm.R3)
	if v.btf != btf.Type(intType) {
		t.Errorf("expected btf to be intType")
	}
}

func TestNewEnumMaybe(t *testing.T) {
	v := newEnumMaybe("BPF_PROG_TYPE_XDP")
	test.AssertEqual(t, v.kind, exprValueKindEnumMaybe)
	test.AssertEqual(t, v.name, "BPF_PROG_TYPE_XDP")
}

func TestAllOffsetsAreAddress(t *testing.T) {
	t.Run("empty offsets", func(t *testing.T) {
		v := newPendingVar(0, &btf.Int{})
		test.AssertTrue(t, v.allOffsetsAreAddress())
	})

	t.Run("all address-only", func(t *testing.T) {
		v := newPendingVar(0, &btf.Int{})
		v.addOffset(pendingOffset{offset: 8, deref: false})
		v.addOffset(pendingOffset{offset: 16, deref: false})
		test.AssertTrue(t, v.allOffsetsAreAddress())
	})

	t.Run("with deref", func(t *testing.T) {
		v := newPendingVar(0, &btf.Int{})
		v.addOffset(pendingOffset{offset: 8, deref: false})
		v.addOffset(pendingOffset{offset: 16, deref: true})
		test.AssertFalse(t, v.allOffsetsAreAddress())
	})

	t.Run("first is deref", func(t *testing.T) {
		v := newPendingVar(0, &btf.Int{})
		v.addOffset(pendingOffset{offset: 8, deref: true})
		v.addOffset(pendingOffset{offset: 16, deref: false})
		test.AssertFalse(t, v.allOffsetsAreAddress())
	})

	t.Run("not pending", func(t *testing.T) {
		// For non-pending (constant), there are no offsets, so vacuously true
		v := newConstant(42)
		test.AssertTrue(t, v.allOffsetsAreAddress())
	})
}

func TestTotalStaticOffset(t *testing.T) {
	t.Run("empty offsets", func(t *testing.T) {
		v := newPendingVar(0, &btf.Int{})
		test.AssertEqual(t, v.totalStaticOffset(), int64(0))
	})

	t.Run("multiple offsets", func(t *testing.T) {
		v := newPendingVar(0, &btf.Int{})
		v.addOffset(pendingOffset{offset: 8})
		v.addOffset(pendingOffset{offset: 16})
		v.addOffset(pendingOffset{offset: -4})
		test.AssertEqual(t, v.totalStaticOffset(), int64(20))
	})

	t.Run("not pending", func(t *testing.T) {
		v := newConstant(42)
		test.AssertEqual(t, v.totalStaticOffset(), int64(0))
	})
}
