// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"unsafe"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// immutableTypes is a set of types which musn't be changed.
type immutableTypes struct {
	// All types contained by the spec, not including types from the base in
	// case the spec was parsed from split BTF.
	types []btf.Type

	// Type IDs indexed by type.
	typeIDs map[btf.Type]btf.TypeID

	// The ID of the first type in types.
	firstTypeID btf.TypeID

	// Types indexed by essential name.
	// Includes all struct flavors and types with the same name.
	namedTypes map[string][]btf.TypeID

	// Byte order of the types. This affects things like struct member order
	// when using bitfields.
	byteOrder binary.ByteOrder
}

// mutableTypes is a set of types which may be changed.
type mutableTypes struct {
	imm           immutableTypes
	mu            sync.RWMutex            // protects copies below
	copies        map[btf.Type]btf.Type   // map[orig]copy
	copiedTypeIDs map[btf.Type]btf.TypeID // map[copy]origID
}

// Spec allows querying a set of Types and loading the set into the
// kernel.
type Spec struct {
	*mutableTypes

	// String table from ELF.
	strings uintptr
}

func TestNewCompiler(t *testing.T) {
	const reg = asm.R8

	opts := CompileExprOptions{
		Expr:      "skb->len == 0",
		LabelExit: "__label_exit",
		Spec:      testBtf,
	}

	t.Run("empty expr", func(t *testing.T) {
		_, err := newCompiler(CompileExprOptions{
			Expr:      "",
			LabelExit: "__label_exit",
			Spec:      testBtf,
		})
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "expression and label exit cannot be empty")
	})

	t.Run("empty btf spec", func(t *testing.T) {
		_, err := newCompiler(CompileExprOptions{
			Expr:      "skb->len == 0",
			LabelExit: "__label_exit",
			Spec:      nil,
		})
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "btf spec cannot be empty")
	})

	t.Run("bpf_rdonly_cast not found", func(t *testing.T) {
		_, err := testBtf.AnyTypeByName(kfuncBpfRdonlyCast)
		test.AssertNoErr(t, err)

		spec := (*Spec)(unsafe.Pointer(testBtf))
		ids := spec.mutableTypes.imm.namedTypes[kfuncBpfRdonlyCast]
		delete(spec.mutableTypes.imm.namedTypes, kfuncBpfRdonlyCast)
		defer func() { spec.mutableTypes.imm.namedTypes[kfuncBpfRdonlyCast] = ids }()

		c, err := newCompiler(opts)
		test.AssertNoErr(t, err)
		test.AssertFalse(t, c.rdonlyCastFastcall)
	})

	t.Run("bpf_rdonly_cast invalid type ID", func(t *testing.T) {
		_, err := testBtf.AnyTypeByName(kfuncBpfRdonlyCast)
		test.AssertNoErr(t, err)

		spec := (*Spec)(unsafe.Pointer(testBtf))
		ids := spec.mutableTypes.imm.namedTypes[kfuncBpfRdonlyCast]
		ids = append(ids, 0xFFFFFFFF)
		spec.mutableTypes.imm.namedTypes[kfuncBpfRdonlyCast] = ids
		defer func() { spec.mutableTypes.imm.namedTypes[kfuncBpfRdonlyCast] = ids[:len(ids)-1] }()

		_, err = newCompiler(opts)
		test.AssertHaveErr(t, err)
		test.AssertErrContains(t, err, "no type with ID")
	})

	t.Run("bpf_rdonly_cast not a function", func(t *testing.T) {
		_, err := testBtf.AnyTypeByName(kfuncBpfRdonlyCast)
		test.AssertNoErr(t, err)

		u64 := getU64Btf(t)
		test.AssertNoErr(t, err)
		u64ID, err := testBtf.TypeID(u64)
		test.AssertNoErr(t, err)
		u64Ptr := &btf.Struct{
			Name: "bpf_rdonly_cast",
		}

		spec := (*Spec)(unsafe.Pointer(testBtf))
		ids := spec.mutableTypes.imm.namedTypes[kfuncBpfRdonlyCast]
		spec.mutableTypes.imm.namedTypes[kfuncBpfRdonlyCast] = []btf.TypeID{u64ID}
		spec.mutableTypes.imm.types[u64ID] = u64Ptr
		defer func() {
			spec.mutableTypes.imm.namedTypes[kfuncBpfRdonlyCast] = ids
			spec.mutableTypes.imm.types[u64ID] = u64
		}()

		_, err = newCompiler(opts)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "bpf_rdonly_cast should be a function")
	})

	t.Run("bpf_rdonly_cast type ID not found", func(t *testing.T) {
		rdonlyCast, err := testBtf.AnyTypeByName(kfuncBpfRdonlyCast)
		test.AssertNoErr(t, err)

		spec := (*Spec)(unsafe.Pointer(testBtf))
		id := spec.mutableTypes.copiedTypeIDs[rdonlyCast]
		delete(spec.mutableTypes.copiedTypeIDs, rdonlyCast)
		defer func() { spec.mutableTypes.copiedTypeIDs[rdonlyCast] = id }()

		_, err = newCompiler(opts)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "failed to get type ID for kfunc bpf_rdonly_cast")
		test.AssertTrue(t, errors.Is(err, btf.ErrNotFound))
	})

	c, err := newCompiler(opts)
	test.AssertNoErr(t, err)
	test.AssertFalse(t, c.rdonlyCastFastcall)
}
