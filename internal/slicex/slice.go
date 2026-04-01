// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package slicex

import (
	"cmp"
	"slices"
	"unsafe"
)

func SortCompact[T cmp.Ordered](s []T) []T {
	slices.Sort(s)
	return slices.Compact(s)
}

func UintptrsToU64s(addrs []uintptr) []uint64 {
	data := unsafe.SliceData(addrs)
	return unsafe.Slice((*uint64)(unsafe.Pointer(data)), len(addrs))
}

func U64sToUintptrs(addrs []uint64) []uintptr {
	data := unsafe.SliceData(addrs)
	return unsafe.Slice((*uintptr)(unsafe.Pointer(data)), len(addrs))
}
