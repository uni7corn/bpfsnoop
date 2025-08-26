// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
)

func PrepareBPFMaps(spec *ebpf.CollectionSpec) map[string]*ebpf.Map {
	numCPU, err := ebpf.PossibleCPU()
	assert.NoErr(err, "Failed to get possible cpu: %v")

	lbrsMapSpec := spec.Maps[".data.lbrs"]
	lbrsMapSpec.Flags |= unix.BPF_F_MMAPABLE
	lbrsMapSpec.ValueSize = uint32(unsafe.Sizeof(LbrData{})) * uint32(numCPU)
	lbrsMapSpec.Contents[0].Value = make([]byte, lbrsMapSpec.ValueSize)
	lbrsData, err := ebpf.NewMap(lbrsMapSpec)
	assert.NoErr(err, "Failed to create lbrs map: %v")

	lbrs, err := ebpf.NewMap(spec.Maps["bpfsnoop_lbrs"])
	assert.NoErr(err, "Failed to create bpfsnoop_lbrs map: %v")

	maxStack, err := readKernelPerfEventMaxStack()
	assert.NoErr(err, "Failed to read kernel.perf_event_max_stack: %v")

	stacksMapSpec := spec.Maps["bpfsnoop_stacks"]
	stacksMapSpec.ValueSize = uint32(maxStack) * 8
	stacks, err := ebpf.NewMap(stacksMapSpec)
	assert.NoErr(err, "Failed to create bpfsnoop_stacks map: %v")

	sessions, err := ebpf.NewMap(spec.Maps["bpfsnoop_sessions"])
	assert.NoErr(err, "Failed to create bpfsnoop_sessions map: %v")

	readyDataMapSpec := spec.Maps[".data.ready"]
	readyDataMapSpec.Flags |= unix.BPF_F_MMAPABLE
	readyData, err := ebpf.NewMap(readyDataMapSpec)
	assert.NoErr(err, "Failed to create ready data map: %v")

	events, err := ebpf.NewMap(spec.Maps["bpfsnoop_events"])
	assert.NoErr(err, "Failed to create events map: %v")

	return map[string]*ebpf.Map{
		"bpfsnoop_sessions": sessions,

		"bpfsnoop_events": events,
		"bpfsnoop_lbrs":   lbrs,
		".data.lbrs":      lbrsData,
		".data.ready":     readyData,
		"bpfsnoop_stacks": stacks,
	}
}

func CloseBPFMaps(maps map[string]*ebpf.Map) {
	for _, m := range maps {
		_ = m.Close()
	}
}
