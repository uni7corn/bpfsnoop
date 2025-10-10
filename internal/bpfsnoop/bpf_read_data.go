// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/fatih/color"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
	"github.com/bpfsnoop/bpfsnoop/internal/bpf"
	"github.com/bpfsnoop/bpfsnoop/internal/cc"
)

const (
	stubReadData = "read_stub"
)

func readKernelData(expr string, helpers *Helpers) error {
	var arg funcArgumentOutput
	arg.expr = expr

	err := PrepareKernelBTF()
	assert.NoErr(err, "Failed to prepare kernel BTF: %v", err)
	krnl := getKernelBTF()

	readSize, err := arg.compile(nil, krnl, krnl, 0, int(cc.MemoryReadFlagForce), "__read_data_fail")
	if err != nil {
		return fmt.Errorf("Failed to compile expression %q: %w", expr, err)
	}

	var insns asm.Instructions
	insns = append(insns,
		asm.Mov.Reg(outputArgRegBuff, asm.R1), // buff = R1
	)
	insns = append(insns, arg.insn...)
	insns = append(insns,
		asm.Return(),
	)

	spec, err := bpf.LoadRead()
	if err != nil {
		return fmt.Errorf("failed to load read bpf spec: %w", err)
	}
	delete(spec.Programs, "read") // not used here

	size := (uint32(readSize) + 7) & (^uint32(7)) // round up to 8-times bytes
	buff := make([]byte, size)
	spec.Maps[".data.buff"].ValueSize = size
	spec.Maps[".data.buff"].Contents[0].Value = buff

	progSpec := spec.Programs["read_data"]
	injectInsns(progSpec, stubReadData, insns)

	progSpec.AttachTo = sysNanosleepSymbol
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create collection: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs["read_data"]
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		return fmt.Errorf("failed to fentry nanosleep: %w", err)
	}
	defer l.Close()

	nanosleep()

	var run bool
	if err := coll.Variables["run"].Get(&run); err != nil {
		return fmt.Errorf("failed to get run: %w", err)
	}
	if !run {
		return errors.New("reading kernel was not triggered")
	}

	if err := coll.Maps[".data.buff"].Lookup(uint32(0), buff); err != nil {
		return fmt.Errorf("failed to lookup .data.buff: %w", err)
	}

	var sb strings.Builder
	f := findSymbolHelper(0, helpers)
	err = __outputFuncArgAttrs(&sb, []funcArgumentOutput{arg}, buff, f)
	if err != nil {
		return fmt.Errorf("failed to output function arg attrs: %w", err)
	}

	fmt.Print("Expr: ")
	if colorfulOutput {
		color.New(color.FgGreen).Printf("%s\n", expr)
	} else {
		fmt.Printf("%s\n", expr)
	}
	fmt.Printf("Out: %s\n", sb.String())

	return nil
}

func readKernelDatum(exprs []string) {
	ksyms, err := NewKallsyms()
	assert.NoErr(err, "Failed to read kallsyms: %v")

	progs, err := NewBPFProgs([]ProgFlag{{all: true}}, false, false)
	assert.NoErr(err, "Failed to prepare BPF programs: %v")

	var helpers Helpers
	helpers.Ksyms = ksyms
	helpers.Progs = progs

	for i, expr := range exprs {
		if i != 0 {
			fmt.Printf("\n---\n")
		}

		err := readKernelData(expr, &helpers)
		assert.NoVerifierErr(err, "Failed to read kernel data for expr %q: %v", expr)
	}
}
