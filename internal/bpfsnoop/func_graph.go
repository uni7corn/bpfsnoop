// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"context"
	"fmt"
)

var fgraphDenyList = []string{
	"*htab_map_lookup_elem",
	"bpf_ringbuf_reserve",
	"bpf_ringbuf_submit",
	"bpf_ktime_get_ns",
	"bpf_get_smp_processor_id",
	"bpf_probe_read_kernel",
	"bpf_probe_read_kernel_str",
}

type FuncGraph struct {
	Func     string
	IP       uint64
	MaxDepth uint
	Kfunc    *KFunc
	Bprog    *bpfProgFuncInfo
	ArgsEnSz int
	ArgsExSz int
	bytes    uint
}

type FuncGraphs map[uint64]*FuncGraph // key is the func IP

func (fg FuncGraphs) Close() {
	for _, g := range fg {
		if g.Bprog != nil {
			_ = g.Bprog.prog.Close()
		}
	}
}

func FindGraphFuncs(ctx context.Context, flags *Flags, kfuncs KFuncs, bprogs *bpfProgs, ksyms *Kallsyms, maxArgs int) (FuncGraphs, error) {
	var kfs []*KFunc
	for _, kf := range kfuncs {
		if kf.Flag.graph {
			kfs = append(kfs, kf)
		}
	}

	var bps []*bpfTracingInfo
	for _, bp := range bprogs.tracings {
		if bp.flag.graph {
			bps = append(bps, bp)
		}
	}

	if len(kfs) == 0 && len(bps) == 0 {
		return nil, nil
	}

	bprogs, err := NewBPFProgs([]ProgFlag{{all: true}}, false, true)
	if err != nil {
		return FuncGraphs{}, fmt.Errorf("failed to prepare bpf progs: %w", err)
	}
	defer bprogs.Close()

	includes, err := kfuncFlags2matches(flags.fgraphInclude)
	if err != nil {
		return FuncGraphs{}, fmt.Errorf("failed to parse include flags: %w", err)
	}

	excludes, err := kfuncFlags2matches(flags.fgraphExclude)
	if err != nil {
		return FuncGraphs{}, fmt.Errorf("failed to parse exclude flags: %w", err)
	}

	extraKfuncs, err := FindKernelFuncs(flags.fgraphExtra, ksyms, maxArgs)
	if err != nil {
		return FuncGraphs{}, fmt.Errorf("failed to find extra kfuncs: %w", err)
	}

	denyKfuncs, err := FindKernelFuncs(fgraphDenyList, ksyms, maxArgs)
	if err != nil {
		return FuncGraphs{}, fmt.Errorf("failed to find deny kfuncs: %w", err)
	}

	engine, err := createGapstoneEngine()
	if err != nil {
		return FuncGraphs{}, fmt.Errorf("failed to create gapstone engine: %w", err)
	}
	defer engine.Close()

	parser := newFuncGraphParser(ctx, ksyms, bprogs, engine, flags.fgraphDepth, maxArgs, includes, excludes)

	for _, deny := range denyKfuncs {
		addr := deny.Ksym.addr
		if err := parser.add(addr, 0); err != nil {
			return nil, fmt.Errorf("failed to add deny kfunc %s: %w", deny.Ksym.name, err)
		}
	}

	if err := parser.wait(); err != nil {
		return nil, fmt.Errorf("failed to wait for initial parsing: %w", err)
	}

	denylist := parser.graphs

	// renew the parser to avoid reusing the same errgroup
	parser = newFuncGraphParser(ctx, ksyms, bprogs, engine, flags.fgraphDepth, maxArgs, includes, excludes)

	for _, kf := range kfs {
		addr := kf.Ksym.addr
		bytes := guessBytes(uintptr(addr), ksyms, 0)
		parser.addParse(addr, bytes, 0, false, kf.Ksym.name)
	}

	for _, bp := range bps {
		addr := bp.funcIP
		bytes := bp.jitedLen
		parser.addParse(uint64(addr), uint(bytes), 0, true, bp.funcName+"[bpf]")
	}

	for _, kf := range extraKfuncs {
		addr := kf.Ksym.addr
		DebugLog("Adding extra fgraph func %s at %#x", kf.Ksym.name, addr)
		if err := parser.add(addr, 1); err != nil {
			return nil, fmt.Errorf("failed to add extra kfunc %s: %w", kf.Ksym.name, err)
		}
	}

	err = parser.wait()
	if err != nil {
		return nil, fmt.Errorf("failed to parse func graphs: %w", err)
	}

	for ip, graph := range parser.graphs {
		if g, ok := denylist[ip]; ok {
			if g.Bprog != nil {
				_ = g.Bprog.prog.Close() // close the bpf prog if it was denied
			}
			delete(parser.graphs, ip)
			continue
		}

		if graph.Kfunc == nil && graph.Bprog == nil {
			delete(parser.graphs, ip) // remove empty graphs
		}
	}
	return parser.graphs, nil
}
