// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/exp/maps"
	"golang.org/x/sync/errgroup"

	"github.com/bpfsnoop/bpfsnoop/internal/bpf"
)

type bpfFgraphConfig struct {
	FuncIP    uint64
	MaxDepth  uint32
	Entry     uint32 // 1 for entry, 0 for exit
	MyPID     uint32
	FnArgsNr  uint32
	WithRet   bool
	Pad       [3]uint8
	FnArgsBuf uint32
}

func (t *bpfTracing) traceGraph(spec *ebpf.CollectionSpec,
	reusedMaps map[string]*ebpf.Map, bp *ebpf.Program, params []FuncParamFlags,
	ret FuncParamFlags, traceeName string, graph *FuncGraph, entry bool,
) error {
	tracingProgName := "bpfsnoop_fgraph"
	progSpec := spec.Programs[tracingProgName]
	fnArgsBufSize, err := injectOutputFuncArgs(progSpec, params, ret, !entry)
	if err != nil {
		return fmt.Errorf("failed to inject output func args: %w", err)
	}
	if entry {
		graph.ArgsEnSz = fnArgsBufSize
	} else {
		graph.ArgsExSz = fnArgsBufSize
	}

	var cfg bpfFgraphConfig
	cfg.FuncIP = graph.IP
	cfg.MaxDepth = uint32(graph.MaxDepth)
	cfg.Entry = uint32(b2i(entry))
	cfg.FnArgsNr = uint32(len(params))
	cfg.WithRet = !entry
	cfg.FnArgsBuf = uint32(fnArgsBufSize)
	cfg.MyPID = uint32(os.Getpid())

	if err := spec.Variables["BSN_FGRAPH_CFG"].Set(cfg); err != nil {
		return fmt.Errorf("failed to set bpfsnoop fgraph config: %w", err)
	}

	attachType := ebpf.AttachTraceFExit
	if entry {
		attachType = ebpf.AttachTraceFEntry
	}

	if bp != nil {
		progSpec.AttachTarget = bp
	}
	progSpec.AttachTo = traceeName
	progSpec.AttachType = attachType

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: reusedMaps,
	})
	if err != nil {
		if ignoreFuncTraceVerifierErr(err, traceeName) {
			return nil
		}
		return fmt.Errorf("failed to create bpf collection for tracing graph target '%s': %w", traceeName, err)
	}
	defer coll.Close()

	prog := coll.Programs[tracingProgName]
	delete(coll.Programs, tracingProgName)
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: attachType,
	})
	if err != nil {
		_ = prog.Close()
		if ignoreFuncTraceErr(err, traceeName) {
			return nil
		}
		return fmt.Errorf("failed to attach tracing graph target '%s': %w", traceeName, err)
	}

	verboseLogIf(entry, "Fentry func graph %s at %#x", traceeName, graph.IP)
	verboseLogIf(!entry, "Fexit func graph %s at %#x", traceeName, graph.IP)

	t.llock.Lock()
	t.progs = append(t.progs, prog)
	t.glnks = append(t.glnks, l)
	t.llock.Unlock()

	graph.traced = true
	return nil
}

func (t *bpfTracing) traceGraphFunc(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, graph *FuncGraph, entry bool) error {
	spec = spec.Copy()

	fn := graph.Kfunc
	traceeName := fn.Ksym.name
	err := t.traceGraph(spec, reusedMaps, nil, fn.Prms, fn.Ret, traceeName, graph, entry)
	if err != nil {
		return fmt.Errorf("failed to trace graph func '%s': %w", traceeName, err)
	}

	return nil
}

func (t *bpfTracing) traceGraphProg(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, graph *FuncGraph, entry bool) error {
	spec = spec.Copy()

	gp := graph.Bprog
	traceeName := gp.funcName
	err := t.traceGraph(spec, reusedMaps, gp.prog, gp.funcParams, gp.retParam, traceeName, graph, entry)
	if err != nil {
		return fmt.Errorf("failed to trace graph prog '%s': %w", traceeName, err)
	}

	return nil
}

func (t *bpfTracing) traceGraphs(reusedMaps map[string]*ebpf.Map, graphs FuncGraphs) error {
	if len(graphs) == 0 {
		return nil
	}

	spec, err := bpf.LoadGraph()
	if err != nil {
		return fmt.Errorf("failed to load graph bpf spec: %w", err)
	}

	traceeIPsMapName := "bpfsnoop_fgraph_tracee_ips"
	traceeIPs, err := ebpf.NewMap(spec.Maps[traceeIPsMapName])
	if err != nil {
		return fmt.Errorf("failed to create tracee IPs map: %w", err)
	}
	defer traceeIPs.Close()

	replacedMaps := map[string]*ebpf.Map{
		traceeIPsMapName:    traceeIPs,
		".data.ready":       reusedMaps[".data.ready"],
		"bpfsnoop_events":   reusedMaps["bpfsnoop_events"],
		"bpfsnoop_sessions": reusedMaps["bpfsnoop_sessions"],
	}

	var errg errgroup.Group

	for _, graph := range graphs {
		graph := graph
		if graph.Kfunc != nil {
			errg.Go(func() error {
				return t.traceGraphFunc(spec, replacedMaps, graph, true)
			})
			errg.Go(func() error {
				return t.traceGraphFunc(spec, replacedMaps, graph, false)
			})
		} else {
			errg.Go(func() error {
				return t.traceGraphProg(spec, replacedMaps, graph, true)
			})
			errg.Go(func() error {
				return t.traceGraphProg(spec, replacedMaps, graph, false)
			})
		}
	}

	if err := errg.Wait(); err != nil {
		return fmt.Errorf("failed to trace graph funcs/progs: %w", err)
	}

	if err := t.populateFgraphTraceeIPs(traceeIPs, graphs); err != nil {
		return fmt.Errorf("failed to populate fgraph tracee IPs map: %w", err)
	}

	return nil
}

func (t *bpfTracing) populateFgraphTraceeIPs(ips *ebpf.Map, graphs FuncGraphs) error {
	traceeIPs := make(map[uint64]struct{}, len(graphs))
	for _, graph := range graphs {
		if !graph.traced {
			continue
		}

		var traceeIP uint64
		if graph.Kfunc != nil {
			traceeIP = graph.Kfunc.Ksym.addr
		} else if graph.Bprog != nil {
			traceeIP = uint64(graph.Bprog.kaddrRange.start)
		} else {
			continue
		}

		// Get the IP of calling trampoline.
		traceeIP += insnCallqSize
		if hasEndbr {
			traceeIP += insnEndbrSize
		}
		traceeIPs[traceeIP] = struct{}{}
	}

	// update_batch is supported since kernel 5.6
	// commit aa2e93b ("bpf: Add generic support for update and delete batch ops")

	keys := maps.Keys(traceeIPs)
	vals := make([]uint32, len(keys))
	if _, err := ips.BatchUpdate(keys, vals, nil); err != nil {
		return fmt.Errorf("failed to update fgraph tracee IPs map: %w", err)
	}

	return nil
}
