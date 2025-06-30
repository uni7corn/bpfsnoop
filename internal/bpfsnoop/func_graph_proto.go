// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/bpfsnoop/gapstone"
	"github.com/cilium/ebpf/btf"
	"github.com/fatih/color"
	"golang.org/x/exp/maps"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
)

type fgraphCallee struct {
	ip    uint64
	name  string
	proto string
	bytes uint
}

type fgraphProto struct {
	ksyms *Kallsyms
	progs *bpfProgs

	engine *gapstone.Engine // disassembler engine

	maxDepth uint

	ips     map[uint64]string
	callees map[uint64][]fgraphCallee
}

func (p *fgraphProto) printDepth(depth uint) {
	color.RGB(58, 64, 94 /* lighter gray */).Fprint(os.Stdout, strings.Repeat("..", int(depth)))
}

func (p *fgraphProto) print(fn string, depth uint) {
	p.printDepth(depth)
	fmt.Print(fn)
}

func (p *fgraphProto) getFuncProto(fn *btf.Func) string {
	var sb strings.Builder
	printFuncProto(&sb, fn, color.New(color.FgYellow), false)
	return sb.String()
}

func (p *fgraphProto) findBtfFunc(name string) *btf.Func {
	var bfunc *btf.Func

	err := iterateKernelBtfs(true, nil, func(s *btf.Spec) bool {
		if bfunc != nil {
			return true
		}

		typ, err := s.AnyTypeByName(name)
		if errors.Is(err, btf.ErrNotFound) {
			return false
		}
		assert.NoErr(err, "Failed to find type %q in btf spec: %v", name)

		fn, ok := typ.(*btf.Func)
		assert.True(ok, "Type %q is not a function type", name)
		bfunc = fn

		return false
	})

	assert.NoErr(err, "Failed to iterate kernel BTFs: %v")

	return bfunc
}

func (p *fgraphProto) getCallee(ctx context.Context, ip uint64) (fgraphCallee, bool) {
	var callee fgraphCallee

	callee.ip = ip

	if prog, ok := p.progs.funcs[uintptr(ip)]; ok {
		if s, ok := p.ips[ip]; ok {
			callee.proto = s
		} else {
			s := p.getFuncProto(prog.funcProto)
			callee.proto = s
			p.ips[ip] = s
		}

		callee.name = prog.funcName
		callee.bytes = uint(prog.kaddrRange.end - prog.kaddrRange.start)
		return callee, true
	}

	if ksym, ok := p.ksyms.a2s[ip]; ok {
		callee.name = ksym.name
		callee.bytes = guessBytes(uintptr(ip), p.ksyms, 0)

		fn := p.findBtfFunc(ksym.name)
		if fn == nil {
			callee.proto = ksym.name + "\n"
			return callee, true
		}

		if s, ok := p.ips[ip]; ok {
			callee.proto = s
		} else {
			s := p.getFuncProto(fn)
			callee.proto = s
			p.ips[ip] = s
		}

		return callee, true
	}

	return callee, false
}

func (p *fgraphProto) parse(ctx context.Context, ip uint64, bytes, depth uint) {
	if depth > p.maxDepth {
		return
	}

	select {
	case <-ctx.Done():
		return
	default:
	}

	callees, ok := p.callees[ip]

	if !ok {
		data, err := readKernel(ip, uint32(bytes))
		assert.NoErr(err, "Failed to read kernel memory at %x: %v", ip, err)

		data = trimTailingInsns(data)

		insts, err := p.engine.Disasm(data, ip, 0)
		for _, inst := range insts {
			if len(inst.Bytes) != 5 || inst.Bytes[0] != 0xe8 {
				// TODO: long jump instructions (0xe9)
				continue // Only handle call instructions (5 bytes, 0xe8).
			}

			calleeIP := getCalleeIP(uint64(inst.Address), ne.Uint32(inst.Bytes[1:5]))
			callee, ok := p.getCallee(ctx, calleeIP)
			if ok {
				callees = append(callees, callee)
			}
		}

		p.callees[ip] = callees
	}

	for _, callee := range callees {
		p.print(callee.proto, depth)
		p.parse(ctx, callee.ip, callee.bytes, depth+1)
	}
}

func ShowFuncGraphProto(flags *Flags) {
	ksyms, err := NewKallsyms()
	assert.NoErr(err, "Failed to create kallsyms: %v")

	pflags, err := flags.ParseProgs()
	assert.NoErr(err, "Failed to parse bpf prog flags: %v")

	progs, err := NewBPFProgs(pflags, true, true)
	assert.NoErr(err, "Failed to find bpf progs: %v")
	bps := progs.tracings

	kfs, err := FindKernelFuncs(flags.kfuncs, ksyms, MAX_BPF_FUNC_ARGS)
	assert.NoErr(err, "Failed to find kfuncs: %v")

	if len(kfs) == 0 && len(bps) == 0 {
		log.Print("Not found any kfuncs/progs")
		return
	}

	bprogs, err := NewBPFProgs([]ProgFlag{{all: true}}, false, true)
	assert.NoErr(err, "Failed to prepare bpf progs: %v")
	defer bprogs.Close()

	engine, err := createGapstoneEngine()
	assert.NoErr(err, "Failed to create gapstone engine: %v")
	defer engine.Close()

	var fp fgraphProto
	fp.ksyms = ksyms
	fp.progs = bprogs
	fp.engine = engine
	fp.maxDepth = flags.fgraphDepth
	fp.ips = make(map[uint64]string, 64)
	fp.callees = make(map[uint64][]fgraphCallee, 64)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	printNewline := false
	if len(kfs) > 0 {
		kfuncs := maps.Values(kfs)
		sort.Slice(kfuncs, func(i, j int) bool {
			return kfuncs[i].Ksym.name < kfuncs[j].Ksym.name
		})

		for _, kf := range kfuncs {
			bfunc := fp.findBtfFunc(kf.Ksym.name)
			assert.NotNil(bfunc, "Failed to find btf func for %s", kf.Ksym.name)
			fp.print(fp.getFuncProto(bfunc), 0)

			addr := kf.Ksym.addr
			bytes := guessBytes(uintptr(addr), ksyms, 0)
			fp.parse(ctx, addr, bytes, 1)

			printNewline = true
			fmt.Println()
		}
	}

	if len(bps) > 0 {
		if printNewline {
			fmt.Println()
		}

		progs := maps.Values(bps)
		sort.Slice(progs, func(i, j int) bool {
			return progs[i].funcName < progs[j].funcName
		})

		for _, bp := range progs {
			fp.print(fp.getFuncProto(bp.fn), 0)

			addr := bp.funcIP
			bytes := bp.jitedLen
			fp.parse(ctx, uint64(addr), uint(bytes), 1)

			fmt.Println()
		}
	}
}
