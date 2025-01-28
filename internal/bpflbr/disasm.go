// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

import (
	"debug/elf"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/Asphaltt/bpflbr/internal/assert"
	"github.com/knightsc/gapstone"
)

const (
	kcorePath = "/proc/kcore"
)

func Disasm(f *Flags) {
	assert.False(len(f.progs) != 0 && len(f.kfuncs) != 0, "progs %v or kfuncs %v to be disassembled?", f.progs, f.kfuncs)

	if len(f.progs) != 0 {
		progs, err := f.ParseProgs()
		assert.NoErr(err, "Failed to parse bpf prog infos: %v")

		assert.SliceLen(progs, 1, "Only one --prog is allowed for --disasm")
		DumpProg(progs)
		return
	}

	if len(f.kfuncs) != 0 {
		assert.SliceLen(f.kfuncs, 1, "Only one --kfunc is allowed for --disasm")

		dumpKfunc(f.kfuncs[0], f.disasmBytes)
		return
	}
}

func readKcore(kaddr uint64, bytes uint) ([]byte, bool) {
	fd, err := os.Open(kcorePath)
	assert.NoErr(err, "Failed to open %s: %v", kcorePath)
	defer fd.Close()

	kcoreElf, err := elf.NewFile(fd)
	assert.NoErr(err, "Failed to read %s: %v", kcorePath)

	for _, prog := range kcoreElf.Progs {
		if prog.Vaddr <= kaddr && kaddr < prog.Vaddr+prog.Memsz {
			remain := uint(prog.Memsz + prog.Vaddr - kaddr)
			data := make([]byte, min(bytes, remain))
			n, err := fd.ReadAt(data, int64(prog.Off+kaddr-prog.Vaddr))
			assert.NoErr(err, "Failed to read %s: %v", kcorePath)
			return data[:n], true
		}
	}

	return nil, false
}

func guessBytes(kaddr uintptr, ks *Kallsyms, bytes uint) uint {
	if bytes != 0 {
		return bytes
	}

	nxt, ok := ks.next(kaddr)
	if !ok {
		return 4096 // limit to 4KiB
	}

	return uint(nxt.addr) - uint(kaddr)
}

func trimTailingInsns(b []byte) []byte {
	skipInsns := map[byte]struct{}{
		0xcc: {}, // int3
		0x90: {}, // nop
	}

	i := len(b) - 1
	for ; i >= 0; i-- {
		if _, ok := skipInsns[b[i]]; !ok {
			break
		}
	}
	return b[:i+1]
}

func dumpKfunc(kfunc string, bytes uint) {
	assert.True(runtime.GOARCH == "amd64", "Only support amd64 arch")

	VerboseLog("Reading /proc/kallsyms ..")
	kallsyms, err := NewKallsyms()
	assert.NoErr(err, "Failed to read /proc/kallsyms: %v")

	var kaddr uint64
	if !strings.HasPrefix(kfunc, "0x") {
		kaddr, err = strconv.ParseUint("0x"+kfunc, 0, 64)
	} else {
		kaddr, err = strconv.ParseUint(kfunc, 0, 64)
	}
	if err != nil {
		// kfunc may be a symbol name
		entry, ok := kallsyms.findBySymbol(kfunc)
		assert.True(ok, "Symbol %s not found in /proc/kallsyms", kfunc)

		kaddr = entry.addr
		kfunc = entry.name
	} else {
		entry, ok := kallsyms.find(uintptr(kaddr))
		assert.True(ok, "Address %#x not found in /proc/kallsyms", kaddr)

		kfunc = entry.name
	}

	bytes = guessBytes(uintptr(kaddr), kallsyms, bytes)
	data, ok := readKcore(kaddr, bytes)
	assert.True(ok, "Failed to read kcore for %s", kfunc)
	data = trimTailingInsns(data)
	log.Printf("Disassembling %s at %#x (%d bytes) ..", kfunc, kaddr, len(data))

	var addr2line *Addr2Line

	vmlinux, err := FindVmlinux()
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			VerboseLog("Dbgsym vmlinux not found")
		} else {
			assert.NoErr(err, "Failed to find vmlinux: %v")
		}
	}
	if err == nil {
		VerboseLog("Found vmlinux: %s", vmlinux)

		textAddr, err := ReadTextAddrFromVmlinux(vmlinux)
		assert.NoErr(err, "Failed to read .text address from vmlinux: %v")

		VerboseLog("Creating addr2line from vmlinux ..")
		kaslr := NewKaslr(kallsyms.Stext(), textAddr)
		addr2line, err = NewAddr2Line(vmlinux, kaslr, kallsyms.SysBPF())
		assert.NoErr(err, "Failed to create addr2line: %v")
	}

	engine, err := gapstone.New(int(gapstone.CS_ARCH_X86), int(gapstone.CS_MODE_64))
	assert.NoErr(err, "Failed to create engine: %v")
	defer engine.Close()

	if !disasmIntelSyntax {
		err = engine.SetOption(uint(gapstone.CS_OPT_SYNTAX), uint(gapstone.CS_OPT_SYNTAX_ATT))
		assert.NoErr(err, "Failed to set syntax: %v")
	}

	VerboseLog("Disassembling bpf progs ..")
	bpfProgs, err := NewBPFProgs(engine, nil, false)
	assert.NoErr(err, "Failed to get bpf progs: %v")
	defer bpfProgs.Close()

	var sb strings.Builder

	li := getLineInfo(uintptr(kaddr), bpfProgs, addr2line, kallsyms)
	fmt.Fprintf(&sb, "; %s+%#x", li.funcName, li.offset)
	if li.fileName != "" {
		fmt.Fprintf(&sb, " %s:%d", li.fileName, li.fileLine)
	}
	if li.isInline {
		fmt.Fprintf(&sb, " [inline]")
	}
	if li.isProg {
		fmt.Fprintf(&sb, " [bpf]")
	}
	fmt.Fprintln(&sb)

	prev := li

	b, pc := data[:], uint64(kaddr)
	for len(b) != 0 {
		insts, err := engine.Disasm(b, pc, 1)
		if err != nil && len(b) <= 10 {
			break
		}
		if err != nil {
			fmt.Print(sb.String())
			if errors.Is(err, gapstone.ErrOK) {
				log.Printf("Finish disassembling early, %d bytes left", len(b))
				log.Fatalf(`Please try: gdb -q -c /proc/kcore -ex 'disas/r %#v,+%d' -ex 'quit'`, pc, len(b))
			}
			assert.NoErr(err, "Failed to disasm: %v")
		}

		li := getLineInfo(uintptr(pc), bpfProgs, addr2line, kallsyms)
		if (li.fromVmlinux || li.isProg) && (prev.fileName != li.fileName || prev.fileLine != li.fileLine) {
			fmt.Fprintf(&sb, "; %s+%#x", li.funcName, li.offset)
			if li.fileName != "" {
				fmt.Fprintf(&sb, " %s:%d", li.fileName, li.fileLine)
			}
			if li.isProg {
				fmt.Fprintf(&sb, " [bpf]")
			}
			fmt.Fprintln(&sb)

			prev = li
		}

		inst := insts[0]

		var opcodes []string
		for _, insn := range inst.Bytes {
			opcodes = append(opcodes, fmt.Sprintf("%02x", insn))
		}
		opcode := strings.Join(opcodes, " ")
		opstr := inst.OpStr
		fmt.Fprintf(&sb, "%#x: %-19s\t%s\t%s", pc, opcode, inst.Mnemonic, opstr)

		var endpoint *branchEndpoint
		if strings.HasPrefix(opstr, "0x") {
			n, err := strconv.ParseUint(opstr, 0, 64)
			if err == nil {
				endpoint = getLineInfo(uintptr(n), bpfProgs, addr2line, kallsyms)
			}
		}
		if endpoint != nil {
			fmt.Fprintf(&sb, "\t; %s+%#x", endpoint.funcName, endpoint.offset)
			if endpoint.fileName != "" {
				fmt.Fprintf(&sb, " %s:%d", endpoint.fileName, endpoint.fileLine)
			}
			if endpoint.isInline {
				fmt.Fprintf(&sb, " [inline]")
			}
			if endpoint.isProg {
				fmt.Fprintf(&sb, " [bpf]")
			}
		}
		fmt.Fprintln(&sb)

		if bytes == 0 && len(inst.Bytes) == 1 &&
			(inst.Bytes[0] == 0xc3 /* retq */ ||
				inst.Bytes[0] == 0xcc /* int3 */) {
			break
		}

		insnSize := uint64(inst.Size)
		pc += insnSize
		b = b[insnSize:]
	}

	fmt.Print(sb.String())
}
