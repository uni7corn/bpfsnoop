// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"unsafe"

	"github.com/Asphaltt/bpflbr/internal/strx"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/fatih/color"
	"golang.org/x/sys/unix"
)

const (
	MAX_STACK_DEPTH = 50
)

type LbrEntry struct {
	From  uintptr
	To    uintptr
	Flags uint64
}
type Event struct {
	Entries [32]LbrEntry
	NrBytes int64
	Retval  int64
	FuncIP  uintptr
	CPU     uint32
	Pid     uint32
	Comm    [16]byte
	StackID int64
}
type FuncStack struct {
	IPs [MAX_STACK_DEPTH]uint64
}

func Run(reader *ringbuf.Reader, progs *bpfProgs, addr2line *Addr2Line, ksyms *Kallsyms, funcStacks *ebpf.Map, w io.Writer) error {
	lbrStack := newLBRStack()
	funcStack := make([]string, 0, MAX_STACK_DEPTH)

	var sb strings.Builder

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}

			return fmt.Errorf("failed to read ringbuf: %w", err)
		}

		if len(record.RawSample) < int(unsafe.Sizeof(Event{})) {
			continue
		}

		event := (*Event)(unsafe.Pointer(&record.RawSample[0]))

		if event.NrBytes < 0 && event.NrBytes == -int64(unix.ENOENT) {
			return fmt.Errorf("LBR not supported")
		}

		if outputFuncStack && event.StackID >= 0 {
			funcStack, err = getFuncStack(event, progs, addr2line, ksyms, funcStacks, funcStack)
			if err != nil {
				return err
			}
		}

		hasLbrEntries := event.NrBytes > 0 && event.Entries[0] != (LbrEntry{})
		hasLbrEntries = hasLbrEntries && getLbrStack(event, progs, addr2line, ksyms, lbrStack)

		var targetName string
		progInfo, isProg := progs.funcs[event.FuncIP]
		if isProg {
			targetName = progInfo.funcName() + "[bpf]"
		} else {
			ksym, ok := ksyms.find(event.FuncIP)
			if ok {
				targetName = ksym.name
			} else {
				targetName = fmt.Sprintf("0x%x", event.FuncIP)
			}
		}

		if noColorOutput {
			fmt.Fprintf(&sb, "Recv a record for %s with", targetName)
			if mode != TracingModeEntry {
				fmt.Fprintf(&sb, " retval=%d/%#x", event.Retval, uint64(event.Retval))
			}
		} else {
			targetName = color.New(color.FgYellow, color.Bold).Sprint(targetName)
			fmt.Fprintf(&sb, "Recv a record for %s with", targetName)
			if mode != TracingModeEntry {
				color.New(color.FgRed).Fprintf(&sb, " retval=%d/%#x", event.Retval, uint64(event.Retval))
			}
		}
		fmt.Fprintf(&sb, " cpu=%d process=(%d:%s)", event.CPU, event.Pid, strx.NullTerminated(event.Comm[:]))

		hasFuncEntries := len(funcStack) > 0
		if hasLbrEntries || hasFuncEntries {
			fmt.Fprintln(&sb, " :")
			if hasLbrEntries {
				fmt.Fprintln(&sb, "LBR stack:")
				lbrStack.output(&sb)
			}
			if hasFuncEntries {
				fmt.Fprintln(&sb, "Func stack:")
				for _, entry := range funcStack {
					fmt.Fprint(&sb, entry)
				}
			}
		} else {
			fmt.Fprintln(&sb)
		}
		fmt.Fprintln(w, sb.String())

		sb.Reset()
		lbrStack.reset()
		funcStack = funcStack[:0]
	}
}

func getLbrStack(event *Event, progs *bpfProgs, addr2line *Addr2Line, ksyms *Kallsyms, stack *lbrStack) bool {
	progInfo, isProg := progs.funcs[event.FuncIP]

	nrEntries := event.NrBytes / int64(8*3)
	entries := event.Entries[:nrEntries]
	if !verbose {
		// Skip the first 14 entries as they are entries for fexit_fn
		// and bpf_get_branch_snapshot helper.
		const nrSkip = 14

		entries = entries[nrSkip:]

		if isProg && mode == TracingModeExit {
			for i := range entries {
				if progInfo.contains(entries[i].From) || progInfo.contains(entries[i].To) {
					entries = entries[i:]
					break
				}
			}

			for i := len(entries) - 1; i >= 0; i-- {
				if progInfo.contains(entries[i].From) || progInfo.contains(entries[i].To) {
					entries = entries[:i+1]
					break
				}
			}
		}

		if len(entries) == 0 {
			return false
		}
	}

	lbrEntries := make([]branchEntry, 0, len(entries))
	for _, entry := range entries {
		from := getLineInfo(entry.From, progs, addr2line, ksyms)
		to := getLineInfo(entry.To, progs, addr2line, ksyms)
		lbrEntries = append(lbrEntries, branchEntry{from, to})
	}

	last := len(lbrEntries) - 1
	stack.pushFirstEntry(lbrEntries[last])
	for i := last - 1; i >= 0; i-- {
		stack.pushEntry(lbrEntries[i])
	}

	return true
}

func getFuncStack(event *Event, progs *bpfProgs, addr2line *Addr2Line, ksym *Kallsyms, funcStacks *ebpf.Map, stack []string) ([]string, error) {
	id := uint32(event.StackID)

	var data FuncStack
	err := funcStacks.Lookup(id, &data)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return stack, nil
		}
		return stack, fmt.Errorf("failed to lookup func stack map: %w", err)
	}
	_ = funcStacks.Delete(id)

	ips := data.IPs[:]
	if !verbose {
		ips = ips[3:] // Skip the first 3 entries as they are entries for fentry/fexit and its trampoline.
	}
	for _, ip := range ips {
		if ip == 0 {
			continue
		}

		li := getLineInfo(uintptr(ip), progs, addr2line, ksym)

		var sb strings.Builder
		fmt.Fprint(&sb, "  ")
		if noColorOutput {
			if verbose {
				fmt.Fprintf(&sb, "0x%x:", ip)
			}
			fmt.Fprintf(&sb, "%-50s", fmt.Sprintf("%s+%#x", li.funcName, li.offset))
			if li.fileName != "" {
				fmt.Fprintf(&sb, "\t; %s:%d", li.fileName, li.fileLine)
			}
		} else {
			if verbose {
				color.New(color.FgBlue).Fprintf(&sb, "%#x", ip)
				fmt.Fprint(&sb, ":")
			}

			offset := fmt.Sprintf("+%#x", li.offset)
			color.RGB(0xE1, 0xD5, 0x77 /* light yellow */).Fprint(&sb, li.funcName)
			fmt.Fprintf(&sb, "%-*s", 50-len(li.funcName), offset)
			if li.fileName != "" {
				color.RGB(0x88, 0x88, 0x88 /* gray */).Fprintf(&sb, "\t; %s:%d", li.fileName, li.fileLine)
			}
		}

		fmt.Fprintln(&sb)

		stack = append(stack, sb.String())
	}

	return stack, nil
}
