// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/fatih/color"

	"github.com/bpfsnoop/bpfsnoop/internal/strx"
)

const (
	sizeOfEvent = int(unsafe.Sizeof(Event{}))
)

const (
	eventTypeUnspec uint16 = iota
	eventTypeFuncEntry
	eventTypeFuncExit
	eventTypeInsn
)

type Event struct {
	Type    uint16
	Length  uint16
	KernNs  uint32
	SessID  uint64
	FuncIP  uintptr
	CPU     uint32
	Pid     uint32
	Comm    [16]byte
	StackID int64
}

func ptr2bytes(p unsafe.Pointer, size int) []byte {
	return unsafe.Slice((*byte)(p), size)
}

type Helpers struct {
	Progs     *bpfProgs
	Addr2line *Addr2Line
	Ksyms     *Kallsyms
	Kfuncs    KFuncs
	Insns     *FuncInsns
}

func Run(reader *ringbuf.Reader, helpers *Helpers, maps map[string]*ebpf.Map, w io.Writer) error {
	lbrStack := newLBRStack()
	fnStack := newFnStack()
	sessions := NewSessions()

	stacks := maps["bpfsnoop_stacks"]
	lbrs := maps["bpfsnoop_lbrs"]
	pkts := maps["bpfsnoop_pkts"]

	var lbrData LbrData
	var pktData PktData

	fg := NewFlameGraph()
	defer fg.Save(outputFlameGraph)

	findSymbol := func(addr uint64) string {
		if prog, ok := helpers.Progs.funcs[uintptr(addr)]; ok {
			return prog.funcName + "[bpf]"
		}

		return helpers.Ksyms.findSymbol(addr)
	}

	var sb strings.Builder

	var record ringbuf.Record
	record.RawSample = make([]byte, 4096)

	unlimited := limitEvents == 0
	for i := int64(limitEvents); unlimited || i > 0; i-- {
		err := reader.ReadInto(&record)
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}

			return fmt.Errorf("failed to read ringbuf: %w", err)
		}

		typ := *(*uint16)(unsafe.Pointer(&record.RawSample[0]))
		if typ == eventTypeInsn {
			event := (*InsnEvent)(unsafe.Pointer(&record.RawSample[0]))
			outputInsnEvent(&sb, sessions, helpers.Insns, event)
			sb.Reset()
			continue
		}

		if len(record.RawSample) < sizeOfEvent {
			continue
		}

		event := (*Event)(unsafe.Pointer(&record.RawSample[0]))
		fnInfo := getFuncInfo(event, helpers)

		var sess *Session
		var duration time.Duration
		withDuration := fnInfo.insnMode
		if withDuration {
			if event.Type == eventTypeFuncEntry {
				sess = sessions.Add(event.SessID, event.KernNs)
			} else {
				s, ok := sessions.GetAndDel(event.SessID + 1)
				if ok {
					sess = s
					duration = time.Duration(event.KernNs - s.started)
				}
			}
		}

		fnName := fnInfo.name
		if event.Type == eventTypeFuncExit {
			fnName += "[ex]"
		} else if event.Type == eventTypeFuncEntry && !fnInfo.isTp {
			fnName += "[en]"
		}

		if colorfulOutput {
			color.New(color.FgYellow, color.Bold).Fprint(&sb, fnName, " ")
			color.New(color.FgBlue).Fprintf(&sb, "args")
		} else {
			fmt.Fprint(&sb, fnName, " args")
		}

		withRetval := event.Type == eventTypeFuncExit
		if fnInfo.argsBuf != 0 {
			b := record.RawSample[sizeOfEvent : sizeOfEvent+int(fnInfo.argsBuf)]
			outputFnArgs(&sb, fnInfo, helpers, b, findSymbol, withRetval)
		} else {
			fmt.Fprint(&sb, "=()")
			if withRetval {
				fmt.Fprint(&sb, " retval=(void)")
			}
		}

		if colorfulOutput {
			color.New(color.FgCyan).Fprintf(&sb, " cpu=%d", event.CPU)
			color.New(color.FgMagenta).Fprintf(&sb, " process=(%d:%s)", event.Pid, strx.NullTerminated(event.Comm[:]))
			if withDuration && withRetval {
				color.RGB(0xFF, 0x00, 0x7F /* rose red */).Fprintf(&sb, " duration=%s", duration)
			}
		} else {
			fmt.Fprintf(&sb, " cpu=%d process=(%d:%s)", event.CPU, event.Pid, strx.NullTerminated(event.Comm[:]))
			if withDuration && withRetval {
				fmt.Fprintf(&sb, " duration=%s", duration)
			}
		}
		fmt.Fprintln(&sb)

		err = outputPktTuple(&sb, fnInfo, &pktData, pkts, event)
		if err != nil {
			return fmt.Errorf("failed to output packet tuple: %w", err)
		}

		if fnInfo.argData != 0 {
			off := sizeOfEvent + int(fnInfo.argsBuf)
			b := record.RawSample[off : off+fnInfo.argData]
			err := outputFuncArgAttrs(&sb, fnInfo, b, findSymbol)
			if err != nil {
				return fmt.Errorf("failed to output function arg attrs: %w", err)
			}
		}

		err = lbrStack.outputStack(&sb, helpers, &lbrData, lbrs, event)
		if err != nil {
			return fmt.Errorf("failed to output LBR stack: %w", err)
		}

		err = fnStack.output(&sb, helpers, stacks, fg, event)
		if err != nil {
			return fmt.Errorf("failed to output function stack: %w", err)
		}

		if sess == nil || withRetval {
			fmt.Fprintln(&sb)
		}
		if sess != nil {
			sess.outputs = append(sess.outputs, sb.String())
			if withRetval {
				for _, output := range sess.outputs {
					fmt.Fprint(w, output)
				}
			}
		} else {
			fmt.Fprint(w, sb.String())
		}

		sb.Reset()
		lbrStack.reset()
		fnStack.reset()
	}

	return ErrFinished
}
