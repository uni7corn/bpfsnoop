// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"strings"

	"github.com/Asphaltt/mybtf"
	"github.com/fatih/color"

	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
)

func dumpOutputArgBuf(data []byte) string {
	sb := &strings.Builder{}

	fmt.Fprint(sb, "[")
	for i, b := range data {
		if i != 0 {
			fmt.Fprint(sb, ",")
		}

		fmt.Fprintf(sb, "%#02x", b)
	}
	fmt.Fprint(sb, "]")

	return sb.String()
}

func outputFuncArgAttrs(sb *strings.Builder, info *funcInfo, data []byte, f btfx.FindSymbol) error {
	fmt.Fprint(sb, "Arg attrs: ")

	gray := color.RGB(0x88, 0x88, 0x88 /* gray */)
	for i, arg := range info.args {
		if i != 0 {
			fmt.Fprint(sb, ", ")
		}

		exception := data[arg.size-1]
		if exception != 0 {
			data = data[arg.size:]
			s := fmt.Sprintf("(%s)'%s'=[NULL]", btfx.Repr(arg.t), arg.expr)
			if colorfulOutput {
				color.New(color.FgRed).Fprint(sb, s)
			} else {
				fmt.Fprint(sb, s)
			}
			continue
		}

		if arg.isDeref {
			s, err := mybtf.DumpData(arg.t, data[:arg.trueDataSize])
			if err != nil {
				return fmt.Errorf("failed to dump deref data: %w", err)
			}

			s = fmt.Sprintf("(%s)'%s'=%s", btfx.Repr(arg.t), arg.expr, s)
			if colorfulOutput {
				gray.Fprint(sb, s)
			} else {
				fmt.Fprint(sb, s)
			}

			data = data[arg.size:]
			continue
		}

		if arg.isBuf {
			s := fmt.Sprintf("(%s)'%s'=%s", btfx.Repr(arg.t), arg.expr,
				dumpOutputArgBuf(data[:arg.trueDataSize]))
			if colorfulOutput {
				gray.Fprint(sb, s)
			} else {
				fmt.Fprint(sb, s)
			}

			data = data[arg.size:]
			continue
		}

		var argStr string
		var argVal, argVal2 uint64
		if arg.isStr {
			argStr, data = readStrN(data, arg.trueDataSize)
		} else {
			argVal, data = readUint64(data)
			if arg.isNumPtr {
				argVal2, data = readUint64(data)
			}
		}

		s := btfx.ReprExprType(arg.expr, arg.t, arg.mem, arg.isStr, arg.isNumPtr, argVal, argVal2, 0, argStr, f)
		if colorfulOutput {
			gray.Fprint(sb, s)
		} else {
			fmt.Fprint(sb, s)
		}

		data = data[1:] // skip the exception result
	}

	fmt.Fprintln(sb)

	return nil
}
