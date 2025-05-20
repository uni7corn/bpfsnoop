// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf/btf"
	"github.com/fatih/color"

	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
	"github.com/bpfsnoop/bpfsnoop/internal/strx"
)

const (
	maxOutputStrLen = 64
)

func outputFnRetval(sb *strings.Builder, info *funcInfo, s string, data []byte, f btfx.FindSymbol) {
	var retval string
	if info.proto != nil {
		var b [24]byte
		copy(b[:], data)
		num1 := *(*uint64)(unsafe.Pointer(&b[0]))
		num2 := *(*uint64)(unsafe.Pointer(&b[8]))
		rettyp := info.proto.Type.(*btf.FuncProto).Return
		retval = btfx.ReprFuncReturn(rettyp, info.retParam.IsStr,
			info.retParam.IsNumberPtr, num1, num2, s, f)
	} else {
		num := *(*uint64)(unsafe.Pointer(&data[0]))
		retval = fmt.Sprintf("%#x/%s", num, num)
	}

	if colorfulOutput {
		color.New(color.FgGreen).Fprintf(sb, " retval")
		fmt.Fprint(sb, "=")
		color.New(color.FgRed).Fprintf(sb, "%s", retval)
	} else {
		fmt.Fprintf(sb, " retval=%s", retval)
	}
}

func readUint64(data []byte) (uint64, []byte) {
	num := *(*uint64)(unsafe.Pointer(&data[0]))
	return num, data[8:]
}

func readStr(data []byte) (string, []byte) {
	str := strx.NullTerminated(data[:maxOutputStrLen])
	return str, data[maxOutputStrLen:]
}

func outputFnArgs(sb *strings.Builder, info *funcInfo, helpers *Helpers, data []byte, f btfx.FindSymbol, withRetval bool) {
	funcParamColors := []*color.Color{
		color.RGB(0x9d, 0x9d, 0x9d),
		color.RGB(0x7a, 0x7a, 0x7a),
		color.RGB(0x54, 0x54, 0x54),
		color.RGB(0x9c, 0x91, 0x91),
		color.RGB(0x7c, 0x74, 0x74),
		color.RGB(0x5c, 0x54, 0x54),
		color.RGB(0x9d, 0x9d, 0x9d),
		color.RGB(0x7a, 0x7a, 0x7a),
		color.RGB(0x54, 0x54, 0x54),
		color.RGB(0x9c, 0x91, 0x91),
		color.RGB(0x7c, 0x74, 0x74),
		color.RGB(0x5c, 0x54, 0x54),
	}

	fmt.Fprintf(sb, "=(")

	params := info.proto.Type.(*btf.FuncProto).Params
	lastIdx, idx := len(params)-1, 0
	for i, param := range info.params {
		if param.partOfPrevParam {
			continue
		}

		if idx != 0 {
			fmt.Fprint(sb, ", ")
		}

		arg, argVal := uint64(0), uint64(0)
		argStr := ""
		if param.IsStr {
			argStr, data = readStr(data)
		} else {
			arg, data = readUint64(data)
			if param.IsNumberPtr {
				argVal, data = readUint64(data)
			}
		}

		valNext := uint64(0)
		if i < lastIdx {
			valNext = *(*uint64)(unsafe.Pointer(&data[0]))
		}

		fp := btfx.ReprFuncParam(&params[idx], i, param.IsStr, param.IsNumberPtr, arg, argVal, valNext, argStr, f)
		if colorfulOutput {
			funcParamColors[i].Fprint(sb, fp)
		} else {
			fmt.Fprintf(sb, "%s", fp)
		}

		idx++
	}
	fmt.Fprintf(sb, ")")

	if !withRetval {
		return
	}

	retStr := ""
	if info.retParam.IsStr {
		retStr = strx.NullTerminated(data[:maxOutputStrLen])
	}
	outputFnRetval(sb, info, retStr, data, f)
}
