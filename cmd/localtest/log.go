// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"

	"github.com/fatih/color"
)

func prInfo(w io.Writer, color *color.Color, format string, a ...any) {
	if colorful {
		color.Fprint(w, "[INF] ")
		color.Fprintf(w, format, a...)
	} else {
		fmt.Fprint(w, "[INF] ")
		fmt.Fprintf(w, format, a...)
	}
}

func prErr(w io.Writer, color *color.Color, format string, a ...any) {
	if colorful {
		color.Fprint(w, "[ERR] ")
		color.Fprintf(w, format, a...)
	} else {
		fmt.Fprint(w, "[ERR] ")
		fmt.Fprintf(w, format, a...)
	}
}

func prSeparatorIf(w io.Writer, b bool) {
	if !b {
		return
	}

	if colorful {
		yellow.Fprintf(w, "\n==========\n\n")
	} else {
		fmt.Fprint(w, "\n==========\n\n")
	}
}

func prLongSeparatorIf(w io.Writer, b bool) {
	if !b {
		return
	}

	if colorful {
		yellow.Fprintf(w, "\n====================\n\n")
	} else {
		fmt.Fprint(w, "\n====================\n\n")
	}
}
