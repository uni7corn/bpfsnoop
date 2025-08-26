// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"strconv"

	sysctl "github.com/lorenzosaino/go-sysctl"
)

var kernelPerfEventMaxStack int

func readKernelPerfEventMaxStack() (int, error) {
	maxStack, err := sysctl.Get("kernel.perf_event_max_stack")
	if err != nil {
		return 0, fmt.Errorf("failed to read kernel.perf_event_max_stack: %w", err)
	}

	n, err := strconv.Atoi(maxStack)
	if err != nil {
		return 0, fmt.Errorf("failed to convert kernel.perf_event_max_stack to int: %w", err)
	}

	kernelPerfEventMaxStack = n
	return n, nil
}
