# Copyright 2025 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0


CMD_BPFTOOL ?=
CMD_CC ?= clang
CMD_CD ?= cd
CMD_CHECKSUM ?= sha256sum
CMD_CP ?= cp
CMD_CXX ?= clang++
CMD_IP ?= ip
CMD_GH ?= gh
CMD_MV ?= mv
CMD_TAR ?= tar
CMD_GIT ?= git
CMD_GIT_MODULES ?= $(CMD_GIT) submodule

ifeq ($(CMD_BPFTOOL),)
	# Debian-based distros install bpftool to /usr/sbin/ which is only in root user's PATH
	CMD_BPFTOOL := $(shell PATH="$$PATH:/usr/local/sbin:/usr/sbin:/sbin" which bpftool)
	ifeq ($(CMD_BPFTOOL),)
		CMD_BPFTOOL := bpftool
	endif
endif

UNAME_ARCH := $(shell uname -m)
GCC_LIB_DIR := /usr/lib/gcc/$(UNAME_ARCH)-linux-gnu/$(shell gcc -dumpversion | cut -d. -f1)

CPU_CORES := $(shell (command -v nproc >/dev/null 2>&1 && nproc) \
		|| grep -E '^processor' /proc/cpuinfo | wc -l)

DIR_BIN := ./bin
DIR_BPF := ./internal/bpf

GOBUILD := go build -v -trimpath
GOBUILD_CGO_CFLAGS := CGO_CFLAGS='-O2 -I$(CURDIR)/lib/capstone/include -I$(CURDIR)/lib/libpcap'
GOBUILD_CGO_LDFLAGS := CGO_LDFLAGS='-O2 -g -L$(CURDIR)/lib/capstone/build -lcapstone -L$(CURDIR)/lib/libpcap -lpcap -static'

ifeq ($(UNAME_ARCH),x86_64)
	TARGET_ARCH := x86
else ifeq ($(UNAME_ARCH),aarch64)
	TARGET_ARCH := arm64
else
	$(error Unsupported architecture: $(UNAME_ARCH).)
endif

GO_RUN_BPF2GO := go run github.com/cilium/ebpf/cmd/bpf2go -cc clang
BPF2GO := cd $(DIR_BPF) && $(GO_RUN_BPF2GO) -go-package bpf
BPF2GO_EXTRA_FLAGS := -g -D__TARGET_ARCH_$(TARGET_ARCH) -I$(CURDIR)/bpf -I$(CURDIR)/bpf/headers -I$(CURDIR)/lib/libbpf/src -Wno-address-of-packed-member -Wall

BPFSNOOP_BPF_OBJ := $(DIR_BPF)/bpfsnoop_bpfel.o $(DIR_BPF)/bpfsnoop_bpfeb.o
BPFSNOOP_BPF_SRC := bpf/bpfsnoop.c $(wildcard bpf/*.h) $(wildcard bpf/headers/*.h)

INSN_BPF_OBJ := $(DIR_BPF)/insn_bpfel.o $(DIR_BPF)/insn_bpfeb.o
INSN_BPF_SRC := bpf/bpfsnoop_insn.c bpf/bpfsnoop_event.h bpf/bpfsnoop_sess.h

GRAPH_BPF_OBJ := $(DIR_BPF)/graph_bpfel.o $(DIR_BPF)/graph_bpfeb.o
GRAPH_BPF_SRC := bpf/bpfsnoop_fgraph.c bpf/bpfsnoop_event.h bpf/bpfsnoop_sess.h bpf/bpfsnoop_fn_args_output.h bpf/bpfsnoop_stack.h

FEAT_BPF_OBJ := $(DIR_BPF)/feat_bpfel.o $(DIR_BPF)/feat_bpfeb.o
FEAT_BPF_SRC := bpf/feature.c

TRACEABLE_BPF_OBJ := $(DIR_BPF)/traceable_bpfel.o $(DIR_BPF)/traceable_bpfeb.o
TRACEABLE_BPF_SRC := bpf/traceable.c

TRACEPOINT_BPF_OBJ := $(DIR_BPF)/tracepoint_bpfel.o $(DIR_BPF)/tracepoint_bpfeb.o
TRACEPOINT_BPF_SRC := bpf/tracepoint.c

TRACEPOINT_MODULE_BPF_OBJ := $(DIR_BPF)/tracepoint_module_bpfel.o $(DIR_BPF)/tracepoint_module_bpfeb.o
TRACEPOINT_MODULE_BPF_SRC := bpf/tracepoint_module.c

READ_BPF_OBJ := $(DIR_BPF)/read_bpfel.o $(DIR_BPF)/read_bpfeb.o
READ_BPF_SRC := bpf/read.c

TAILCALL_BPF_OBJ := $(DIR_BPF)/tailcall_bpfel.o $(DIR_BPF)/tailcall_bpfeb.o
TAILCALL_BPF_SRC := bpf/tailcall.c

BPF_OBJS := $(BPFSNOOP_BPF_OBJ) \
			$(INSN_BPF_OBJ) \
			$(GRAPH_BPF_OBJ) \
			$(READ_BPF_OBJ) \
			$(FEAT_BPF_OBJ) \
			$(TAILCALL_BPF_OBJ) \
			$(TRACEABLE_BPF_OBJ) \
			$(TRACEPOINT_BPF_OBJ) \
			$(TRACEPOINT_MODULE_BPF_OBJ)

BPFSNOOP_OBJ := bpfsnoop
BPFSNOOP_SRC := $(shell find internal -type f -name '*.go') main.go
BPFSNOOP_CSM := $(BPFSNOOP_OBJ).sha256sum
RELEASE_NOTES ?= release_notes.txt

# Do our best to detect changes in submodules and rebuild them...
LIBCAPSTONE_DIR := lib/capstone
LIBCAPSTONE_SRC := $(LIBCAPSTONE_DIR) \
	$(shell find $(LIBCAPSTONE_DIR) -type f -name '*.[ch]' 2>/dev/null)
LIBCAPSTONE_OBJ := $(LIBCAPSTONE_DIR)/build/libcapstone.a

LIBPCAP_DIR := lib/libpcap
LIBPCAP_SRC := $(LIBPCAP_DIR) \
	$(shell find $(LIBPCAP_DIR) -type f -name '*.[ch]' 2>/dev/null)
LIBPCAP_OBJ := $(LIBPCAP_DIR)/libpcap.a

LIBBPF_OBJ := lib/libbpf/src

VMLINUX_OBJ := bpf/headers/vmlinux.h
VMLINUX_SRC := /sys/kernel/btf/vmlinux

GIT_MODULES_DIR := .git/modules

LOCALTEST_OBJ := localtest
LOCALTEST_SRC := $(shell find ./cmd/localtest/ -type f -name '*.go')

XDPCRC_DIR := ./cmd/xdpcrc
XDPCRC_BPF_OBJ := $(XDPCRC_DIR)/xdp_bpfel.o $(XDPCRC_DIR)/xdp_bpfeb.o
XDPCRC_BPF_OBJ += $(XDPCRC_BPF_OBJ:%.o=%.go)
XDPCRC_OBJ := xdpcrc
XDPCRC_SRC := $(wildcard $(XDPCRC_DIR)/*.go $(XDPCRC_DIR)/*.c)
