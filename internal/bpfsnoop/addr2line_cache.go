// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Asphaltt/addr2line"
	"github.com/goccy/go-json"
	"github.com/ulikunitz/xz"
)

const (
	dbgsymCacheFile = "dbgsym.json.xz"

	cacheBatchLimit = 30
)

type dbgsymCacheData struct {
	Entries map[uintptr]*addr2line.Addr2LineEntry `json:"entries"`
}

type dbgsymCache struct {
	newEntriesCnt int

	cacheFile string

	cache map[uintptr]*addr2line.Addr2LineEntry
}

func newDbgsymCache() (*dbgsymCache, error) {
	dirname, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get current user home dir: %w", err)
	}

	var d dbgsymCache
	cacheDir := filepath.Join(dirname, ".cache", "bpfsnoop")
	_ = os.MkdirAll(cacheDir, 0x666)
	d.cacheFile = filepath.Join(cacheDir, dbgsymCacheFile)

	err = d.loadFile()
	if err != nil {
		return nil, fmt.Errorf("failed to load dbgsym cache: %w", err)
	}

	return &d, nil
}

func (d *dbgsymCache) loadFile() error {
	if !fileExists(d.cacheFile) {
		d.cache = make(map[uintptr]*addr2line.Addr2LineEntry)
		return nil
	}

	fd, err := os.Open(d.cacheFile)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", d.cacheFile, err)
	}
	defer fd.Close()

	r, err := xz.NewReader(fd)
	if err != nil {
		return fmt.Errorf("failed to new xz reader: %w", err)
	}

	var entries dbgsymCacheData
	err = json.NewDecoder(r).Decode(&entries)
	if err != nil {
		return fmt.Errorf("failed to json decode: %w", err)
	}

	d.cache = entries.Entries
	return nil
}

func (d *dbgsymCache) saveFile() error {
	entries := dbgsymCacheData{
		Entries: d.cache,
	}

	fd, err := os.CreateTemp(filepath.Dir(d.cacheFile), "dbgsym-*.json.xz")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(fd.Name()) // ignore error as it has been renamed.
	defer fd.Close()

	w, err := xz.NewWriter(fd)
	if err != nil {
		return fmt.Errorf("failed to new xz writer: %w", err)
	}

	err = json.NewEncoder(w).Encode(entries)
	if err != nil {
		return fmt.Errorf("failed to json encode: %w", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("failed to close xz writer: %w", err)
	}

	err = fd.Close()
	if err != nil {
		return fmt.Errorf("failed to close file: %w", err)
	}

	err = os.Rename(fd.Name(), d.cacheFile)
	if err != nil {
		return fmt.Errorf("failed to rename temp file to %s: %w", d.cacheFile, err)
	}

	return nil
}

func (d *dbgsymCache) get(addr uintptr) (*addr2line.Addr2LineEntry, bool) {
	entry, ok := d.cache[addr]
	return entry, ok
}

func (d *dbgsymCache) add(addr uintptr, entry *addr2line.Addr2LineEntry) error {
	if _, ok := d.cache[addr]; ok {
		return nil
	}

	d.cache[addr] = entry
	d.newEntriesCnt++

	if d.newEntriesCnt%cacheBatchLimit == 0 {
		err := d.saveFile()
		if err != nil {
			return fmt.Errorf("failed to save dbgsym cache: %w", err)
		}
	}

	return nil
}
