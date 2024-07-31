// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadSync returns the embedded CollectionSpec for sync.
func loadSync() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_SyncBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load sync: %w", err)
	}

	return spec, err
}

// loadSyncObjects loads sync and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*syncObjects
//	*syncPrograms
//	*syncMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadSyncObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadSync()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// syncSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type syncSpecs struct {
	syncProgramSpecs
	syncMapSpecs
}

// syncSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type syncProgramSpecs struct {
	BpfProgKernArraymapdelete *ebpf.ProgramSpec `ebpf:"bpf_prog_kern_arraymapdelete"`
	BpfProgKernArraymapupdate *ebpf.ProgramSpec `ebpf:"bpf_prog_kern_arraymapupdate"`
	BpfProgKernHmapdelete     *ebpf.ProgramSpec `ebpf:"bpf_prog_kern_hmapdelete"`
	BpfProgKernHmapupdate     *ebpf.ProgramSpec `ebpf:"bpf_prog_kern_hmapupdate"`
	BpfProgKernLruhmapdelete  *ebpf.ProgramSpec `ebpf:"bpf_prog_kern_lruhmapdelete"`
	BpfProgKernLruhmapupdate  *ebpf.ProgramSpec `ebpf:"bpf_prog_kern_lruhmapupdate"`
}

// syncMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type syncMapSpecs struct {
	MapEvents *ebpf.MapSpec `ebpf:"map_events"`
}

// syncObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadSyncObjects or ebpf.CollectionSpec.LoadAndAssign.
type syncObjects struct {
	syncPrograms
	syncMaps
}

func (o *syncObjects) Close() error {
	return _SyncClose(
		&o.syncPrograms,
		&o.syncMaps,
	)
}

// syncMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadSyncObjects or ebpf.CollectionSpec.LoadAndAssign.
type syncMaps struct {
	MapEvents *ebpf.Map `ebpf:"map_events"`
}

func (m *syncMaps) Close() error {
	return _SyncClose(
		m.MapEvents,
	)
}

// syncPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadSyncObjects or ebpf.CollectionSpec.LoadAndAssign.
type syncPrograms struct {
	BpfProgKernArraymapdelete *ebpf.Program `ebpf:"bpf_prog_kern_arraymapdelete"`
	BpfProgKernArraymapupdate *ebpf.Program `ebpf:"bpf_prog_kern_arraymapupdate"`
	BpfProgKernHmapdelete     *ebpf.Program `ebpf:"bpf_prog_kern_hmapdelete"`
	BpfProgKernHmapupdate     *ebpf.Program `ebpf:"bpf_prog_kern_hmapupdate"`
	BpfProgKernLruhmapdelete  *ebpf.Program `ebpf:"bpf_prog_kern_lruhmapdelete"`
	BpfProgKernLruhmapupdate  *ebpf.Program `ebpf:"bpf_prog_kern_lruhmapupdate"`
}

func (p *syncPrograms) Close() error {
	return _SyncClose(
		p.BpfProgKernArraymapdelete,
		p.BpfProgKernArraymapupdate,
		p.BpfProgKernHmapdelete,
		p.BpfProgKernHmapupdate,
		p.BpfProgKernLruhmapdelete,
		p.BpfProgKernLruhmapupdate,
	)
}

func _SyncClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed sync_x86_bpfel.o
var _SyncBytes []byte
