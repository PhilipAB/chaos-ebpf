// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || loong64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64

package tshaper

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type tshaperIn6Addr struct{ In6U struct{ U6Addr8 [16]uint8 } }

// loadTshaper returns the embedded CollectionSpec for tshaper.
func loadTshaper() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_TshaperBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load tshaper: %w", err)
	}

	return spec, err
}

// loadTshaperObjects loads tshaper and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*tshaperObjects
//	*tshaperPrograms
//	*tshaperMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadTshaperObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadTshaper()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// tshaperSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tshaperSpecs struct {
	tshaperProgramSpecs
	tshaperMapSpecs
}

// tshaperSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tshaperProgramSpecs struct {
	XdpTrafficShaper *ebpf.ProgramSpec `ebpf:"xdp_traffic_shaper"`
}

// tshaperMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tshaperMapSpecs struct {
	DropRate            *ebpf.MapSpec `ebpf:"drop_rate"`
	DroppedPktsMap      *ebpf.MapSpec `ebpf:"dropped_pkts_map"`
	EnableIpv4          *ebpf.MapSpec `ebpf:"enable_ipv4"`
	EnableIpv6          *ebpf.MapSpec `ebpf:"enable_ipv6"`
	Ipv4Mask            *ebpf.MapSpec `ebpf:"ipv4_mask"`
	Ipv4RangeExemptList *ebpf.MapSpec `ebpf:"ipv4_range_exempt_list"`
	Ipv6Mask            *ebpf.MapSpec `ebpf:"ipv6_mask"`
	Ipv6RangeExemptList *ebpf.MapSpec `ebpf:"ipv6_range_exempt_list"`
	PortMap             *ebpf.MapSpec `ebpf:"port_map"`
	SupportedProtocols  *ebpf.MapSpec `ebpf:"supported_protocols"`
	TotalPktsMap        *ebpf.MapSpec `ebpf:"total_pkts_map"`
}

// tshaperObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadTshaperObjects or ebpf.CollectionSpec.LoadAndAssign.
type tshaperObjects struct {
	tshaperPrograms
	tshaperMaps
}

func (o *tshaperObjects) Close() error {
	return _TshaperClose(
		&o.tshaperPrograms,
		&o.tshaperMaps,
	)
}

// tshaperMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadTshaperObjects or ebpf.CollectionSpec.LoadAndAssign.
type tshaperMaps struct {
	DropRate            *ebpf.Map `ebpf:"drop_rate"`
	DroppedPktsMap      *ebpf.Map `ebpf:"dropped_pkts_map"`
	EnableIpv4          *ebpf.Map `ebpf:"enable_ipv4"`
	EnableIpv6          *ebpf.Map `ebpf:"enable_ipv6"`
	Ipv4Mask            *ebpf.Map `ebpf:"ipv4_mask"`
	Ipv4RangeExemptList *ebpf.Map `ebpf:"ipv4_range_exempt_list"`
	Ipv6Mask            *ebpf.Map `ebpf:"ipv6_mask"`
	Ipv6RangeExemptList *ebpf.Map `ebpf:"ipv6_range_exempt_list"`
	PortMap             *ebpf.Map `ebpf:"port_map"`
	SupportedProtocols  *ebpf.Map `ebpf:"supported_protocols"`
	TotalPktsMap        *ebpf.Map `ebpf:"total_pkts_map"`
}

func (m *tshaperMaps) Close() error {
	return _TshaperClose(
		m.DropRate,
		m.DroppedPktsMap,
		m.EnableIpv4,
		m.EnableIpv6,
		m.Ipv4Mask,
		m.Ipv4RangeExemptList,
		m.Ipv6Mask,
		m.Ipv6RangeExemptList,
		m.PortMap,
		m.SupportedProtocols,
		m.TotalPktsMap,
	)
}

// tshaperPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadTshaperObjects or ebpf.CollectionSpec.LoadAndAssign.
type tshaperPrograms struct {
	XdpTrafficShaper *ebpf.Program `ebpf:"xdp_traffic_shaper"`
}

func (p *tshaperPrograms) Close() error {
	return _TshaperClose(
		p.XdpTrafficShaper,
	)
}

func _TshaperClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed tshaper_bpfel.o
var _TshaperBytes []byte
