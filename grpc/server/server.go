package server

import (
	"context"

	"github.com/cilium/ebpf/link"
	"github.com/florianl/go-tc"
	"github.com/philipab/ebpf-proto/ebpf/bitflip"
	"github.com/philipab/ebpf-proto/ebpf/bwmanager"
	"github.com/philipab/ebpf-proto/ebpf/delay"
	"github.com/philipab/ebpf-proto/ebpf/duplication"
	"github.com/philipab/ebpf-proto/ebpf/tshaper"
	nf "github.com/philipab/ebpf-proto/grpc/protos"
)

const AF_UNSPEC uint32 = 0

type NetworkfilterServer struct {
	nf.UnimplementedNetworkFilterServer
	tickerCancel           context.CancelFunc
	attachedLinks          map[string]link.Link
	tShaperEbpfPrograms    map[string]*tshaper.TshaperObjectsWrapper
	bwManagerEbpfPrograms  map[string]*bwmanager.BwObjectsWrapper
	duplGenEbpfPrograms    map[string]*duplication.DuplicateGenObjectsWrapper
	bitflipGenEbpfPrograms map[string]*bitflip.BitflipGenObjectsWrapper
	delayGenEbpfPrograms   map[string]*delay.DelayGenObjectsWrapper
	tcPrograms             map[string]*tc.Object
	clsactQdisc            *tc.Object
	fqQdisc                *tc.Object
	tcConnection           *tc.Tc
}

func NewNetworkfilterServer() *NetworkfilterServer {
	// Global maps to keep track of attached XDP programs
	attachedLinks := make(map[string]link.Link)
	trafficShaperEbpfPrograms := make(map[string]*tshaper.TshaperObjectsWrapper)
	bwManagerEbpfPrograms := make(map[string]*bwmanager.BwObjectsWrapper)
	duplGenEbpfPrograms := make(map[string]*duplication.DuplicateGenObjectsWrapper)
	bitflipGenEbpfPrograms := make(map[string]*bitflip.BitflipGenObjectsWrapper)
	delayGenEbpfPrograms := make(map[string]*delay.DelayGenObjectsWrapper)

	// Reference to keep track of applied tc ebpf filters
	tcFilters := make(map[string]*tc.Object)

	return &NetworkfilterServer{
		attachedLinks:          attachedLinks,
		tShaperEbpfPrograms:    trafficShaperEbpfPrograms,
		bwManagerEbpfPrograms:  bwManagerEbpfPrograms,
		duplGenEbpfPrograms:    duplGenEbpfPrograms,
		bitflipGenEbpfPrograms: bitflipGenEbpfPrograms,
		delayGenEbpfPrograms:   delayGenEbpfPrograms,
		tcPrograms:             tcFilters,
		clsactQdisc:            nil,
		tcConnection:           nil,
	}
}
