package server

import (
	"context"
	"fmt"

	grpcErrors "github.com/philipab/ebpf-proto/grpc/grpc-errors"
	nf "github.com/philipab/ebpf-proto/grpc/protos"
	"google.golang.org/grpc/codes"
)

// Enable network filter to randomly drop x% of processed packets (attaches the according eBPF program)
// Important(!): If a traffic shaper for the specified namespace and interface already exists, it will be replaced by the new filter
// @req: Please refer to the paramater descriptions in /grpc/protos/networkfilter.proto
func (nfs *NetworkfilterServer) EnableNetworkFilter(ctx context.Context, req *nf.EnableTrafficShaperRequest) (*nf.Response, error) {
	filter := req.GetFilter()
	if filter == nil {
		return nil, grpcErrors.SimpleGrpcError("parameter filter is missing", req, codes.InvalidArgument)
	}
	ns := filter.GetNamespace()
	if ns == "" {
		ns = "HOST"
	}
	switch iFace := filter.GetInterface(); iFace {
	case "DOCKER":
		return nfs.enableNetworkFilterResponse(req, ns, "docker0")
	case "CNI":
		return nfs.enableNetworkFilterResponse(req, ns, "cni0")
	case "LO":
		return nfs.enableNetworkFilterResponse(req, ns, "lo")
	case "ALL":
		return nfs.enableAllTsResponse(req, ns)
	case "ETH":
		if err := nfs.attachEthFilter(req); err != nil {
			return nil, grpcErrors.InternalGrpcError("failed to attach eth filter(s): %v", req, err)
		}
		message := fmt.Sprintf("eth filter(s) in namespace %s attached successfully", ns)
		return &nf.Response{Success: true, Message: message}, nil
	default:
		return nfs.enableNetworkFilterResponse(req, ns, iFace)
	}
}

// Disable the network filter (detaches the according eBPF program)
// @req: Please refer to the paramater descriptions in /grpc/protos/networkfilter.proto
func (nfs *NetworkfilterServer) DisableNetworkFilter(ctx context.Context, req *nf.DisableRequest) (*nf.Response, error) {
	ns := req.GetNamespace()
	switch iFace := req.GetInterface(); iFace {
	case "DOCKER":
		return nfs.disableNetworkFilterResponse(req, ns, "docker0")
	case "CNI":
		return nfs.disableNetworkFilterResponse(req, ns, "cni0")
	case "LO":
		return nfs.disableNetworkFilterResponse(req, ns, "lo")
	case "ALL":
		return nfs.disableAllTsResponse(req, ns)
	case "ETH":
		if err := nfs.detachEthFilter(ns); err != nil {
			return nil, grpcErrors.InternalGrpcError("failed to detach eth filter(s): %v", req, err)
		}
		message := fmt.Sprintf("eth filter(s) in namespace %s detached successfully", ns)
		return &nf.Response{Success: true, Message: message}, nil
	default:
		return nfs.disableNetworkFilterResponse(req, ns, iFace)
	}
}

// This function is called ControlTicker because it controls/verifies the behaviour of our traffic shaper eBPF program
// This function should only be used for testing purposes
// @req: Please refer to the paramater descriptions in /grpc/protos/networkfilter.proto
func (nfs *NetworkfilterServer) ControlTicker(ctx context.Context, req *nf.TickerRequest) (*nf.Response, error) {
	if req.Enable {
		// If the ticker is already running, don't start another.
		if nfs.tickerCancel != nil {
			return &nf.Response{
				Success: false,
				Message: "Ticker is already running",
			}, nil
		}

		tickerCtx, cancel := context.WithCancel(context.Background())
		nfs.tickerCancel = cancel
		go nfs.runTicker(tickerCtx, req.GetFilter(), req.GetNamespace()) // Start the ticker in a separate goroutine
	} else {
		// If the ticker isn't running, there's nothing to cancel.
		if nfs.tickerCancel == nil {
			return &nf.Response{
				Success: false,
				Message: "Ticker isn't running",
			}, nil
		}

		nfs.tickerCancel()     // Stop the ticker
		nfs.tickerCancel = nil // Clear the cancel function
	}

	return &nf.Response{
		Success: true,
		Message: "Ticker operation successful.",
	}, nil
}
