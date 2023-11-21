package server

import (
	"context"
	"fmt"

	grpcErrors "github.com/philipab/ebpf-proto/grpc/grpc-errors"
	nf "github.com/philipab/ebpf-proto/grpc/protos"
	"google.golang.org/grpc/codes"
)

func (nfs *NetworkfilterServer) EnableDelayGen(ctx context.Context, req *nf.DelayRequest) (*nf.Response, error) {
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
		return nfs.enableDelayGenResponse(req, ns, "docker0")
	case "CNI":
		return nfs.enableDelayGenResponse(req, ns, "cni0")
	case "LO":
		return nfs.enableDelayGenResponse(req, ns, "lo")
	case "ALL":
		return nfs.enableAllDelayGenResponse(req, ns)
	case "ETH":
		if err := nfs.attachDelayGenEth(req); err != nil {
			return nil, grpcErrors.InternalGrpcError("failed to attach eth filter(s): %v", req, err)
		}
		message := fmt.Sprintf("eth filter(s) in namespace %s attached successfully", ns)
		return &nf.Response{Success: true, Message: message}, nil
	default:
		return nfs.enableDelayGenResponse(req, ns, iFace)
	}
}

func (nfs *NetworkfilterServer) DisableDelayGen(ctx context.Context, req *nf.DisableRequest) (*nf.Response, error) {
	ns := req.GetNamespace()
	if ns == "" {
		ns = "HOST"
	}
	switch iFace := req.GetInterface(); iFace {
	case "DOCKER":
		return nfs.disableDelayGenResponse(req, ns, "docker0")
	case "CNI":
		return nfs.disableDelayGenResponse(req, ns, "cni0")
	case "LO":
		return nfs.disableDelayGenResponse(req, ns, "lo")
	case "ALL":
		return nfs.disableAllDelayGenResponse(req, ns)
	case "ETH":
		if err := nfs.detachDelayGenEth(ns); err != nil {
			return nil, grpcErrors.InternalGrpcError("failed to detach eth filter(s): %v", req, err)
		}
		message := fmt.Sprintf("eth filter(s) in namespace %s detached successfully", ns)
		return &nf.Response{Success: true, Message: message}, nil
	default:
		return nfs.disableDelayGenResponse(req, ns, iFace)
	}
}
