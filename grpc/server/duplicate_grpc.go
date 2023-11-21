package server

import (
	"context"
	"fmt"

	grpcErrors "github.com/philipab/ebpf-proto/grpc/grpc-errors"
	nf "github.com/philipab/ebpf-proto/grpc/protos"
	"google.golang.org/grpc/codes"
)

func (nfs *NetworkfilterServer) EnableDuplicationGen(ctx context.Context, req *nf.DuplRequest) (*nf.Response, error) {
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
		return nfs.enableDuplicationGenResponse(req, ns, "docker0")
	case "CNI":
		return nfs.enableDuplicationGenResponse(req, ns, "cni0")
	case "LO":
		return nfs.enableDuplicationGenResponse(req, ns, "lo")
	case "ALL":
		return nfs.enableAllDuplGenResponse(req, ns)
	case "ETH":
		if err := nfs.attachDuplicationGenEth(req); err != nil {
			return nil, grpcErrors.InternalGrpcError("failed to attach eth filter(s): %v", req, err)
		}
		message := fmt.Sprintf("eth filter(s) in namespace %s attached successfully", ns)
		return &nf.Response{Success: true, Message: message}, nil
	default:
		return nfs.enableDuplicationGenResponse(req, ns, iFace)
	}
}

func (nfs *NetworkfilterServer) DisableDuplicationGen(ctx context.Context, req *nf.DisableTcRequest) (*nf.Response, error) {
	ns := req.GetNamespace()
	ingrEgrControl := req.GetTrafficDirection()
	if ns == "" {
		ns = "HOST"
	}
	switch iFace := req.GetInterface(); iFace {
	case "DOCKER":
		return nfs.disableDuplGenResponse(req, ns, "docker0", ingrEgrControl)
	case "CNI":
		return nfs.disableDuplGenResponse(req, ns, "cni0", ingrEgrControl)
	case "LO":
		return nfs.disableDuplGenResponse(req, ns, "lo", ingrEgrControl)
	case "ALL":
		return nfs.disableAllDuplGenResponse(req, ns, ingrEgrControl)
	case "ETH":
		if err := nfs.detachDuplGenEth(ns, ingrEgrControl); err != nil {
			return nil, grpcErrors.InternalGrpcError("failed to detach eth filter(s): %v", req, err)
		}
		message := fmt.Sprintf("eth filter(s) in namespace %s detached successfully", ns)
		return &nf.Response{Success: true, Message: message}, nil
	default:
		return nfs.disableDuplGenResponse(req, ns, iFace, ingrEgrControl)
	}
}
