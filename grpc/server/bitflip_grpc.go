package server

import (
	"context"
	"fmt"

	grpcErrors "github.com/philipab/ebpf-proto/grpc/grpc-errors"
	nf "github.com/philipab/ebpf-proto/grpc/protos"
	"google.golang.org/grpc/codes"
)

func (nfs *NetworkfilterServer) EnableBitflipGen(ctx context.Context, req *nf.BitflipRequest) (*nf.Response, error) {
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
		return nfs.enableBitflipGenResponse(req, ns, "docker0")
	case "CNI":
		return nfs.enableBitflipGenResponse(req, ns, "cni0")
	case "LO":
		return nfs.enableBitflipGenResponse(req, ns, "lo")
	case "ALL":
		return nfs.enableAllBitflipGenResponse(req, ns)
	case "ETH":
		if err := nfs.attachBitflipGenEth(req); err != nil {
			return nil, grpcErrors.InternalGrpcError("failed to attach eth filter(s): %v", req, err)
		}
		message := fmt.Sprintf("eth filter(s) in namespace %s attached successfully", ns)
		return &nf.Response{Success: true, Message: message}, nil
	default:
		return nfs.enableBitflipGenResponse(req, ns, iFace)
	}
}

func (nfs *NetworkfilterServer) DisableBitflipGen(ctx context.Context, req *nf.DisableTcRequest) (*nf.Response, error) {
	ns := req.GetNamespace()
	ingrEgrControl := req.GetTrafficDirection()
	if ns == "" {
		ns = "HOST"
	}
	switch iFace := req.GetInterface(); iFace {
	case "DOCKER":
		return nfs.disableBitflipGenResponse(req, ns, "docker0", ingrEgrControl)
	case "CNI":
		return nfs.disableBitflipGenResponse(req, ns, "cni0", ingrEgrControl)
	case "LO":
		return nfs.disableBitflipGenResponse(req, ns, "lo", ingrEgrControl)
	case "ALL":
		return nfs.disableAllBitflipGenResponse(req, ns, ingrEgrControl)
	case "ETH":
		if err := nfs.detachBitflipGenEth(ns, ingrEgrControl); err != nil {
			return nil, grpcErrors.InternalGrpcError("failed to detach eth filter(s): %v", req, err)
		}
		message := fmt.Sprintf("eth filter(s) in namespace %s detached successfully", ns)
		return &nf.Response{Success: true, Message: message}, nil
	default:
		return nfs.disableBitflipGenResponse(req, ns, iFace, ingrEgrControl)
	}
}
