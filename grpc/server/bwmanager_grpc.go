package server

import (
	"context"
	"fmt"

	grpcErrors "github.com/philipab/ebpf-proto/grpc/grpc-errors"
	nf "github.com/philipab/ebpf-proto/grpc/protos"
	"google.golang.org/grpc/codes"
)

func (nfs *NetworkfilterServer) EnableBandwidthManager(ctx context.Context, req *nf.BWRequest) (*nf.Response, error) {
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
		return nfs.enableBwManagerResponse(req, ns, "docker0")
	case "CNI":
		return nfs.enableBwManagerResponse(req, ns, "cni0")
	case "LO":
		return nfs.enableBwManagerResponse(req, ns, "lo")
	case "ALL":
		return nfs.enableAllBwResponse(req, ns)
	case "ETH":
		if err := nfs.attachBandwidthManagerEth(req); err != nil {
			return nil, grpcErrors.InternalGrpcError("failed to attach eth filter(s): %v", req, err)
		}
		message := fmt.Sprintf("eth filter(s) in namespace %s attached successfully", ns)
		return &nf.Response{Success: true, Message: message}, nil
	default:
		return nfs.enableBwManagerResponse(req, ns, iFace)
	}
}

func (nfs *NetworkfilterServer) DisableBandwidthManager(ctx context.Context, req *nf.DisableTcRequest) (*nf.Response, error) {
	ns := req.GetNamespace()
	ingrEgrControl := req.GetTrafficDirection()
	if ns == "" {
		ns = "HOST"
	}
	switch iFace := req.GetInterface(); iFace {
	case "DOCKER":
		return nfs.disableBwManagerResponse(req, ns, "docker0", ingrEgrControl)
	case "CNI":
		return nfs.disableBwManagerResponse(req, ns, "cni0", ingrEgrControl)
	case "LO":
		return nfs.disableBwManagerResponse(req, ns, "lo", ingrEgrControl)
	case "ALL":
		return nfs.disableAllBwResponse(req, ns, ingrEgrControl)
	case "ETH":
		if err := nfs.detachBwEth(ns, ingrEgrControl); err != nil {
			return nil, grpcErrors.InternalGrpcError("failed to detach eth filter(s): %v", req, err)
		}
		message := fmt.Sprintf("eth filter(s) in namespace %s detached successfully", ns)
		return &nf.Response{Success: true, Message: message}, nil
	default:
		return nfs.disableBwManagerResponse(req, ns, iFace, ingrEgrControl)
	}
}
