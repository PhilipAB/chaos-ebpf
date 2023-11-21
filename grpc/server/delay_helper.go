package server

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/florianl/go-tc/core"
	"github.com/philipab/ebpf-proto/ebpf/delay"
	grpcErrors "github.com/philipab/ebpf-proto/grpc/grpc-errors"
	nsswitcher "github.com/philipab/ebpf-proto/grpc/ns-switcher"
	nf "github.com/philipab/ebpf-proto/grpc/protos"
	progrFilter "github.com/philipab/ebpf-proto/grpc/server/filter"
)

const PROGRAM_TYPE_DELAY = "delayGenerator"

/**************************************************************************************************************
 * Enable helper functions
 *
 * The following functions generate return statements for the enable delay generator RPC
 **************************************************************************************************************/

func (nfs *NetworkfilterServer) enableDelayGenResponse(req *nf.DelayRequest, ns string, iFaceName string) (*nf.Response, error) {
	if err := nfs.attachDelayGen(iFaceName, req); err != nil {
		return nil, grpcErrors.EbpfAttachDetachGrpcError(req, "attach", ns, iFaceName, err)
	}
	message := fmt.Sprintf("delay generator for interface %s in namespace %s enabled successfully.", iFaceName, ns)
	return &nf.Response{Success: true, Message: message}, nil
}

func (nfs *NetworkfilterServer) enableAllDelayGenResponse(req *nf.DelayRequest, ns string) (*nf.Response, error) {
	var successfulAttachments []string
	var failedAttachments []string
	interfaces := []string{"docker0", "cni0", "lo"}
	for _, iFace := range interfaces {
		if err := nfs.attachDelayGen(iFace, req); err != nil {
			log.Printf("failed attaching interface %s in namespace %s: %v", iFace, ns, err)
			failedAttachments = append(failedAttachments, iFace)
		} else {
			successfulAttachments = append(successfulAttachments, iFace)
		}
	}
	err := nfs.attachDelayGenEth(req)
	if err != nil {
		log.Printf("failed attaching eth interfaces in namespace %s: %v", ns, err)
		failedAttachments = append(failedAttachments, "eth")
	} else {
		successfulAttachments = append(successfulAttachments, "eth")
	}

	// string join handles empty/not initialized arrays gracefully
	message := fmt.Sprintf("delay generator(s) for interface(s) %s in namespace %s enabled successfully.", strings.Join(successfulAttachments, ", "), ns)
	grpcErr := grpcErrors.AttachDetachAllGrpcError(req, "attach", ns, strings.Join(failedAttachments, ", "))
	if len(failedAttachments) == 0 {
		return &nf.Response{Success: true, Message: message}, nil
	} else if len(successfulAttachments) > 0 {
		return &nf.Response{Success: false, Message: message}, grpcErr
	} else { // no delay generators were attached successfully
		return nil, grpcErr
	}
}

/**************************************************************************************************************
 * Disable helper functions
 *
 * The following functions generate return statements for the disable trafficshaper RPC
 **************************************************************************************************************/

func (nfs *NetworkfilterServer) disableDelayGenResponse(req *nf.DisableRequest, ns string, iFaceName string) (*nf.Response, error) {
	if err := nfs.detachDelayGen(iFaceName, ns); err != nil {
		return nil, grpcErrors.EbpfAttachDetachGrpcError(req, "detach", ns, iFaceName, err)
	}
	message := fmt.Sprintf("delay generator for interface %s in namespace %s disabled successfully.", iFaceName, ns)
	return &nf.Response{Success: true, Message: message}, nil
}

func (nfs *NetworkfilterServer) disableAllDelayGenResponse(req *nf.DisableRequest, ns string) (*nf.Response, error) {
	var successfulDetachments []string
	var failedDetachments []string
	interfaces := []string{"docker0", "cni0", "lo"}
	for _, iFace := range interfaces {
		if err := nfs.detachDelayGen(iFace, ns); err != nil {
			log.Printf("failed detaching interface %s in namespace %s: %v", iFace, ns, err)
			failedDetachments = append(failedDetachments, iFace)
		} else {
			successfulDetachments = append(successfulDetachments, iFace)
		}
	}
	err := nfs.detachDelayGenEth(ns)
	if err != nil {
		log.Printf("failed detaching eth interfaces in namespace %s: %v", ns, err)
		failedDetachments = append(failedDetachments, "eth")
	} else {
		successfulDetachments = append(successfulDetachments, "eth")
	}

	// string join handles empty/not initialized arrays gracefully
	message := fmt.Sprintf("delay generators for interfaces %s in namespace %s disabled successfully.", strings.Join(successfulDetachments, ", "), ns)
	grpcErr := grpcErrors.AttachDetachAllGrpcError(req, "detach", ns, strings.Join(failedDetachments, ", "))
	if len(failedDetachments) == 0 {
		return &nf.Response{Success: true, Message: message}, nil
	} else if len(successfulDetachments) > 0 {
		return &nf.Response{Success: false, Message: message}, grpcErr
	} else { // no filters were detached successfully
		return nil, grpcErr
	}
}

/**************************************************************************************************************
 * Attach delay generator helper functions
 *
 * The following functions hold the logic to attach delay generators
 **************************************************************************************************************/

func (nfs *NetworkfilterServer) attachDelayGen(nwInterfaceName string, req *nf.DelayRequest) error {
	newObjs := delay.DelayGenObjectsWrapper{}
	if err := delay.LoadDelayGenObjectsWrapper(&newObjs, nil); err != nil {
		return fmt.Errorf("failed to load eBPF objects: %v", err)
	}
	// Before attaching the program, we need to update the maps!
	filterObj := progrFilter.ConvertDelayGenToFilterMapSpecs(&newObjs)
	if err := progrFilter.UpdateFilterMaps(req.GetFilter(), filterObj); err != nil {
		return fmt.Errorf("failed initializing/updating ebpf maps: %v", err)
	}
	var key uint32 = 0
	var delay uint32
	if req.Delay != nil {
		delay = req.GetDelay()
	} else {
		// Set default delay rate to 500ms
		delay = 500
	}
	// Flag 0 on update refers to UpdateAny and creates a new element or updates an existing one
	if err := newObjs.DelayMap.Update(&key, &delay, 0); err != nil {
		return fmt.Errorf("error updating delay map: %v", err)
	}
	if req.Jitter != nil {
		jitter := req.GetJitter()
		if err := newObjs.JitterMap.Update(&key, &jitter, 0); err != nil {
			return fmt.Errorf("error updating jitter map: %v", err)
		}
	}
	if req.DropHorizon != nil {
		dropHorizon := req.GetDropHorizon()
		if err := newObjs.DropHorizonMap.Update(&key, &dropHorizon, 0); err != nil {
			return fmt.Errorf("error updating drop_horizon map: %v", err)
		}
	}
	defer newObjs.Close()
	ns := req.GetFilter().GetNamespace()
	// handle (unique identifier)
	var handle uint32 = 0x00000004
	//info (fourth highest filter priority + process all protocols)
	var info uint32 = core.BuildHandle(0x0004, 0x0300)
	log.Printf("current info: %d", info)
	// true, because delay generator is only applicable to egress
	tcFilter, trafficDirection, err := nfs.attachTc(ns, nwInterfaceName, newObjs.EgressDelay, true, handle, info)
	if err != nil {
		return err
	}
	nfs.tcPrograms[PROGRAM_TYPE_DELAY+trafficDirection+ns+nwInterfaceName] = tcFilter
	nfs.delayGenEbpfPrograms[trafficDirection+ns+nwInterfaceName] = &newObjs
	return nil
}

func (nfs *NetworkfilterServer) attachDelayGenEth(req *nf.DelayRequest) error {
	nsSwitcher, err := switchNetworkNamespace(req.GetFilter().GetNamespace())
	if err != nil {
		return err
	}
	if nsSwitcher != nil {
		defer nsSwitcher.Close()
	}

	// Enumerate all network interfaces.
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Failed to enumerate network interfaces: %s", err)
		return err
	}
	for _, iface := range interfaces {
		if strings.HasPrefix(iface.Name, "eth") || strings.HasPrefix(iface.Name, "enp") {
			err := nfs.attachDelayGen(iface.Name, req)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

/**************************************************************************************************************
 * Detach delay generator helper functions
 *
 * The following functions hold the logic to detach delay generators
 **************************************************************************************************************/

func (nfs *NetworkfilterServer) detachDelayGen(ifaceName string, ns string) error {
	// newObjs := delay.DelayGenObjectsWrapper{}
	// if err := delay.LoadDelayGenObjectsWrapper(&newObjs, nil); err != nil {
	// 	return fmt.Errorf("failed to load eBPF objects: %v", err)
	// }
	// defer newObjs.Close()
	// fd := uint32(newObjs.EgressDelay.FD())
	trafficDirectionString := "egress"
	filterKey := trafficDirectionString + ns + ifaceName
	delayGenObj, ok := nfs.delayGenEbpfPrograms[filterKey]
	if !ok || delayGenObj == nil {
		return fmt.Errorf("failed to load eBPF objects for namespace %s, interface %s, traffic direction %s", ns, ifaceName, trafficDirectionString)
	}
	defer delayGenObj.Close()
	delete(nfs.delayGenEbpfPrograms, filterKey)

	// only applicable for egress ... therefore always try to detach egress
	return nfs.detachTc(ifaceName, ns, true, PROGRAM_TYPE_DELAY)
}

func (nfs *NetworkfilterServer) detachDelayGenEth(namespace string) error {
	// Enumerate all network interfaces.
	nsSwitcher, err := nsswitcher.SwitchToHostNamespace()
	if err != nil {
		return fmt.Errorf("failed to switch to host's network namespace: %v", err)
	}
	defer nsSwitcher.Close()
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Failed to enumerate network interfaces: %s", err)
		return err
	}
	for _, iface := range interfaces {
		if strings.HasPrefix(iface.Name, "eth") || strings.HasPrefix(iface.Name, "enp") {
			nfs.detachDelayGen(iface.Name, namespace)
		}
	}
	return nil
}
