package server

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/florianl/go-tc/core"
	"github.com/philipab/ebpf-proto/ebpf/bitflip"
	grpcErrors "github.com/philipab/ebpf-proto/grpc/grpc-errors"
	nsswitcher "github.com/philipab/ebpf-proto/grpc/ns-switcher"
	nf "github.com/philipab/ebpf-proto/grpc/protos"
	progrFilter "github.com/philipab/ebpf-proto/grpc/server/filter"
)

const PROGRAM_TYPE_BITFLIP = "bitflipGenerator"

/**************************************************************************************************************
 * Enable helper functions
 *
 * The following functions generate return statements for the enable bitflip generator RPC
 **************************************************************************************************************/

func (nfs *NetworkfilterServer) enableBitflipGenResponse(req *nf.BitflipRequest, ns string, iFaceName string) (*nf.Response, error) {
	if err := nfs.attachBitflipGen(iFaceName, req); err != nil {
		return nil, grpcErrors.EbpfAttachDetachGrpcError(req, "attach", ns, iFaceName, err)
	}
	message := fmt.Sprintf("bitflip generator for interface %s in namespace %s enabled successfully.", iFaceName, ns)
	return &nf.Response{Success: true, Message: message}, nil
}

func (nfs *NetworkfilterServer) enableAllBitflipGenResponse(req *nf.BitflipRequest, ns string) (*nf.Response, error) {
	var successfulAttachments []string
	var failedAttachments []string
	interfaces := []string{"docker0", "cni0", "lo"}
	for _, iFace := range interfaces {
		if err := nfs.attachBitflipGen(iFace, req); err != nil {
			log.Printf("failed attaching interface %s in namespace %s: %v", iFace, ns, err)
			failedAttachments = append(failedAttachments, iFace)
		} else {
			successfulAttachments = append(successfulAttachments, iFace)
		}
	}
	err := nfs.attachBitflipGenEth(req)
	if err != nil {
		log.Printf("failed attaching eth interfaces in namespace %s: %v", ns, err)
		failedAttachments = append(failedAttachments, "eth")
	} else {
		successfulAttachments = append(successfulAttachments, "eth")
	}

	// string join handles empty/not initialized arrays gracefully
	message := fmt.Sprintf("bitflip generator(s) for interface(s) %s in namespace %s enabled successfully.", strings.Join(successfulAttachments, ", "), ns)
	grpcErr := grpcErrors.AttachDetachAllGrpcError(req, "attach", ns, strings.Join(failedAttachments, ", "))
	if len(failedAttachments) == 0 {
		return &nf.Response{Success: true, Message: message}, nil
	} else if len(successfulAttachments) > 0 {
		return &nf.Response{Success: false, Message: message}, grpcErr
	} else { // no bitflip generators were attached successfully
		return nil, grpcErr
	}
}

/**************************************************************************************************************
 * Disable helper functions
 *
 * The following functions generate return statements for the disable trafficshaper RPC
 **************************************************************************************************************/

func (nfs *NetworkfilterServer) disableBitflipGenResponse(req *nf.DisableTcRequest, ns string, iFaceName string, trafficDirection bool) (*nf.Response, error) {
	if err := nfs.detachBitflipGen(iFaceName, ns, trafficDirection); err != nil {
		return nil, grpcErrors.EbpfAttachDetachGrpcError(req, "detach", ns, iFaceName, err)
	}
	message := fmt.Sprintf("bitflip generator for interface %s in namespace %s disabled successfully.", iFaceName, ns)
	return &nf.Response{Success: true, Message: message}, nil
}

func (nfs *NetworkfilterServer) disableAllBitflipGenResponse(req *nf.DisableTcRequest, ns string, trafficDirection bool) (*nf.Response, error) {
	var successfulDetachments []string
	var failedDetachments []string
	interfaces := []string{"docker0", "cni0", "lo"}
	for _, iFace := range interfaces {
		if err := nfs.detachBitflipGen(iFace, ns, trafficDirection); err != nil {
			log.Printf("failed detaching interface %s in namespace %s: %v", iFace, ns, err)
			failedDetachments = append(failedDetachments, iFace)
		} else {
			successfulDetachments = append(successfulDetachments, iFace)
		}
	}
	err := nfs.detachBitflipGenEth(ns, trafficDirection)
	if err != nil {
		log.Printf("failed detaching eth interfaces in namespace %s: %v", ns, err)
		failedDetachments = append(failedDetachments, "eth")
	} else {
		successfulDetachments = append(successfulDetachments, "eth")
	}

	// string join handles empty/not initialized arrays gracefully
	message := fmt.Sprintf("bitflip generators for interfaces %s in namespace %s disabled successfully.", strings.Join(successfulDetachments, ", "), ns)
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
 * Attach bitflip generator helper functions
 *
 * The following functions hold the logic to attach bitflip generators
 **************************************************************************************************************/

func (nfs *NetworkfilterServer) attachBitflipGen(nwInterfaceName string, req *nf.BitflipRequest) error {
	newObjs := bitflip.BitflipGenObjectsWrapper{}
	if err := bitflip.LoadBitflipGenObjectsWrapper(&newObjs, nil); err != nil {
		return fmt.Errorf("failed to load eBPF objects: %v", err)
	}
	// Before attaching the program, we need to update the maps!
	filterObj := progrFilter.ConvertBitflipGenToFilterMapSpecs(&newObjs)
	if err := progrFilter.UpdateFilterMaps(req.GetFilter(), filterObj); err != nil {
		return fmt.Errorf("failed initializing/updating ebpf maps: %v", err)
	}
	var key uint32 = 0
	var value uint32
	if req.BitflipProbability != nil {
		value = req.GetBitflipProbability()
	} else {
		// Set default bitflip probability to 5%
		value = 5
	}
	// Flag 0 on update refers to UpdateAny and creates a new element or updates an existing one
	if err := newObjs.BitflipProbability.Update(&key, &value, 0); err != nil {
		return fmt.Errorf("error updating bitflip_probability map: %v", err)
	}
	var recalcEnabled uint8 = 0
	if req.RecalcChecksum != nil && req.GetRecalcChecksum() {
		recalcEnabled = 1
	}
	// Flag 0 on update refers to UpdateAny and creates a new element or updates an existing one
	if err := newObjs.RecalculateChecksum.Update(&key, &recalcEnabled, 0); err != nil {
		return fmt.Errorf("error updating recalculate_checksum map: %v", err)
	}
	defer newObjs.Close()
	ns := req.GetFilter().GetNamespace()
	// handle (unique identifier)
	var handle uint32 = 0x00000003
	//info (third highest filter priority + process all protocols)
	var info uint32 = core.BuildHandle(0x0003, 0x0300)
	log.Printf("current info: %d", info)
	tcFilter, trafficDirection, err := nfs.attachTc(ns, nwInterfaceName, newObjs.Bitflip, req.GetTrafficDirection(), handle, info)
	if err != nil {
		return err
	}
	nfs.tcPrograms[PROGRAM_TYPE_BITFLIP+trafficDirection+ns+nwInterfaceName] = tcFilter
	nfs.bitflipGenEbpfPrograms[trafficDirection+ns+nwInterfaceName] = &newObjs
	return nil
}

func (nfs *NetworkfilterServer) attachBitflipGenEth(req *nf.BitflipRequest) error {
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
			err := nfs.attachBitflipGen(iface.Name, req)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

/**************************************************************************************************************
 * Detach bitflip generator helper functions
 *
 * The following functions hold the logic to detach bitflip generators
 **************************************************************************************************************/

func (nfs *NetworkfilterServer) detachBitflipGen(ifaceName string, ns string, trafficDirection bool) error {
	// newObjs := bitflip.BitflipGenObjectsWrapper{}
	// if err := bitflip.LoadBitflipGenObjectsWrapper(&newObjs, nil); err != nil {
	// 	return fmt.Errorf("failed to load eBPF objects: %v", err)
	// }
	// defer newObjs.Close()
	// fd := uint32(newObjs.Bitflip.FD())
	trafficDirectionString := getTrafficDirectionString(trafficDirection)
	filterKey := trafficDirectionString + ns + ifaceName
	bitflipGenObj, ok := nfs.bitflipGenEbpfPrograms[filterKey]
	if !ok || bitflipGenObj == nil {
		return fmt.Errorf("failed to load eBPF objects for namespace %s, interface %s, traffic direction %s", ns, ifaceName, trafficDirectionString)
	}
	defer bitflipGenObj.Close()
	delete(nfs.bitflipGenEbpfPrograms, filterKey)

	return nfs.detachTc(ifaceName, ns, trafficDirection, PROGRAM_TYPE_BITFLIP)
}

func (nfs *NetworkfilterServer) detachBitflipGenEth(namespace string, ingressEgressControl bool) error {
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
			nfs.detachBitflipGen(iface.Name, namespace, ingressEgressControl)
		}
	}
	return nil
}
