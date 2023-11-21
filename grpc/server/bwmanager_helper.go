package server

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/florianl/go-tc/core"
	"github.com/philipab/ebpf-proto/ebpf/bwmanager"
	grpcErrors "github.com/philipab/ebpf-proto/grpc/grpc-errors"
	nsswitcher "github.com/philipab/ebpf-proto/grpc/ns-switcher"
	nf "github.com/philipab/ebpf-proto/grpc/protos"
	progrFilter "github.com/philipab/ebpf-proto/grpc/server/filter"
)

const PROGRAM_TYPE_BWMANAGER = "bwmanager"

/**************************************************************************************************************
 * Enable helper functions
 *
 * The following functions generate return statements for the enable bw manager RPC
 **************************************************************************************************************/

func (nfs *NetworkfilterServer) enableBwManagerResponse(req *nf.BWRequest, ns string, iFaceName string) (*nf.Response, error) {
	if err := nfs.attachBandwidthManager(iFaceName, req); err != nil {
		return nil, grpcErrors.EbpfAttachDetachGrpcError(req, "attach", ns, iFaceName, err)
	}
	message := fmt.Sprintf("bw manager for interface %s in namespace %s enabled successfully.", iFaceName, ns)
	return &nf.Response{Success: true, Message: message}, nil
}

func (nfs *NetworkfilterServer) enableAllBwResponse(req *nf.BWRequest, ns string) (*nf.Response, error) {
	var successfulAttachments []string
	var failedAttachments []string
	interfaces := []string{"docker0", "cni0", "lo"}
	for _, iFace := range interfaces {
		if err := nfs.attachBandwidthManager(iFace, req); err != nil {
			log.Printf("failed attaching interface %s in namespace %s: %v", iFace, ns, err)
			failedAttachments = append(failedAttachments, iFace)
		} else {
			successfulAttachments = append(successfulAttachments, iFace)
		}
	}
	err := nfs.attachBandwidthManagerEth(req)
	if err != nil {
		log.Printf("failed attaching eth interfaces in namespace %s: %v", ns, err)
		failedAttachments = append(failedAttachments, "eth")
	} else {
		successfulAttachments = append(successfulAttachments, "eth")
	}

	// string join handles empty/not initialized arrays gracefully
	message := fmt.Sprintf("bw manager(s) for interface(s) %s in namespace %s enabled successfully.", strings.Join(successfulAttachments, ", "), ns)
	grpcErr := grpcErrors.AttachDetachAllGrpcError(req, "attach", ns, strings.Join(failedAttachments, ", "))
	if len(failedAttachments) == 0 {
		return &nf.Response{Success: true, Message: message}, nil
	} else if len(successfulAttachments) > 0 {
		return &nf.Response{Success: false, Message: message}, grpcErr
	} else { // no bw managers were attached successfully
		return nil, grpcErr
	}
}

/**************************************************************************************************************
 * Disable helper functions
 *
 * The following functions generate return statements for the disable trafficshaper RPC
 **************************************************************************************************************/

func (nfs *NetworkfilterServer) disableBwManagerResponse(req *nf.DisableTcRequest, ns string, iFaceName string, trafficDirection bool) (*nf.Response, error) {
	if err := nfs.detachBw(iFaceName, ns, trafficDirection); err != nil {
		return nil, grpcErrors.EbpfAttachDetachGrpcError(req, "detach", ns, iFaceName, err)
	}
	message := fmt.Sprintf("bw manager for interface %s in namespace %s disabled successfully.", iFaceName, ns)
	return &nf.Response{Success: true, Message: message}, nil
}

func (nfs *NetworkfilterServer) disableAllBwResponse(req *nf.DisableTcRequest, ns string, trafficDirection bool) (*nf.Response, error) {
	var successfulDetachments []string
	var failedDetachments []string
	interfaces := []string{"docker0", "cni0", "lo"}
	for _, iFace := range interfaces {
		if err := nfs.detachBw(iFace, ns, trafficDirection); err != nil {
			log.Printf("failed detaching interface %s in namespace %s: %v", iFace, ns, err)
			failedDetachments = append(failedDetachments, iFace)
		} else {
			successfulDetachments = append(successfulDetachments, iFace)
		}
	}
	err := nfs.detachBwEth(ns, trafficDirection)
	if err != nil {
		log.Printf("failed detaching eth interfaces in namespace %s: %v", ns, err)
		failedDetachments = append(failedDetachments, "eth")
	} else {
		successfulDetachments = append(successfulDetachments, "eth")
	}

	// string join handles empty/not initialized arrays gracefully
	message := fmt.Sprintf("bw managers for interfaces %s in namespace %s disabled successfully.", strings.Join(successfulDetachments, ", "), ns)
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
 * Attach bandwidth manager helper functions
 *
 * The following functions hold the logic to attach bandwidth managers
 **************************************************************************************************************/

func (nfs *NetworkfilterServer) attachBandwidthManager(nwInterfaceName string, req *nf.BWRequest) error {
	newObjs := bwmanager.BwObjectsWrapper{}
	if err := bwmanager.LoadBwObjectsWrapper(&newObjs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf"},
	}); err != nil {
		return fmt.Errorf("failed to load eBPF objects: %v", err)
	}
	// Before attaching the program, we need to update the maps!
	filterObj := progrFilter.ConvertBwmanagerToFilterMapSpecs(&newObjs)
	if err := progrFilter.UpdateFilterMaps(req.GetFilter(), filterObj); err != nil {
		return fmt.Errorf("failed initializing/updating ebpf maps: %v", err)
	}
	var key uint32 = 0
	var value uint64
	if req.Bandwidth != nil {
		value = req.GetBandwidth()
	} else {
		// Set default bandwidth to 1MB/s
		value = uint64(1000000)
	}
	// Flag 0 on update refers to UpdateAny and creates a new element or updates an existing one
	if err := newObjs.BytesPerSecond.Update(&key, &value, 0); err != nil {
		return fmt.Errorf("error updating bytes_per_second map: %v", err)
	}
	// defer newObjs.Close()
	ns := req.GetFilter().GetNamespace()
	// handle (unique identifier)
	var handle uint32 = 0x00000001
	//info (highest filter priority + process all protocols)
	var info uint32 = core.BuildHandle(0x0001, 0x0300)
	log.Printf("current info: %d", info)
	tcFilter, trafficDirection, err := nfs.attachTc(ns, nwInterfaceName, newObjs.TcLimitBandwidth, req.GetTrafficDirection(), handle, info)
	if err != nil {
		return err
	}
	nfs.tcPrograms[PROGRAM_TYPE_BWMANAGER+trafficDirection+ns+nwInterfaceName] = tcFilter
	if ebpfProgr, ok := nfs.bwManagerEbpfPrograms[trafficDirection+ns+nwInterfaceName]; ok {
		// Close old eBPF reference!
		ebpfProgr.Close()
	}
	nfs.bwManagerEbpfPrograms[trafficDirection+ns+nwInterfaceName] = &newObjs
	if duplGenObj, ok := nfs.duplGenEbpfPrograms[trafficDirection+ns+nwInterfaceName]; ok {
		var fd uint32 = uint32(duplGenObj.DuplicatePkt.FD())
		if err := newObjs.NextProgrFd.Update(&key, &fd, 0); err != nil {
			log.Print("failed to chain duplicate generator after bw manager")
		}
	}
	return nil
}

func (nfs *NetworkfilterServer) attachBandwidthManagerEth(req *nf.BWRequest) error {
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
			err := nfs.attachBandwidthManager(iface.Name, req)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

/**************************************************************************************************************
 * Detach bandwidth manager helper functions
 *
 * The following functions hold the logic to detach bandwidth managers
 **************************************************************************************************************/

func (nfs *NetworkfilterServer) detachBw(ifaceName string, ns string, trafficDirection bool) error {
	// newObjs := bwmanager.BwObjectsWrapper{}
	// if err := bwmanager.LoadBwObjectsWrapper(&newObjs, &ebpf.CollectionOptions{
	// 	Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf"},
	// }); err != nil {
	// 	return fmt.Errorf("failed to load eBPF objects: %v", err)
	// }
	// defer newObjs.Close()
	// fd := uint32(newObjs.TcLimitBandwidth.FD())
	trafficDirectionString := getTrafficDirectionString(trafficDirection)
	filterKey := trafficDirectionString + ns + ifaceName
	bwManagerObj, ok := nfs.bwManagerEbpfPrograms[filterKey]
	if !ok || bwManagerObj == nil {
		return fmt.Errorf("failed to load eBPF objects for namespace %s, interface %s, traffic direction %s", ns, ifaceName, trafficDirectionString)
	}
	defer bwManagerObj.Close()
	delete(nfs.bwManagerEbpfPrograms, filterKey)

	// return nfs.detachTc(ifaceName, ns, trafficDirection, PROGRAM_TYPE_BWMANAGER, fd)
	return nfs.detachTc(ifaceName, ns, trafficDirection, PROGRAM_TYPE_BWMANAGER)
}

func (nfs *NetworkfilterServer) detachBwEth(namespace string, ingressEgressControl bool) error {
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
			nfs.detachBw(iface.Name, namespace, ingressEgressControl)
		}
	}
	return nil
}
