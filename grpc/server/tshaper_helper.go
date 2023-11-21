package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/philipab/ebpf-proto/ebpf/tshaper"
	grpcErrors "github.com/philipab/ebpf-proto/grpc/grpc-errors"
	nsswitcher "github.com/philipab/ebpf-proto/grpc/ns-switcher"
	nf "github.com/philipab/ebpf-proto/grpc/protos"
	progrFilter "github.com/philipab/ebpf-proto/grpc/server/filter"
)

/**************************************************************************************************************
 * Enable helper functions
 *
 * The following functions generate return statements for the enable trafficshaper RPC
 **************************************************************************************************************/

func (nfs *NetworkfilterServer) enableNetworkFilterResponse(req *nf.EnableTrafficShaperRequest, ns string, iFaceName string) (*nf.Response, error) {
	if err := nfs.attachFilter(iFaceName, req); err != nil {
		return nil, grpcErrors.EbpfAttachDetachGrpcError(req, "attach", ns, iFaceName, err)
	}
	message := fmt.Sprintf("filter for interface %s in namespace %s enabled successfully.", iFaceName, ns)
	return &nf.Response{Success: true, Message: message}, nil
}

func (nfs *NetworkfilterServer) enableAllTsResponse(req *nf.EnableTrafficShaperRequest, ns string) (*nf.Response, error) {
	var successfulAttachments []string
	var failedAttachments []string
	interfaces := []string{"docker0", "cni0", "lo"}
	for _, iFace := range interfaces {
		if err := nfs.attachFilter(iFace, req); err != nil {
			log.Printf("failed attaching interface %s in namespace %s: %v", iFace, ns, err)
			failedAttachments = append(failedAttachments, iFace)
		} else {
			successfulAttachments = append(successfulAttachments, iFace)
		}
	}
	err := nfs.attachEthFilter(req)
	if err != nil {
		log.Printf("failed attaching eth interfaces in namespace %s: %v", ns, err)
		failedAttachments = append(failedAttachments, "eth")
	} else {
		successfulAttachments = append(successfulAttachments, "eth")
	}

	// string join handles empty/not initialized arrays gracefully
	message := fmt.Sprintf("filter for interface(s) %s in namespace %s enabled successfully.", strings.Join(successfulAttachments, ", "), ns)
	grpcErr := grpcErrors.AttachDetachAllGrpcError(req, "attach", ns, strings.Join(failedAttachments, ", "))
	if len(failedAttachments) == 0 {
		return &nf.Response{Success: true, Message: message}, nil
	} else if len(successfulAttachments) > 0 {
		return &nf.Response{Success: false, Message: message}, grpcErr
	} else { // no filters were attached successfully
		return nil, grpcErr
	}
}

/**************************************************************************************************************
 * Disable helper functions
 *
 * The following functions generate return statements for the disable trafficshaper RPC
 **************************************************************************************************************/

func (nfs *NetworkfilterServer) disableNetworkFilterResponse(req *nf.DisableRequest, ns string, iFaceName string) (*nf.Response, error) {
	if err := nfs.detachFilter(iFaceName, ns); err != nil {
		return nil, grpcErrors.EbpfAttachDetachGrpcError(req, "detach", ns, iFaceName, err)
	}
	message := fmt.Sprintf("filter for interface %s in namespace %s disabled successfully.", iFaceName, ns)
	return &nf.Response{Success: true, Message: message}, nil
}

func (nfs *NetworkfilterServer) disableAllTsResponse(req *nf.DisableRequest, ns string) (*nf.Response, error) {
	var successfulDetachments []string
	var failedDetachments []string
	interfaces := []string{"docker0", "cni0", "lo"}
	for _, iFace := range interfaces {
		if err := nfs.detachFilter(iFace, ns); err != nil {
			log.Printf("failed detaching interface %s in namespace %s: %v", iFace, ns, err)
			failedDetachments = append(failedDetachments, iFace)
		} else {
			successfulDetachments = append(successfulDetachments, iFace)
		}
	}
	err := nfs.detachEthFilter(ns)
	if err != nil {
		log.Printf("failed detaching eth interfaces in namespace %s: %v", ns, err)
		failedDetachments = append(failedDetachments, "eth")
	} else {
		successfulDetachments = append(successfulDetachments, "eth")
	}

	// string join handles empty/not initialized arrays gracefully
	message := fmt.Sprintf("filter for interfaces %s in namespace %s disabled successfully.", strings.Join(successfulDetachments, ", "), ns)
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
 * Attach traffic shaper helper functions
 *
 * The following functions hold the logic to attach traffic shapers
 **************************************************************************************************************/

func (nfs *NetworkfilterServer) attachFilter(ifaceName string, req *nf.EnableTrafficShaperRequest) error {
	nsSwitcher, err := switchNetworkNamespace(req.GetFilter().GetNamespace())
	if err != nil {
		return err
	}
	if nsSwitcher != nil {
		defer nsSwitcher.Close()
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("failed to lookup network interface %s: %v", ifaceName, err)
	}

	if err := nfs.updateReferences(iface, ifaceName, req); err != nil {
		return err
	}

	return nil
}

func (nfs *NetworkfilterServer) attachEthFilter(req *nf.EnableTrafficShaperRequest) error {
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
			if err := nfs.updateReferences(&iface, iface.Name, req); err != nil {
				return err
			}
		}
	}
	return nil
}

func (nfs *NetworkfilterServer) updateReferences(iface *net.Interface, ifaceName string, req *nf.EnableTrafficShaperRequest) error {
	namespace := req.GetFilter().GetNamespace()
	newObjs := tshaper.TshaperObjectsWrapper{}
	if err := tshaper.LoadTshaperObjectsWrapper(&newObjs, nil); err != nil {
		return fmt.Errorf("failed to load eBPF objects: %v", err)
	}
	if namespace != "" {
		if _, ok := nfs.tShaperEbpfPrograms[namespace+ifaceName]; ok {
			log.Printf("Updating traffic shaper for namespace %s and interface %s...", namespace, ifaceName)
			if err := nfs.detachFilter(ifaceName, namespace); err != nil {
				return fmt.Errorf("failed to update traffic shaper for namespace %s and interface %s - detachment of old programm failed: %v", namespace, ifaceName, err)
			}
		} else {
			log.Printf("Adding traffic shaper for namespace %s and interface %s...", namespace, ifaceName)
		}
		nfs.tShaperEbpfPrograms[namespace+ifaceName] = &newObjs
	} else {
		if _, ok := nfs.tShaperEbpfPrograms["HOST"+ifaceName]; ok {
			log.Printf("Updating traffic shaper for namespace HOST and interface %s...", ifaceName)
			if err := nfs.detachFilter(ifaceName, "HOST"); err != nil {
				return fmt.Errorf("failed to update traffic shaper for namespace HOST and interface %s - detachment of old programm failed: %v", ifaceName, err)
			}
		} else {
			log.Printf("Adding traffic shaper for namespace HOST and interface %s...", ifaceName)
		}
		nfs.tShaperEbpfPrograms["HOST"+ifaceName] = &newObjs
	}

	// Before attaching the program, we need to update the maps!
	filterObj := progrFilter.ConvertTshaperToFilterMapSpecs(&newObjs)
	if err := progrFilter.UpdateFilterMaps(req.GetFilter(), filterObj); err != nil {
		return fmt.Errorf("failed initializing/updating ebpf maps: %v", err)
	}
	key := uint32(0)
	var value uint32
	if req.DropRate != nil {
		value = req.GetDropRate()
	} else {
		// Set default drop rate value
		value = uint32(5)
	}
	// Flag 0 on update refers to UpdateAny and creates a new element or updates an existing one
	if err := newObjs.DropRate.Update(&key, &value, 0); err != nil {
		return fmt.Errorf("failed updating drop_rate map: %v", err)
	}

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   newObjs.XdpTrafficShaper,
		Interface: iface.Index,
	})
	if err != nil {
		return fmt.Errorf("could not attach XDP program: %v", err)
	}

	nfs.attachedLinks[ifaceName] = l
	log.Printf("Attached XDP program to interface %q (index %d)", iface.Name, iface.Index)
	return nil
}

/**************************************************************************************************************
 * Detach traffic shaper helper functions
 *
 * The following functions hold the logic to detach traffic shapers
 **************************************************************************************************************/

func (nfs *NetworkfilterServer) detachFilter(ifaceName string, namespace string) error {
	link, ok := nfs.attachedLinks[ifaceName]
	if ok {
		if err := link.Close(); err != nil {
			return err
		}
		delete(nfs.attachedLinks, ifaceName)
	}
	if _, ok := nfs.tShaperEbpfPrograms[namespace+ifaceName]; ok {
		if err := nfs.tShaperEbpfPrograms[namespace+ifaceName].Close(); err != nil {
			return err
		}
		delete(nfs.tShaperEbpfPrograms, namespace+ifaceName)
	} else if _, ok := nfs.tShaperEbpfPrograms["HOST"+ifaceName]; ok && namespace == "" {
		if err := nfs.tShaperEbpfPrograms["HOST"+ifaceName].Close(); err != nil {
			return err
		}
		delete(nfs.tShaperEbpfPrograms, "HOST"+ifaceName)
	} else {
		return fmt.Errorf("failed to close eBPF program for namespace %s and interface %s - not found", namespace, ifaceName)
	}
	if !ok {
		return fmt.Errorf("failed to close eBPF program link for namespace %s and interface %s - not found", namespace, ifaceName)
	}
	return nil
}

func (nfs *NetworkfilterServer) detachEthFilter(namespace string) error {
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
			if err := nfs.detachFilter(iface.Name, namespace); err != nil {
				return err
			}
		}
	}
	return nil
}

/**************************************************************************************************************
 * Control Ticker helper
 *
 * The following functions create and run a ticker for debugging purposes
 **************************************************************************************************************/

func (nfs *NetworkfilterServer) runTicker(ctx context.Context, iface string, namespace string) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if namespace == "" {
				namespace = "HOST"
			}
			if obj, ok := nfs.tShaperEbpfPrograms[namespace+iface]; ok && obj != nil {
				total, dropped, err := getCounters(nfs.tShaperEbpfPrograms[namespace+iface].TotalPktsMap, nfs.tShaperEbpfPrograms[namespace+iface].DroppedPktsMap)
				if err != nil {
					log.Printf("Error reading counters: %s", err)
					continue
				}
				log.Printf("Currently processed packets: %d", total)
				log.Printf("Currently dropped packets: %d", dropped)
			}
		case <-ctx.Done():
			return
		}
	}
}

func getCounters(totalMap *ebpf.Map, droppedMap *ebpf.Map) (uint32, uint32, error) {
	var key uint32
	var total, dropped uint32

	if err := totalMap.Lookup(&key, &total); err != nil {
		return 0, 0, fmt.Errorf("error reading total packets counter: %w", err)
	}

	if err := droppedMap.Lookup(&key, &dropped); err != nil {
		return 0, 0, fmt.Errorf("error reading dropped packets counter: %w", err)
	}

	return total, dropped, nil
}
