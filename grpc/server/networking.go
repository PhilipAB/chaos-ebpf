package server

import (
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/mdlayher/netlink"
	nsswitcher "github.com/philipab/ebpf-proto/grpc/ns-switcher"
	"golang.org/x/sys/unix"
)

func switchNetworkNamespace(namespace string) (*nsswitcher.NamespaceSwitcher, error) {
	if namespace == "" || namespace == "HOST" {
		// By default, if no network namespace is provided, we switch to the host network namespace
		nsSwitcher, err := nsswitcher.SwitchToHostNamespace()
		if err != nil {
			return nil, fmt.Errorf("failed to switch to host's network namespace: %v", err)
		}
		return nsSwitcher, nil
	} else if namespace != "CONTAINER" {
		// Else, if specific network is specified, we switch to this one, as long as it is not the CONTAINER namespace
		nsSwitcher, err := nsswitcher.SwitchToNamedNamespace(namespace)
		if err != nil {
			return nil, fmt.Errorf("failed to switch to network namespace %s: %v", namespace, err)
		}
		return nsSwitcher, nil
	}
	// Else (if namespace == "CONTAINER") we stay on the current CONTAINER network namespace
	return nil, nil
}

func openTcConnection() (*tc.Tc, error) {
	// Open a netlink/tc connection to the Linux kernel. This connection is
	// used to manage the tc/qdisc and tc/filter to which
	// the eBPF program will be attached
	tcConnection, err := tc.Open(&tc.Config{})
	if err != nil {
		return nil, fmt.Errorf("could not open rtnetlink socket: %v", err)
	}

	// For enhanced error messages from the kernel, it is recommended to set
	// option `NETLINK_EXT_ACK`, which is supported since 4.12 kernel.
	//
	// If not supported, `unix.ENOPROTOOPT` is returned.
	if err := tcConnection.SetOption(netlink.ExtendedAcknowledge, true); err != nil {
		log.Printf("could not set option ExtendedAcknowledge: %v\n", err)
	}
	return tcConnection, nil
}

func (nfs *NetworkfilterServer) createClsactQdisc(ns string, iface *net.Interface) error {
	var err error
	if nfs.tcConnection == nil {
		nfs.tcConnection, err = openTcConnection()
		if err != nil {
			return err
		}
	}
	// Create a qdisc/clsact object that will be attached to the ingress part
	// of the networking interface.
	nfs.clsactQdisc = &tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC, // Allow IPv4 or IPv6
			Ifindex: uint32(iface.Index),
			Handle:  core.BuildHandle(tc.HandleRoot, 0),
			Parent:  tc.HandleIngress,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}

	// Attach the qdisc/clsact to the networking interface.
	if err := nfs.tcConnection.Qdisc().Replace(nfs.clsactQdisc); err != nil {
		return fmt.Errorf("could not assign clsact to %s: %v", iface.Name, err)
	}
	return nil
}

// Fair queueing qdisc to process delayed packets
func (nfs *NetworkfilterServer) createFqQdisc(ns string, iface *net.Interface) error {
	var err error
	if nfs.tcConnection == nil {
		nfs.tcConnection, err = openTcConnection()
		if err != nil {
			return err
		}
	}
	// configure default fq values:
	// Reference: https://man7.org/linux/man-pages/man8/tc-fq.8.html
	pLimit := uint32(10000)
	flowPLimit := uint32(100)

	nfs.fqQdisc = &tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC, // Allow IPv4 or IPv6
			Ifindex: uint32(iface.Index),
			Handle:  core.BuildHandle(0x123, 0),
			Parent:  tc.HandleRoot,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "fq",
			Fq: &tc.Fq{
				PLimit:     &pLimit,
				FlowPLimit: &flowPLimit,
			},
		},
	}

	// Attach the qdisc/fq to the networking interface.
	if err := nfs.tcConnection.Qdisc().Replace(nfs.fqQdisc); err != nil {
		return fmt.Errorf("could not assign fq to %s: %v", iface.Name, err)
	}
	return nil
}

// returns a tc filter object pointer, a string specifying the traffic direction and (potentionally) an error
// @ns: network namespace name
// @nwInterfaceName: network interface name
// @tcProgram: an ebpf program of TC type
// @ingressEgressControl: traffic direction for filter, true = egress traffic, else ingress traffic
// @handle: unique identifier for our filter ... should be different for different types of filters
// @info: upper 16 bits specify the priority, lower 16 bits the protocol ... ->
// e.g. core.BuildHandle(0x0001, 0x0300) would be priority = 0x0001 (= 1) and protocol (in network byte order!!!) = 0x0300 (=3)
func (nfs *NetworkfilterServer) attachTc(ns string, nwInterfaceName string, tcProgr *ebpf.Program, ingressEgressControl bool, handle uint32, info uint32) (*tc.Object, string, error) {
	nsSwitcher, err := switchNetworkNamespace(ns)
	if err != nil {
		return nil, "", err
	}
	if nsSwitcher != nil {
		defer nsSwitcher.Close()
	}

	iface, err := net.InterfaceByName(nwInterfaceName)
	if err != nil {
		return nil, "", fmt.Errorf("looking up network interface %s failed: %v", nwInterfaceName, err)
	}

	var trafficDirection string
	var trafficDirectionTcFilter uint32
	if ingressEgressControl {
		trafficDirection = "egress"
		trafficDirectionTcFilter = tc.HandleMinEgress
	} else {
		trafficDirection = "ingress"
		trafficDirectionTcFilter = tc.HandleMinIngress
	}

	// only attach fqQdisc for delay generator (handle 0x00000004)
	if nfs.fqQdisc == nil && handle == 0x00000004 {
		if err := nfs.createFqQdisc(ns, iface); err != nil {
			return nil, trafficDirection, err
		}
	}

	if nfs.clsactQdisc == nil {
		if err := nfs.createClsactQdisc(ns, iface); err != nil {
			return nil, trafficDirection, err
		}
	}

	fd := uint32(tcProgr.FD())
	flags := uint32(0x1)

	// Create a tc/tcFilter object that will attach the eBPF program to the qdisc/clsact.
	tcFilter := &tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  handle,
			Parent:  core.BuildHandle(tc.HandleRoot, trafficDirectionTcFilter),
			// According to https://github.com/florianl/go-tc/issues/21#issuecomment-771089889 ...
			// the info field encodes the priority (upper 16 bit) and the protocol (lower 16 bit)
			// let's set it to priority 1 and protocol ETH_P_ALL from:
			// https://github.com/torvalds/linux/blob/98b1cc82c4affc16f5598d4fa14b1858671b2263/include/uapi/linux/if_ether.h#L132
			// #define ETH_P_ALL	0x0003		/* Every packet (be careful!!!) */
			// to network byte order -> 0x0300 starting with  least significant byte
			Info: info,
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &fd,
				Flags: &flags,
			},
		},
	}

	// Attach the tc/filter object with the eBPF program to the qdisc/clsact.
	if err := nfs.tcConnection.Filter().Replace(tcFilter); err != nil {
		return tcFilter, trafficDirection, fmt.Errorf("could not attach filter for eBPF program: %v", err)
	}
	return tcFilter, trafficDirection, nil
}

func getTrafficDirectionString(trafficDirection bool) string {
	if trafficDirection {
		return "egress"
	} else {
		return "ingress"
	}
}

func (nfs *NetworkfilterServer) detachTc(ifaceName string, ns string, ingressEgressControl bool, programType string) error {
	trafficDirection := getTrafficDirectionString(ingressEgressControl)
	filterKey := programType + trafficDirection + ns + ifaceName
	filter, ok := nfs.tcPrograms[filterKey]
	if !(ok && filter != nil) {
		return fmt.Errorf("%s for ns %s, interface %s and traffic direction %s not found", programType, ns, ifaceName, trafficDirection)
	}

	if err := nfs.tcConnection.Filter().Delete(filter); err != nil {
		return fmt.Errorf("could not detach filter for eBPF program: %v", err)
	}
	delete(nfs.tcPrograms, filterKey)
	// if delay generator is detached, we do not need fq qdisc anymore
	if nfs.fqQdisc != nil && programType == PROGRAM_TYPE_DELAY {
		if err := nfs.cleanUpFqQdisc(); err != nil {
			return err
		}
	}
	// If there are no filters anymore, we don't need the tc connection and qdiscs anymore -> so close them
	if len(nfs.tcPrograms) == 0 {
		err := nfs.cleanUpConnection()
		if err != nil {
			return err
		}
	}
	return nil
}

// alternative way to attach tc programs --- widely used in other programs! --- better abstraction?!
// Example based on https://github.com/d0u9/blog_samples/blob/master/bpf/cilium_ebpf_basic/main.go
// func attachTc(ns string, nwInterfaceName string, tcProgr *ebpf.Program, ingressEgressControl bool) error {
// 	nsSwitcher, err := switchNetworkNamespace(ns)
// 	if err != nil {
// 		return err
// 	}
// 	if nsSwitcher != nil {
// 		defer nsSwitcher.Close()
// 	}

// 	link, err := netlink2.LinkByName(nwInterfaceName)
// 	if err != nil {
// 		log.Fatalf("cannot find %s: %v", nwInterfaceName, err)
// 		return err
// 	}

// 	attrs := netlink2.QdiscAttrs{
// 		LinkIndex: link.Attrs().Index,
// 		Handle:    netlink2.MakeHandle(0xffff, 0),
// 		Parent:    netlink2.HANDLE_CLSACT,
// 	}

// 	qdisc := &netlink2.GenericQdisc{
// 		QdiscAttrs: attrs,
// 		QdiscType:  "clsact",
// 	}

// 	if err := netlink2.QdiscAdd(qdisc); err != nil {
// 		log.Fatalf("cannot add clsact qdisc: %v", err)
// 		return err
// 	}

// 	filterAttrs := netlink2.FilterAttrs{
// 		LinkIndex: link.Attrs().Index,
// 		Parent:    netlink2.HANDLE_MIN_INGRESS,
// 		Handle:    netlink2.MakeHandle(0, 1),
// 		Protocol:  unix.ETH_P_ALL,
// 		Priority:  1,
// 	}

// 	filter := &netlink2.BpfFilter{
// 		FilterAttrs:  filterAttrs,
// 		Fd:           tcProgr.FD(),
// 		Name:         "hi-tc",
// 		DirectAction: true,
// 	}

// 	if err := netlink2.FilterAdd(filter); err != nil {
// 		log.Fatalf("cannot attach bpf object to filter: %v", err)
// 		return err
// 	}
// 	return nil
// }
