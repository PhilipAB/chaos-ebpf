package filter

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/philipab/ebpf-proto/ebpf/bitflip"
	"github.com/philipab/ebpf-proto/ebpf/bwmanager"
	"github.com/philipab/ebpf-proto/ebpf/delay"
	"github.com/philipab/ebpf-proto/ebpf/duplication"
	"github.com/philipab/ebpf-proto/ebpf/tshaper"
	nf "github.com/philipab/ebpf-proto/grpc/protos"
)

type FilterMapSpecs struct {
	EnableIpv4          *ebpf.Map `ebpf:"enable_ipv4"`
	EnableIpv6          *ebpf.Map `ebpf:"enable_ipv6"`
	Ipv4Mask            *ebpf.Map `ebpf:"ipv4_mask"`
	Ipv4RangeExemptList *ebpf.Map `ebpf:"ipv4_range_exempt_list"`
	Ipv6Mask            *ebpf.Map `ebpf:"ipv6_mask"`
	Ipv6RangeExemptList *ebpf.Map `ebpf:"ipv6_range_exempt_list"`
	PortMap             *ebpf.Map `ebpf:"port_map"`
	SupportedProtocols  *ebpf.Map `ebpf:"supported_protocols"`
}

func ConvertTshaperToFilterMapSpecs(obj *tshaper.TshaperObjectsWrapper) *FilterMapSpecs {
	return &FilterMapSpecs{
		EnableIpv4:          obj.EnableIpv4,
		EnableIpv6:          obj.EnableIpv6,
		Ipv4Mask:            obj.Ipv4Mask,
		Ipv4RangeExemptList: obj.Ipv4RangeExemptList,
		Ipv6Mask:            obj.Ipv6Mask,
		Ipv6RangeExemptList: obj.Ipv6RangeExemptList,
		PortMap:             obj.PortMap,
		SupportedProtocols:  obj.SupportedProtocols,
	}
}

func ConvertBwmanagerToFilterMapSpecs(obj *bwmanager.BwObjectsWrapper) *FilterMapSpecs {
	return &FilterMapSpecs{
		EnableIpv4:          obj.EnableIpv4,
		EnableIpv6:          obj.EnableIpv6,
		Ipv4Mask:            obj.Ipv4Mask,
		Ipv4RangeExemptList: obj.Ipv4RangeExemptList,
		Ipv6Mask:            obj.Ipv6Mask,
		Ipv6RangeExemptList: obj.Ipv6RangeExemptList,
		PortMap:             obj.PortMap,
		SupportedProtocols:  obj.SupportedProtocols,
	}
}

func ConvertDuplGenToFilterMapSpecs(obj *duplication.DuplicateGenObjectsWrapper) *FilterMapSpecs {
	return &FilterMapSpecs{
		EnableIpv4:          obj.EnableIpv4,
		EnableIpv6:          obj.EnableIpv6,
		Ipv4Mask:            obj.Ipv4Mask,
		Ipv4RangeExemptList: obj.Ipv4RangeExemptList,
		Ipv6Mask:            obj.Ipv6Mask,
		Ipv6RangeExemptList: obj.Ipv6RangeExemptList,
		PortMap:             obj.PortMap,
		SupportedProtocols:  obj.SupportedProtocols,
	}
}

func ConvertBitflipGenToFilterMapSpecs(obj *bitflip.BitflipGenObjectsWrapper) *FilterMapSpecs {
	return &FilterMapSpecs{
		EnableIpv4:          obj.EnableIpv4,
		EnableIpv6:          obj.EnableIpv6,
		Ipv4Mask:            obj.Ipv4Mask,
		Ipv4RangeExemptList: obj.Ipv4RangeExemptList,
		Ipv6Mask:            obj.Ipv6Mask,
		Ipv6RangeExemptList: obj.Ipv6RangeExemptList,
		PortMap:             obj.PortMap,
		SupportedProtocols:  obj.SupportedProtocols,
	}
}

func ConvertDelayGenToFilterMapSpecs(obj *delay.DelayGenObjectsWrapper) *FilterMapSpecs {
	return &FilterMapSpecs{
		EnableIpv4:          obj.EnableIpv4,
		EnableIpv6:          obj.EnableIpv6,
		Ipv4Mask:            obj.Ipv4Mask,
		Ipv4RangeExemptList: obj.Ipv4RangeExemptList,
		Ipv6Mask:            obj.Ipv6Mask,
		Ipv6RangeExemptList: obj.Ipv6RangeExemptList,
		PortMap:             obj.PortMap,
		SupportedProtocols:  obj.SupportedProtocols,
	}
}

func UpdateFilterMaps(filter *nf.Filter, obj *FilterMapSpecs) error {
	key := uint32(0)

	/**************************************************************************************************************
	 * IPv4 configuration
	 *
	 * enable/disable ipv4 for traffic shaping and configure IPv4 exempt list
	 **************************************************************************************************************/
	ipv4Value := uint32(1)
	if !filter.GetEnableIpv4() {
		ipv4Value = uint32(0)
	}

	if err := obj.EnableIpv4.Update(&key, &ipv4Value, 0); err != nil {
		return fmt.Errorf("failed updating EnableIpv4 map: %v", err)
	}

	ipv4Ips := filter.GetIpv4Range()
	if ipv4Ips == nil || len(ipv4Ips) <= 0 {
		ipv4Range, err := ipv4ToUint32("10.42.0.0")
		if err != nil {
			return fmt.Errorf("could not parse IPv4 address: %v", err)
		}
		if err := obj.Ipv4RangeExemptList.Update(&key, &ipv4Range, 0); err != nil {
			return fmt.Errorf("failed updating Ipv4RangeExemptList map: %v", err)
		}
	} else {
		for i := uint32(0); i < uint32(len(ipv4Ips)); i++ {
			ipv4Range, err := ipv4ToUint32(ipv4Ips[i])
			if err != nil {
				return fmt.Errorf("could not parse IPv4 address: %v", err)
			}
			if err := obj.Ipv4RangeExemptList.Update(&i, &ipv4Range, 0); err != nil {
				return fmt.Errorf("failed updating Ipv4RangeExemptList map: %v", err)
			}
		}
	}

	if ports := filter.GetPorts(); ports != nil {
		for i := uint32(0); i < uint32(len(ports)); i++ {
			if err := obj.PortMap.Update(&i, &ports[i], 0); err != nil {
				return fmt.Errorf("failed updating Port map: %v", err)
			}
		}
	}

	ipv4MaskString := filter.GetIpv4Mask()
	if ipv4MaskString == "" {
		ipv4MaskString = "255.255.0.0"
	}
	ipv4Mask, err := ipv4ToUint32(ipv4MaskString)
	if err != nil {
		return fmt.Errorf("could not parse IPv4 address: %v", err)
	}
	if err := obj.Ipv4Mask.Update(&key, &ipv4Mask, 0); err != nil {
		return fmt.Errorf("failed updating Ipv4Mask map: %v", err)
	}

	/**************************************************************************************************************
	 * IPv6 configuration
	 *
	 * enable/disable ipv6 for traffic shaping and configure IPv6 exempt list
	 **************************************************************************************************************/
	ipv6Value := uint32(1)
	if !filter.GetEnableIpv6() {
		ipv6Value = uint32(0)
	}
	if err := obj.EnableIpv6.Update(&key, &ipv6Value, 0); err != nil {
		return fmt.Errorf("failed updating EnableIpv6 map: %v", err)
	}

	// Configure supported protocols:
	ipProtoIcmp := uint32(1)
	ipProtoTcp := uint32(6)
	ipProtoUdp := uint32(17)

	icmpEnabled := uint32(1)
	tcpEnabled := uint32(1)
	udpEnabled := uint32(1)

	if !filter.GetEnableIcmp() {
		icmpEnabled = uint32(0)
	}
	if !filter.GetEnableTcp() {
		tcpEnabled = uint32(0)
	}
	if !filter.GetEnableUdp() {
		udpEnabled = uint32(0)
	}

	if err := obj.SupportedProtocols.Update(&ipProtoIcmp, &icmpEnabled, 0); err != nil {
		return fmt.Errorf("updating icmpEnabled flag: %v", err)
	}
	if err := obj.SupportedProtocols.Update(&ipProtoTcp, &tcpEnabled, 0); err != nil {
		return fmt.Errorf("updating tcpEnabled flag: %v", err)
	}
	if err := obj.SupportedProtocols.Update(&ipProtoUdp, &udpEnabled, 0); err != nil {
		return fmt.Errorf("updating udpEnabled flag: %v", err)
	}
	return nil
}

// parts of the parameter description are copied and rephrased from the docs of the net package
// Reference: https://go.dev/src/net/ip.go (ParseIP function)
// @ipStr: Should be an IPv4 dotted decimal ("192.0.2.1").
// If ipStr is not a valid textual representation of an IPv4 address this function will throw an error
func ipv4ToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("IP address %s is invalid", ipStr)
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0, fmt.Errorf("IP address: %s does not refer to IPv4 protocol", ipStr)
	}
	// In our eBPF program we processes IPv4 addresses as uint32, hence the conversion
	return binary.BigEndian.Uint32(ipv4), nil
}

// parts of the parameter description are copied and rephrased from the docs of the net package
// Reference: https://go.dev/src/net/ip.go (ParseIP function)
// @ipStr: Can be in IPv6 ("2001:db8::68") or IPv4-mapped IPv6 ("::ffff:192.0.2.1") form.
// If ipStr is not a valid textual representation of an IPv6 address this function will throw an error
func ipv6ToBytes(ipStr string) ([16]byte, error) {
	ipv4Len := 4
	var ipv6Bytes [16]byte
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipv6Bytes, fmt.Errorf("IP address %s is invalid", ipStr)
	}
	if len(ip) == ipv4Len {
		return ipv6Bytes, fmt.Errorf("got IPv4 address but need IPv6: %s", ipStr)
	}
	ipv6 := ip.To16()
	if ipv6 == nil {
		return ipv6Bytes, fmt.Errorf("IP address: %s does not refer to IPv6 protocol", ipStr)
	}
	copiedBytes := copy(ipv6Bytes[:], ipv6) // let's copy the IPv6 address into a fixed size byte array to ensure it has the correct length
	if copiedBytes != 16 {
		return ipv6Bytes, fmt.Errorf("failed to parse IPv6 address - invalid length: %s", ipStr)
	}
	return ipv6Bytes, nil
}
