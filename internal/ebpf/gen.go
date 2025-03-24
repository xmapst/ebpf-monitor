package ebpf

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"time"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf ebpf.c

type EthernetType uint16

func (et EthernetType) String() string {
	switch et {
	case 0x0800:
		return "IPv4"
	case 0x86DD:
		return "IPv6"
	case 0x805:
		return "RARP"
	case 0x806:
		return "ARP"
	case 0x8847:
		return "MPLS"
	case 0x8848:
		return "MPLS-TP"
	case 0x8100:
		return "VLAN"
	default:
		return fmt.Sprintf("0x%x", uint16(et))
	}
}

func (et EthernetType) MarshalJSON() ([]byte, error) {
	return json.Marshal(et.String())
}

type IPProtocol uint16

func (protocol IPProtocol) String() string {
	switch protocol {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("0x%x", uint16(protocol))
	}
}

func (protocol IPProtocol) MarshalJSON() ([]byte, error) {
	return json.Marshal(protocol.String())
}

type sPacketInfo struct {
	SrcIP     [4]byte
	DstIP     [4]byte
	SrcIPv6   [16]byte
	DstIPv6   [16]byte
	SrcPort   uint16
	DstPort   uint16
	SrcMAC    [6]byte
	DstMAC    [6]byte
	EthType   EthernetType
	IPProto   IPProtocol
	PktSize   uint32
	Direction uint8
}

type SPacket struct {
	Timestamp int64        `json:"timestamp"`
	SrcMAC    string       `json:"src_mac"`
	DstMAC    string       `json:"dst_mac"`
	SrcIP     netip.Addr   `json:"src_ip"`
	DstIP     netip.Addr   `json:"dst_ip"`
	SrcPort   uint16       `json:"src_port"`
	DstPort   uint16       `json:"dst_port"`
	Size      uint32       `json:"size"`
	EthType   EthernetType `json:"type"`
	IPProto   IPProtocol   `json:"proto"`
	Direction string       `json:"direction"`
}

const (
	FlowDirectionUnknown = "unknown"
	FlowDirectionIngress = "ingress"
	FlowDirectionEgress  = "egress"
)

func (pi *sPacketInfo) DirectionStr() string {
	switch pi.Direction {
	case 1:
		return FlowDirectionIngress
	case 2:
		return FlowDirectionEgress
	default:
		return FlowDirectionUnknown
	}
}

// ToPacket 转换PacketInfo 为 Packet
func (pi *sPacketInfo) toPacket() *SPacket {
	var srcIP, dstIP netip.Addr
	if pi.EthType == EthernetType(0x0800) { // IPv4
		srcIP = netip.AddrFrom4(pi.SrcIP)
		dstIP = netip.AddrFrom4(pi.DstIP)
	} else if pi.EthType == EthernetType(0x86DD) { // IPv6
		srcIP = netip.AddrFrom16(pi.SrcIPv6)
		dstIP = netip.AddrFrom16(pi.DstIPv6)
	}

	packet := &SPacket{
		Timestamp: time.Now().Unix(),
		SrcMAC:    net.HardwareAddr(pi.SrcMAC[:]).String(),
		DstMAC:    net.HardwareAddr(pi.DstMAC[:]).String(),
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   pi.SrcPort,
		DstPort:   pi.DstPort,
		Size:      pi.PktSize,
		EthType:   pi.EthType,
		IPProto:   pi.IPProto,
		Direction: pi.DirectionStr(),
	}

	return packet
}

func (p *SPacket) Marshal() ([]byte, error) {
	return json.Marshal(p)
}

type ipKey struct {
	Family uint32
	Addr   [16]byte
}
