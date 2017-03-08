package packet

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func GetPacketSource(iface string, promisc bool, timeout time.Duration) (*gopacket.PacketSource, error) {
	handle, err := pcap.OpenLive(iface, 65535, promisc, timeout)
	if err != nil {
		return nil, err
	}

	if err := handle.SetBPFFilter("tcp"); err != nil {
		return nil, err
	}

	return gopacket.NewPacketSource(handle, handle.LinkType()), nil
}
