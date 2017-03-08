package main

import (
	"bufio"
	"bytes"
	"flag"
	"log"
	"net/http"
	"time"

	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/vibhavp/http-intercept/packet"
)

var iface string
var promisc bool
var timeout int64
var methods [6]string = [6]string{"GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS"}

func init() {
	flag.StringVar(&iface, "iface", "eth0", "interface to scan")
	flag.BoolVar(&promisc, "promisc", false, "set interface to promiscuous mode")
	flag.Int64Var(&timeout, "timeout", 5, "timeout in seconds")
}

func isRequest(data []byte) *http.Request {
	for _, method := range methods {
		if bytes.HasPrefix(data, []byte(method)) {
			// try reading from the request
			req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
			if err != nil {
				return nil
			}
			return req
		}
	}

	return nil
}

func getSrcDest(p gopacket.Packet) (string, string) {
	if l := p.Layer(layers.LayerTypeIPv4); l != nil {
		ipv4 := l.(*layers.IPv4)
		return ipv4.SrcIP.String(), ipv4.DstIP.String()
	}
	if l := p.Layer(layers.LayerTypeIPv6); l != nil {
		ipv6 := l.(*layers.IPv6)
		return ipv6.SrcIP.String(), ipv6.DstIP.String()
	}
	// ideally, this should work regardless of what protocol the network layer is using
	panic("packet doesn't have an IPv4/6 network layer")
}

func fmtHeader(h http.Header) string {
	str := ""
	for k, v := range h {
		str += "\n"
		str += fmt.Sprintf("%s: %s", k, v)
	}
	return str
}

func main() {
	flag.Parse()

	source, err := packet.GetPacketSource(iface, promisc, time.Duration(timeout)*time.Second)
	if err != nil {
		log.Fatal(err)
	}

	for packet := range source.Packets() {
		if layer := packet.Layer(layers.LayerTypeTCP); layer != nil {
			tcp := layer.(*layers.TCP)
			src, dest := getSrcDest(packet)
			if req := isRequest(tcp.Payload); req != nil {
				log.Printf(`HTTP REQUEST:
From: %s:%d
To: %s:%d
Version: %d.%d
Method: %s
Headers: %s
`, src, tcp.SrcPort, dest, tcp.DstPort, req.ProtoMajor, req.ProtoMinor, req.Method, fmtHeader(req.Header))
			}
		}
	}
}
