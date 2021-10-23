// This code is a derivative of https://github.com/google/gopacket/blob/master/examples/pcapdump/main.go which is BSD licensed:
// https://github.com/google/gopacket/blob/master/LICENSE

// Copyright 2012 Google, Inc. All rights reserved.

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/pcap"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers" // pulls in all layers decoders
)

var iface = flag.String("i", "eth0", "Interface to read packets from")

func main() {
	defer util.Run()()
	var handle *pcap.Handle
	var err error

	var ief *net.Interface
	if ief, err = net.InterfaceByName(*iface); err != nil {
		log.Fatalf("could not get interface: %v", err)
	}
	var addrs []net.Addr
	if addrs, err = ief.Addrs(); err != nil { // get addresses
		log.Fatalf("could not get interface addresses: %v", err)
	}
	var ips []net.IP = make([]net.IP, len(addrs))
	for i, addr := range addrs {
		ips[i] = addr.(*net.IPNet).IP
		fmt.Printf("Interface %s has IP %s\n", *iface, ips[i])
	}

	// This is a little complicated because we want to allow all possible options
	// for creating the packet capture handle... instead of all this you can
	// just call pcap.OpenLive if you want a simple handle.
	inactive, err := pcap.NewInactiveHandle(*iface)
	if err != nil {
		log.Fatalf("could not create: %v", err)
	}
	defer inactive.CleanUp()
	if err = inactive.SetSnapLen(65536); err != nil {
		log.Fatalf("could not set snap length: %v", err)
	} else if err = inactive.SetPromisc(true); err != nil {
		log.Fatalf("could not set promisc mode: %v", err)
	} else if err = inactive.SetTimeout(time.Second); err != nil {
		log.Fatalf("could not set timeout: %v", err)
	}
	if handle, err = inactive.Activate(); err != nil {
		log.Fatal("PCAP Activate error:", err)
	}
	defer handle.Close()

	if len(flag.Args()) > 0 {
		bpffilter := strings.Join(flag.Args(), " ")
		fmt.Fprintf(os.Stderr, "Using BPF filter %q\n", bpffilter)
		if err = handle.SetBPFFilter(bpffilter); err != nil {
			log.Fatal("BPF filter error:", err)
		}
	}
	Run(handle, ips)
}

func Run(src gopacket.PacketDataSource, ips []net.IP) {
	if !flag.Parsed() {
		log.Fatalln("Run called without flags.Parse() being called")
	}
	var dec gopacket.Decoder
	var ok bool
	if dec, ok = gopacket.DecodersByLayerName["Ethernet"]; !ok {
		log.Fatalln("No decoder named", "Ethernet")
	}
	source := gopacket.NewPacketSource(src, dec)
	source.Lazy = false
	source.NoCopy = true
	source.DecodeStreamsAsDatagrams = true
	fmt.Fprintln(os.Stderr, "Starting to read packets")

	for packet := range source.Packets() {
		var transportLayer = packet.TransportLayer()
		var networkLayer = packet.NetworkLayer()
		if transportLayer != nil && transportLayer.LayerType() == layers.LayerTypeTCP {
			var tcpLayer = transportLayer.(*layers.TCP)
			var destIP net.IP
			var sourceIP net.IP
			if networkLayer.LayerType() == layers.LayerTypeIPv6 {
				destIP = networkLayer.(*layers.IPv6).DstIP
				sourceIP = networkLayer.(*layers.IPv6).SrcIP
			} else {
				destIP = networkLayer.(*layers.IPv4).DstIP
				sourceIP = networkLayer.(*layers.IPv4).SrcIP
			}
			var inbound bool = false
			for _, ip := range ips {
				if net.IP.Equal(ip, destIP) {
					inbound = true
					break
				}
			}
			if inbound {
				if tcpLayer.SYN == true {
					fmt.Printf("SYN to %s:%d from %s\n", destIP, tcpLayer.DstPort, sourceIP)
				}
			}
		}
	}
}
