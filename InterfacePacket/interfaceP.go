package interfacep

import (
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type interP struct {
	Interface   string
	Packet      string
	PacketCount int
	//LogType     string
}

func InterfacePacket() {
	fmt.Println("Welcome to Interface and Packet Scans:")
	var infoP interP

	fmt.Printf("Please enter the interface name: ")
	fmt.Scanln(&infoP.Interface)
	fmt.Println(infoP.Interface)
	fmt.Printf("Please enter the packet name [TCP UDP ICMP DNS]: ")
	fmt.Scanln(&infoP.Packet)
	fmt.Println(infoP.Packet)
	fmt.Printf("How many packets do you want to scan? : ")
	fmt.Scanln(&infoP.PacketCount)
	fmt.Println(infoP.PacketCount)
	//fmt.Print("What type do you want to record [ .PCAP | .LOG ]")
	//fmt.Scanln(&infoP.LogType)
	//fmt.Println(infoP.LogType)

	handle, err := pcap.OpenLive(infoP.Interface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("The interface you entered does not exist", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	file, err := os.OpenFile("packet.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	logger := log.New(file, "", log.LstdFlags)

	packetCount := infoP.PacketCount // You want packet count
	receivedPackets := 0

	for receivedPackets < packetCount {
		packet, err := packetSource.NextPacket()
		if err != nil {
			log.Fatal(err)
		}

		switch infoP.Packet {
		case "TCP":
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				logger.Printf("Source Port: %d, Destination Port: %d\n", tcp.SrcPort, tcp.DstPort)
			}
		case "UDP":
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer != nil {
				udp, _ := udpLayer.(*layers.UDP)
				logger.Printf("Source Port: %d, Destination Port: %d\n", udp.SrcPort, udp.DstPort)
			}
		case "ICMP":
			icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
			if icmpLayer != nil {
				icmp, _ := icmpLayer.(*layers.ICMPv4)
				logger.Printf("Type: %d, Code: %d\n", icmp.TypeCode.Type(), icmp.TypeCode.Code())
			}
		case "DNS":
			dnsLayer := packet.Layer(layers.LayerTypeDNS)
			if dnsLayer != nil {
				dns, _ := dnsLayer.(*layers.DNS)
				logger.Printf("Source Port: %d, Destination Port: %d\n", dns.LayerType(), dns.NSCount)
			}
		}

		receivedPackets++
	}
}

func Interfacep() {
	InterfacePacket()
}
