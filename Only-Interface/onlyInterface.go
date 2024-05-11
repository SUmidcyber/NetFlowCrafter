package onlyinterfaces_data

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type inter struct {
	Interface string
}

func onlyinterfaces() {
	fmt.Println("Welcome to Only Interface scan...")
	var info inter

	fmt.Printf("Please enter the interface name: ")
	fmt.Scanln(&info.Interface)
	fmt.Println(info.Interface)

	handle, err := pcap.OpenLive(info.Interface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("The interface you entered does not exist", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Log dosyasını açma veya oluşturma
	file, err := os.OpenFile("all-data.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	logger := log.New(file, "", log.LstdFlags)

	maxLength := 50
	delay := 200 * time.Millisecond
	progressChar := "="

	for i := 0; i <= maxLength; i++ {
		progress := ""
		for j := 0; j < i; j++ {
			progress += progressChar
		}
		fmt.Printf("\r[%-10s]", progress)
		time.Sleep(delay)
		if i == maxLength {
			fmt.Println("\nLoading Finish!")
		}
	}

	fmt.Println("Listening for packets on interface:", info.Interface)
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			logger.Printf("Source IP: %s, Destination IP: %s\n", ip.SrcIP, ip.DstIP)
		}

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			logger.Printf("Source Port: %d, Destination Port: %d\n", tcp.SrcPort, tcp.DstPort)
		}

		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			logger.Printf("Source Port: %d, Destination Port: %d\n", udp.SrcPort, udp.DstPort)
		}
	}
}

func Onlyinterfaces_data() {
	onlyinterfaces()
}
