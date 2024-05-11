# Go Network Traffic Analyzer

The Go Network Traffic Analyzer is a versatile tool designed to monitor and analyze network traffic. It allows you to observe various network protocols, record traffic data, and analyze live traffic from specific network interfaces.
Features

    Protocol Monitoring: Monitor various network protocols such as TCP, UDP, ICMP, etc.
    Live Traffic Monitoring: Analyze live traffic from a specified network interface.
    Traffic Recording: Record traffic data to log files for later analysis.
    Flexible Usage: User-friendly interface and simple command-line options for flexible usage.

Usage

Select the desired network interface and specify the protocols you want to monitor by running the program. Traffic monitoring will start automatically.

bash

    go run interfaceP.go  and  go run onlyInterface.go

Requirements

    Go (version 1.13 or newer)
    github.com/google/gopacket and github.com/google/gopacket/pcap libraries

Contributing

    Fork the project and make your enhancements.
    Open an issue on GitHub for bug reports and suggestions.
    Read, understand, and improve the code.
# Listening to the network interface and analyzing TCP packets:
    interface := "eth0"
    packetType := "TCP"
    
    // Ağ arabirimini ve paket türünü belirtin
    handle, err := pcap.OpenLive(interface, 1600, true, pcap.BlockForever)
    if err != nil {
        log.Fatal("Error opening interface:", err)
    }
    defer handle.Close()
    
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    
    // TCP paketlerini dinleme ve analiz etme
    for packet := range packetSource.Packets() {
        tcpLayer := packet.Layer(layers.LayerTypeTCP)
        if tcpLayer != nil {
            tcp, _ := tcpLayer.(*layers.TCP)
            fmt.Printf("Source Port: %d, Destination Port: %d\n", tcp.SrcPort, tcp.DstPort)
        }
    }

# Interacting with a specific network device and analyzing ICMP packets:
    interface := "eth0"
    packetType := "ICMP"
    
    // Ağ arabirimini ve paket türünü belirtin
    handle, err := pcap.OpenLive(interface, 1600, true, pcap.BlockForever)
    if err != nil {
        log.Fatal("Error opening interface:", err)
    }
    defer handle.Close()
    
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    
    // ICMP paketlerini dinleme ve analiz etme
    for packet := range packetSource.Packets() {
        icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
        if icmpLayer != nil {
            icmp, _ := icmpLayer.(*layers.ICMPv4)
            fmt.Printf("Type: %d, Code: %d\n", icmp.TypeCode.Type(), icmp.TypeCode.Code())
        }
    }


