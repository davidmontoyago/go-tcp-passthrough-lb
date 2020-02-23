package main

import (
	"log"
	"net"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

func main() {
	var packetConn net.PacketConn
	var rawConn *ipv4.RawConn
	var err error
	packetConn, err = net.ListenPacket("ip4:tcp", "127.0.0.1")
	if err != nil {
		panic(err)
	}
	rawConn, err = ipv4.NewRawConn(packetConn)
	if err != nil {
		panic(err)
	}

	filter, err := bpf.Assemble([]bpf.Instruction{
		// Load IPv4 packet length
		bpf.LoadMemShift{Off: 0},
		// Get destination dport
		bpf.LoadIndirect{Off: 2, Size: 2},
		// Correct dport?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(9000), SkipFalse: 1},
		// Accept
		bpf.RetConstant{Val: 65535},
		// Ignore
		bpf.RetConstant{Val: 0},
	})

	// this is not supported in OSX :(
	if err = rawConn.SetBPF(filter); err != nil {
		rawConn.Close()
		log.Fatalf("setting packet filter: %s", err)
	}

	for {
		buf := make([]byte, 1024)
		read, ipAddr, err := rawConn.ReadFromIP(buf)
		if err != nil {
			log.Fatalln(err)
		}

		log.Println("read", read, "bytes", "from", ipAddr)
	}

}
