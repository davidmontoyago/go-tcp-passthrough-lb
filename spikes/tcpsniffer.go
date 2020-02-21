package main

/*
 * Simply opens the l0 interface and assembles packages with *tcpassembly.Assembler.
 * Assembler requires a StreamPool with a StreamFactory that provides a new stream (in this case a ReaderStream) eveytime a package
 * is assembled into its appropiate stream.
 */
import (
	"bytes"
	"io"
	"log"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

type tcpStreamFactory struct{}

func (s *tcpStreamFactory) New(a, b gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	go readAssembledTCP(&r)
	return &r
}

func readAssembledTCP(r io.Reader) {
	var buf bytes.Buffer
	_, err := io.Copy(&buf, r)
	if err != nil {
		log.Fatalln("failed to read", err)
	}
	log.Println("got", buf.String())
}

func main() {
	streamFactory := &tcpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	var handle *pcap.Handle
	var err error
	if handle, err = pcap.OpenLive("lo0", 1600, true, pcap.BlockForever); err != nil {
		log.Fatalln(err)
	}
	if err := handle.SetBPFFilter("tcp and port 9000"); err != nil {
		log.Fatalln(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
		}
	}
}
