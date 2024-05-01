package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// uint32ToIP converts a uint32 number to an IPv4 address string.
func uint32ToIP(ipUint uint32) string {
	ip := make(net.IP, 4)
	ip[3] = byte(ipUint >> 24)
	ip[2] = byte((ipUint >> 16) & 0xFF)
	ip[1] = byte((ipUint >> 8) & 0xFF)
	ip[0] = byte(ipUint & 0xFF)

	return ip.String()
}

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// Open a ringbuf reader from userspace RINGBUF map described in the
	// eBPF C program.
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	// Attach the XDP program to the interface.
	ifname := "eth0" // Change this to an interface on your machine.
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpLoadBalancer,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer link.Close()

	log.Printf("XDP program successfully loaded on %s\n", ifname)

	quit := make(chan os.Signal, 5)
	signal.Notify(quit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		log.Println("Received signal, Shutting down lb...")
		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	log.Println("Waiting for events...")

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, ringbuffer closed, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}
		if event.Direction == 0 {
			log.Printf("incoming TCP packet from: %s\n", uint32ToIP(event.Addr))
		} else if event.Direction == 1 {
			log.Printf("outgoing TCP packet to: %s\n", uint32ToIP(event.Addr))
		}
	}

}
