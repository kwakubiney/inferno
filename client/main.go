package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
)

func convertIPtoU32(address string) uint32 {
	ipAsAByte := net.ParseIP(address).To4()
	return binary.LittleEndian.Uint32(ipAsAByte)
}

const (
	ingress = "blocked"
)

func main() {
	var ipToBeBlockedFromIngress = flag.String("ingress", "", "this blocks ingress traffic having the given source IP address")
	var ipToBeBlockedToEgress = flag.String("egress", "", "this blocks egress traffic having the given destination IP address")
	flag.Parse()
	if *ipToBeBlockedFromIngress != "" || *ipToBeBlockedToEgress != "" {
		loadPinOptions := ebpf.LoadPinOptions{}
		blockedMap, err := ebpf.LoadPinnedMap(fmt.Sprintf("/sys/fs/bpf/tc/globals/%s", ingress), &loadPinOptions)
		if err != nil {
			log.Fatal(err)
		}
		if *ipToBeBlockedFromIngress != "" {
			err = blockedMap.Put(convertIPtoU32(*ipToBeBlockedFromIngress), uint32(0))
			fmt.Println("ingress detected")
			fmt.Println("-----------------")
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("ingress traffic from %s successfully blocked\n", *ipToBeBlockedFromIngress)
		}
		if *ipToBeBlockedToEgress != "" {
			err = blockedMap.Put(convertIPtoU32(*ipToBeBlockedToEgress), uint32(1))
			fmt.Println("egress detected")
			fmt.Println("-----------------")
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("egress traffic to %s successfully blocked\n", *ipToBeBlockedToEgress)
			if err != nil {
				log.Fatal(err)
			}
		}
	} else {
		flag.Usage()
	}
}
