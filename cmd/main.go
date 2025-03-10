package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/xmapst/ebpf-monitor/internal/ebpf"
)

func main() {
	iface := flag.String("iface", "eth0", "interface")
	flag.Parse()

	var eventCh = make(chan *ebpf.SPacket, 1024)
	manager := ebpf.New(*iface, eventCh)
	if err := manager.Start(); err != nil {
		log.Fatalln(err)
	}
	defer manager.Close()
	for event := range eventCh {
		if event == nil {
			continue
		}
		data, err := event.Marshal()
		if err != nil {
			log.Println(err)
			return
		}
		fmt.Println(string(data))
	}
}
