package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/dustin/go-humanize"

	"github.com/xmapst/ebpf-monitor/internal/ebpf"
)

var storage = make(map[string]uint32)

func main() {
	iface := flag.String("iface", "eth0", "interface")
	flag.Parse()

	var eventCh = make(chan *ebpf.SPacket, 1024)
	go func() {
		for event := range eventCh {
			if event == nil {
				continue
			}
			var key = fmt.Sprintf("%s#%s", event.SrcIP, event.Direction)
			if v, ok := storage[key]; ok {
				storage[key] = v + event.Size
			} else {
				storage[key] = event.Size
			}
		}
	}()

	manager := ebpf.New(*iface, eventCh)
	if err := manager.Start(); err != nil {
		log.Fatalln(err)
	}
	defer manager.Close()

	ticker := time.NewTicker(time.Second * 1)
	defer ticker.Stop()
	for range ticker.C {
		for k, v := range storage {
			ip, direction, found := strings.Cut(k, "#")
			if !found {
				continue
			}
			fmt.Printf("src_ip: %s, direction: %s, size: %s", ip, direction, humanize.Bytes(uint64(v)))
		}
	}
}
