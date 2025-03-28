package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/pires/go-proxyproto"

	"github.com/xmapst/ebpf-monitor/internal/api"
	"github.com/xmapst/ebpf-monitor/internal/ebpf"
	"github.com/xmapst/ebpf-monitor/internal/metrics"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {
	iface := flag.String("iface", "eth0", "interface")
	listen := flag.String("listen", "tcp://0.0.0.0:8080", "listen address")
	flag.Parse()
	var eventCh = make(chan *ebpf.SPacket, 1024)
	var collector = metrics.New("metrics")
	defer collector.Close()
	go func() {
		for event := range eventCh {
			if event == nil {
				continue
			}
			collector.CollectPacket(event)
		}
	}()

	manager := ebpf.New(*iface, eventCh)
	if err := manager.Start(); err != nil {
		log.Fatalln(err)
	}
	defer manager.Close()

	// 启动http api接口
	proto, addr, ok := strings.Cut(*listen, "://")
	if !ok {
		log.Fatalf("[WARN]bad format %s, expected PROTO://ADDR", *listen)
	}
	ln, err := listenerInit(proto, addr)
	if err != nil {
		log.Fatalln(err)
	}
	defer ln.Close()

	_http := http.Server{
		Handler:      api.New(manager, collector),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	if err = _http.Serve(&proxyproto.Listener{Listener: ln}); err != nil {
		log.Fatalln(err)
	}
}

func listenerInit(proto, addr string) (net.Listener, error) {
	switch proto {
	case "tcp":
		return net.Listen("tcp", addr)
	case "unix":
		if err := syscall.Unlink(addr); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		origUmask := syscall.Umask(0o777)
		l, err := net.Listen("unix", addr)
		syscall.Umask(origUmask)
		if err != nil {
			return nil, err
		}
		err = os.Chown(addr, 0, os.Getgid())
		if err != nil {
			return nil, err
		}
		err = os.Chmod(addr, 0o666)
		if err != nil {
			return nil, err
		}
		return l, nil
	default:
		return nil, fmt.Errorf("unknown protocol %s", proto)
	}
}
