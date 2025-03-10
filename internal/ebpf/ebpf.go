package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

type IManager interface {
	Start() error
	Close()
	GetLinkType() string
}

type SManager struct {
	ctx      context.Context
	cancel   context.CancelFunc
	objects  *xdpObjects
	link     []*link.Link
	reader   *perf.Reader
	linkType string

	ifname  string
	eventCh chan *SPacket
}

func New(ifname string, eventCh chan *SPacket) IManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &SManager{
		ctx:     ctx,
		cancel:  cancel,
		ifname:  ifname,
		eventCh: eventCh,
	}
}

func (m *SManager) Start() error {
	iface, err := net.InterfaceByName(m.ifname)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %s", m.ifname, err)
	}

	if err = rlimit.RemoveMemlock(); err != nil {
		log.Printf("failed to remove memlock: %s", err.Error())
	}
	var ebpfObj xdpObjects
	if err = loadXdpObjects(&ebpfObj, nil); err != nil {
		return fmt.Errorf("failed to load eBPF objects: %s", err.Error())
	}

	m.objects = &ebpfObj
	err = m.attachXDP(iface.Index)
	if err != nil {
		m.Close()
		return err
	}

	m.reader, err = perf.NewReader(m.objects.Events, os.Getpagesize())
	if err != nil {
		m.Close()
		return fmt.Errorf("failed to create perf event reader: %s", err.Error())
	}
	go m.monitorEvents()
	return nil
}

func (m *SManager) attachXDP(index int) error {
	flagNames := []string{"offload", "driver", "generic"}
	var errs []string
	for i, mode := range []link.XDPAttachFlags{link.XDPOffloadMode, link.XDPDriverMode, link.XDPGenericMode} {
		flagName := flagNames[i]
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   m.objects.XdpProgram,
			Interface: index,
			Flags:     mode,
		})
		if err == nil {
			m.linkType = flagName
			m.link = append(m.link, &l)
			log.Printf("XDP program attached successfully, current mode: %s", flagName)
			return nil
		}
		errs = append(errs, fmt.Sprintf("failed to attach XDP program with %s mode: %s", flagName, err.Error()))
	}
	return errors.New(strings.Join(errs, "\n"))
}

func (m *SManager) monitorEvents() {
	for {
		select {
		case <-m.ctx.Done():
			return
		default:
			record, err := m.reader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				log.Printf("[ERROR] failed to read perf event record: %s", err)
				continue
			}
			var pi = new(sPacketInfo)
			if err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, pi); err != nil {
				continue
			}
			packet := pi.toPacket()
			if packet.SrcIP == "" || packet.DstIP == "" {
				continue
			}
			m.eventCh <- pi.toPacket()
		}
	}
}

func (m *SManager) Close() {
	m.cancel()
	if m.reader != nil {
		_ = m.reader.Close()
	}
	for _, l := range m.link {
		_ = (*l).Close()
	}
	if m.objects != nil {
		_ = m.objects.Close()
	}
	return
}

func (m *SManager) GetLinkType() string {
	return m.linkType
}
