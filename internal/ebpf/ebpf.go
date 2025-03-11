package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

type IManager interface {
	Start() error
	Close()
	AddRule(sip string, rate int) error
	DelRule(sip string) error
}

type sManager struct {
	ctx     context.Context
	cancel  context.CancelFunc
	objects *ebpfObjects
	links   []*link.Link
	reader  *perf.Reader

	ifname  string
	eventCh chan *SPacket
}

func New(ifname string, eventCh chan *SPacket) IManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &sManager{
		ctx:     ctx,
		cancel:  cancel,
		ifname:  ifname,
		eventCh: eventCh,
	}
}

func (m *sManager) Start() error {
	iface, err := net.InterfaceByName(m.ifname)
	if err != nil {
		return err
	}

	if err = rlimit.RemoveMemlock(); err != nil {
		return err
	}
	var ebpfObj ebpfObjects
	if err = loadEbpfObjects(&ebpfObj, nil); err != nil {
		return err
	}

	m.objects = &ebpfObj
	err = m.attachTCXIngress(iface.Index)
	if err != nil {
		m.Close()
		return err
	}
	err = m.attachTCXEgress(iface.Index)
	if err != nil {
		m.Close()
		return err
	}

	m.reader, err = perf.NewReader(m.objects.Events, os.Getpagesize())
	if err != nil {
		m.Close()
		return err
	}
	go m.monitorEvents()
	return nil
}

func (m *sManager) attachTCXIngress(index int) error {
	l, err := link.AttachTCX(link.TCXOptions{
		Program:   m.objects.IngressProg,
		Interface: index,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return err
	}
	m.links = append(m.links, &l)
	return nil
}

func (m *sManager) attachTCXEgress(index int) error {
	l, err := link.AttachTCX(link.TCXOptions{
		Program:   m.objects.EgressProg,
		Interface: index,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return err
	}
	m.links = append(m.links, &l)
	return nil
}

func (m *sManager) monitorEvents() {
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
				log.Println(err)
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

func (m *sManager) Close() {
	m.cancel()
	if m.reader != nil {
		_ = m.reader.Close()
	}
	for _, l := range m.links {
		_ = (*l).Close()
	}
	if m.objects != nil {
		_ = m.objects.Close()
	}
	return
}

// AddRule 添加限速规则
func (m *sManager) AddRule(sip string, rate int) error {
	if m.objects == nil {
		return errors.New("ebpf objects is nil")
	}
	if err := m.objects.RateLimitMap.Put([]byte(sip), uint32(rate)); err != nil {
		return err
	}
	return nil
}

// DelRule 删除限速规则
func (m *sManager) DelRule(sip string) error {
	if m.objects == nil {
		return errors.New("ebpf objects is nil")
	}
	if err := m.objects.RateLimitMap.Delete([]byte(sip)); err != nil {
		return err
	}
	return nil
}
