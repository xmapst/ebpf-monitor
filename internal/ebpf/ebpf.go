package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"log"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var BpfName = "bpf_monitor"

type IManager interface {
	Start() error
	Close()
	AddRule(sip string, rate int) error
	DelRule(sip string) error
}

type sManager struct {
	ctx     context.Context
	cancel  context.CancelFunc
	spec    *ebpf.CollectionSpec
	objects *ebpfObjects
	tcObjs  []*tc.Object
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
		objects: &ebpfObjects{},
	}
}

func (m *sManager) Start() error {
	link, err := netlink.LinkByName(m.ifname)
	if err != nil {
		return errors.WithStack(err)
	}

	if err = rlimit.RemoveMemlock(); err != nil {
		return errors.WithStack(err)
	}

	m.spec, err = loadEbpf()
	if err != nil {
		return errors.WithStack(err)
	}

	if err = m.spec.LoadAndAssign(m.objects, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
		},
	}); err != nil {
		return errors.WithStack(err)
	}

	linkAttrs := link.Attrs()
	err = m.addFilter(uint32(linkAttrs.Index), uint32(m.objects.IngressProg.FD()), tc.HandleMinIngress)
	if err != nil {
		return errors.WithStack(err)
	}
	err = m.addFilter(uint32(linkAttrs.Index), uint32(m.objects.EgressProg.FD()), tc.HandleMinEgress)
	if err != nil {
		return errors.WithStack(err)
	}

	m.reader, err = perf.NewReader(m.objects.Events, os.Getpagesize())
	if err != nil {
		m.Close()
		return errors.WithStack(err)
	}
	go m.monitorEvents()
	return nil
}

func (m *sManager) addFilter(ifindex, fd uint32, parent uint32) error {
	return m.withTcnl(func(tcnl *tc.Tc) error {
		tcObj := m.tcObject(ifindex, fd, parent)
		err := tcnl.Filter().Add(tcObj)
		if err != nil {
			return errors.WithStack(err)
		}

		objs, e := tcnl.Filter().Get(&tcObj.Msg)
		if e != nil {
			return errors.WithStack(e)
		}
		for _, obj := range objs {
			if obj.Attribute.BPF != nil && obj.Attribute.BPF.Name != nil && *obj.Attribute.BPF.Name == BpfName {
				tcObj = &obj
				m.tcObjs = append(m.tcObjs, tcObj)
				return nil
			}
		}
		return nil
	})
}

func (m *sManager) tcObject(ifindex, fd uint32, parent uint32) *tc.Object {
	return &tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: ifindex,
			Parent:  core.BuildHandle(tc.HandleRoot, parent),
			Handle:  0,
			Info:    1<<16 | uint32(m.htons(unix.ETH_P_ALL)),
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:   &fd,
				Name: &BpfName,
			},
		},
	}
}

func (m *sManager) htons(n uint16) uint16 {
	b := *(*[2]byte)(unsafe.Pointer(&n))
	return binary.BigEndian.Uint16(b[:])
}

func (m *sManager) withTcnl(fn func(nl *tc.Tc) error) (err error) {
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return errors.WithStack(err)
	}
	defer func() {
		if e := tcnl.Close(); e != nil {
			err = errors.WithStack(e)
		}
	}()

	return fn(tcnl)
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
			if !packet.SrcIP.IsValid() || !packet.DstIP.IsValid() {
				continue
			}
			m.eventCh <- pi.toPacket()
		}
	}
}

func (m *sManager) Close() {
	m.cancel()
	for _, tcOb := range m.tcObjs {
		err := m.withTcnl(func(nl *tc.Tc) error {
			return nl.Filter().Delete(tcOb)
		})
		if err != nil {
			log.Println(err)
		}
	}
	if m.reader != nil {
		_ = m.reader.Close()
	}
	if m.objects != nil {
		_ = m.objects.Close()
	}
	return
}

// AddRule 添加限速规则
func (m *sManager) AddRule(sip string, limit int) error {
	if m.objects == nil {
		return errors.New("ebpf objects is nil")
	}
	return nil
}

// DelRule 删除限速规则
func (m *sManager) DelRule(sip string) error {
	if m.objects == nil {
		return errors.New("ebpf objects is nil")
	}
	return nil
}
