package metrics

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/xmapst/ebpf-monitor/internal/ebpf"
)

type SMetricsSummary struct {
	Upload   STrafficMetrics         `json:"upload"`
	Download STrafficMetrics         `json:"download"`
	Items    map[string]*SStatistics `json:"items"`
}

type STrafficMetrics struct {
	Bytes        int64 `json:"bytes,omitempty"`
	TotalBytes   int64 `json:"total_bytes"`
	TotalPackets int64 `json:"total_packets"`
}

type SStatistics struct {
	Mac         string          `json:"mac"`
	IP          string          `json:"ip"`
	Hostname    string          `json:"hostname,omitempty"`
	Upload      STrafficMetrics `json:"upload"`
	Download    STrafficMetrics `json:"download"`
	FirstSeenAt int64           `json:"first_seen_at"`
	LastSeenAt  int64           `json:"last_seen_at"`
}

// SCollector handles the collection and aggregation of network metrics
type SCollector struct {
	sync.RWMutex
	summary  SMetricsSummary
	done     chan struct{}
	filePath string
}

// New creates and initializes a new metrics collector instance
func New(dir string) *SCollector {
	_ = os.MkdirAll(dir, 0755)
	mc := &SCollector{
		filePath: filepath.Join(dir, "metrics.json"),
		done:     make(chan struct{}),
	}

	var summary SMetricsSummary
	if metrics, err := mc.load(); err == nil && metrics != nil {
		summary = *metrics
	} else {
		summary = SMetricsSummary{
			Items: make(map[string]*SStatistics),
		}
	}

	mc.summary = summary

	go mc.autoCleanup()
	go mc.autoPersist()
	return mc
}

func (mc *SCollector) save() error {
	mc.Lock()
	defer mc.Unlock()

	data, err := json.Marshal(&mc.summary)
	if err != nil {
		return err
	}
	return os.WriteFile(mc.filePath, data, 0644)
}

func (mc *SCollector) load() (*SMetricsSummary, error) {
	mc.Lock()
	defer mc.Unlock()

	data, err := os.ReadFile(mc.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var metrics SMetricsSummary
	if err = json.Unmarshal(data, &metrics); err != nil {
		return nil, err
	}
	return &metrics, nil
}

// periodically persist metrics data
func (mc *SCollector) autoPersist() {
	ticker := time.NewTicker(time.Minute * 1)
	defer ticker.Stop()
	for {
		select {
		case <-mc.done:
			return
		case <-ticker.C:
			if err := mc.save(); err != nil {
				log.Printf("保存指标数据失败: %v", err)
			}
		}
	}
}

// periodically removes stale metrics data
func (mc *SCollector) autoCleanup() {
	ticker := time.NewTicker(time.Minute * 10)
	defer ticker.Stop()
	for {
		select {
		case <-mc.done:
			return
		case <-ticker.C:
			mc.CleanupStaleMetrics(time.Hour * 24 * 15)
		}
	}
}

func (mc *SCollector) CleanupStaleMetrics(retention time.Duration) {
	mc.Lock()
	defer mc.Unlock()
	now := time.Now().Unix()
	for key, stats := range mc.summary.Items {
		if now-stats.LastSeenAt > int64(retention.Seconds()) {
			delete(mc.summary.Items, key)
		}
	}
}

// CollectPacket processes metrics for a single packet
func (mc *SCollector) CollectPacket(packet *ebpf.SPacket) {
	mc.Lock()
	defer mc.Unlock()

	key := fmt.Sprintf("%s#%s", packet.SrcMAC, packet.SrcIP)
	if packet.Direction == ebpf.FlowDirectionEgress {
		key = fmt.Sprintf("%s#%s", packet.DstMAC, packet.DstIP)
	}
	if stats, ok := mc.summary.Items[key]; ok {
		stats.LastSeenAt = time.Now().Unix()
		if packet.Direction == ebpf.FlowDirectionIngress {
			mc.summary.Upload.TotalBytes += int64(packet.Size)
			mc.summary.Upload.TotalPackets += 1

			stats.Upload.TotalBytes += int64(packet.Size)
			stats.Upload.TotalPackets += 1
			stats.Upload.Bytes = int64(packet.Size)
		} else {
			mc.summary.Download.TotalBytes += int64(packet.Size)
			mc.summary.Download.TotalPackets += 1

			stats.Download.TotalBytes += int64(packet.Size)
			stats.Download.TotalPackets += 1
			stats.Download.Bytes = int64(packet.Size)
		}
		return
	}
	stats := &SStatistics{
		Mac:         packet.SrcMAC,
		IP:          packet.SrcIP,
		FirstSeenAt: time.Now().Unix(),
		LastSeenAt:  time.Now().Unix(),
	}
	domains, err := net.LookupAddr(packet.SrcIP)
	if err == nil {
		for _, domain := range domains {
			if domain != "" {
				domain = domain[:len(domain)-1]
				break
			}
		}
	}
	if packet.Direction == ebpf.FlowDirectionIngress {
		mc.summary.Upload.TotalBytes += int64(packet.Size)
		mc.summary.Upload.TotalPackets += 1

		stats.Upload.TotalBytes = int64(packet.Size)
		stats.Upload.TotalPackets = 1
		stats.Upload.Bytes = int64(packet.Size)
	} else {
		mc.summary.Download.TotalBytes += int64(packet.Size)
		mc.summary.Download.TotalPackets += 1

		stats.Download.TotalBytes = int64(packet.Size)
		stats.Download.TotalPackets = 1
		stats.Download.Bytes = int64(packet.Size)
	}
	mc.summary.Items[key] = stats
}

type SSourcePage struct {
	Total    int             `json:"total"`
	Upload   STrafficMetrics `json:"upload"`
	Download STrafficMetrics `json:"download"`
	Items    []SStatistics   `json:"items"`
}

func (mc *SCollector) GenerateReport(page int, pageSize int, order string, sortDir string) SSourcePage {
	mc.RLock()
	defer mc.RUnlock()

	var result []SStatistics
	for _, stats := range mc.summary.Items {
		result = append(result, *stats)
	}
	getField := func(s SStatistics) int64 {
		switch order {
		case "upload":
			return s.Upload.Bytes
		case "download":
			return s.Download.Bytes
		case "first_seen_at":
			return s.FirstSeenAt
		default: // last_seen_at
			return s.LastSeenAt
		}
	}
	if sortDir == "" {
		sortDir = "desc"
	}

	sort.Slice(result, func(i, j int) bool {
		if sortDir == "desc" {
			return getField(result[i]) > getField(result[j])
		}
		return getField(result[i]) < getField(result[j])
	})
	if page == 0 {
		page = 1
	}
	if pageSize == 0 {
		pageSize = 20
	}
	start := (page - 1) * pageSize
	end := start + pageSize
	if end > len(result) {
		end = len(result)
	}
	return SSourcePage{
		Total:    len(mc.summary.Items),
		Upload:   mc.summary.Upload,
		Download: mc.summary.Download,
		Items:    result[start:end],
	}
}

func (mc *SCollector) Close() error {
	close(mc.done)
	if err := mc.save(); err != nil {
		return err
	}
	return nil
}
