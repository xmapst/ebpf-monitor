package metrics

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/xmapst/ebpf-monitor/internal/ebpf"
)

const (
	retentionDuration = time.Hour * 24 * 15 // 15天
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
	IP          netip.Addr      `json:"ip"`
	Hostname    string          `json:"hostname,omitempty"`
	Upload      STrafficMetrics `json:"upload"`
	Download    STrafficMetrics `json:"download"`
	FirstSeenAt int64           `json:"first_seen_at"`
	LastSeenAt  int64           `json:"last_seen_at"`
}

type SCollector struct {
	sync.RWMutex
	summary  SMetricsSummary
	done     chan struct{}
	filePath string
}

func New(dir string) *SCollector {
	_ = os.MkdirAll(dir, 0755)
	filePath := filepath.Join(dir, "metrics.json")
	mc := &SCollector{
		filePath: filePath,
		done:     make(chan struct{}),
	}

	// 初始化 summary：加载历史数据或新建
	if metrics, err := mc.load(); err == nil && metrics != nil {
		mc.summary = *metrics
	} else {
		mc.summary = SMetricsSummary{
			Items: make(map[string]*SStatistics),
		}
	}

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

func (mc *SCollector) autoPersist() {
	ticker := time.NewTicker(time.Minute)
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

func (mc *SCollector) autoCleanup() {
	ticker := time.NewTicker(time.Minute * 10)
	defer ticker.Stop()
	for {
		select {
		case <-mc.done:
			return
		case <-ticker.C:
			mc.CleanupStaleMetrics(retentionDuration)
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

func (mc *SCollector) updateTrafficMetrics(tm *STrafficMetrics, size uint32) {
	tm.TotalBytes += int64(size)
	tm.TotalPackets++
	// 用最近一次的包大小作为当前值，可根据需求调整为累计值
	tm.Bytes = int64(size)
}

func (mc *SCollector) CollectPacket(packet *ebpf.SPacket) {
	now := time.Now().Unix()
	mc.Lock()
	defer mc.Unlock()

	var (
		mac = packet.SrcMAC
		ip  = packet.SrcIP
	)
	if packet.Direction == ebpf.FlowDirectionEgress {
		mac = packet.DstMAC
		ip = packet.DstIP
	}
	key := fmt.Sprintf("%s#%s", mac, ip)

	stats, exists := mc.summary.Items[key]
	if exists {
		stats.LastSeenAt = now
		if packet.Direction == ebpf.FlowDirectionIngress {
			mc.updateTrafficMetrics(&mc.summary.Upload, packet.Size)
			mc.updateTrafficMetrics(&stats.Upload, packet.Size)
		} else {
			mc.updateTrafficMetrics(&mc.summary.Download, packet.Size)
			mc.updateTrafficMetrics(&stats.Download, packet.Size)
		}
		return
	}

	// 新建统计项
	stats = &SStatistics{
		Mac:         mac,
		IP:          ip,
		FirstSeenAt: now,
		LastSeenAt:  now,
	}
	// 尝试反向解析域名
	if domains, err := net.LookupAddr(ip.String()); err == nil && len(domains) > 0 {
		// 去掉末尾的点
		if len(domains[0]) > 0 && domains[0][len(domains[0])-1] == '.' {
			stats.Hostname = domains[0][:len(domains[0])-1]
		} else {
			stats.Hostname = domains[0]
		}
	}

	if packet.Direction == ebpf.FlowDirectionIngress {
		mc.updateTrafficMetrics(&mc.summary.Upload, packet.Size)
		mc.updateTrafficMetrics(&stats.Upload, packet.Size)
	} else {
		mc.updateTrafficMetrics(&mc.summary.Download, packet.Size)
		mc.updateTrafficMetrics(&stats.Download, packet.Size)
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

	// 根据 order 参数获取排序字段
	getField := func(s SStatistics) int64 {
		switch order {
		case "upload":
			return s.Upload.Bytes
		case "download":
			return s.Download.Bytes
		case "first_seen_at":
			return s.FirstSeenAt
		default: // 默认为 last_seen_at
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
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
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
