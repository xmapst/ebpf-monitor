package utils

import (
	"net"
	"strings"
)

var (
	localIPs = []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"192.88.99.0/24",
		"192.168.0.0/16",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/4",
		"233.252.0.0/24",
		"240.0.0.0/4",
		"255.255.255.255/32",
	}
	localIPNets []*net.IPNet
)

func init() {
	for _, ip := range localIPs {
		_, ipNet, err := net.ParseCIDR(ip)
		if err != nil {
			continue
		}
		localIPNets = append(localIPNets, ipNet)
	}
}

func IsLocalIP(ip string) bool {
	ip = strings.TrimSpace(ip)
	ipNet := net.ParseIP(ip)
	for _, localIPNet := range localIPNets {
		if localIPNet.Contains(ipNet) {
			return true
		}
	}
	return false
}
