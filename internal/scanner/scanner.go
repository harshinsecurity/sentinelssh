package scanner

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/harshinsecurity/sentinelssh/internal/analyzer"
	"github.com/harshinsecurity/sentinelssh/pkg/models"
)

func ScanHost(target string, port int, timeout time.Duration) models.ScanResult {
	result := models.ScanResult{Target: target, Port: port, Status: "closed"}

	ip := net.ParseIP(target)
	if ip == nil {
		ips, err := net.LookupIP(target)
		if err != nil || len(ips) == 0 {
			result.Status = "resolution_failed"
			return result
		}
		ip = ips[0]
	}

	result.IP = ip.String()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return result
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))
	banner, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		result.Status = "error"
		result.Banner = err.Error()
		return result
	}

	result.Banner = strings.TrimSpace(banner)
	result.Status = analyzer.AnalyzeVersion(result.Banner)
	return result
}
