//go:build darwin

package metrics

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

func GetMetrics() (*SystemMetrics, error) {
	metrics := &SystemMetrics{}

	if err := getMemInfoDarwin(metrics); err != nil {
		return nil, fmt.Errorf("failed to get memory info: %w", err)
	}

	if err := getLoadAvgDarwin(metrics); err != nil {
		return nil, fmt.Errorf("failed to get load avg: %w", err)
	}

	if err := getCPUUsageDarwin(metrics); err != nil {
		metrics.CPUUsagePercent = 0.0
	}

	if err := getDiskUsageDarwin(metrics); err != nil {
		return nil, fmt.Errorf("failed to get disk usage: %w", err)
	}

	return metrics, nil
}

func getMemInfoDarwin(m *SystemMetrics) error {
	out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
	if err != nil {
		return err
	}
	totalBytes, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return err
	}
	m.MemTotalMB = float64(totalBytes) / (1024 * 1024)

	out, err = exec.Command("vm_stat").Output()
	if err != nil {
		return err
	}

	var pageSize float64 = 4096
	var freePages float64 = 0
	var activePages float64 = 0

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "page size of") {
			parts := strings.Fields(line)
			if len(parts) >= 8 {
				if ps, err := strconv.ParseFloat(parts[7], 64); err == nil {
					pageSize = ps
				}
			}
		}
		if strings.Contains(line, "Pages free:") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				val := strings.TrimSuffix(parts[2], ".")
				if fp, err := strconv.ParseFloat(val, 64); err == nil {
					freePages = fp
				}
			}
		}
		if strings.Contains(line, "Pages active:") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				val := strings.TrimSuffix(parts[2], ".")
				if ap, err := strconv.ParseFloat(val, 64); err == nil {
					activePages = ap
				}
			}
		}
	}

	freeMB := (freePages * pageSize) / (1024 * 1024)
	activeMB := (activePages * pageSize) / (1024 * 1024)
	m.MemFreeMB = freeMB
	m.MemUsedMB = activeMB
	if m.MemTotalMB > 0 {
		m.MemUsedPercent = (m.MemUsedMB / m.MemTotalMB) * 100.0
	}

	return nil
}

func getLoadAvgDarwin(m *SystemMetrics) error {
	out, err := exec.Command("sysctl", "-n", "vm.loadavg").Output()
	if err != nil {
		return err
	}
	fields := strings.Fields(string(out))
	if len(fields) >= 4 {
		m.LoadAvg1m, _ = strconv.ParseFloat(fields[1], 64)
		m.LoadAvg5m, _ = strconv.ParseFloat(fields[2], 64)
		m.LoadAvg15m, _ = strconv.ParseFloat(fields[3], 64)
		return nil
	}
	return fmt.Errorf("failed to parse vm.loadavg output: %s", string(out))
}

func getCPUUsageDarwin(m *SystemMetrics) error {
	out, err := exec.Command("top", "-l", "1", "-n", "0").Output()
	if err != nil {
		return err
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "CPU usage:") {
			parts := strings.Fields(line)
			for i, p := range parts {
				if strings.Contains(p, "idle") && i > 0 {
					idleStr := strings.TrimSuffix(parts[i-1], "%")
					if idlePct, err := strconv.ParseFloat(idleStr, 64); err == nil {
						m.CPUUsagePercent = 100.0 - idlePct
						return nil
					}
				}
			}
		}
	}
	return fmt.Errorf("failed to parse cpu usage")
}

func getDiskUsageDarwin(m *SystemMetrics) error {
	var stat syscall.Statfs_t
	err := syscall.Statfs("/", &stat)
	if err != nil {
		return err
	}

	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	avail := stat.Bavail * uint64(stat.Bsize)
	used := total - free

	const gb = 1024 * 1024 * 1024
	m.DiskTotalGB = float64(total) / gb
	m.DiskUsedGB = float64(used) / gb
	m.DiskFreeGB = float64(avail) / gb
	if total > 0 {
		m.DiskUsedPercent = (float64(used) / float64(total)) * 100.0
	}
	return nil
}
