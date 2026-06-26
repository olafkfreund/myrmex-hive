//go:build linux

package metrics

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func GetMetrics() (*SystemMetrics, error) {
	metrics := &SystemMetrics{}

	if err := getMemInfo(metrics); err != nil {
		return nil, fmt.Errorf("failed to get memory info: %w", err)
	}

	if err := getLoadAvg(metrics); err != nil {
		return nil, fmt.Errorf("failed to get load avg: %w", err)
	}

	if err := getCPUUsage(metrics); err != nil {
		metrics.CPUUsagePercent = 0.0
	}

	if err := getDiskUsage(metrics); err != nil {
		return nil, fmt.Errorf("failed to get disk usage: %w", err)
	}

	return metrics, nil
}

func getMemInfo(m *SystemMetrics) error {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return err
	}
	defer file.Close()

	var total, free, available int64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		val, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}

		switch key {
		case "MemTotal":
			total = val // in kB
		case "MemFree":
			free = val
		case "MemAvailable":
			available = val
		}
	}

	if total == 0 {
		return fmt.Errorf("could not read total memory")
	}

	m.MemTotalMB = float64(total) / 1024.0
	m.MemFreeMB = float64(free) / 1024.0

	used := total - available
	if available == 0 {
		used = total - free
	}
	m.MemUsedMB = float64(used) / 1024.0
	m.MemUsedPercent = (float64(used) / float64(total)) * 100.0

	return nil
}

func getLoadAvg(m *SystemMetrics) error {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return fmt.Errorf("invalid format of /proc/loadavg")
	}

	m.LoadAvg1m, err = strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return err
	}
	m.LoadAvg5m, err = strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return err
	}
	m.LoadAvg15m, err = strconv.ParseFloat(fields[2], 64)
	if err != nil {
		return err
	}

	return nil
}

func readCPUStat() ([]uint64, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "cpu" {
			return nil, fmt.Errorf("invalid format of /proc/stat")
		}

		stats := make([]uint64, len(fields)-1)
		for i := 1; i < len(fields); i++ {
			val, err := strconv.ParseUint(fields[i], 10, 64)
			if err != nil {
				return nil, err
			}
			stats[i-1] = val
		}
		return stats, nil
	}
	return nil, fmt.Errorf("empty /proc/stat")
}

func getCPUUsage(m *SystemMetrics) error {
	stat1, err := readCPUStat()
	if err != nil {
		return err
	}

	time.Sleep(100 * time.Millisecond)

	stat2, err := readCPUStat()
	if err != nil {
		return err
	}

	if len(stat1) < 4 || len(stat2) < 4 {
		return fmt.Errorf("invalid CPU stats")
	}

	idle1 := stat1[3] + stat1[4] // idle + iowait
	nonIdle1 := stat1[0] + stat1[1] + stat1[2] + stat1[5] + stat1[6]
	total1 := idle1 + nonIdle1

	idle2 := stat2[3] + stat2[4]
	nonIdle2 := stat2[0] + stat2[1] + stat2[2] + stat2[5] + stat2[6]
	total2 := idle2 + nonIdle2

	totalDiff := float64(total2) - float64(total1)
	idleDiff := float64(idle2) - float64(idle1)

	if totalDiff == 0 {
		m.CPUUsagePercent = 0.0
		return nil
	}

	m.CPUUsagePercent = ((totalDiff - idleDiff) / totalDiff) * 100.0
	return nil
}

func getDiskUsage(m *SystemMetrics) error {
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
	} else {
		m.DiskUsedPercent = 0.0
	}

	return nil
}
