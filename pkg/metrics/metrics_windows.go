//go:build windows

package metrics

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

func GetMetrics() (*SystemMetrics, error) {
	metrics := &SystemMetrics{}

	psScript := `
		$mem = Get-CimInstance Win32_OperatingSystem
		$cpu = Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average
		$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
		
		$totalMem = [math]::Round($mem.TotalVisibleMemorySize / 1024, 2)
		$freeMem = [math]::Round($mem.FreePhysicalMemory / 1024, 2)
		$usedMem = $totalMem - $freeMem
		
		$totalDisk = [math]::Round($disk.Size / 1GB, 2)
		$freeDisk = [math]::Round($disk.FreeSpace / 1GB, 2)
		$usedDisk = $totalDisk - $freeDisk
		
		@{
			MemTotal = $totalMem
			MemFree = $freeMem
			MemUsed = $usedMem
			MemUsedPct = [math]::Round(($usedMem / $totalMem) * 100, 2)
			CpuAvg = [math]::Round($cpu.Average, 2)
			DiskTotal = $totalDisk
			DiskFree = $freeDisk
			DiskUsed = $usedDisk
			DiskUsedPct = [math]::Round(($usedDisk / $totalDisk) * 100, 2)
		} | ConvertTo-Json
	`

	cmd := exec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute powershell: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(output, &data); err != nil {
		return nil, fmt.Errorf("failed to parse powershell json output: %w", err)
	}

	getFloat := func(key string) float64 {
		val, ok := data[key]
		if !ok || val == nil {
			return 0.0
		}
		if f, ok := val.(float64); ok {
			return f
		}
		return 0.0
	}

	metrics.MemTotalMB = getFloat("MemTotal")
	metrics.MemFreeMB = getFloat("MemFree")
	metrics.MemUsedMB = getFloat("MemUsed")
	metrics.MemUsedPercent = getFloat("MemUsedPct")
	metrics.CPUUsagePercent = getFloat("CpuAvg")
	metrics.DiskTotalGB = getFloat("DiskTotal")
	metrics.DiskUsedGB = getFloat("DiskUsed")
	metrics.DiskFreeGB = getFloat("DiskFree")
	metrics.DiskUsedPercent = getFloat("DiskUsedPct")

	// Windows doesn't have native load averages; substitute CPU load
	metrics.LoadAvg1m = metrics.CPUUsagePercent / 100.0
	metrics.LoadAvg5m = metrics.CPUUsagePercent / 100.0
	metrics.LoadAvg15m = metrics.CPUUsagePercent / 100.0

	return metrics, nil
}
