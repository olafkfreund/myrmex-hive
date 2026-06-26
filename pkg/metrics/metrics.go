package metrics

type SystemMetrics struct {
	CPUUsagePercent float64 `json:"cpu_usage_percent"`
	LoadAvg1m       float64 `json:"load_avg_1m"`
	LoadAvg5m       float64 `json:"load_avg_5m"`
	LoadAvg15m      float64 `json:"load_avg_15m"`
	MemTotalMB      float64 `json:"mem_total_mb"`
	MemFreeMB       float64 `json:"mem_free_mb"`
	MemUsedMB       float64 `json:"mem_used_mb"`
	MemUsedPercent  float64 `json:"mem_used_percent"`
	DiskTotalGB     float64 `json:"disk_total_gb"`
	DiskUsedGB      float64 `json:"disk_used_gb"`
	DiskFreeGB      float64 `json:"disk_free_gb"`
	DiskUsedPercent float64 `json:"disk_used_percent"`
}
