package metrics

import (
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
)

// Sample mirrors the server's MetricSampleInputSerializer — sub_dimension/unit/kind
// distinguish CPU aggregate vs per-core, disk mount vs device, network interface
// (Codex 교차검증: 원래 MetricSample(metric_type, value)만으로는 대시보드를 표현 못 함).
type Sample struct {
	MetricType   string  `json:"metric_type"`
	SubDimension string  `json:"sub_dimension"`
	Value        float64 `json:"value"`
	Unit         string  `json:"unit"`
	Kind         string  `json:"kind"`
	CollectedAt  string  `json:"collected_at"`
}

// CollectCPU returns the aggregate CPU utilization percentage.
// Phase 1 scope: aggregate only. Per-core (sub_dimension=core-N) is a
// straightforward extension via cpu.Percent(interval, true) — deferred to
// keep the first vertical slice small.
func CollectCPU() ([]Sample, error) {
	percentages, err := cpu.Percent(200*time.Millisecond, false)
	if err != nil {
		return nil, err
	}
	if len(percentages) == 0 {
		return nil, nil
	}
	return []Sample{
		{
			MetricType:   "cpu",
			SubDimension: "aggregate",
			Value:        percentages[0],
			Unit:         "%",
			Kind:         "gauge",
			CollectedAt:  time.Now().UTC().Format(time.RFC3339),
		},
	}, nil
}
