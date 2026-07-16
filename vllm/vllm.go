package vllm

import (
	"context"
	"sync"
	"time"

	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/proto"
)

type storedMetrics struct {
	mu      sync.RWMutex
	history map[string][]MetricSnapshot
}

// MetricSnapshot is one metric family captured at a particular scrape time.
// Family contains its complete Prometheus representation, including labels and
// histogram buckets where applicable.
type MetricSnapshot struct {
	CapturedAt time.Time
	Family     *dto.MetricFamily
}

// VLLM scrapes a vLLM endpoint and retains history for the selected metric
// families.
type VLLM struct {
	scraper *Client
	metrics storedMetrics
}

// NewVLLM constructs a vLLM metrics collector. Pass an empty endpoint to use
// DefaultEndpoint.
func NewVLLM(endpoint string, options ...Option) (*VLLM, error) {
	scraper, err := NewClient(endpoint, options...)
	if err != nil {
		return nil, err
	}

	return &VLLM{
		scraper: scraper,
		metrics: storedMetrics{
			history: make(map[string][]MetricSnapshot),
		},
	}, nil
}

// Scrape fetches metrics and stores timestamped snapshots of the selected
// vLLM metric families. The returned families are the complete scrape result.
func (v *VLLM) Scrape(ctx context.Context) (MetricFamilies, error) {
	families, err := v.scraper.Scrape(ctx)
	if err != nil {
		return nil, err
	}

	v.store(time.Now(), families)
	return families, nil
}

// History returns the snapshots stored for one metric family. Both the slice
// and contained protobuf messages are copies and may be changed by the caller.
func (v *VLLM) History(name string) []MetricSnapshot {
	v.metrics.mu.RLock()
	defer v.metrics.mu.RUnlock()

	return cloneSnapshots(v.metrics.history[name])
}

// Histories returns all selected-family histories, keyed by the metric family
// name that was scraped. The returned map and protobuf messages are copies.
func (v *VLLM) Histories() map[string][]MetricSnapshot {
	v.metrics.mu.RLock()
	defer v.metrics.mu.RUnlock()

	histories := make(map[string][]MetricSnapshot, len(v.metrics.history))
	for name, snapshots := range v.metrics.history {
		histories[name] = cloneSnapshots(snapshots)
	}
	return histories
}

func (v *VLLM) store(capturedAt time.Time, families MetricFamilies) {
	v.metrics.mu.Lock()
	defer v.metrics.mu.Unlock()

	for name, family := range selectedFamilies(families) {
		v.metrics.history[name] = append(v.metrics.history[name], MetricSnapshot{
			CapturedAt: capturedAt,
			Family:     cloneMetricFamily(family),
		})
	}
}

func cloneSnapshots(snapshots []MetricSnapshot) []MetricSnapshot {
	clones := make([]MetricSnapshot, len(snapshots))
	for i, snapshot := range snapshots {
		clones[i] = MetricSnapshot{
			CapturedAt: snapshot.CapturedAt,
			Family:     cloneMetricFamily(snapshot.Family),
		}
	}
	return clones
}

func cloneMetricFamily(family *dto.MetricFamily) *dto.MetricFamily {
	if family == nil {
		return nil
	}
	return proto.Clone(family).(*dto.MetricFamily)
}
