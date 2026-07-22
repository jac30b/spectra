// Package vllm fetches and parses metrics exposed by a vLLM server.
package vllm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"iter"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

const (
	// DefaultEndpoint is the standard metrics endpoint for a local vLLM server.
	DefaultEndpoint = "http://127.0.0.1:8000/metrics"
	defaultMaxBody  = 32 << 20 // 32 MiB
)

// MetricFamilies contains parsed Prometheus metric families, keyed by metric
// name. The protobuf model preserves metric types, labels, timestamps,
// histogram buckets, and summary quantiles.
type MetricFamilies map[string]*dto.MetricFamily

// Client scrapes a Prometheus metrics endpoint.
type Client struct {
	endpoint    string
	httpClient  *http.Client
	maxBodySize int64
}

// Option customizes a Client.
type Option func(*Client)

// WithHTTPClient sets the HTTP client used for scrapes. A nil client is
// ignored.
func WithHTTPClient(client *http.Client) Option {
	return func(c *Client) {
		if client != nil {
			c.httpClient = client
		}
	}
}

// WithMaxBodySize limits the metrics response size. Non-positive values leave
// the default 32 MiB limit in place.
func WithMaxBodySize(bytes int64) Option {
	return func(c *Client) {
		if bytes > 0 {
			c.maxBodySize = bytes
		}
	}
}

// NewClient constructs a metrics client. Pass an empty endpoint to use
// DefaultEndpoint.
func NewClient(endpoint string, options ...Option) (*Client, error) {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}

	parsed, err := url.ParseRequestURI(endpoint)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("invalid metrics endpoint %q", endpoint)
	}

	client := &Client{
		endpoint: endpoint,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		maxBodySize: defaultMaxBody,
	}
	for _, option := range options {
		if option != nil {
			option(client)
		}
	}

	return client, nil
}

// Scrape fetches and parses the current metrics from the configured endpoint.
func (c *Client) Scrape(ctx context.Context) (MetricFamilies, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create metrics request: %w", err)
	}
	req.Header.Set("Accept", string(expfmt.NewFormat(expfmt.TypeTextPlain)))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("scrape metrics: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("scrape metrics: server returned %s: %s", resp.Status, strings.TrimSpace(string(message)))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("read metrics response: %w", err)
	}
	if int64(len(body)) > c.maxBodySize {
		return nil, fmt.Errorf("metrics response exceeds %d bytes", c.maxBodySize)
	}

	format := expfmt.ResponseFormat(resp.Header)
	if format.FormatType() == expfmt.TypeUnknown {
		format = expfmt.NewFormat(expfmt.TypeTextPlain)
	}

	metrics, err := parse(bytes.NewReader(body), format)
	if err != nil {
		return nil, fmt.Errorf("parse metrics response: %w", err)
	}
	return metrics, nil
}

// Parse decodes Prometheus text exposition format from reader.
func Parse(reader io.Reader) (MetricFamilies, error) {
	return parse(reader, expfmt.NewFormat(expfmt.TypeTextPlain))
}

type MetricKind string

const (
	MetricKindHistogram MetricKind = "histogram"
	MetricKindGauge     MetricKind = "gauge"
	MetricKindCounter   MetricKind = "counter"
	MetricKindSummary   MetricKind = "summary"
)

type AggregationKind string

const (
	AggregationP95      AggregationKind = "p95"
	AggregationLatest   AggregationKind = "latest"
	AggregationAverage  AggregationKind = "average"
	AggregationIncrease AggregationKind = "increase"
	AggregationRate     AggregationKind = "rate"
)

type MetricUnit string

const (
	MetricUnitSeconds         MetricUnit = "seconds"
	MetricUnitCount           MetricUnit = "count"
	MetricUnitPercent         MetricUnit = "percent"
	MetricUnitTokens          MetricUnit = "tokens"
	MetricUnitTokensPerSecond MetricUnit = "tokens_per_second"
)

type MetricDefinition struct {
	ID            string
	DisplayName   string
	Names         []string
	Kind          MetricKind
	Aggregation   AggregationKind
	Unit          MetricUnit
	HigherIsWorse bool
}

var selectedMetricGroups = []MetricDefinition{
	{
		ID:            "ttft",
		DisplayName:   "TTFT",
		Names:         []string{"vllm:time_to_first_token_seconds"},
		Kind:          MetricKindHistogram,
		Aggregation:   AggregationP95,
		Unit:          MetricUnitSeconds,
		HigherIsWorse: true,
	},
	{
		ID:            "inter_token_latency",
		DisplayName:   "inter-token latency",
		Names:         []string{"vllm:inter_token_latency_seconds", "vllm:time_per_output_token_seconds"},
		Kind:          MetricKindHistogram,
		Aggregation:   AggregationP95,
		Unit:          MetricUnitSeconds,
		HigherIsWorse: true,
	},
	{
		ID:            "e2e_latency",
		DisplayName:   "E2E request latency",
		Names:         []string{"vllm:e2e_request_latency_seconds"},
		Kind:          MetricKindHistogram,
		Aggregation:   AggregationP95,
		Unit:          MetricUnitSeconds,
		HigherIsWorse: true,
	},
	{
		ID:            "queue_time",
		DisplayName:   "request queue time",
		Names:         []string{"vllm:request_queue_time_seconds"},
		Kind:          MetricKindHistogram,
		Aggregation:   AggregationP95,
		Unit:          MetricUnitSeconds,
		HigherIsWorse: true,
	},
	{
		ID:            "prefill_time",
		DisplayName:   "request prefill time",
		Names:         []string{"vllm:request_prefill_time_seconds"},
		Kind:          MetricKindHistogram,
		Aggregation:   AggregationP95,
		Unit:          MetricUnitSeconds,
		HigherIsWorse: true,
	},
	{
		ID:            "decode_time",
		DisplayName:   "request decode time",
		Names:         []string{"vllm:request_decode_time_seconds"},
		Kind:          MetricKindHistogram,
		Aggregation:   AggregationP95,
		Unit:          MetricUnitSeconds,
		HigherIsWorse: true,
	},
	{
		ID:            "requests_running",
		DisplayName:   "running requests",
		Names:         []string{"vllm:num_requests_running"},
		Kind:          MetricKindGauge,
		Aggregation:   AggregationAverage,
		Unit:          MetricUnitCount,
		HigherIsWorse: true,
	},
	{
		ID:            "requests_waiting",
		DisplayName:   "waiting requests",
		Names:         []string{"vllm:num_requests_waiting"},
		Kind:          MetricKindGauge,
		Aggregation:   AggregationAverage,
		Unit:          MetricUnitCount,
		HigherIsWorse: true,
	},
	{
		ID:            "cache_usage",
		DisplayName:   "KV cache usage",
		Names:         []string{"vllm:kv_cache_usage_perc", "vllm:gpu_cache_usage_perc"},
		Kind:          MetricKindGauge,
		Aggregation:   AggregationAverage,
		Unit:          MetricUnitPercent,
		HigherIsWorse: true,
	},
	{
		ID:            "prompt_tokens",
		DisplayName:   "prompt tokens",
		Names:         []string{"vllm:request_prompt_tokens", "vllm:prompt_tokens_total"},
		Kind:          MetricKindHistogram,
		Aggregation:   AggregationP95,
		Unit:          MetricUnitTokens,
		HigherIsWorse: false,
	},
	{
		ID:            "generation_tokens",
		DisplayName:   "generation tokens",
		Names:         []string{"vllm:request_generation_tokens", "vllm:generation_tokens_total"},
		Kind:          MetricKindHistogram,
		Aggregation:   AggregationP95,
		Unit:          MetricUnitTokens,
		HigherIsWorse: false,
	},
	{
		ID:            "prompt_throughput",
		DisplayName:   "prompt throughput",
		Names:         []string{"vllm:avg_prompt_throughput_toks_per_s"},
		Kind:          MetricKindGauge,
		Aggregation:   AggregationAverage,
		Unit:          MetricUnitTokensPerSecond,
		HigherIsWorse: false,
	},
	{
		ID:            "generation_throughput",
		DisplayName:   "generation throughput",
		Names:         []string{"vllm:avg_generation_throughput_toks_per_s"},
		Kind:          MetricKindGauge,
		Aggregation:   AggregationAverage,
		Unit:          MetricUnitTokensPerSecond,
		HigherIsWorse: false,
	},
}

func selectedMetricDefinition(name string) (MetricDefinition, bool) {
	for _, group := range selectedMetricGroups {
		if slices.Contains(group.Names, name) {
			return group, true
		}
	}
	return MetricDefinition{}, false
}

func (d MetricDefinition) containsName(name string) bool {
	return slices.Contains(d.Names, name)
}

func scanSelectedFamilies(families MetricFamilies) iter.Seq[selectedMetricFamily] {
	return func(yield func(selectedMetricFamily) bool) {
		for _, family := range families {
			name := family.GetName()
			definition, ok := selectedMetricDefinition(name)
			if !ok {
				continue
			}
			if !yield(selectedMetricFamily{definition: definition, name: name, family: family}) {
				return
			}
		}
	}
}

type selectedMetricFamily struct {
	definition MetricDefinition
	name       string
	family     *dto.MetricFamily
}

func parse(reader io.Reader, format expfmt.Format) (MetricFamilies, error) {
	decoder := expfmt.NewDecoder(reader, format)
	families := make(MetricFamilies)

	for {
		family := new(dto.MetricFamily)
		err := decoder.Decode(family)
		if err == io.EOF {
			return families, nil
		}
		if err != nil {
			return nil, err
		}
		if family.GetName() == "" {
			return nil, fmt.Errorf("metric family has no name")
		}

		if existing, ok := families[family.GetName()]; ok {
			existing.Metric = append(existing.Metric, family.Metric...)
			continue
		}
		families[family.GetName()] = family
	}
}
