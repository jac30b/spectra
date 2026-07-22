package vllm

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/proto"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

const testMetrics = `# HELP vllm:num_requests_running Number of requests currently running.
# TYPE vllm:num_requests_running gauge
vllm:num_requests_running{model_name="test-model"} 2
# HELP vllm:request_success_total Successful requests.
# TYPE vllm:request_success_total counter
vllm:request_success_total{finished_reason="stop",model_name="test-model"} 12 1710000000000
# HELP vllm:time_to_first_token_seconds Time to first token.
# TYPE vllm:time_to_first_token_seconds histogram
vllm:time_to_first_token_seconds_bucket{le="0.1",model_name="test-model"} 3
vllm:time_to_first_token_seconds_bucket{le="+Inf",model_name="test-model"} 5
vllm:time_to_first_token_seconds_sum{model_name="test-model"} 0.7
vllm:time_to_first_token_seconds_count{model_name="test-model"} 5
`

const aliasMetrics = `# HELP vllm:kv_cache_usage_perc KV cache usage.
# TYPE vllm:kv_cache_usage_perc gauge
vllm:kv_cache_usage_perc{model_name="test-model"} 0.42
# HELP vllm:gpu_cache_usage_perc GPU cache usage.
# TYPE vllm:gpu_cache_usage_perc gauge
vllm:gpu_cache_usage_perc{model_name="test-model"} 0.43
# HELP vllm:inter_token_latency_seconds Inter-token latency.
# TYPE vllm:inter_token_latency_seconds histogram
vllm:inter_token_latency_seconds_bucket{le="0.1",model_name="test-model"} 4
vllm:inter_token_latency_seconds_bucket{le="+Inf",model_name="test-model"} 4
vllm:inter_token_latency_seconds_sum{model_name="test-model"} 0.2
vllm:inter_token_latency_seconds_count{model_name="test-model"} 4
# HELP vllm:time_per_output_token_seconds Time per output token.
# TYPE vllm:time_per_output_token_seconds histogram
vllm:time_per_output_token_seconds_bucket{le="0.1",model_name="test-model"} 5
vllm:time_per_output_token_seconds_bucket{le="+Inf",model_name="test-model"} 5
vllm:time_per_output_token_seconds_sum{model_name="test-model"} 0.3
vllm:time_per_output_token_seconds_count{model_name="test-model"} 5
`

func TestParse(t *testing.T) {
	families, err := Parse(strings.NewReader(testMetrics))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	gauge := families["vllm:num_requests_running"]
	if gauge.GetType() != dto.MetricType_GAUGE || len(gauge.Metric) != 1 {
		t.Fatalf("unexpected gauge family: %#v", gauge)
	}
	if got := gauge.Metric[0].GetGauge().GetValue(); got != 2 {
		t.Errorf("gauge value = %v, want 2", got)
	}
	if got := gauge.Metric[0].Label[0].GetValue(); got != "test-model" {
		t.Errorf("model_name = %q, want test-model", got)
	}

	counter := families["vllm:request_success_total"]
	if counter.GetType() != dto.MetricType_COUNTER {
		t.Fatalf("unexpected counter family: %#v", counter)
	}
	if got := counter.Metric[0].GetCounter().GetValue(); got != 12 {
		t.Errorf("counter value = %v, want 12", got)
	}
	if got := counter.Metric[0].GetTimestampMs(); got != 1710000000000 {
		t.Errorf("timestamp = %d, want 1710000000000", got)
	}

	histogram := families["vllm:time_to_first_token_seconds"]
	if histogram.GetType() != dto.MetricType_HISTOGRAM {
		t.Fatalf("unexpected histogram family: %#v", histogram)
	}
	value := histogram.Metric[0].GetHistogram()
	if value.GetSampleCount() != 5 || value.GetSampleSum() != 0.7 || len(value.Bucket) != 2 {
		t.Errorf("unexpected histogram: %#v", value)
	}
}

func TestClientScrape(t *testing.T) {
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if !strings.Contains(r.Header.Get("Accept"), "text/plain") {
			t.Errorf("Accept = %q, want text/plain", r.Header.Get("Accept"))
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     http.Header{"Content-Type": []string{"text/plain; version=0.0.4"}},
			Body:       io.NopCloser(strings.NewReader(testMetrics)),
		}, nil
	})}

	client, err := NewClient("http://vllm.test/metrics", WithHTTPClient(httpClient))
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	families, err := client.Scrape(context.Background())
	if err != nil {
		t.Fatalf("Scrape() error = %v", err)
	}
	if len(families) != 3 {
		t.Errorf("Scrape() returned %d families, want 3", len(families))
	}
}

func TestClientErrors(t *testing.T) {
	t.Run("status", func(t *testing.T) {
		httpClient := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Status:     "503 Service Unavailable",
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("not ready\n")),
			}, nil
		})}

		client, _ := NewClient("http://vllm.test/metrics", WithHTTPClient(httpClient))
		_, err := client.Scrape(context.Background())
		if err == nil || !strings.Contains(err.Error(), "503 Service Unavailable") {
			t.Fatalf("Scrape() error = %v, want status error", err)
		}
	})

	t.Run("body limit", func(t *testing.T) {
		httpClient := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(testMetrics)),
			}, nil
		})}

		client, _ := NewClient("http://vllm.test/metrics", WithHTTPClient(httpClient), WithMaxBodySize(10))
		_, err := client.Scrape(context.Background())
		if err == nil || !strings.Contains(err.Error(), "exceeds 10 bytes") {
			t.Fatalf("Scrape() error = %v, want body limit error", err)
		}
	})
}

func TestNewClientRejectsInvalidEndpoint(t *testing.T) {
	if _, err := NewClient("127.0.0.1:8000/metrics"); err == nil {
		t.Fatal("NewClient() error = nil, want invalid endpoint error")
	}
}

func TestSelectedMetricDefinition(t *testing.T) {
	definition, ok := selectedMetricDefinition("vllm:time_to_first_token_seconds")
	if !ok {
		t.Fatal("selectedMetricDefinition() ok = false, want true")
	}
	if definition.ID != "ttft" ||
		definition.Kind != MetricKindHistogram ||
		definition.Aggregation != AggregationP95 ||
		definition.Unit != MetricUnitSeconds ||
		!definition.HigherIsWorse {
		t.Fatalf("unexpected TTFT definition: %#v", definition)
	}

	cacheDefinition, ok := selectedMetricDefinition("vllm:gpu_cache_usage_perc")
	if !ok {
		t.Fatal("selectedMetricDefinition() for gpu cache ok = false, want true")
	}
	if cacheDefinition.ID != "cache_usage" ||
		cacheDefinition.Kind != MetricKindGauge ||
		cacheDefinition.Aggregation != AggregationAverage ||
		cacheDefinition.Unit != MetricUnitPercent ||
		!cacheDefinition.containsName("vllm:kv_cache_usage_perc") {
		t.Fatalf("unexpected cache definition: %#v", cacheDefinition)
	}

	if _, ok := selectedMetricDefinition("vllm:request_success_total"); ok {
		t.Fatal("selectedMetricDefinition() for unselected metric ok = true, want false")
	}
}

func TestScanSelectedFamiliesIncludesMetadata(t *testing.T) {
	families, err := Parse(strings.NewReader(testMetrics))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	selected := make(map[string]selectedMetricFamily)
	for family := range scanSelectedFamilies(families) {
		selected[family.name] = family
	}

	running, ok := selected["vllm:num_requests_running"]
	if !ok {
		t.Fatal("scanSelectedFamilies() missing num_requests_running")
	}
	if running.definition.ID != "requests_running" ||
		running.definition.Kind != MetricKindGauge ||
		running.definition.Aggregation != AggregationAverage {
		t.Fatalf("unexpected running requests metadata: %#v", running.definition)
	}
	if _, ok := selected["vllm:request_success_total"]; ok {
		t.Fatal("scanSelectedFamilies() included unselected request_success_total")
	}
}

func TestPrintSelectedMetrics(t *testing.T) {
	families, err := Parse(strings.NewReader(testMetrics))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	collector := &VLLM{metrics: storedMetrics{history: make(map[string][]MetricSnapshot)}}
	capturedAt := time.Date(2026, time.July, 17, 12, 0, 0, 0, time.UTC)
	collector.store(capturedAt, families)

	var output strings.Builder
	if err := collector.PrintSelectedMetrics(&output); err != nil {
		t.Fatalf("PrintSelectedMetrics() error = %v", err)
	}

	got := output.String()
	for _, want := range []string{
		"vllm:num_requests_running{model_name=\"test-model\"} 2",
		"vllm:time_to_first_token_seconds_sum{model_name=\"test-model\"} 0.7",
		"1784289600000",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("PrintSelectedMetrics() output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "vllm:request_success_total") {
		t.Errorf("PrintSelectedMetrics() included an unselected metric:\n%s", got)
	}
}

func TestStoreKeepsBothSelectedAliases(t *testing.T) {
	families, err := Parse(strings.NewReader(aliasMetrics))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	collector := &VLLM{metrics: storedMetrics{history: make(map[string][]MetricSnapshot)}}
	capturedAt := time.Date(2026, time.July, 17, 12, 0, 0, 0, time.UTC)
	collector.store(capturedAt, families)

	for _, name := range []string{
		"vllm:kv_cache_usage_perc",
		"vllm:gpu_cache_usage_perc",
		"vllm:inter_token_latency_seconds",
		"vllm:time_per_output_token_seconds",
	} {
		history := collector.History(name)
		if len(history) != 1 {
			t.Fatalf("%s history length = %d, want 1", name, len(history))
		}
		if history[0].Definition.ID == "" {
			t.Fatalf("%s stored empty metric definition", name)
		}
	}
}

func TestPrintSelectedMetricsUsesPreferredAlias(t *testing.T) {
	families, err := Parse(strings.NewReader(aliasMetrics))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	collector := &VLLM{metrics: storedMetrics{history: make(map[string][]MetricSnapshot)}}
	collector.store(time.Date(2026, time.July, 17, 12, 0, 0, 0, time.UTC), families)

	var output strings.Builder
	if err := collector.PrintSelectedMetrics(&output); err != nil {
		t.Fatalf("PrintSelectedMetrics() error = %v", err)
	}

	got := output.String()
	for _, want := range []string{
		"vllm:kv_cache_usage_perc{model_name=\"test-model\"} 0.42",
		"vllm:inter_token_latency_seconds_sum{model_name=\"test-model\"} 0.2",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("PrintSelectedMetrics() output missing preferred alias %q:\n%s", want, got)
		}
	}
	for _, notWant := range []string{
		"vllm:gpu_cache_usage_perc",
		"vllm:time_per_output_token_seconds",
	} {
		if strings.Contains(got, notWant) {
			t.Errorf("PrintSelectedMetrics() included fallback alias %q:\n%s", notWant, got)
		}
	}
}

func TestVLLMScrapeStoresSelectedMetricHistory(t *testing.T) {
	httpClient := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     http.Header{"Content-Type": []string{"text/plain; version=0.0.4"}},
			Body:       io.NopCloser(strings.NewReader(testMetrics)),
		}, nil
	})}

	collector, err := NewVLLM("http://vllm.test/metrics", WithHTTPClient(httpClient))
	if err != nil {
		t.Fatalf("NewVLLM() error = %v", err)
	}
	if _, err := collector.Scrape(context.Background()); err != nil {
		t.Fatalf("first Scrape() error = %v", err)
	}
	if _, err := collector.Scrape(context.Background()); err != nil {
		t.Fatalf("second Scrape() error = %v", err)
	}

	history := collector.History("vllm:num_requests_running")
	if len(history) != 2 {
		t.Fatalf("running request history length = %d, want 2", len(history))
	}
	if history[0].CapturedAt.IsZero() || history[0].Family.GetMetric()[0].GetGauge().GetValue() != 2 {
		t.Errorf("unexpected stored snapshot: %#v", history[0])
	}
	if history[0].Definition.ID != "requests_running" ||
		history[0].Definition.Kind != MetricKindGauge ||
		history[0].Definition.Aggregation != AggregationAverage {
		t.Errorf("unexpected stored definition: %#v", history[0].Definition)
	}

	history[0].Family.Metric[0].Gauge.Value = proto.Float64(99)
	history[0].Definition.Names[0] = "mutated"
	freshHistory := collector.History("vllm:num_requests_running")
	if got := freshHistory[0].Family.GetMetric()[0].GetGauge().GetValue(); got != 2 {
		t.Errorf("mutating returned history changed stored value to %v", got)
	}
	if got := freshHistory[0].Definition.Names[0]; got != "vllm:num_requests_running" {
		t.Errorf("mutating returned definition changed stored name to %q", got)
	}

	all := collector.Histories()
	if _, ok := all["vllm:request_success_total"]; ok {
		t.Error("stored unselected request_success_total history")
	}
}
