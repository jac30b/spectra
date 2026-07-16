package vllm

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
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

func TestPrintMetricFamilies(t *testing.T) {
	families, err := Parse(strings.NewReader(testMetrics))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	var output bytes.Buffer
	if err := PrintMetricFamilies(&output, families); err != nil {
		t.Fatalf("PrintMetricFamilies() error = %v", err)
	}

	got := output.String()
	for _, want := range []string{
		"# TYPE vllm:num_requests_running gauge",
		"vllm:num_requests_running{model_name=\"test-model\"} 2",
		"# TYPE vllm:time_to_first_token_seconds histogram",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("PrintMetricFamilies() output missing %q:\n%s", want, got)
		}
	}
}

func TestPrintSelectedMetrics(t *testing.T) {
	families, err := Parse(strings.NewReader(testMetrics))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	var output bytes.Buffer
	if err := PrintSelectedMetrics(&output, families); err != nil {
		t.Fatalf("PrintSelectedMetrics() error = %v", err)
	}

	got := output.String()
	for _, want := range []string{
		"vllm:num_requests_running{model_name=\"test-model\"} 2",
		"vllm:time_to_first_token_seconds_sum{model_name=\"test-model\"} 0.7",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("PrintSelectedMetrics() output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "vllm:request_success_total") {
		t.Errorf("PrintSelectedMetrics() included an unselected metric:\n%s", got)
	}
}
