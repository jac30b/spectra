package main

import (
	"testing"
	"time"

	"github.com/jac30b/spectra/vllm"
)

func TestParseRecordConfig(t *testing.T) {
	config, err := parseRecordConfig([]string{
		"--pid", "1234",
		"--prometheus-url", "http://localhost:8000/metrics",
		"--duration", "120s",
		"--output", "run.spectra",
	})
	if err != nil {
		t.Fatalf("parseRecordConfig() error = %v", err)
	}

	if config.PID != 1234 {
		t.Errorf("PID = %d, want 1234", config.PID)
	}
	if config.PrometheusURL != "http://localhost:8000/metrics" {
		t.Errorf("PrometheusURL = %q", config.PrometheusURL)
	}
	if config.Duration != 120*time.Second {
		t.Errorf("Duration = %s, want 120s", config.Duration)
	}
	if config.Output != "run.spectra" {
		t.Errorf("Output = %q, want run.spectra", config.Output)
	}
}

func TestParseRecordConfigDefaults(t *testing.T) {
	config, err := parseRecordConfig(nil)
	if err != nil {
		t.Fatalf("parseRecordConfig() error = %v", err)
	}

	if config.PrometheusURL != vllm.DefaultEndpoint {
		t.Errorf("PrometheusURL = %q, want %q", config.PrometheusURL, vllm.DefaultEndpoint)
	}
	if config.Duration != 120*time.Second {
		t.Errorf("Duration = %s, want 120s", config.Duration)
	}
}

func TestParseRecordConfigRejectsInvalidInput(t *testing.T) {
	tests := [][]string{
		{"--duration", "0s"},
		{"unexpected"},
	}
	for _, args := range tests {
		if _, err := parseRecordConfig(args); err == nil {
			t.Errorf("parseRecordConfig(%v) error = nil, want error", args)
		}
	}
}
