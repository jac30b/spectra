package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	PID         int      `yaml:"pid"`
	Tracepoints []string `yaml:"tracepoints"`

	tracepoints map[string]struct{} `yaml:"-"`
}

func loadConfig(configPath string) (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	config.tracepoints = make(map[string]struct{}, len(config.Tracepoints))
	for _, tp := range config.Tracepoints {
		config.tracepoints[tp] = struct{}{}
	}

	return &config, nil
}

func (c *Config) isTracepointEnabled(name string) bool {
	_, exists := c.tracepoints[name]
	return exists
}
