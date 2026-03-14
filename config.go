package main

import (
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"

	"github.com/mitchellh/go-ps"
	"gopkg.in/yaml.v3"
)

type Config struct {
	PID         int      `yaml:"pid"`
	ProcessName string   `yaml:"process_name"`
	Tracepoints []string `yaml:"tracepoints"`

	tracepoints      map[string]struct{} `yaml:"-"`
	processNameRegex *regexp.Regexp      `yaml:"-"`
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
	if config.PID < 0 {
		return nil, fmt.Errorf("pid must be greater than or equal to 0")
	}

	config.tracepoints = make(map[string]struct{}, len(config.Tracepoints))
	for _, tp := range config.Tracepoints {
		config.tracepoints[tp] = struct{}{}
	}

	if config.ProcessName != "" {
		config.processNameRegex, err = regexp.Compile(config.ProcessName)
		if err != nil {
			return nil, fmt.Errorf("failed to compile process_name regex: %w", err)
		}
	}

	return &config, nil
}

func (c *Config) isTracepointEnabled(name string) bool {
	_, exists := c.tracepoints[name]
	return exists
}

func (c *Config) resolveTargetPIDs() ([]uint32, error) {
	if c.processNameRegex == nil {
		return []uint32{uint32(c.PID)}, nil
	}

	targets := make(map[uint32]struct{})
	if c.PID > 0 {
		targets[uint32(c.PID)] = struct{}{}
	}

	processes, err := ps.Processes()
	if err != nil {
		return nil, err
	}

	for _, proc := range processes {
		if c.processNameRegex.MatchString(proc.Executable()) {
			targets[uint32(proc.Pid())] = struct{}{}
		}
	}

	if len(targets) == 0 {
		return nil, os.ErrNotExist
	}

	pids := slices.Collect(maps.Keys(targets))
	slices.Sort(pids)

	return pids, nil
}
