package main

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/shirou/gopsutil/v3/process"
	"gopkg.in/yaml.v3"
)

type Config struct {
	PID                  int      `yaml:"pid"`
	ProcessName          string   `yaml:"process_name"`
	Tracepoints          []string `yaml:"tracepoints"`
	EnableProcessMonitor bool     `yaml:"enable_process_monitor"`
	LibCudaPath          string   `yaml:"lib_cuda_path"`
	CollectorEndpoint    string   `yaml:"collector_endpoint"`

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
		if c.PID <= 0 {
			return []uint32{uint32(c.PID)}, nil
		}
		return []uint32{uint32(c.PID)}, nil
	}

	targets := make(map[uint32]struct{})
	if c.PID > 0 {
		targets[uint32(c.PID)] = struct{}{}
	}

	processes, err := process.Processes()
	if err != nil {
		return nil, err
	}

	for _, proc := range processes {
		if c.processNameRegex.MatchString(buildProbeString(proc)) {
			targets[uint32(proc.Pid)] = struct{}{}
		}
	}

	if len(targets) == 0 {
		return nil, os.ErrNotExist
	}

	pids := slices.Collect(maps.Keys(targets))
	slices.Sort(pids)

	return pids, nil
}

// buildProbeString builds a string probed against process_name regex.
// It concatenates the exe path, raw cmdline, and any relative arguments
// resolved against the process CWD. This allows patterns that match a project
// directory name to match a script launched with a relative path from that
// directory, without false-positives from shells whose CWD happens to be there.
func buildProbeString(proc *process.Process) string {
	var parts []string

	if exe, err := proc.Exe(); err == nil {
		parts = append(parts, exe)
	}

	args, err := proc.CmdlineSlice()
	if err != nil {
		return strings.Join(parts, "\x00")
	}
	parts = append(parts, strings.Join(args, " "))

	cwd, err := proc.Cwd()
	if err != nil {
		return strings.Join(parts, "\x00")
	}

	for _, arg := range args {
		if strings.HasPrefix(arg, "./") || strings.HasPrefix(arg, "../") {
			parts = append(parts, filepath.Join(cwd, arg))
		}
	}

	return strings.Join(parts, "\x00")
}
