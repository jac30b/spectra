package main

import (
	"bufio"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/v3/process"
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
		if c.PID <= 0 {
			return []uint32{uint32(c.PID)}, nil
		}
		pids := slices.Collect(maps.Keys(pidCandidates(uint32(c.PID))))
		slices.Sort(pids)
		return pids, nil
	}

	targets := make(map[uint32]struct{})
	if c.PID > 0 {
		maps.Copy(targets, pidCandidates(uint32(c.PID)))
	}

	processes, err := process.Processes()
	if err != nil {
		return nil, err
	}

	for _, proc := range processes {
		if c.processNameRegex.MatchString(buildProbeString(proc)) {
			maps.Copy(targets, pidCandidates(uint32(proc.Pid)))
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

// pidCandidates returns all PID aliases visible across nested namespaces for a
// process, so filtering can match whichever PID variant the kernel reports.
func pidCandidates(pid uint32) map[uint32]struct{} {
	candidates := map[uint32]struct{}{pid: {}}

	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	f, err := os.Open(statusPath)
	if err != nil {
		return candidates
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "NSpid:\t") && !strings.HasPrefix(line, "NSpid:") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			return candidates
		}

		for _, raw := range fields[1:] {
			parsed, err := strconv.ParseUint(raw, 10, 32)
			if err != nil || parsed == 0 {
				continue
			}
			candidates[uint32(parsed)] = struct{}{}
		}

		return candidates
	}

	return candidates
}
