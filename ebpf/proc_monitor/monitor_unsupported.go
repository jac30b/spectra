//go:build !linux

package proc_monitor

import (
	"errors"
	"fmt"
	"runtime"

	"go.uber.org/zap"
)

var ErrUnsupportedPlatform = errors.New("eBPF process monitoring is only supported on linux")

type ProcessMonitor struct{}

func NewProcessMonitor(logger *zap.Logger, onProcessDiscovered func(pid uint32, comm string)) (*ProcessMonitor, error) {
	return nil, fmt.Errorf("%w: %s/%s", ErrUnsupportedPlatform, runtime.GOOS, runtime.GOARCH)
}

func (pm *ProcessMonitor) Start() error {
	return fmt.Errorf("%w: %s/%s", ErrUnsupportedPlatform, runtime.GOOS, runtime.GOARCH)
}

func (pm *ProcessMonitor) Stop() error {
	return nil
}

func (pm *ProcessMonitor) GetDiscoveredPIDs() []uint32 {
	return nil
}

func (pm *ProcessMonitor) RemovePID(pid uint32) {}
