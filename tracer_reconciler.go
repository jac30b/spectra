package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/jac30b/spectra/ebpf"
	"github.com/jac30b/spectra/ebpf/proc_monitor"
	"github.com/shirou/gopsutil/v3/process"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

// tracerReconciler manages a dynamic set of per-PID tracers.
type tracerReconciler struct {
	config         *Config
	logger         *zap.Logger
	tracers        map[uint32]*ebpf.Tracer
	mu             sync.RWMutex
	procMonitor    *proc_monitor.ProcessMonitor
	monitorEnabled bool
	stopChan       chan struct{}
	wg             sync.WaitGroup
}

func newTracerReconciler(config *Config, logger *zap.Logger) *tracerReconciler {
	return &tracerReconciler{
		config:   config,
		logger:   logger,
		tracers:  make(map[uint32]*ebpf.Tracer),
		stopChan: make(chan struct{}),
	}
}

func (r *tracerReconciler) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tracers)
}

func (r *tracerReconciler) Reconcile(ctx context.Context) error {
	pids, err := r.config.resolveTargetPIDs()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	desired := make(map[uint32]struct{}, len(pids))
	for _, pid := range pids {
		desired[pid] = struct{}{}
		if _, exists := r.tracers[pid]; exists {
			continue
		}

		tracer, err := r.newTracer(ctx, pid)
		if err != nil {
			return err
		}
		r.tracers[pid] = tracer

		fields := []zap.Field{zap.Uint32("pid", pid)}
		if meta, err := resolveProcessMeta(pid); err == nil {
			fields = append(fields,
				zap.String("process_name", meta.name),
				zap.String("process_exe", meta.exe),
				zap.String("process_cmdline", meta.cmdline),
			)
		}
		r.logger.Info("attached tracer", fields...)
	}

	for pid, tracer := range r.tracers {
		if _, exists := desired[pid]; exists {
			continue
		}
		if err := tracer.Stop(); err != nil {
			return err
		}
		delete(r.tracers, pid)
		r.logger.Info("detached tracer", zap.Uint32("pid", pid))
	}

	return nil
}

// PerPIDResponse holds tracepoint data for a specific process.
type PerPIDResponse struct {
	PID      uint32
	Meta     processMeta
	Response ebpf.PullResponse
}

func (r *tracerReconciler) Pull(ctx context.Context) (ebpf.PullResponse, error) {
	perPIDResponses, err := r.PullPerPID(ctx)
	if err != nil {
		return ebpf.PullResponse{}, err
	}

	resp := ebpf.NewPullResponse()
	for _, ppr := range perPIDResponses {
		mergeCounts(resp.Futex, ppr.Response.Futex)
		mergeCounts(resp.SchedSwitch, ppr.Response.SchedSwitch)
		mergeCounts(resp.PageFault, ppr.Response.PageFault)
		mergeCounts(resp.Ioctl, ppr.Response.Ioctl)
	}

	return resp, nil
}

func (r *tracerReconciler) PullPerPID(ctx context.Context) ([]PerPIDResponse, error) {
	var (
		errg    errgroup.Group
		tracers = r.snapshotTracers()
		results = make(chan PerPIDResponse, len(tracers))
	)

	for pid, tracer := range tracers {
		errg.Go(func() error {
			res, err := tracer.Pull(ctx)
			if err != nil {
				return fmt.Errorf("pid %d: %w", pid, err)
			}

			meta, _ := resolveProcessMeta(pid)
			results <- PerPIDResponse{
				PID:      pid,
				Meta:     meta,
				Response: res,
			}
			return nil
		})
	}

	err := errg.Wait()
	close(results)

	var responses []PerPIDResponse
	for result := range results {
		responses = append(responses, result)
	}

	return responses, err
}

func (r *tracerReconciler) StartProcessMonitor(ctx context.Context) error {
	if !r.config.EnableProcessMonitor {
		r.logger.Info("process monitor disabled")
		return nil
	}

	monitor, err := proc_monitor.NewProcessMonitor(r.logger, r.onProcessDiscovered)
	if err != nil {
		return fmt.Errorf("failed to create process monitor: %w", err)
	}

	r.procMonitor = monitor
	r.monitorEnabled = true

	if err := monitor.Start(); err != nil {
		return fmt.Errorf("failed to start process monitor: %w", err)
	}

	// Start goroutine to check for dead processes
	r.wg.Add(1)
	go r.monitorProcessLifetimes()

	r.logger.Info("process monitor started - watching for SPECTRA env var")
	return nil
}

func (r *tracerReconciler) onProcessDiscovered(pid uint32, comm string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if we're already tracing this PID
	if _, exists := r.tracers[pid]; exists {
		r.logger.Debug("process already being traced", zap.Uint32("pid", pid))
		return
	}

	// Create tracer for the discovered process
	tracer, err := r.newTracer(context.Background(), pid)
	if err != nil {
		r.logger.Error("failed to create tracer for discovered process",
			zap.Uint32("pid", pid),
			zap.String("comm", comm),
			zap.Error(err))
		return
	}

	r.tracers[pid] = tracer
	r.logger.Info("auto-attached tracer for process with SPECTRA",
		zap.Uint32("pid", pid),
		zap.String("comm", comm))
}

func (r *tracerReconciler) monitorProcessLifetimes() {
	defer r.wg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopChan:
			return
		case <-ticker.C:
			r.cleanupDeadProcesses()
		}
	}
}

func (r *tracerReconciler) cleanupDeadProcesses() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for pid, tracer := range r.tracers {
		// Check if process still exists
		if _, err := process.NewProcess(int32(pid)); err != nil {
			// Process is dead, stop tracing
			r.logger.Info("process exited, stopping tracer",
				zap.Uint32("pid", pid))

			if err := tracer.Stop(); err != nil {
				r.logger.Error("error stopping tracer",
					zap.Uint32("pid", pid),
					zap.Error(err))
			}
			delete(r.tracers, pid)

			// Also remove from monitor's discovered list
			if r.procMonitor != nil {
				r.procMonitor.RemovePID(pid)
			}
		}
	}
}

func (r *tracerReconciler) Stop() error {
	close(r.stopChan)

	// Stop process monitor
	if r.procMonitor != nil {
		r.procMonitor.Stop()
	}

	// Wait for goroutines
	r.wg.Wait()

	r.mu.Lock()
	defer r.mu.Unlock()

	var err error
	for pid, tracer := range r.tracers {
		err = errors.Join(err, tracer.Stop())
		delete(r.tracers, pid)
	}
	return err
}

func (r *tracerReconciler) newTracer(ctx context.Context, pid uint32) (*ebpf.Tracer, error) {
	tracer, err := ebpf.NewTracer(ctx, pid,
		ebpf.WithLogger(r.logger),
		ebpf.WithTraceFutex(r.config.isTracepointEnabled("futex")),
		ebpf.WithTraceSchedSwitch(r.config.isTracepointEnabled("sched_switch")),
		ebpf.WithTracePageFault(r.config.isTracepointEnabled("page_fault_user")),
		ebpf.WithTraceIoctl(r.config.isTracepointEnabled("ioctl")),
		ebpf.WithTraceMmap(r.config.isTracepointEnabled("mmap")),
		ebpf.WithTraceClone3(r.config.isTracepointEnabled("clone3")),
		ebpf.WithTraceOpenat(r.config.isTracepointEnabled("openat")))
	if err != nil {
		return nil, err
	}
	return tracer, nil
}

func (r *tracerReconciler) snapshotTracers() map[uint32]*ebpf.Tracer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	snapshot := make(map[uint32]*ebpf.Tracer, len(r.tracers))
	for pid, tracer := range r.tracers {
		snapshot[pid] = tracer
	}

	return snapshot
}

func mergeCounts(dst, src map[uint64]uint64) {
	for bucket, count := range src {
		dst[bucket] += count
	}
}

type processMeta struct {
	name    string
	exe     string
	cmdline string
}

func resolveProcessMeta(pid uint32) (processMeta, error) {
	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		return processMeta{}, err
	}

	meta := processMeta{}
	if name, err := proc.Name(); err == nil {
		meta.name = name
	}
	if exe, err := proc.Exe(); err == nil {
		meta.exe = exe
	}
	if cmdline, err := proc.Cmdline(); err == nil {
		meta.cmdline = cmdline
	}

	return meta, nil
}
