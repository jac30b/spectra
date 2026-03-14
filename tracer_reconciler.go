package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/jac30b/spectra/ebpf"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

// tracerReconciler manages a dynamic set of per-PID tracers.
type tracerReconciler struct {
	config  *Config
	logger  *zap.Logger
	tracers map[uint32]*ebpf.Tracer
	mu      sync.RWMutex
}

func newTracerReconciler(config *Config, logger *zap.Logger) *tracerReconciler {
	return &tracerReconciler{
		config:  config,
		logger:  logger,
		tracers: make(map[uint32]*ebpf.Tracer),
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
		r.logger.Info("attached tracer", zap.Uint32("pid", pid))
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

func (r *tracerReconciler) Pull(ctx context.Context) (ebpf.PullResponse, error) {
	var (
		errg    errgroup.Group
		tracers = r.snapshotTracers()
		results = make(chan ebpf.PullResponse, len(tracers))
	)

	for pid, tracer := range tracers {
		pid := pid
		tracer := tracer
		errg.Go(func() error {
			res, err := tracer.Pull(ctx)
			if err != nil {
				return fmt.Errorf("pid %d: %w", pid, err)
			}
			results <- res
			return nil
		})
	}

	err := errg.Wait()
	close(results)

	resp := ebpf.NewPullResponse()
	for result := range results {
		mergeCounts(resp.Futex, result.Futex)
		mergeCounts(resp.SchedSwitch, result.SchedSwitch)
		mergeCounts(resp.PageFault, result.PageFault)
		mergeCounts(resp.Ioctl, result.Ioctl)
	}

	return resp, err
}

func (r *tracerReconciler) Stop() error {
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
		ebpf.WithTraceIoctl(r.config.isTracepointEnabled("ioctl")))
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
