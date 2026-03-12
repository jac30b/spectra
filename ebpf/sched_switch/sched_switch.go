package sched_switch

import (
	"context"
	"errors"

	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

type schedSwitch struct {
	link   link.Link
	obj    *sched_switch_tracepointObjects
	logger *zap.Logger
}

func StartTracingSchedSwitch(logger *zap.Logger, pid uint32) (*schedSwitch, error) {
	spec, err := loadSched_switch_tracepoint()
	if err != nil {
		logger.Error("failed to load sched_switch tracepoint spec", zap.Error(err))
		return nil, err
	}

	// Set the target_pid constant before loading
	if err := spec.Variables["target_pid"].Set(pid); err != nil {
		logger.Error("failed to set target_pid", zap.Uint32("pid", pid), zap.Error(err))
		return nil, err
	}

	var obj sched_switch_tracepointObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		logger.Error("failed to load sched_switch tracepoint objects", zap.Error(err))
		return nil, err
	}

	// Attach to sched:sched_switch tracepoint
	l, err := link.Tracepoint("sched", "sched_switch", obj.SchedSwitchHandler, nil)
	if err != nil {
		logger.Error("failed to attach to sched_switch tracepoint", zap.Error(err))
		return nil, err
	}

	logger.Info("started sched_switch tracing", zap.Uint32("target_pid", pid))

	return &schedSwitch{
		link:   l,
		obj:    &obj,
		logger: logger,
	}, nil
}

func (s *schedSwitch) Stop() error {
	s.logger.Info("stopping sched_switch tracing")
	var err error
	if s.link != nil {
		err = errors.Join(err, s.link.Close())
	}

	if s.obj != nil {
		err = errors.Join(err, s.obj.Close())
	}
	if err != nil {
		s.logger.Error("error during sched_switch tracing shutdown", zap.Error(err))
		return err
	}
	s.logger.Info("sched_switch tracing stopped successfully")
	return nil
}

func (s *schedSwitch) Pull(ctx context.Context) (map[uint64]uint64, error) {
	var (
		ret = make(map[uint64]uint64)

		key   uint64
		value uint64
	)

	iter := s.obj.SchedOffcpuUs.Iterate()
	for iter.Next(&key, &value) {
		if value > 0 {
			ret[key] = value
		}
	}

	if err := iter.Err(); err != nil {
		return nil, err
	}

	return ret, nil
}
