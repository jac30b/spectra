package clone3

import (
	"context"
	"errors"

	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

type clone3Tracer struct {
	entry  link.Link
	obj    *clone3_tracepointObjects
	logger *zap.Logger
}

func StartTracingClone3(logger *zap.Logger, pid uint32) (*clone3Tracer, error) {
	spec, err := loadClone3_tracepoint()
	if err != nil {
		logger.Error("failed to load clone3 tracepoint spec", zap.Error(err))
		return nil, err
	}

	// Set the target_pid constant before loading
	if err := spec.Variables["target_pid"].Set(pid); err != nil {
		logger.Error("failed to set target_pid", zap.Uint32("pid", pid), zap.Error(err))
		return nil, err
	}

	var obj clone3_tracepointObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		logger.Error("failed to load clone3 tracepoint objects", zap.Error(err))
		return nil, err
	}

	// Attach to sys_enter_clone3 tracepoint
	linkEntry, err := link.Tracepoint("syscalls", "sys_enter_clone3", obj.Clone3Entry, nil)
	if err != nil {
		_ = obj.Close()
		logger.Error("failed to attach to sys_enter_clone3 tracepoint", zap.Error(err))
		return nil, err
	}

	logger.Info("started clone3 tracing", zap.Uint32("target_pid", pid))

	return &clone3Tracer{
		entry:  linkEntry,
		obj:    &obj,
		logger: logger,
	}, nil
}

func (c *clone3Tracer) Stop() error {
	c.logger.Info("stopping clone3 tracing")
	var err error
	if c.entry != nil {
		err = errors.Join(err, c.entry.Close())
	}

	if c.obj != nil {
		err = errors.Join(err, c.obj.Close())
	}
	if err != nil {
		c.logger.Error("error during clone3 tracing shutdown", zap.Error(err))
		return err
	}
	c.logger.Info("clone3 tracing stopped successfully")
	return nil
}

func (c *clone3Tracer) Pull(ctx context.Context) (map[uint64]uint64, error) {
	var (
		ret = make(map[uint64]uint64)

		key   uint64
		value uint64
	)

	iter := c.obj.Clone3Counts.Iterate()
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
