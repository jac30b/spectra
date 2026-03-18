package openat

import (
	"context"
	"errors"

	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

type openatTracer struct {
	entry  link.Link
	obj    *openat_tracepointObjects
	logger *zap.Logger
}

func StartTracingOpenat(logger *zap.Logger, pid uint32) (*openatTracer, error) {
	spec, err := loadOpenat_tracepoint()
	if err != nil {
		logger.Error("failed to load openat tracepoint spec", zap.Error(err))
		return nil, err
	}

	// Set the target_pid constant before loading
	if err := spec.Variables["target_pid"].Set(pid); err != nil {
		logger.Error("failed to set target_pid", zap.Uint32("pid", pid), zap.Error(err))
		return nil, err
	}

	var obj openat_tracepointObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		logger.Error("failed to load openat tracepoint objects", zap.Error(err))
		return nil, err
	}

	// Attach to sys_enter_openat tracepoint
	linkEntry, err := link.Tracepoint("syscalls", "sys_enter_openat", obj.OpenatEntry, nil)
	if err != nil {
		_ = obj.Close()
		logger.Error("failed to attach to sys_enter_openat tracepoint", zap.Error(err))
		return nil, err
	}

	logger.Info("started openat tracing", zap.Uint32("target_pid", pid))

	return &openatTracer{
		entry:  linkEntry,
		obj:    &obj,
		logger: logger,
	}, nil
}

func (o *openatTracer) Stop() error {
	o.logger.Info("stopping openat tracing")
	var err error
	if o.entry != nil {
		err = errors.Join(err, o.entry.Close())
	}

	if o.obj != nil {
		err = errors.Join(err, o.obj.Close())
	}
	if err != nil {
		o.logger.Error("error during openat tracing shutdown", zap.Error(err))
		return err
	}
	o.logger.Info("openat tracing stopped successfully")
	return nil
}

func (o *openatTracer) Pull(ctx context.Context) (map[uint64]uint64, error) {
	var (
		ret = make(map[uint64]uint64)

		key   uint64
		value uint64
	)

	iter := o.obj.OpenatCounts.Iterate()
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
