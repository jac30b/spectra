package mmap

import (
	"context"
	"errors"

	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

type mmapTracer struct {
	entry  link.Link
	exit   link.Link
	obj    *mmap_tracepointObjects
	logger *zap.Logger
}

func StartTracingMmap(logger *zap.Logger, pid uint32) (*mmapTracer, error) {
	spec, err := loadMmap_tracepoint()
	if err != nil {
		logger.Error("failed to load mmap tracepoint spec", zap.Error(err))
		return nil, err
	}

	// Set the target_pid constant before loading
	if err := spec.Variables["target_pid"].Set(pid); err != nil {
		logger.Error("failed to set target_pid", zap.Uint32("pid", pid), zap.Error(err))
		return nil, err
	}

	var obj mmap_tracepointObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		logger.Error("failed to load mmap tracepoint objects", zap.Error(err))
		return nil, err
	}

	// Attach to sys_enter_mmap tracepoint
	linkEntry, err := link.Tracepoint("syscalls", "sys_enter_mmap", obj.MmapEntry, nil)
	if err != nil {
		_ = obj.Close()
		logger.Error("failed to attach to sys_enter_mmap tracepoint", zap.Error(err))
		return nil, err
	}

	// Attach to sys_exit_mmap tracepoint
	linkExit, err := link.Tracepoint("syscalls", "sys_exit_mmap", obj.MmapExit, nil)
	if err != nil {
		_ = linkEntry.Close()
		_ = obj.Close()
		logger.Error("failed to attach to sys_exit_mmap tracepoint", zap.Error(err))
		return nil, err
	}

	logger.Info("started mmap tracing", zap.Uint32("target_pid", pid))

	return &mmapTracer{
		entry:  linkEntry,
		exit:   linkExit,
		obj:    &obj,
		logger: logger,
	}, nil
}

func (m *mmapTracer) Stop() error {
	m.logger.Info("stopping mmap tracing")
	var err error
	if m.entry != nil {
		err = errors.Join(err, m.entry.Close())
	}
	if m.exit != nil {
		err = errors.Join(err, m.exit.Close())
	}

	if m.obj != nil {
		err = errors.Join(err, m.obj.Close())
	}
	if err != nil {
		m.logger.Error("error during mmap tracing shutdown", zap.Error(err))
		return err
	}
	m.logger.Info("mmap tracing stopped successfully")
	return nil
}

func (m *mmapTracer) Pull(ctx context.Context) (map[uint64]uint64, error) {
	var (
		ret = make(map[uint64]uint64)

		key   uint64
		value uint64
	)

	iter := m.obj.MmapExecUs.Iterate()
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
