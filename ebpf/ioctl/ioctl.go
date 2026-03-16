package ioctl

import (
	"context"
	"errors"

	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

type ioctlTracer struct {
	entry  link.Link
	exit   link.Link
	obj    *ioctl_tracepointObjects
	logger *zap.Logger
}

func StartTracingIoctl(logger *zap.Logger, pid uint32) (*ioctlTracer, error) {
	spec, err := loadIoctl_tracepoint()
	if err != nil {
		logger.Error("failed to load ioctl tracepoint spec", zap.Error(err))
		return nil, err
	}

	// Set the target_pid constant before loading
	if err := spec.Variables["target_pid"].Set(pid); err != nil {
		logger.Error("failed to set target_pid", zap.Uint32("pid", pid), zap.Error(err))
		return nil, err
	}

	var obj ioctl_tracepointObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		logger.Error("failed to load ioctl tracepoint objects", zap.Error(err))
		return nil, err
	}

	// Attach to sys_enter_ioctl tracepoint
	linkEntry, err := link.Tracepoint("syscalls", "sys_enter_ioctl", obj.IoctlEntry, nil)
	if err != nil {
		_ = obj.Close()
		logger.Error("failed to attach to sys_enter_ioctl tracepoint", zap.Error(err))
		return nil, err
	}

	// Attach to sys_exit_ioctl tracepoint
	linkExit, err := link.Tracepoint("syscalls", "sys_exit_ioctl", obj.IoctlExit, nil)
	if err != nil {
		_ = linkEntry.Close()
		_ = obj.Close()
		logger.Error("failed to attach to sys_exit_ioctl tracepoint", zap.Error(err))
		return nil, err
	}

	logger.Info("started ioctl tracing", zap.Uint32("target_pid", pid))

	return &ioctlTracer{
		entry:  linkEntry,
		exit:   linkExit,
		obj:    &obj,
		logger: logger,
	}, nil
}

func (i *ioctlTracer) Stop() error {
	i.logger.Info("stopping ioctl tracing")
	var err error
	if i.entry != nil {
		err = errors.Join(err, i.entry.Close())
	}
	if i.exit != nil {
		err = errors.Join(err, i.exit.Close())
	}

	if i.obj != nil {
		err = errors.Join(err, i.obj.Close())
	}
	if err != nil {
		i.logger.Error("error during ioctl tracing shutdown", zap.Error(err))
		return err
	}
	i.logger.Info("ioctl tracing stopped successfully")
	return nil
}

func (i *ioctlTracer) Pull(ctx context.Context) (map[uint64]uint64, error) {
	var (
		ret = make(map[uint64]uint64)

		key   uint64
		value uint64
	)

	// DIAGNOSTIC: dump diag_tgids map to see what TGIDs the BPF program sees
	{
		var dk uint32
		var dv uint64
		diagIter := i.obj.DiagTgids.Iterate()
		for diagIter.Next(&dk, &dv) {
			if dk == 0 {
				i.logger.Info("DIAG: target_pid baked into BPF",
					zap.Uint64("target_pid_value", dv))
			} else {
				i.logger.Info("DIAG: TGID seen by ioctl tracepoint",
					zap.Uint32("tgid", dk),
					zap.Uint64("event_count", dv))
			}
		}
		if err := diagIter.Err(); err != nil {
			i.logger.Warn("DIAG: error iterating diag_tgids", zap.Error(err))
		}
	}

	iter := i.obj.IoctlDurationUs.Iterate()
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
