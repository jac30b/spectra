package futex

import (
	"context"
	"errors"

	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

type futex struct {
	entry  link.Link
	exit   link.Link
	obj    *futex_tracepointObjects
	logger *zap.Logger
}

func StartTracingFutex(logger *zap.Logger, pid uint32) (*futex, error) {
	spec, err := loadFutex_tracepoint()
	if err != nil {
		logger.Error("failed to load futex tracepoint spec", zap.Error(err))
		return nil, err
	}

	// Set the target_pid constant before loading
	if err := spec.Variables["target_pid"].Set(pid); err != nil {
		logger.Error("failed to set target_pid", zap.Uint32("pid", pid), zap.Error(err))
		return nil, err
	}

	var obj futex_tracepointObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		logger.Error("failed to load futex tracepoint objects", zap.Error(err))
		return nil, err
	}

	// Attach to sys_enter_futex tracepoint
	linkEntry, err := link.Tracepoint("syscalls", "sys_enter_futex", obj.FutexEntry, nil)
	if err != nil {
		logger.Error("failed to attach to sys_enter_futex tracepoint", zap.Error(err))
		return nil, err
	}

	// Attach to sys_exit_futex tracepoint
	linkExit, err := link.Tracepoint("syscalls", "sys_exit_futex", obj.FutexExit, nil)
	if err != nil {
		logger.Error("failed to attach to sys_exit_futex tracepoint", zap.Error(err))
		return nil, err
	}

	logger.Info("started futex tracing", zap.Uint32("target_pid", pid))

	return &futex{
		entry:  linkEntry,
		exit:   linkExit,
		obj:    &obj,
		logger: logger,
	}, nil
}

func (f *futex) Stop() error {
	f.logger.Info("stopping futex tracing")
	var err error
	if f.entry != nil {
		err = errors.Join(err, f.entry.Close())
	}
	if f.exit != nil {
		err = errors.Join(err, f.exit.Close())
	}

	if f.obj != nil {
		err = errors.Join(err, f.obj.Close())
	}
	if err != nil {
		f.logger.Error("error during futex tracing shutdown", zap.Error(err))
		return err
	}
	f.logger.Info("futex tracing stopped successfully")
	return nil
}

func (f *futex) Pull(context context.Context) (map[uint64]uint64, error) {
	var (
		ret = make(map[uint64]uint64)

		key   uint64
		value uint64
	)

	iter := f.obj.FutexWaitUs.Iterate()
	for iter.Next(&key, &value) {
		if value > 0 {
			ret[key] = value
		}
	}

	if err := iter.Err(); err != nil {
		return nil, err
	}

	return ret, nil

	// SKIP WAKE FOR NOW - we can add it back in later if we want to track wake times as well
	// iter = f.obj.FutexWakeUs.Iterate()
	// for iter.Next(&key, &value) {
	// 	if value > 0 {
	// 		fmt.Printf("%6d μs: %d calls\n", key, value)
	// 	}
	// }

	// if err := iter.Err(); err != nil {
	// 	log.Printf("Error iterating wake histogram: %v", err)
	// }

}
