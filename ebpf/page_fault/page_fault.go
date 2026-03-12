package page_fault

import (
	"context"
	"errors"

	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

type pageFault struct {
	link   link.Link
	obj    *page_fault_tracepointObjects
	logger *zap.Logger
}

func StartTracingPageFault(logger *zap.Logger, pid uint32) (*pageFault, error) {
	spec, err := loadPage_fault_tracepoint()
	if err != nil {
		logger.Error("failed to load page_fault tracepoint spec", zap.Error(err))
		return nil, err
	}

	// Set the target_pid constant before loading
	if err := spec.Variables["target_pid"].Set(pid); err != nil {
		logger.Error("failed to set target_pid", zap.Uint32("pid", pid), zap.Error(err))
		return nil, err
	}

	var obj page_fault_tracepointObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		logger.Error("failed to load page_fault tracepoint objects", zap.Error(err))
		return nil, err
	}

	// Attach to exceptions:page_fault_user tracepoint
	l, err := link.Tracepoint("exceptions", "page_fault_user", obj.PageFaultUserHandler, nil)
	if err != nil {
		logger.Error("failed to attach to page_fault_user tracepoint", zap.Error(err))
		return nil, err
	}

	logger.Info("started page_fault tracing", zap.Uint32("target_pid", pid))

	return &pageFault{
		link:   l,
		obj:    &obj,
		logger: logger,
	}, nil
}

func (p *pageFault) Stop() error {
	p.logger.Info("stopping page_fault tracing")
	var err error
	if p.link != nil {
		err = errors.Join(err, p.link.Close())
	}

	if p.obj != nil {
		err = errors.Join(err, p.obj.Close())
	}
	if err != nil {
		p.logger.Error("error during page_fault tracing shutdown", zap.Error(err))
		return err
	}
	p.logger.Info("page_fault tracing stopped successfully")
	return nil
}

func (p *pageFault) Pull(ctx context.Context) (map[uint64]uint64, error) {
	var (
		ret = make(map[uint64]uint64)

		key   uint64
		value uint64
	)

	iter := p.obj.PageFaultCount.Iterate()
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
