package cuda_trace

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

type CudaTrace struct {
	entry  []link.Link
	exit   []link.Link
	exe    *link.Executable
	obj    *cuda_traceObjects
	logger *zap.Logger
}

var cudaAllocSymbols = []string{"cuMemAlloc_v2", "cuMemAlloc"}

func StartTracingCudaTrace(logger *zap.Logger, pid uint32, libCudaPath string) (*CudaTrace, error) {
	spec, err := loadCuda_trace()
	if err != nil {
		logger.Error("failed to load cuda_trace spec", zap.Error(err))
		return nil, err
	}

	if err := spec.Variables["target_pid"].Set(pid); err != nil {
		logger.Error("failed to set target_pid", zap.Uint32("pid", pid), zap.Error(err))
		return nil, err
	}

	var obj cuda_traceObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		logger.Error("failed to load cuda_trace objects", zap.Error(err))
		return nil, err
	}

	exe, err := link.OpenExecutable(libCudaPath)
	if err != nil {
		_ = obj.Close()
		logger.Error("failed to open executable", zap.String("path", libCudaPath), zap.Error(err))
		return nil, err
	}

	entryLinks := make([]link.Link, 0, len(cudaAllocSymbols))
	exitLinks := make([]link.Link, 0, len(cudaAllocSymbols))

	for _, symbol := range cudaAllocSymbols {
		linkEntry, err := exe.Uprobe(symbol, obj.UprobeCuMemAlloc, &link.UprobeOptions{PID: int(pid)})
		if err != nil {
			continue
		}

		linkExit, err := exe.Uretprobe(symbol, obj.UretprobeCuMemAlloc, &link.UprobeOptions{PID: int(pid)})
		if err != nil {
			_ = linkEntry.Close()
			continue
		}

		entryLinks = append(entryLinks, linkEntry)
		exitLinks = append(exitLinks, linkExit)
		logger.Info("attached cuda allocation probes", zap.String("symbol", symbol), zap.Uint32("target_pid", pid))
	}

	if len(entryLinks) == 0 || len(exitLinks) == 0 {
		_ = obj.Close()
		logger.Error("failed to attach CUDA allocation uprobes", zap.Strings("symbols", cudaAllocSymbols))
		return nil, fmt.Errorf("failed to attach CUDA uprobes for symbols %v", cudaAllocSymbols)
	}

	logger.Info("started cuda tracing", zap.Uint32("target_pid", pid))
	logger.Info("attached to libcuda.so", zap.String("path", libCudaPath))

	return &CudaTrace{
		entry:  entryLinks,
		exit:   exitLinks,
		exe:    exe,
		obj:    &obj,
		logger: logger,
	}, nil
}

func (c *CudaTrace) Stop() error {
	c.logger.Info("stopping cuda tracing")
	var err error
	for _, l := range c.entry {
		err = errors.Join(err, l.Close())
	}
	for _, l := range c.exit {
		err = errors.Join(err, l.Close())
	}
	if c.obj != nil {
		err = errors.Join(err, c.obj.Close())
	}
	if err != nil {
		c.logger.Error("error during cuda tracing shutdown", zap.Error(err))
		return err
	}
	c.logger.Info("cuda tracing stopped successfully")
	return nil
}

func (c *CudaTrace) Pull(context context.Context) (map[uint64]uint64, error) {
	var (
		ret = make(map[uint64]uint64)

		key   uint64
		value uint64
	)

	iter := c.obj.CudaAllocs.Iterate()
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
