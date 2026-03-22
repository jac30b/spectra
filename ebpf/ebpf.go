package ebpf

import (
	"context"
	"errors"
	"maps"
	"sync/atomic"

	"github.com/jac30b/spectra/ebpf/clone3"
	"github.com/jac30b/spectra/ebpf/cuda_trace"
	"github.com/jac30b/spectra/ebpf/futex"
	"github.com/jac30b/spectra/ebpf/ioctl"
	"github.com/jac30b/spectra/ebpf/mmap"
	"github.com/jac30b/spectra/ebpf/openat"
	"github.com/jac30b/spectra/ebpf/page_fault"
	"github.com/jac30b/spectra/ebpf/sched_switch"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type Tracepoint[T any] interface {
	Pull(ctx context.Context) (T, error)
	Stop() error
}

type options struct {
	traceFutex       bool
	traceSchedSwitch bool
	tracePageFault   bool
	traceIoctl       bool
	traceMmap        bool
	traceClone3      bool
	traceOpenat      bool
	traceCuda        bool
	libCudaPath      string
	logger           *zap.Logger
}

type Option interface {
	apply(*options)
}

type traceFutexOpt bool

func (c traceFutexOpt) apply(opts *options) {
	opts.traceFutex = bool(c)
}

func WithTraceFutex(c bool) Option {
	return traceFutexOpt(c)
}

type traceSchedSwitchOpt bool

func (c traceSchedSwitchOpt) apply(opts *options) {
	opts.traceSchedSwitch = bool(c)
}

func WithTraceSchedSwitch(c bool) Option {
	return traceSchedSwitchOpt(c)
}

type tracePageFaultOpt bool

func (c tracePageFaultOpt) apply(opts *options) {
	opts.tracePageFault = bool(c)
}

func WithTracePageFault(c bool) Option {
	return tracePageFaultOpt(c)
}

type traceIoctlOpt bool

func (c traceIoctlOpt) apply(opts *options) {
	opts.traceIoctl = bool(c)
}

func WithTraceIoctl(c bool) Option {
	return traceIoctlOpt(c)
}

type traceMmapOpt bool

func (c traceMmapOpt) apply(opts *options) {
	opts.traceMmap = bool(c)
}

func WithTraceMmap(c bool) Option {
	return traceMmapOpt(c)
}

type traceClone3Opt bool

func (c traceClone3Opt) apply(opts *options) {
	opts.traceClone3 = bool(c)
}

func WithTraceClone3(c bool) Option {
	return traceClone3Opt(c)
}

type traceOpenatOpt bool

func (c traceOpenatOpt) apply(opts *options) {
	opts.traceOpenat = bool(c)
}

func WithTraceOpenat(c bool) Option {
	return traceOpenatOpt(c)
}

type traceCudaOpt bool

func (c traceCudaOpt) apply(opts *options) {
	opts.traceCuda = bool(c)
}

func WithTraceCuda(c bool) Option {
	return traceCudaOpt(c)
}

type libCudaPathOpt string

func (p libCudaPathOpt) apply(opts *options) {
	opts.libCudaPath = string(p)
}

func WithLibCudaPath(p string) Option {
	return libCudaPathOpt(p)
}

type Tracer struct {
	fut     Tracepoint[map[uint64]uint64]
	sched   Tracepoint[map[uint64]uint64]
	pf      Tracepoint[map[uint64]uint64]
	ioctl   Tracepoint[map[uint64]uint64]
	mmapTp  Tracepoint[map[uint64]uint64]
	clone3  Tracepoint[map[uint64]uint64]
	openat  Tracepoint[map[uint64]uint64]
	cuda    Tracepoint[map[uint64]uint64]
	logger  *zap.Logger
	options *options

	running atomic.Bool
}

type loggerOption struct {
	Log *zap.Logger
}

func (l loggerOption) apply(opts *options) {
	opts.logger = l.Log
}

func WithLogger(log *zap.Logger) Option {
	return loggerOption{Log: log}
}

// NewTracer creates a new Tracer with the given options.
func NewTracer(ctx context.Context, pid uint32, opts ...Option) (*Tracer, error) {
	options := &options{
		traceFutex:  true,
		libCudaPath: "/usr/lib/x86_64-linux-gnu/libcuda.so.1",
		logger:      zap.NewNop(),
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	tr := &Tracer{
		logger:  options.logger,
		options: options,
	}

	if err := tr.start(pid); err != nil {
		return nil, err
	}

	return tr, nil
}

func (t *Tracer) start(pid uint32) error {
	var (
		fut   Tracepoint[map[uint64]uint64]
		sched Tracepoint[map[uint64]uint64]
		pf    Tracepoint[map[uint64]uint64]
		io    Tracepoint[map[uint64]uint64]
		mm    Tracepoint[map[uint64]uint64]
		cl3   Tracepoint[map[uint64]uint64]
		open  Tracepoint[map[uint64]uint64]
		cu    Tracepoint[map[uint64]uint64]
	)

	t.logger.Info("Starting eBPF tracer",
		zap.Uint32("pid", pid))

	if t.options.traceFutex {
		tp, err := futex.StartTracingFutex(t.options.logger, pid)
		if err != nil {
			return err
		}
		fut = tp
	}

	if t.options.traceSchedSwitch {
		tp, err := sched_switch.StartTracingSchedSwitch(t.options.logger, pid)
		if err != nil {
			if fut != nil {
				_ = fut.Stop()
			}
			return err
		}
		sched = tp
	}

	if t.options.tracePageFault {
		tp, err := page_fault.StartTracingPageFault(t.options.logger, pid)
		if err != nil {
			if sched != nil {
				_ = sched.Stop()
			}
			if fut != nil {
				_ = fut.Stop()
			}
			return err
		}
		pf = tp
	}

	if t.options.traceIoctl {
		tp, err := ioctl.StartTracingIoctl(t.options.logger, pid)
		if err != nil {
			if pf != nil {
				_ = pf.Stop()
			}
			if sched != nil {
				_ = sched.Stop()
			}
			if fut != nil {
				_ = fut.Stop()
			}
			return err
		}
		io = tp
	}

	if t.options.traceMmap {
		tp, err := mmap.StartTracingMmap(t.options.logger, pid)
		if err != nil {
			if io != nil {
				_ = io.Stop()
			}
			if pf != nil {
				_ = pf.Stop()
			}
			if sched != nil {
				_ = sched.Stop()
			}
			if fut != nil {
				_ = fut.Stop()
			}
			return err
		}
		mm = tp
	}

	if t.options.traceClone3 {
		tp, err := clone3.StartTracingClone3(t.options.logger, pid)
		if err != nil {
			if mm != nil {
				_ = mm.Stop()
			}
			if io != nil {
				_ = io.Stop()
			}
			if pf != nil {
				_ = pf.Stop()
			}
			if sched != nil {
				_ = sched.Stop()
			}
			if fut != nil {
				_ = fut.Stop()
			}
			return err
		}
		cl3 = tp
	}

	if t.options.traceOpenat {
		tp, err := openat.StartTracingOpenat(t.options.logger, pid)
		if err != nil {
			if cl3 != nil {
				_ = cl3.Stop()
			}
			if mm != nil {
				_ = mm.Stop()
			}
			if io != nil {
				_ = io.Stop()
			}
			if pf != nil {
				_ = pf.Stop()
			}
			if sched != nil {
				_ = sched.Stop()
			}
			if fut != nil {
				_ = fut.Stop()
			}
			return err
		}
		open = tp
	}

	if t.options.traceCuda {
		tp, err := cuda_trace.StartTracingCudaTrace(t.options.logger, pid, t.options.libCudaPath)
		if err != nil {
			if open != nil {
				_ = open.Stop()
			}
			if cl3 != nil {
				_ = cl3.Stop()
			}
			if mm != nil {
				_ = mm.Stop()
			}
			if io != nil {
				_ = io.Stop()
			}
			if pf != nil {
				_ = pf.Stop()
			}
			if sched != nil {
				_ = sched.Stop()
			}
			if fut != nil {
				_ = fut.Stop()
			}
			return err
		}
		cu = tp
	}

	t.fut = fut
	t.sched = sched
	t.pf = pf
	t.ioctl = io
	t.mmapTp = mm
	t.clone3 = cl3
	t.openat = open
	t.cuda = cu
	t.running.Store(true)
	return nil
}

func (t *Tracer) Restart(pid uint32) error {
	if t.running.Load() {
		if err := t.Stop(); err != nil {
			return err
		}
	}
	return t.start(pid)
}

func (t *Tracer) Pull(ctx context.Context) (PullResponse, error) {
	var (
		errg errgroup.Group

		resp     = NewPullResponse()
		runAsync = func(tp Tracepoint[map[uint64]uint64], target map[uint64]uint64) {
			errg.Go(func() error {
				ret, err := tp.Pull(ctx)
				if err != nil {
					return err
				}
				maps.Copy(target, ret)
				return nil
			})
		}
	)

	if t.fut != nil {
		runAsync(t.fut, resp.Futex)
	}

	if t.sched != nil {
		runAsync(t.sched, resp.SchedSwitch)
	}

	if t.pf != nil {
		runAsync(t.pf, resp.PageFault)
	}

	if t.ioctl != nil {
		runAsync(t.ioctl, resp.Ioctl)
	}

	if t.mmapTp != nil {
		runAsync(t.mmapTp, resp.Mmap)
	}

	if t.clone3 != nil {
		runAsync(t.clone3, resp.Clone3)
	}

	if t.openat != nil {
		runAsync(t.openat, resp.Openat)
	}

	if t.cuda != nil {
		runAsync(t.cuda, resp.Cuda)
	}

	if err := errg.Wait(); err != nil {
		return PullResponse{}, err
	}

	return resp, nil
}

func (t *Tracer) Stop() error {
	var err error
	if t.fut != nil {
		err = errors.Join(err, t.fut.Stop())
	}
	if t.sched != nil {
		err = errors.Join(err, t.sched.Stop())
	}
	if t.pf != nil {
		err = errors.Join(err, t.pf.Stop())
	}
	if t.ioctl != nil {
		err = errors.Join(err, t.ioctl.Stop())
	}
	if t.mmapTp != nil {
		err = errors.Join(err, t.mmapTp.Stop())
	}
	if t.clone3 != nil {
		err = errors.Join(err, t.clone3.Stop())
	}
	if t.openat != nil {
		err = errors.Join(err, t.openat.Stop())
	}
	if t.cuda != nil {
		err = errors.Join(err, t.cuda.Stop())
	}

	t.fut = nil
	t.sched = nil
	t.pf = nil
	t.ioctl = nil
	t.mmapTp = nil
	t.clone3 = nil
	t.openat = nil
	t.cuda = nil
	t.running.Store(false)
	return err
}
