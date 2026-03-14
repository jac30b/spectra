package ebpf

import (
	"context"
	"errors"
	"maps"
	"sync/atomic"

	"github.com/jac30b/spectra/ebpf/futex"
	"github.com/jac30b/spectra/ebpf/ioctl"
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

type Tracer struct {
	fut     Tracepoint[map[uint64]uint64]
	sched   Tracepoint[map[uint64]uint64]
	pf      Tracepoint[map[uint64]uint64]
	ioctl   Tracepoint[map[uint64]uint64]
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
		traceFutex: true,
		logger:     zap.NewNop(),
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

	t.fut = fut
	t.sched = sched
	t.pf = pf
	t.ioctl = io
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

	t.fut = nil
	t.sched = nil
	t.pf = nil
	t.ioctl = nil
	t.running.Store(false)
	return err
}
