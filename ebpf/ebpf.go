package ebpf

import (
	"context"
	"errors"
	"maps"

	"github.com/jac30b/spectra/ebpf/futex"
	"github.com/jac30b/spectra/ebpf/ioctl"
	page_fault "github.com/jac30b/spectra/ebpf/page_fault"
	sched_switch "github.com/jac30b/spectra/ebpf/sched_switch"
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
	fut    Tracepoint[map[uint64]uint64]
	sched  Tracepoint[map[uint64]uint64]
	pf     Tracepoint[map[uint64]uint64]
	ioctl  Tracepoint[map[uint64]uint64]
	logger *zap.Logger
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
		logger: options.logger,
	}

	if options.traceFutex {
		tp, err := futex.StartTracingFutex(options.logger, pid)
		if err != nil {
			return nil, err
		}

		tr.fut = tp
	}

	if options.traceSchedSwitch {
		tp, err := sched_switch.StartTracingSchedSwitch(options.logger, pid)
		if err != nil {
			return nil, err
		}

		tr.sched = tp
	}

	if options.tracePageFault {
		tp, err := page_fault.StartTracingPageFault(options.logger, pid)
		if err != nil {
			return nil, err
		}

		tr.pf = tp
	}

	if options.traceIoctl {
		tp, err := ioctl.StartTracingIoctl(options.logger, pid)
		if err != nil {
			return nil, err
		}

		tr.ioctl = tp
	}

	return tr, nil
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
	return err
}
