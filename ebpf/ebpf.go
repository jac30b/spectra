package ebpf

import (
	"context"
	"errors"

	"github.com/jac30b/spectra/ebpf/futex"
	"go.uber.org/zap"
)

type Tracepoint[T any] interface {
	Pull(ctx context.Context) (T, error)
	Stop() error
}

type options struct {
	traceFutex bool
	logger     *zap.Logger
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

type Tracer struct {
	fut    Tracepoint[map[uint64]uint64]
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

	return tr, nil
}

// Pull retrieves the latest data from all tracepoints.
type PullResponse struct {
	Futex map[uint64]uint64
}

func (t *Tracer) Pull(ctx context.Context) (PullResponse, error) {
	ret, err := t.fut.Pull(ctx)
	if err != nil {
		return PullResponse{}, err
	}

	return PullResponse{
		Futex: ret,
	}, nil
}

func (t *Tracer) Stop() error {
	var err error
	if t.fut != nil {
		err = errors.Join(err, t.fut.Stop())
	}
	return err
}
