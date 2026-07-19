//go:build !linux

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"runtime"

	"go.uber.org/zap"
)

var ErrUnsupportedPlatform = errors.New("eBPF tracing is only supported on linux")

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

type loggerOption struct {
	Log *zap.Logger
}

func (l loggerOption) apply(opts *options) {
	opts.logger = l.Log
}

func WithLogger(log *zap.Logger) Option {
	return loggerOption{Log: log}
}

type Tracer struct{}

func NewTracer(ctx context.Context, pid uint32, opts ...Option) (*Tracer, error) {
	return nil, fmt.Errorf("%w: %s/%s", ErrUnsupportedPlatform, runtime.GOOS, runtime.GOARCH)
}

func (t *Tracer) Restart(pid uint32) error {
	return fmt.Errorf("%w: %s/%s", ErrUnsupportedPlatform, runtime.GOOS, runtime.GOARCH)
}

func (t *Tracer) Pull(ctx context.Context) (PullResponse, error) {
	return PullResponse{}, fmt.Errorf("%w: %s/%s", ErrUnsupportedPlatform, runtime.GOOS, runtime.GOARCH)
}

func (t *Tracer) Stop() error {
	return nil
}
