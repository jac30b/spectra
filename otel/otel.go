package otel

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/jac30b/spectra/ebpf"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.uber.org/zap"
)

type PubSub interface {
	Sub(...string) chan ebpf.TracepointData
	Unsub(chan ebpf.TracepointData, ...string)
}

type OltpExporter struct {
	mp            *sdkmetric.MeterProvider
	m             metric.Meter
	ps            PubSub
	subscriptions []subscription
	done          chan struct{}
	closeOnce     sync.Once
	wg            sync.WaitGroup
	handlers      map[string]func(ebpf.TracepointData)
	latestByTopic sync.Map
	metricsReg    metric.Registration
	logger        *zap.Logger
}

type subscription struct {
	topic string
	ch    chan ebpf.TracepointData
}

var latencyBucketUpperBoundsUs = []uint64{
	1,
	2,
	4,
	8,
	16,
	32,
	64,
	128,
	256,
	512,
	1_000,
	2_000,
	5_000,
	10_000,
	20_000,
	50_000,
	100_000,
	200_000,
	500_000,
	1_000_000,
}

func initMeterProvider(ctx context.Context) (*sdkmetric.MeterProvider, error) {
	// Create the gRPC exporter (defaults to localhost:4317)
	exporter, err := otlpmetricgrpc.New(ctx,
		otlpmetricgrpc.WithInsecure(), // no TLS for local dev
		// otlpmetricgrpc.WithEndpoint("otel-collector:4317"),
	)
	if err != nil {
		return nil, err
	}
	// Create a MeterProvider with a periodic reader that flushes every 2s
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(
			sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(2*time.Second)),
		),
	)
	// Register as the global MeterProvider
	otel.SetMeterProvider(mp)
	return mp, nil
}

func NewOltpExporter(ctx context.Context, logger *zap.Logger, ps PubSub, topics ...string) (*OltpExporter, error) {
	logger.Debug("initializing otlp metric exporter")

	mp, err := initMeterProvider(ctx)
	if err != nil {
		logger.Error("failed to initialize otlp metric exporter", zap.Error(err))
		return nil, err
	}
	logger.Debug("otlp metric exporter initialized; collector connection configured")

	// Get a Meter and create instruments
	meter := otel.Meter("spectra")

	o := &OltpExporter{
		m:        meter,
		mp:       mp,
		ps:       ps,
		done:     make(chan struct{}),
		handlers: make(map[string]func(ebpf.TracepointData)),
		logger:   logger,
	}

	if err := o.initHandlers(); err != nil {
		_ = mp.Shutdown(ctx)
		return nil, err
	}

	for _, topic := range uniqueTopics(topics) {
		ch := ps.Sub(topic)
		o.subscriptions = append(o.subscriptions, subscription{topic: topic, ch: ch})
		o.logger.Debug("subscribed to pubsub topic", zap.String("topic", topic))
		o.wg.Add(1)
		go o.runSubscription(ctx, topic, ch)
	}

	return o, nil
}

func uniqueTopics(topics []string) []string {
	slices.Sort(topics)
	return slices.Compact(topics)
}

func (o *OltpExporter) runSubscription(ctx context.Context, topic string, ch <-chan ebpf.TracepointData) {
	defer o.wg.Done()
	o.logger.Debug("starting topic subscription loop", zap.String("topic", topic))

	for {
		select {
		case <-ctx.Done():
			o.logger.Debug("stopping topic subscription loop: context canceled", zap.String("topic", topic))
			return
		case <-o.done:
			o.logger.Debug("stopping topic subscription loop: exporter closing", zap.String("topic", topic))
			return
		case tpData, ok := <-ch:
			if !ok {
				o.logger.Debug("stopping topic subscription loop: channel closed", zap.String("topic", topic))
				return
			}
			o.logger.Debug("received tracepoint payload",
				zap.String("topic", topic),
				zap.Int("buckets", len(tpData.Data)),
			)
			o.handleMessage(topic, tpData)
		}
	}
}

func (o *OltpExporter) handleMessage(topic string, tpData ebpf.TracepointData) {
	h, ok := o.handlers[topic]
	if !ok {
		return
	}
	h(tpData)
}

func (o *OltpExporter) initHandlers() error {
	futexCounter, err := o.m.Int64ObservableCounter("spectra.futex.wait.events",
		metric.WithDescription("Cumulative futex wait events by latency bucket"),
		metric.WithUnit("{events}"),
	)
	if err != nil {
		return err
	}

	schedCounter, err := o.m.Int64ObservableCounter("spectra.sched_switch.offcpu.events",
		metric.WithDescription("Cumulative sched switch off-CPU events by latency bucket"),
		metric.WithUnit("{events}"),
	)
	if err != nil {
		return err
	}

	ioctlCounter, err := o.m.Int64ObservableCounter("spectra.ioctl.duration.events",
		metric.WithDescription("Cumulative ioctl events by latency bucket"),
		metric.WithUnit("{events}"),
	)
	if err != nil {
		return err
	}

	pageFaultCounter, err := o.m.Int64ObservableCounter("spectra.page_fault.events",
		metric.WithDescription("Cumulative page fault events by fault bucket"),
		metric.WithUnit("{events}"),
	)
	if err != nil {
		return err
	}

	mmapCounter, err := o.m.Int64ObservableCounter("spectra.mmap.exec.events",
		metric.WithDescription("Cumulative mmap PROT_EXEC events by latency bucket"),
		metric.WithUnit("{events}"),
	)
	if err != nil {
		return err
	}

	clone3Counter, err := o.m.Int64ObservableCounter("spectra.clone3.events",
		metric.WithDescription("Cumulative clone3 syscall count"),
		metric.WithUnit("{events}"),
	)
	if err != nil {
		return err
	}

	openatCounter, err := o.m.Int64ObservableCounter("spectra.openat.events",
		metric.WithDescription("Cumulative openat events by filename length bucket"),
		metric.WithUnit("{events}"),
	)
	if err != nil {
		return err
	}

	o.handlers["futex"] = func(tpData ebpf.TracepointData) {
		o.storeLatest("futex", tpData)
	}
	o.handlers["sched_switch"] = func(tpData ebpf.TracepointData) {
		o.storeLatest("sched_switch", tpData)
	}
	o.handlers["ioctl"] = func(tpData ebpf.TracepointData) {
		o.storeLatest("ioctl", tpData)
	}
	o.handlers["page_fault_user"] = func(tpData ebpf.TracepointData) {
		o.storeLatest("page_fault_user", tpData)
	}
	// Allow both names for compatibility.
	o.handlers["page_fault"] = o.handlers["page_fault_user"]
	o.handlers["mmap"] = func(tpData ebpf.TracepointData) {
		o.storeLatest("mmap", tpData)
	}
	o.handlers["clone3"] = func(tpData ebpf.TracepointData) {
		o.storeLatest("clone3", tpData)
	}
	o.handlers["openat"] = func(tpData ebpf.TracepointData) {
		o.storeLatest("openat", tpData)
	}

	o.metricsReg, err = o.m.RegisterCallback(func(ctx context.Context, obs metric.Observer) error {
		o.observeLatency(obs, "futex", futexCounter)
		o.observeLatency(obs, "sched_switch", schedCounter)
		o.observeLatency(obs, "ioctl", ioctlCounter)
		o.observeLatency(obs, "mmap", mmapCounter)
		o.observeClone3(obs, clone3Counter)
		o.observeOpenat(obs, openatCounter)
		o.observePageFault(obs, pageFaultCounter)
		return nil
	}, futexCounter, schedCounter, ioctlCounter, pageFaultCounter, mmapCounter, clone3Counter, openatCounter)
	if err != nil {
		return err
	}

	return nil
}

func (o *OltpExporter) storeLatest(topic string, tpData ebpf.TracepointData) {
	// Copy the data map
	copied := make(map[uint64]uint64, len(tpData.Data))
	for k, v := range tpData.Data {
		copied[k] = v
	}
	// Store both data and process metadata
	o.latestByTopic.Store(topic, ebpf.TracepointData{
		Data:    copied,
		Process: tpData.Process,
	})
}

func (o *OltpExporter) observeLatency(obs metric.Observer, topic string, counter metric.Int64ObservableCounter) {
	v, ok := o.latestByTopic.Load(topic)
	if !ok {
		return
	}

	tpData, ok := v.(ebpf.TracepointData)
	if !ok {
		return
	}

	normalized := normalizeLatencyCounts(tpData.Data)
	for bucketUs, count := range normalized {
		attrs := []attribute.KeyValue{
			attribute.String("type", "tracepoint"),
			attribute.String("tracepoint", topic),
			attribute.String("tracepoint_type", "latency_us"),
			attribute.String("bucket.us", bucketUs),
		}
		// Add process metadata if available
		if tpData.Process.PID > 0 {
			attrs = append(attrs, attribute.String("process.pid", fmt.Sprintf("%d", tpData.Process.PID)))
			if tpData.Process.Name != "" {
				attrs = append(attrs, attribute.String("process.name", tpData.Process.Name))
			}
			if tpData.Process.Cmdline != "" {
				attrs = append(attrs, attribute.String("process.cmdline", tpData.Process.Cmdline))
			}
		}
		obs.ObserveInt64(counter, int64(count), metric.WithAttributes(attrs...))
	}
}

func normalizeLatencyCounts(raw map[uint64]uint64) map[string]uint64 {
	normalized := make(map[string]uint64, len(raw))
	for latencyUs, count := range raw {
		bucket := latencyBucketLabel(latencyUs)
		normalized[bucket] += count
	}
	return normalized
}

func latencyBucketLabel(latencyUs uint64) string {
	for _, upperBound := range latencyBucketUpperBoundsUs {
		if latencyUs <= upperBound {
			return fmt.Sprintf("%d", upperBound)
		}
	}
	return "inf"
}

func (o *OltpExporter) observePageFault(obs metric.Observer, counter metric.Int64ObservableCounter) {
	v, ok := o.latestByTopic.Load("page_fault_user")
	if !ok {
		return
	}

	tpData, ok := v.(ebpf.TracepointData)
	if !ok {
		return
	}

	for bucket, count := range tpData.Data {
		bucketType := "error_code"
		if bucket == 0 {
			bucketType = "total"
		}

		attrs := []attribute.KeyValue{
			attribute.String("type", "tracepoint"),
			attribute.String("tracepoint", "page_fault_user"),
			attribute.String("tracepoint_type", "count"),
			attribute.String("bucket.type", bucketType),
			attribute.String("bucket.code", fmt.Sprintf("%08b", bucket)),
		}
		// Add process metadata if available
		if tpData.Process.PID > 0 {
			attrs = append(attrs, attribute.String("process.pid", fmt.Sprintf("%d", tpData.Process.PID)))
			if tpData.Process.Name != "" {
				attrs = append(attrs, attribute.String("process.name", tpData.Process.Name))
			}
			if tpData.Process.Cmdline != "" {
				attrs = append(attrs, attribute.String("process.cmdline", tpData.Process.Cmdline))
			}
		}
		obs.ObserveInt64(counter, int64(count), metric.WithAttributes(attrs...))
	}
}

func (o *OltpExporter) observeClone3(obs metric.Observer, counter metric.Int64ObservableCounter) {
	v, ok := o.latestByTopic.Load("clone3")
	if !ok {
		return
	}

	tpData, ok := v.(ebpf.TracepointData)
	if !ok {
		return
	}

	// clone3 has a single key (0) with the total count
	for _, count := range tpData.Data {
		attrs := []attribute.KeyValue{
			attribute.String("type", "tracepoint"),
			attribute.String("tracepoint", "clone3"),
			attribute.String("tracepoint_type", "count"),
		}
		// Add process metadata if available
		if tpData.Process.PID > 0 {
			attrs = append(attrs, attribute.String("process.pid", fmt.Sprintf("%d", tpData.Process.PID)))
			if tpData.Process.Name != "" {
				attrs = append(attrs, attribute.String("process.name", tpData.Process.Name))
			}
			if tpData.Process.Cmdline != "" {
				attrs = append(attrs, attribute.String("process.cmdline", tpData.Process.Cmdline))
			}
		}
		obs.ObserveInt64(counter, int64(count), metric.WithAttributes(attrs...))
	}
}

func (o *OltpExporter) observeOpenat(obs metric.Observer, counter metric.Int64ObservableCounter) {
	v, ok := o.latestByTopic.Load("openat")
	if !ok {
		return
	}

	tpData, ok := v.(ebpf.TracepointData)
	if !ok {
		return
	}

	// openat buckets by filename length (power of 2 buckets)
	for lengthBucket, count := range tpData.Data {
		attrs := []attribute.KeyValue{
			attribute.String("type", "tracepoint"),
			attribute.String("tracepoint", "openat"),
			attribute.String("tracepoint_type", "filename_length"),
			attribute.String("bucket.length", fmt.Sprintf("%d", lengthBucket)),
		}
		// Add process metadata if available
		if tpData.Process.PID > 0 {
			attrs = append(attrs, attribute.String("process.pid", fmt.Sprintf("%d", tpData.Process.PID)))
			if tpData.Process.Name != "" {
				attrs = append(attrs, attribute.String("process.name", tpData.Process.Name))
			}
			if tpData.Process.Cmdline != "" {
				attrs = append(attrs, attribute.String("process.cmdline", tpData.Process.Cmdline))
			}
		}
		obs.ObserveInt64(counter, int64(count), metric.WithAttributes(attrs...))
	}
}

func (o *OltpExporter) Close(ctx context.Context) error {
	var err error
	o.closeOnce.Do(func() {
		o.logger.Debug("closing otlp exporter")
		close(o.done)
		for _, sub := range o.subscriptions {
			o.logger.Debug("unsubscribing from pubsub topic", zap.String("topic", sub.topic))
			o.ps.Unsub(sub.ch, sub.topic)
		}
		o.wg.Wait()
		if o.metricsReg != nil {
			err = errors.Join(err, o.metricsReg.Unregister())
		}
		err = errors.Join(err, o.mp.Shutdown(ctx)) // flushes remaining metrics on exit
		if err != nil {
			o.logger.Error("otlp exporter shutdown completed with error", zap.Error(err))
			return
		}
		o.logger.Debug("otlp exporter closed")
	})
	return err
}
