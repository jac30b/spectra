package otel

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.uber.org/zap"
)

type PubSub interface {
	Sub(...string) chan map[uint64]uint64
	Unsub(chan map[uint64]uint64, ...string)
}

type OltpExporter struct {
	mp            *sdkmetric.MeterProvider
	m             metric.Meter
	ps            PubSub
	subscriptions []subscription
	done          chan struct{}
	closeOnce     sync.Once
	wg            sync.WaitGroup
	handlers      map[string]func(map[uint64]uint64)
	latestByTopic sync.Map
	metricsReg    metric.Registration
	logger        *zap.Logger
}

type subscription struct {
	topic string
	ch    chan map[uint64]uint64
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
		handlers: make(map[string]func(map[uint64]uint64)),
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

func (o *OltpExporter) runSubscription(ctx context.Context, topic string, ch <-chan map[uint64]uint64) {
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
		case data, ok := <-ch:
			if !ok {
				o.logger.Debug("stopping topic subscription loop: channel closed", zap.String("topic", topic))
				return
			}
			o.logger.Debug("received tracepoint payload",
				zap.String("topic", topic),
				zap.Int("buckets", len(data)),
			)
			o.handleMessage(topic, data)
		}
	}
}

func (o *OltpExporter) handleMessage(topic string, data map[uint64]uint64) {
	h, ok := o.handlers[topic]
	if !ok {
		return
	}
	h(data)
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

	o.handlers["futex"] = func(data map[uint64]uint64) {
		o.storeLatest("futex", data)
	}
	o.handlers["sched_switch"] = func(data map[uint64]uint64) {
		o.storeLatest("sched_switch", data)
	}
	o.handlers["ioctl"] = func(data map[uint64]uint64) {
		o.storeLatest("ioctl", data)
	}
	o.handlers["page_fault_user"] = func(data map[uint64]uint64) {
		o.storeLatest("page_fault_user", data)
	}
	// Allow both names for compatibility.
	o.handlers["page_fault"] = o.handlers["page_fault_user"]

	o.metricsReg, err = o.m.RegisterCallback(func(ctx context.Context, obs metric.Observer) error {
		o.observeLatency(obs, "futex", futexCounter)
		o.observeLatency(obs, "sched_switch", schedCounter)
		o.observeLatency(obs, "ioctl", ioctlCounter)
		o.observePageFault(obs, pageFaultCounter)
		return nil
	}, futexCounter, schedCounter, ioctlCounter, pageFaultCounter)
	if err != nil {
		return err
	}

	return nil
}

func (o *OltpExporter) storeLatest(topic string, data map[uint64]uint64) {
	copied := make(map[uint64]uint64, len(data))
	for k, v := range data {
		copied[k] = v
	}
	o.latestByTopic.Store(topic, copied)
}

func (o *OltpExporter) observeLatency(obs metric.Observer, topic string, counter metric.Int64ObservableCounter) {
	v, ok := o.latestByTopic.Load(topic)
	if !ok {
		return
	}

	data, ok := v.(map[uint64]uint64)
	if !ok {
		return
	}

	normalized := normalizeLatencyCounts(data)
	for bucketUs, count := range normalized {
		obs.ObserveInt64(counter, int64(count), metric.WithAttributes(
			attribute.String("type", "tracepoint"),
			attribute.String("tracepoint", topic),
			attribute.String("tracepoint_type", "latency_us"),
			attribute.String("bucket.us", bucketUs),
		))
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

	data, ok := v.(map[uint64]uint64)
	if !ok {
		return
	}

	for bucket, count := range data {
		bucketType := "error_code"
		if bucket == 0 {
			bucketType = "total"
		}

		obs.ObserveInt64(counter, int64(count), metric.WithAttributes(
			attribute.String("type", "tracepoint"),
			attribute.String("tracepoint", "page_fault_user"),
			attribute.String("tracepoint_type", "count"),
			attribute.String("bucket.type", bucketType),
			attribute.String("bucket.code", fmt.Sprintf("%08b", bucket)),
		))
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
