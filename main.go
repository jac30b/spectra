package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cskr/pubsub/v2"
	"github.com/jac30b/spectra/ebpf"
	"github.com/jac30b/spectra/otel"
	"go.uber.org/zap"
)

type spectra struct {
	ps         *pubsub.PubSub[string, map[uint64]uint64]
	reconciler *tracerReconciler
	logger     *zap.Logger
	exporter   *otel.OltpExporter
	config     *Config
	waiting    bool
}

func main() {
	// Initialize zap logger
	logger, err := zap.NewDevelopment()
	if err != nil {
		os.Stderr.WriteString("failed to initialize logger: " + err.Error() + "\n")
		os.Exit(1)
	}
	defer logger.Sync()

	if err := rlimit.RemoveMemlock(); err != nil {
		logger.Error("failed to remove memlock rlimit", zap.Error(err))
		os.Exit(1)
	}

	ps := pubsub.New[string, map[uint64]uint64](1024)

	// Parse command line flags
	configShortFlag := flag.String("c", "config.yml", "Path to config file")
	configLongFlag := flag.String("config", "config.yml", "Path to config file (alternative to -c)")
	flag.Parse()

	configPath := *configShortFlag
	if *configLongFlag != "config.yml" {
		configPath = *configLongFlag
	}

	// Load configuration from YAML file
	config, err := loadConfig(configPath)
	if err != nil {
		logger.Error("failed to load config", zap.String("path", configPath), zap.Error(err))
		os.Exit(1)
	}

	logger.Info("Starting spectra tracer",
		zap.Int("pid", config.PID),
		zap.String("process_name", config.ProcessName),
		zap.Strings("tracepoints", config.Tracepoints),
	)

	s := &spectra{
		ps:     ps,
		logger: logger,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exporter, err := otel.NewOltpExporter(ctx, logger, ps, config.Tracepoints...)
	if err != nil {
		logger.Error("failed to create otlp exporter", zap.Error(err))
		os.Exit(1)
	}
	logger.Debug("otlp exporter initialized")
	s.exporter = exporter
	s.config = config
	s.reconciler = newTracerReconciler(config, logger)
	if err := s.reconciler.Reconcile(ctx); err != nil {
		logger.Error("failed to start tracer", zap.Error(err))
		os.Exit(1)
	}

	s.run(ctx)
}

func (s *spectra) run(ctx context.Context) {
	var (
		pullTicker    = time.NewTicker(2 * time.Second)
		stop          = make(chan os.Signal, 1)
		reconcileWG   sync.WaitGroup
		reconcileDone = make(chan struct{})
	)
	defer pullTicker.Stop()

	signal.Notify(stop, os.Interrupt)
	defer signal.Stop(stop)

	reconcileWG.Add(1)
	go s.runReconcilation(ctx, &reconcileWG, reconcileDone)

	for {
		select {
		case <-pullTicker.C:
			if s.reconciler.Count() == 0 {
				if s.config.ProcessName != "" && !s.waiting {
					s.logger.Info("waiting for matching processes",
						zap.String("process_name", s.config.ProcessName),
					)
					s.waiting = true
				}
				continue
			}

			s.waiting = false
			res, err := s.reconciler.Pull(ctx)
			if err != nil {
				s.logger.Error("failed to pull data", zap.Error(err))
			}
			s.publish(res)
		case <-stop:
			s.logger.Info("received interrupt signal, shutting down")
			close(reconcileDone)
			reconcileWG.Wait()
			err := s.exporter.Close(ctx)
			if err != nil {
				s.logger.Error("failed to close exporter", zap.Error(err))
			}
			err = s.reconciler.Stop()
			if err != nil {
				s.logger.Error("failed to stop tracers", zap.Error(err))
			}
			s.logger.Info("tracer stopped successfully")
			return
		}
	}
}

func (s *spectra) runReconcilation(ctx context.Context, wg *sync.WaitGroup, exit chan struct{}) {
	var (
		reconcileTicker = time.NewTicker(5 * time.Second)
	)
	defer wg.Done()
	defer reconcileTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-exit:
			return
		case <-reconcileTicker.C:
			if err := s.reconciler.Reconcile(ctx); err != nil {
				s.logger.Error("failed to reconcile tracers", zap.Error(err))
			}
		}
	}
}

func (s *spectra) publish(res ebpf.PullResponse) {
	if len(res.Futex) > 0 {
		s.logger.Debug("publishing tracepoint payload",
			zap.String("topic", "futex"),
			zap.Int("buckets", len(res.Futex)),
		)
		s.ps.Pub(res.Futex, "futex")
	}

	if len(res.SchedSwitch) > 0 {
		s.logger.Debug("publishing tracepoint payload",
			zap.String("topic", "sched_switch"),
			zap.Int("buckets", len(res.SchedSwitch)),
		)
		s.ps.Pub(res.SchedSwitch, "sched_switch")
	}

	if len(res.PageFault) > 0 {
		s.logger.Debug("publishing tracepoint payload",
			zap.String("topic", "page_fault_user"),
			zap.Int("buckets", len(res.PageFault)),
		)
		s.ps.Pub(res.PageFault, "page_fault_user")
	}

	if len(res.Ioctl) > 0 {
		s.logger.Debug("publishing tracepoint payload",
			zap.String("topic", "ioctl"),
			zap.Int("buckets", len(res.Ioctl)),
		)
		s.ps.Pub(res.Ioctl, "ioctl")
	}
}
