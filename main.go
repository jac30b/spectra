package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cskr/pubsub/v2"
	"github.com/jac30b/spectra/ebpf"
	"github.com/jac30b/spectra/otel"
	"github.com/jac30b/spectra/vllm"
	"go.uber.org/zap"
)

const vllmScrapeInterval = 2 * time.Second

type recordConfig struct {
	PID           int
	PrometheusURL string
	Duration      time.Duration
	Output        string
}

type spectra struct {
	ps         *pubsub.PubSub[string, ebpf.TracepointData]
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

	if len(os.Args) > 1 && os.Args[1] == "record" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()

		if err := runRecord(ctx, logger, os.Args[2:]); errors.Is(err, flag.ErrHelp) {
			return
		} else if err != nil {
			logger.Error("recording failed", zap.Error(err))
			os.Exit(1)
		}
		return
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		logger.Error("failed to remove memlock rlimit", zap.Error(err))
		os.Exit(1)
	}

	ps := pubsub.New[string, ebpf.TracepointData](1024)

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

	exporter, err := otel.NewOltpExporter(ctx, logger, config.CollectorEndpoint, ps, config.Tracepoints...)
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

	// Start process monitor if enabled
	if config.EnableProcessMonitor {
		if err := s.reconciler.StartProcessMonitor(ctx); err != nil {
			logger.Error("failed to start process monitor", zap.Error(err))
		}
	}

	s.run(ctx)
}

func parseRecordConfig(args []string) (*recordConfig, error) {
	config := &recordConfig{}
	flags := flag.NewFlagSet("record", flag.ContinueOnError)
	flags.IntVar(&config.PID, "pid", 0, "PID to record (reserved for future use)")
	flags.StringVar(&config.PrometheusURL, "prometheus-url", vllm.DefaultEndpoint, "Prometheus metrics endpoint")
	flags.DurationVar(&config.Duration, "duration", 120*time.Second, "Recording duration")
	flags.StringVar(&config.Output, "output", "", "Output file (reserved for future use)")

	if err := flags.Parse(args); err != nil {
		return nil, err
	}
	if flags.NArg() != 0 {
		return nil, fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	if config.Duration <= 0 {
		return nil, fmt.Errorf("duration must be greater than zero")
	}

	return config, nil
}

func runRecord(ctx context.Context, logger *zap.Logger, args []string) error {
	config, err := parseRecordConfig(args)
	if err != nil {
		return err
	}

	client, err := vllm.NewVLLM(config.PrometheusURL)
	if err != nil {
		return err
	}

	recordCtx, cancel := context.WithTimeout(ctx, config.Duration)
	defer cancel()

	logger.Info("recording vLLM metrics",
		zap.String("prometheus_url", config.PrometheusURL),
		zap.Duration("duration", config.Duration),
	)

	scrape := func() error {
		families, err := client.Scrape(recordCtx)
		if err != nil {
			return err
		}

		return vllm.PrintSelectedMetrics(os.Stdout, families)
	}

	if err := scrape(); err != nil {
		if recordCtx.Err() != nil {
			return nil
		}
		return err
	}

	ticker := time.NewTicker(vllmScrapeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-recordCtx.Done():
			if errors.Is(recordCtx.Err(), context.DeadlineExceeded) {
				logger.Info("recording duration elapsed")
			} else {
				logger.Info("recording interrupted")
			}
			return nil
		case <-ticker.C:
			if err := scrape(); err != nil {
				if recordCtx.Err() != nil {
					return nil
				}
				return err
			}
		}
	}
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
			perPIDResponses, err := s.reconciler.PullPerPID(ctx)
			if err != nil {
				s.logger.Error("failed to pull data", zap.Error(err))
			}
			s.logger.Debug("pull result",
				zap.Int("processes", len(perPIDResponses)),
			)
			s.publishPerPID(perPIDResponses)
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

func (s *spectra) publishPerPID(perPIDResponses []PerPIDResponse) {
	for _, ppr := range perPIDResponses {
		processMeta := ebpf.ProcessMeta{
			PID:     ppr.PID,
			Name:    ppr.Meta.name,
			Exe:     ppr.Meta.exe,
			Cmdline: ppr.Meta.cmdline,
		}

		if len(ppr.Response.Futex) > 0 {
			s.logger.Debug("publishing tracepoint payload",
				zap.String("topic", "futex"),
				zap.Int("buckets", len(ppr.Response.Futex)),
				zap.Uint32("pid", ppr.PID),
			)
			s.ps.Pub(ebpf.TracepointData{
				Data:    ppr.Response.Futex,
				Process: processMeta,
			}, "futex")
		}

		if len(ppr.Response.SchedSwitch) > 0 {
			s.logger.Debug("publishing tracepoint payload",
				zap.String("topic", "sched_switch"),
				zap.Int("buckets", len(ppr.Response.SchedSwitch)),
				zap.Uint32("pid", ppr.PID),
			)
			s.ps.Pub(ebpf.TracepointData{
				Data:    ppr.Response.SchedSwitch,
				Process: processMeta,
			}, "sched_switch")
		}

		if len(ppr.Response.PageFault) > 0 {
			s.logger.Debug("publishing tracepoint payload",
				zap.String("topic", "page_fault_user"),
				zap.Int("buckets", len(ppr.Response.PageFault)),
				zap.Uint32("pid", ppr.PID),
			)
			s.ps.Pub(ebpf.TracepointData{
				Data:    ppr.Response.PageFault,
				Process: processMeta,
			}, "page_fault_user")
		}

		if len(ppr.Response.Ioctl) > 0 {
			s.logger.Debug("publishing tracepoint payload",
				zap.String("topic", "ioctl"),
				zap.Int("buckets", len(ppr.Response.Ioctl)),
				zap.Uint32("pid", ppr.PID),
			)
			s.ps.Pub(ebpf.TracepointData{
				Data:    ppr.Response.Ioctl,
				Process: processMeta,
			}, "ioctl")
		}

		if len(ppr.Response.Mmap) > 0 {
			s.logger.Debug("publishing tracepoint payload",
				zap.String("topic", "mmap"),
				zap.Int("buckets", len(ppr.Response.Mmap)),
				zap.Uint32("pid", ppr.PID),
			)
			s.ps.Pub(ebpf.TracepointData{
				Data:    ppr.Response.Mmap,
				Process: processMeta,
			}, "mmap")
		}

		if len(ppr.Response.Clone3) > 0 {
			s.logger.Debug("publishing tracepoint payload",
				zap.String("topic", "clone3"),
				zap.Int("buckets", len(ppr.Response.Clone3)),
				zap.Uint32("pid", ppr.PID),
			)
			s.ps.Pub(ebpf.TracepointData{
				Data:    ppr.Response.Clone3,
				Process: processMeta,
			}, "clone3")
		}

		if len(ppr.Response.Openat) > 0 {
			s.logger.Debug("publishing tracepoint payload",
				zap.String("topic", "openat"),
				zap.Int("buckets", len(ppr.Response.Openat)),
				zap.Uint32("pid", ppr.PID),
			)
			s.ps.Pub(ebpf.TracepointData{
				Data:    ppr.Response.Openat,
				Process: processMeta,
			}, "openat")
		}

		if len(ppr.Response.Cuda) > 0 {
			s.logger.Debug("publishing tracepoint payload",
				zap.String("topic", "cuda"),
				zap.Int("buckets", len(ppr.Response.Cuda)),
				zap.Uint32("pid", ppr.PID),
			)
			s.ps.Pub(ebpf.TracepointData{
				Data:    ppr.Response.Cuda,
				Process: processMeta,
			}, "cuda")
		}
	}
}
