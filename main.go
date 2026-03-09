package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/jac30b/spectra/ebpf"
	"go.uber.org/zap"
)

func init() {
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}
}

func main() {
	// Initialize zap logger
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	// Parse command line flags
	pidFlag := flag.Int("pid", 0, "PID to trace (0 = trace all processes)")
	flag.Parse()

	logger.Info("Starting spectra tracer", zap.Int("pid", *pidFlag))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		tick = time.Tick(5 * time.Second)
		stop = make(chan os.Signal, 5)
	)

	signal.Notify(stop, os.Interrupt)

	tracer, err := ebpf.NewTracer(ctx, uint32(*pidFlag), ebpf.WithLogger(logger), ebpf.WithTraceFutex(true))
	if err != nil {
		logger.Fatal("failed to create tracer", zap.Error(err))
	}

	for {
		select {
		case <-tick:
			res, err := tracer.Pull(ctx)
			if err != nil {
				logger.Error("failed to pull data", zap.Error(err))
				continue
			}
			data, err := json.Marshal(res)
			if err != nil {
				logger.Error("failed to marshal data", zap.Error(err))
				continue
			}
			logger.Debug("futex stats", zap.String("data", string(data)))
		case <-stop:
			logger.Info("received interrupt signal, shutting down")
			err = tracer.Stop()
			if err != nil {
				logger.Error("failed to stop tracer", zap.Error(err))
			}
			logger.Info("tracer stopped successfully")
			return
		}
	}
}
