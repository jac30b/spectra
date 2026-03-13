# spectra

Full-stack eBPF observability for LLM inference — trace GPU compute, memory, I/O, and network across CUDA, ROCm, Vulkan, and OpenCL.

## Overview

Spectra attaches lightweight eBPF programs to Linux kernel tracepoints and collects per-process performance histograms in real time. It currently monitors:

| Tracepoint | What it measures |
|---|---|
| **Futex** | Lock contention (wait time in μs) |
| **SchedSwitch** | Off-CPU time between context switches (μs) |
| **PageFault** | User-space page fault frequency (count) |
| **Ioctl** | Device driver / ioctl syscall latency (μs) |

## Requirements

- Linux kernel ≥ 5.8 (for BPF ring buffer support)
- Root privileges (or `CAP_BPF` + `CAP_PERFMON`)
- Go 1.21+

## Quick Start

```bash
# Build
make

# Use default config.yml
sudo ./spectra

# Use a specific config file
sudo ./spectra -c /path/to/config.yml
sudo ./spectra --config /path/to/config.yml
```

## Flags

| Flag | Default | Description |
|---|---|---|
| `-c` | `config.yml` | Path to config file |
| `--config` | `config.yml` | Path to config file (alias of `-c`) |

## Configuration

`config.yml` controls the traced PID and enabled tracepoints:

```yaml
pid: 0
tracepoints:
  - futex
  - sched_switch
  - page_fault_user
  - ioctl
```

## Project Structure

```
spectra/
├── main.go              # CLI entry point
├── ebpf/
│   ├── ebpf.go          # Tracer orchestrator
│   ├── response.go      # PullResponse + zap/pretty-print support
│   ├── futex/            # Futex tracepoint (enter/exit)
│   ├── sched_switch/     # Context-switch tracepoint
│   ├── page_fault/       # User-space page fault tracepoint
│   └── ioctl/            # Ioctl tracepoint (enter/exit)
└── Makefile
```

## TODO

- [ ] Add support for monitoring based on process name
- [ ] Add support for GPU hardware (CUDA/ROCm ioctl interception)
- [ ] Export metrics to Prometheus / OpenTelemetry
- [ ] Add network tracing (TCP retransmits, socket latency)
- [ ] Per-CPU histogram breakdowns
- [ ] Web dashboard for real-time visualization
- [ ] Configurable histogram bucket sizes
- [ ] Alerting thresholds via config file
- [ ] Container-aware tracing (cgroup filtering)
