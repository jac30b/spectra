# OTel Metrics Export for Spectra

Spectra currently collects eBPF histogram data (futex, sched_switch, page_fault, ioctl) via `Tracer.Pull()` and logs it with zap. This plan adds OTel SDK instrumentation to spectra so it can export metrics via OTLP to a standard OTel Collector — enabling export to Prometheus, Grafana, Jaeger, or any OTLP-compatible backend.

## Architecture

```
┌──────────────────┐  OTLP/gRPC  ┌──────────────────────┐
│  sudo ./spectra  │ ──────────► │  otelcol (standard)   │
│   ebpf.Tracer    │  :4317      │   otlpreceiver        │
│   Pull() → OTel  │             │   ──► exporters       │
│   SDK metrics    │             │   (debug, prometheus,  │
└──────────────────┘             │    otlp, etc.)        │
                                 └──────────────────────┘
```

Two separate processes:
1. **spectra** — eBPF tracer app, uses OTel Go SDK to push metrics via OTLP
2. **otelcol** — standard OTel Collector receives metrics and routes them through the pipeline

## Key Design Decisions

> [!IMPORTANT]
> **Metrics, not traces.** Spectra's [PullResponse](file://wsl.localhost/Ubuntu/home/pedro/git/spectra/ebpf/response.go#24-42) is histogram data (bucket → count/duration), which maps naturally to OTel **Gauge** metrics. Each tracepoint becomes a metric with bucket as an attribute.

> [!IMPORTANT]
> **No custom receiver needed.** Spectra uses the OTel Go SDK to export metrics directly via OTLP. The standard `otlpreceiver` in the OTel Collector handles ingestion.

> [!WARNING]
> **Root privileges.** The eBPF tracer requires `CAP_BPF` / root. The spectra binary must be run with `sudo` or appropriate capabilities.

## Proposed Changes

### Spectra App (OTel SDK Integration)

Add OTel Go SDK to `main.go` to create metrics from [PullResponse](file://wsl.localhost/Ubuntu/home/pedro/git/spectra/ebpf/response.go#24-42) and export them via OTLP gRPC.

---

#### [NEW] [otel.go](file:///wsl.localhost/Ubuntu/home/pedro/git/spectra/otel.go)

OTel SDK setup in a dedicated file:

- `initOTel(ctx) (shutdown func(), err error)` — initializes:
  - OTLP gRPC exporter (targeting `localhost:4317` by default)
  - `MeterProvider` with a `PeriodicReader`
  - Resource with `service.name = "spectra"`
- Returns a shutdown function for graceful cleanup

---

#### [NEW] [metrics.go](file:///wsl.localhost/Ubuntu/home/pedro/git/spectra/metrics.go)

Metrics conversion from `PullResponse` to OTel instruments:

- `recordMetrics(meter, resp PullResponse)` — records each tracepoint's data as OTel gauge observations:

| PullResponse field | OTel Metric Name | Type | Attributes |
|---|---|---|---|
| `Futex` | `spectra.futex.duration` | Int64 Gauge | `bucket` (hex string) |
| `SchedSwitch` | `spectra.sched_switch.duration` | Int64 Gauge | `bucket` (hex string) |
| `PageFault` | `spectra.page_fault.count` | Int64 Gauge | `bucket` (hex string) |
| `Ioctl` | `spectra.ioctl.duration` | Int64 Gauge | `bucket` (hex string) |

Each metric data point has:
- A `bucket` attribute (hex-formatted key from the map)
- An int64 value (the count/duration from the map)

---

#### [MODIFY] [main.go](file:///wsl.localhost/Ubuntu/home/pedro/git/spectra/main.go)

Changes to the main function:
1. Call `initOTel(ctx)` at startup, `defer shutdown()`
2. Create a `Meter` from the global `MeterProvider`
3. In the Pull loop, call `recordMetrics(meter, res)` after each `Pull()`
4. Add a `--otel-endpoint` flag (default `localhost:4317`) for the collector address

---

#### [MODIFY] [go.mod](file:///wsl.localhost/Ubuntu/home/pedro/git/spectra/go.mod)

Add OTel SDK dependencies:
- `go.opentelemetry.io/otel`
- `go.opentelemetry.io/otel/sdk`
- `go.opentelemetry.io/otel/sdk/metric`
- `go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc`
- `go.opentelemetry.io/otel/metric`

---

### OTel Collector (Standard)

No custom build needed — use the standard OTel Collector or Contrib distribution.

#### [NEW] [otel-config.yaml](file:///wsl.localhost/Ubuntu/home/pedro/git/spectra/otel-col/otel-config.yaml)

Sample collector config for local testing:
```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

exporters:
  debug:
    verbosity: detailed

service:
  pipelines:
    metrics:
      receivers: [otlp]
      exporters: [debug]
```

For production, swap `debug` for `prometheusremotewrite`, `otlp`, or any other exporter.

---

#### [MODIFY] [builder-config.yaml](file:///wsl.localhost/Ubuntu/home/pedro/git/spectra/builder-config.yaml)

Simplify — no custom receiver needed. Only standard components:
- `otlpreceiver` (receives OTLP from spectra)
- `debugexporter` (for testing)
- `otlpexporter` (for forwarding)
- `batchprocessor` (batching for production)

## Verification Plan

### Build Verification
```bash
# 1. Build spectra with OTel SDK
go build -o spectra .

# 2. Install standard OTel Collector (or use Docker)
docker pull otel/opentelemetry-collector:latest
```

### Manual Verification
1. Start the OTel Collector:
   ```bash
   # Using config from this repo
   docker run --rm -p 4317:4317 \
     -v $(pwd)/otel-col/otel-config.yaml:/etc/otelcol/config.yaml \
     otel/opentelemetry-collector:latest

   # Or if built with OCB
   ./otelcol-spectra/otelcol-spectra --config otel-col/otel-config.yaml
   ```
2. Start spectra in another terminal:
   ```bash
   sudo ./spectra --otel-endpoint localhost:4317
   ```
3. Wait for one interval (5s) and confirm the debug exporter in the collector outputs spectra metrics
4. Verify metrics contain expected names (`spectra.futex.duration`, etc.) and bucket attributes
5. Send `SIGINT` to spectra and confirm graceful shutdown of both OTel SDK and eBPF tracer

> [!NOTE]
> The `convertToMetrics()` function can be unit-tested independently with mock [PullResponse](file://wsl.localhost/Ubuntu/home/pedro/git/spectra/ebpf/response.go#24-42) data — no root or eBPF required.
