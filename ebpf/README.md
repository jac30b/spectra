# ebpf – eBPF Tracepoint Tracer

This package attaches eBPF programs to Linux kernel tracepoints and collects
per-process performance data. A `Tracer` can monitor any combination of the
tracepoints listed below by passing the corresponding `With*` option.

## Tracepoints

| Tracepoint | Kernel Hook | Map Values | Unit |
|---|---|---|---|
| **Futex** | `syscalls/sys_enter_futex`, `sys_exit_futex` | Time spent waiting on a futex | μs |
| **SchedSwitch** | `sched/sched_switch` | Time the process spent off-CPU between context switches | μs |
| **PageFault** | `exceptions/page_fault_user` | Number of user-space page faults observed | count |
| **Ioctl** | `syscalls/sys_enter_ioctl`, `sys_exit_ioctl` | Duration of ioctl syscalls | μs |

## PullResponse

`Tracer.Pull()` returns a `PullResponse` with one map per tracepoint.
Each map is a histogram: **key = bucket**, **value = number of events in that bucket**.

### Interpreting values

| Color | Futex (μs) | SchedSwitch (μs) | PageFault (count) | Ioctl (μs) |
|---|---|---|---|---|
| 🟢 Green | < 1,000 | < 5,000 | < 100 | < 1,000 |
| 🟡 Yellow | 1,000 – 10,000 | 5,000 – 50,000 | 100 – 1,000 | 1,000 – 10,000 |
| 🔴 Red | > 10,000 | > 50,000 | > 1,000 | > 10,000 |

### Quick start

```go
tr, err := ebpf.NewTracer(ctx, pid,
    ebpf.WithTraceFutex(true),
    ebpf.WithTraceSchedSwitch(true),
    ebpf.WithTracePageFault(true),
    ebpf.WithTraceIoctl(true),
)
if err != nil { /* handle */ }
defer tr.Stop()

resp, err := tr.Pull(ctx)
if err != nil { /* handle */ }

fmt.Println(resp) // color-coded pretty print
```
