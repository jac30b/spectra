# ebpf – eBPF Tracepoint Tracer

This package attaches eBPF programs to Linux kernel tracepoints and collects
per-process performance data. A `Tracer` can monitor any combination of the
tracepoints listed below by passing the corresponding `With*` option.

## Available Tracepoints

### Futex (`WithTraceFutex`)

Monitors **futex** (fast userspace mutex) wait operations. This is one of the
most important probes for identifying thread contention and synchronization
bottlenecks in multi-threaded applications.

**Why it matters:** Thread pools (used by virtually all compute frameworks)
synchronize via futex. High latency here indicates lock contention, where
threads are competing for shared resources.

| Hook | What it measures |
|------|------------------|
| `syscalls/sys_enter_futex` | Start of futex operation |
| `syscalls/sys_exit_futex` | Duration spent waiting |

**Key insight:** ~56k futex calls in 60s is typical for busy thread pools.
Latencies above 1ms suggest contention issues.

---

### SchedSwitch (`WithTraceSchedSwitch`)

Captures **scheduler context switches** when the traced process is moved
off-CPU. Measures how long the process waited before getting CPU time again.

**Why it matters:** Reveals CPU scheduling pressure. High off-CPU times mean
the process is being preempted by higher-priority work or competing with other
processes for CPU cores.

| Hook | What it measures |
|------|------------------|
| `sched/sched_switch` | Time off-CPU between switches |

**Key insight:** Consistent off-CPU times >5ms suggest the process lacks
sufficient CPU priority or the system is overloaded.

---

### PageFault (`WithTracePageFault`)

Counts **user-space page faults** triggered by the traced process.

**Why it matters:** Page faults occur when accessing memory not currently in
RAM. High counts indicate memory pressure, cold data access, or working-set
thrashing. Major faults (disk I/O) are much more expensive than minor faults.

| Hook | What it measures |
|------|------------------|
| `exceptions/page_fault_user` | Count of page faults |

**Key insight:** Sudden spikes often correlate with loading large datasets or
memory-mapped files being accessed for the first time.

---

### Ioctl (`WithTraceIoctl`)

Measures duration of **ioctl** system calls to device drivers.

**Why it matters:** Ioctl is the primary interface for userspace to communicate
with kernel drivers. This is especially critical for GPU workloads where all
commands (kernel dispatch, memory allocation, synchronization) flow through
driver ioctls.

| Hook | What it measures |
|------|------------------|
| `syscalls/sys_enter_ioctl` | Start of ioctl |
| `syscalls/sys_exit_ioctl` | Duration of ioctl call |

**Key insight:** Slow ioctls (>1ms) often indicate driver bottlenecks,
GPU command queue saturation, or hardware synchronization delays.

---

### Mmap (`WithTraceMmap`)

Tracks **mmap** syscalls with `PROT_EXEC` protection flags.

**Why it matters:** Memory mappings with execute permission are used when
loading JIT-compiled code, dynamic libraries, or runtime-generated kernels.
This tracepoint specifically targets executable memory allocations which are
characteristic of just-in-time compilation workflows.

| Hook | What it measures |
|------|------------------|
| `syscalls/sys_enter_mmap` | Filters for PROT_EXEC mappings |
| `syscalls/sys_exit_mmap` | Duration of executable mmap |

**Key insight:** Frequent executable mmaps indicate active JIT compilation
or dynamic code generation. Latency here reflects kernel overhead for setting
up executable memory regions.

---

### Clone3 (`WithTraceClone3`)

Counts **clone3** syscalls for thread and process creation.

**Why it matters:** Modern Linux uses clone3 (via pthreads or direct calls) for
creating threads and processes. High counts indicate aggressive thread spawning,
which can be a bottleneck due to context switching overhead and kernel
scheduling costs.

| Hook | What it measures |
|------|------------------|
| `syscalls/sys_enter_clone3` | Count of thread/process creations |

**Key insight:** Worker pools that spawn processes per task (e.g., data loading)
can generate hundreds of clone3 calls. Unexpected churn suggests inefficient
thread pool management.

---

### Openat (`WithTraceOpenat`)

Counts **openat** syscalls, bucketed by filename length.

**Why it matters:** File opens indicate library loading, data access patterns,
and cache behavior. The histogram buckets by filename length to identify
patterns (short names often indicate temporary files, long names indicate
library paths).

| Hook | What it measures |
|------|------------------|
| `syscalls/sys_enter_openat` | Count of file opens by path length |

**Key insight:** Bursts of openat calls often correlate with loading shared
libraries, opening datasets, or cache misses requiring disk access.

---

## Quick Reference

| Tracepoint | Kernel Hook | Map Values | Unit | Use Case |
|---|---|---|---|---|
| **Futex** | `sys_enter/exit_futex` | Wait time on locks | μs | Thread contention |
| **SchedSwitch** | `sched/sched_switch` | Off-CPU time | μs | Scheduling pressure |
| **PageFault** | `page_fault_user` | Memory fault count | count | Memory pressure |
| **Ioctl** | `sys_enter/exit_ioctl` | Driver call duration | μs | GPU/driver latency |
| **Mmap** | `sys_enter/exit_mmap` | Executable mmap duration | μs | JIT code loading |
| **Clone3** | `sys_enter_clone3` | Thread creation count | count | Thread churn |
| **Openat** | `sys_enter_openat` | File open patterns | count | I/O patterns |

## PullResponse

`Tracer.Pull()` returns a `PullResponse` with one map per tracepoint.
Each map is a histogram: **key = bucket**, **value = number of events in that bucket**.

### Interpreting values

| Color | Futex (μs) | SchedSwitch (μs) | PageFault (count) | Ioctl (μs) | Mmap (μs) | Clone3 (count) | Openat (count) |
|---|---|---|---|---|---|---|---|
| 🟢 Green | < 1,000 | < 5,000 | < 100 | < 1,000 | < 100 | < 10 | < 100 |
| 🟡 Yellow | 1,000 – 10,000 | 5,000 – 50,000 | 100 – 1,000 | 1,000 – 10,000 | 100 – 1,000 | 10 – 100 | 100 – 1,000 |
| 🔴 Red | > 10,000 | > 50,000 | > 1,000 | > 10,000 | > 1,000 | > 100 | > 1,000 |

### Quick start

```go
tr, err := ebpf.NewTracer(ctx, pid,
    ebpf.WithTraceFutex(true),
    ebpf.WithTraceSchedSwitch(true),
    ebpf.WithTracePageFault(true),
    ebpf.WithTraceIoctl(true),
    ebpf.WithTraceMmap(true),
    ebpf.WithTraceClone3(true),
    ebpf.WithTraceOpenat(true),
)
if err != nil { /* handle */ }
defer tr.Stop()

resp, err := tr.Pull(ctx)
if err != nil { /* handle */ }

fmt.Println(resp) // color-coded pretty print
```

## Design Philosophy

This tracer is **general-purpose** — it measures fundamental Linux behaviors
that affect any compute-intensive workload. While specific frameworks may
exhibit characteristic patterns (e.g., JIT engines using PROT_EXEC mmap, GPU
workloads having high ioctl traffic), the underlying mechanisms are universal.

For framework-specific interpretation guidance, see `ebf_tracing.md`.
