# eBPF Tracing


## Tinygrad

tinygrad's CPU backend compiles kernels via LLVM/Clang, mmaps them as executable memory, and runs them across a thread pool. These are the highest-value kernel probes for monitoring it.

### Memory Allocation & JIT Code Execution

#### 1. `mmap` — JIT kernel loading

tinygrad `mmap`s compiled kernels with `PROT_READ|PROT_WRITE|PROT_EXEC` (`ops_cpu.py`). Every compiled kernel hits this path.

```sh
bpftrace -e 'tracepoint:syscalls:sys_enter_mmap /args->prot & 4/ {
  printf("EXEC mmap pid=%d tid=%d len=%d\n", pid, tid, args->len);
}'
```

#### 2. `futex` — Thread synchronization / contention

tinygrad's thread pool synchronizes via futex. ~56k calls in 60s of MNIST training. High latency here means thread contention.

```sh
bpftrace -e '
tracepoint:syscalls:sys_enter_futex /comm == "python3"/ {
  @start[tid] = nsecs;
}
tracepoint:syscalls:sys_exit_futex /comm == "python3" && @start[tid]/ {
  @futex_wait_us = hist((nsecs - @start[tid]) / 1000);
  delete(@start[tid]);
}'
```

#### 3. `clone3` — Thread/process creation

Watch for unexpected thread churn or excessive spawning:

```sh
bpftrace -e 'tracepoint:syscalls:sys_enter_clone3 /comm == "python3"/ {
  printf("clone3 pid=%d tid=%d\n", pid, tid);
}'
```

#### 4. `openat` — File opens (libraries, data, cache)

Catches shared library loads, dataset reads, and kernel cache hits:

```sh
bpftrace -e 'tracepoint:syscalls:sys_enter_openat /comm == "python3"/ {
  printf("open pid=%d %s\n", pid, str(args->filename));
}'
```

### Scheduler & CPU Performance

#### 5. `sched_switch` — CPU scheduling overhead

See how tinygrad threads get scheduled and how often they're preempted:

```sh
bpftrace -e 'tracepoint:sched:sched_switch /comm == "python3"/ {
  printf("switch pid=%d tid=%d prev_state=%d\n", pid, tid, args->prev_state);
}'
```

#### 6. Hardware PMCs — Cache misses

For actual compute kernels, syscall tracing misses the point. Cache misses are critical for matmul/conv performance:

```sh
bpftrace -e 'hardware:cache-misses:1000 /comm == "python3"/ {
  @[ustack(5)] = count();
}'
```

#### 7. `page_fault_user` — Memory pressure

tinygrad allocates large tensors. Major page faults indicate cold memory or allocation overhead:

```sh
bpftrace -e 'tracepoint:exceptions:page_fault_user /comm == "python3"/ {
  @faults = count();
}'
```

### Priority Summary

| Priority | Tracepoint | Why |
|----------|------------|-----|
| #1 | `sys_enter_mmap` (filter `PROT_EXEC`) | Every JIT kernel load |
| #2 | `sys_enter_futex` | Thread pool contention |
| #3 | `sched:sched_switch` | CPU scheduling overhead |
| #4 | `exceptions:page_fault_user` | Memory pressure / cold data |
| #5 | `sys_enter_clone3` | Thread creation overhead |
| #6 | `hardware:cache-misses` | Actual compute efficiency |

### GPU Notes (if applicable)

If the machine has a GPU, add these:

- **NVIDIA** (`/dev/nvidiactl`): `sys_enter_ioctl` filtered by the nvidia device fd — covers command submission, memory allocation, and sync.
- **AMD** (`/dev/kfd`): Same idea, `sys_enter_ioctl` on the KFD fd — covers queue dispatch, VRAM allocation, and fences.

On a GPU backend, `ioctl` becomes the single most important probe since all GPU work funnels through it.



## Other

### Universal Probes (All Engines)

#### 1. `futex` — Thread pool contention

Every engine uses thread pools (ATen, XLA threadpool, tinygrad workers). This is the single best probe for CPU-side bottlenecks.

```sh
bpftrace -e '
tracepoint:syscalls:sys_enter_futex /comm == "python3"/ {
  @start[tid] = nsecs;
}
tracepoint:syscalls:sys_exit_futex /comm == "python3" && @start[tid]/ {
  @futex_wait_us = hist((nsecs - @start[tid]) / 1000);
  delete(@start[tid]);
}'
```

#### 2. `sched_switch` — CPU scheduling overhead

How threads get scheduled, preempted, and migrated across cores.

```sh
bpftrace -e 'tracepoint:sched:sched_switch /comm == "python3"/ {
  printf("switch pid=%d tid=%d prev_state=%d\n", pid, tid, args->prev_state);
}'
```

#### 3. `page_fault_user` — Memory pressure

All engines allocate large tensors. Page faults reveal cold memory, allocation overhead, and NUMA effects.

```sh
bpftrace -e 'tracepoint:exceptions:page_fault_user /comm == "python3"/ {
  @faults = count();
}'
```

#### 4. `hardware:cache-misses` — Compute efficiency

Matmul and conv are memory-bound across all engines. Cache misses are the real performance story.

```sh
bpftrace -e 'hardware:cache-misses:1000 /comm == "python3"/ {
  @[ustack(5)] = count();
}'
```

### GPU Probes (All Engines with GPU)

#### 5. `ioctl` — GPU command submission

**The single most important probe when a GPU is present.** All GPU work — kernel dispatch, memory alloc, synchronization — flows through driver ioctls.

```sh
# NVIDIA (/dev/nvidiactl, /dev/nvidia0)
bpftrace -e 'tracepoint:syscalls:sys_enter_ioctl /comm == "python3"/ {
  printf("ioctl fd=%d cmd=0x%x pid=%d\n", args->fd, args->cmd, pid);
}'
```

### JIT-Specific Probes (tinygrad, JAX/XLA)

#### 6. `mmap` with `PROT_EXEC` — JIT kernel loading

Only relevant for engines that compile at runtime. tinygrad mmaps compiled C/LLVM kernels. XLA compiles HLO -> LLVM -> machine code the same way.

**Not useful for PyTorch** (ships precompiled kernels via cuDNN/MKL).

```sh
bpftrace -e 'tracepoint:syscalls:sys_enter_mmap /args->prot & 4/ {
  printf("EXEC mmap pid=%d tid=%d len=%d\n", pid, tid, args->len);
}'
```

## PyTorch-Specific Probes

#### 7. `clone3` / `memfd_create` — DataLoader workers

PyTorch's DataLoader spawns subprocesses and shares tensors via shared memory. Other engines don't do this as heavily.

```sh
bpftrace -e '
tracepoint:syscalls:sys_enter_clone3 /comm == "python3"/ {
  printf("clone3 pid=%d\n", pid);
}
tracepoint:syscalls:sys_enter_memfd_create /comm == "python3"/ {
  printf("memfd pid=%d name=%s\n", pid, str(args->uname));
}'
```

#### 8. `openat` — Shared library / precompiled kernel loads

PyTorch loads cuDNN, MKL, etc. at runtime via `dlopen`. Watching `openat` for `.so` files catches this.

```sh
bpftrace -e 'tracepoint:syscalls:sys_enter_openat /comm == "python3"/ {
  printf("open pid=%d %s\n", pid, str(args->filename));
}'
```

### Ollama-Specific Probes

Ollama is a Go binary wrapping llama.cpp (C++), not a Python process. No GIL, no import machinery. Model weights are mmap'd directly from GGUF files, and the Go runtime has its own goroutine scheduler on top of llama.cpp's thread pool.

Note: The Ollama process name may vary — the inference worker often shows up as `ollama_llama_se` or similar. Adjust `comm` filters accordingly.

#### 9. `mmap` (large) — Model weight loading

Ollama/llama.cpp `mmap`s GGUF model files directly. Multi-GB mappings — the biggest I/O event.

```sh
bpftrace -e 'tracepoint:syscalls:sys_enter_mmap /comm == "ollama" || comm == "ollama_llama_se"/ {
  if (args->len > 1048576) {
    printf("mmap pid=%d len=%luMB flags=0x%x\n", pid, args->len / 1048576, args->flags);
  }
}'
```

#### 10. `page_fault_user` — Model page-in from disk

Since weights are mmap'd, actual disk reads happen on demand via page faults. This is the key probe for cold start vs warm inference — if the model is in page cache, faults are fast; if not, you're waiting on disk.

```sh
bpftrace -e 'tracepoint:exceptions:page_fault_user /comm == "ollama" || comm == "ollama_llama_se"/ {
  @faults = count();
  @faults_by_tid[tid] = count();
}'
```

#### 11. `madvise` — Memory management hints

llama.cpp uses `madvise(MADV_SEQUENTIAL)` and `MADV_WILLNEED` to hint the kernel about model access patterns. Tracing this shows prefetch behavior.

```sh
bpftrace -e 'tracepoint:syscalls:sys_enter_madvise /comm == "ollama" || comm == "ollama_llama_se"/ {
  printf("madvise pid=%d len=%luMB advice=%d\n", pid, args->len / 1048576, args->behavior);
}'
```

#### 12. `read` / `readv` — KV cache and tokenizer I/O

Unlike mmap'd weights, some data paths use explicit reads.

```sh
bpftrace -e 'tracepoint:syscalls:sys_enter_read /comm == "ollama" || comm == "ollama_llama_se"/ {
  if (args->count > 4096) {
    printf("read pid=%d fd=%d len=%lu\n", pid, args->fd, args->count);
  }
}'
```
#
### 13. `futex` — Go runtime + llama.cpp thread pool

Double the futex traffic: Go's runtime uses futex for goroutine scheduling, and llama.cpp has its own thread pool for matrix ops.

```sh
bpftrace -e '
tracepoint:syscalls:sys_enter_futex /comm == "ollama" || comm == "ollama_llama_se"/ {
  @start[tid] = nsecs;
}
tracepoint:syscalls:sys_exit_futex /(comm == "ollama" || comm == "ollama_llama_se") && @start[tid]/ {
  @futex_wait_us = hist((nsecs - @start[tid]) / 1000);
  delete(@start[tid]);
}'
```

#### 14. `epoll_wait` — HTTP API server latency

Ollama runs an HTTP API server. Tracing epoll shows request queuing and scheduling delays.

```sh
bpftrace -e '
tracepoint:syscalls:sys_enter_epoll_wait /comm == "ollama"/ {
  @start[tid] = nsecs;
}
tracepoint:syscalls:sys_exit_epoll_wait /comm == "ollama" && @start[tid]/ {
  @epoll_us = hist((nsecs - @start[tid]) / 1000);
  delete(@start[tid]);
}'
```

### Cross-Engine Priority Matrix

| Probe | tinygrad | PyTorch | JAX/XLA | Ollama | Why |
|-------|----------|---------|---------|--------|-----|
| `futex` | High | High | Medium | High | Thread sync everywhere |
| `ioctl` (GPU) | High | **#1** | **#1** | High | GPU command submission |
| `mmap PROT_EXEC` | **#1** | Low | High | Low | JIT engines only |
| `mmap` (large) | Low | Low | Low | **#1** | GGUF model weight loading |
| `page_fault_user` | High | High | High | **#1** | Model page-in from disk |
| `sched_switch` | High | High | High | High | Scheduling overhead |
| `cache-misses` | High | High | High | High | Always memory-bound |
| `clone3` / `memfd` | Low | **High** | Low | Low | PyTorch DataLoader |
| `epoll_wait` | Low | Low | Low | High | HTTP API server latency |
| `madvise` | Low | Low | Low | High | Model prefetch behavior |
| `openat` (`.so`) | Low | Medium | Low | Low | Precompiled kernel loading |

### TL;DR

- **CPU workload, any engine**: `futex` + `sched_switch` + `cache-misses`
- **GPU workload, any engine**: `ioctl` is king
- **JIT engines (tinygrad, JAX)**: add `mmap PROT_EXEC`
- **PyTorch specifically**: add `clone3` + `memfd_create` for DataLoader
- **Ollama specifically**: `mmap` (large) + `page_fault_user` + `madvise` for model loading; `epoll_wait` for API latency
