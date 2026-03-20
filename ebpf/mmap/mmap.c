// go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/mman.h>

// Generic tracepoint format for syscall entry
struct trace_event_raw_sys_enter {
  struct {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
  } ent;
  long int id;
  unsigned long args[6];
};

// start_times stores the entry timestamp for each thread ID
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 1024);
} start_times SEC(".maps");

// mmap_exec_us: Histogram of mmap with PROT_EXEC duration in microseconds
// This catches JIT code loading, dynamic library mapping, and executable memory allocation
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u64);
  __type(value, __u64);
  __uint(max_entries, 256);
} mmap_exec_us SEC(".maps");

// target_pid: PID to filter (0 = trace all processes)
volatile const __u32 target_pid = 0;

// PROT_EXEC = 0x4
#define PROT_EXEC 0x4

SEC("tracepoint/syscalls/sys_enter_mmap")
int mmap_entry(struct trace_event_raw_sys_enter *ctx) {
  // Check PID filter (TGID = process ID)
  if (target_pid != 0) {
    __u32 current_tgid = bpf_get_current_pid_tgid() >> 32;
    if (current_tgid != target_pid) {
      return 0;
    }
  }

  // args[2] is the 'prot' parameter (protection flags)
  int prot = (int)ctx->args[2];

  // Filter for PROT_EXEC - executable memory mappings
  if (!(prot & PROT_EXEC)) {
    return 0;
  }

  __u32 tid = bpf_get_current_pid_tgid();
  __u64 ts = bpf_ktime_get_ns();

  bpf_map_update_elem(&start_times, &tid, &ts, BPF_ANY);

  return 0;
}

SEC("tracepoint/syscalls/sys_exit_mmap")
int mmap_exit(void *ctx) {
  // Check PID filter (TGID = process ID)
  if (target_pid != 0) {
    __u32 current_tgid = bpf_get_current_pid_tgid() >> 32;
    if (current_tgid != target_pid) {
      return 0;
    }
  }

  __u32 tid = bpf_get_current_pid_tgid();
  __u64 *start_ts = bpf_map_lookup_elem(&start_times, &tid);

  if (start_ts) {
    __u64 delta_us = (bpf_ktime_get_ns() - *start_ts) / 1000;
    __u64 init_val = 1;
    __u64 *count;

    count = bpf_map_lookup_elem(&mmap_exec_us, &delta_us);
    if (count) {
      __sync_fetch_and_add(count, 1);
    } else {
      bpf_map_update_elem(&mmap_exec_us, &delta_us, &init_val, BPF_ANY);
    }

    bpf_map_delete_elem(&start_times, &tid);
  }

  return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
