// go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Generic tracepoint format for syscall entry
struct trace_event_raw_sys_enter
{
    struct
    {
        unsigned short common_type;
        unsigned char common_flags;
        unsigned char common_preempt_count;
        int common_pid;
    } ent;
    long int id;
    unsigned long args[6];
};

// start_data stores the entry timestamp and the ioctl cmd for each thread
struct ioctl_start_t
{
    __u64 ts;
    __u32 cmd;
};

// start_times stores the entry data for each thread ID
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct ioctl_start_t);
    __uint(max_entries, 1024);
} start_times SEC(".maps");

// ioctl_duration_us: Histogram of ioctl duration in microseconds
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 256);
} ioctl_duration_us SEC(".maps");

// target_pid: PID to filter (0 = trace all processes)
volatile const __u32 target_pid = 0;

// DIAGNOSTIC: Record TGIDs seen before PID filter is applied.
// Key = tgid, Value = count of events from that tgid.
// Also stores key=0 with value=target_pid so Go side can read what was set.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
} diag_tgids SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_ioctl")
int ioctl_entry(struct trace_event_raw_sys_enter *ctx)
{
    __u32 current_tgid = bpf_get_current_pid_tgid() >> 32;

    // DIAGNOSTIC: Record this TGID before any filtering
    __u64 *existing = bpf_map_lookup_elem(&diag_tgids, &current_tgid);
    if (existing)
    {
        __sync_fetch_and_add(existing, 1);
    }
    else
    {
        __u64 one = 1;
        bpf_map_update_elem(&diag_tgids, &current_tgid, &one, BPF_ANY);
    }

    // Also record the target_pid value at key=0 for Go-side comparison
    __u32 zero_key = 0;
    __u64 tp_val = (__u64)target_pid;
    bpf_map_update_elem(&diag_tgids, &zero_key, &tp_val, BPF_NOEXIST);

    // Check PID filter (TGID = process ID)
    if (target_pid != 0)
    {
        if (current_tgid != target_pid)
        {
            return 0;
        }
    }

    __u32 tid = bpf_get_current_pid_tgid();

    // args[1] is the ioctl cmd
    __u32 cmd = (__u32)ctx->args[1];

    struct ioctl_start_t start_data = {};
    start_data.ts = bpf_ktime_get_ns();
    start_data.cmd = cmd;

    bpf_map_update_elem(&start_times, &tid, &start_data, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ioctl")
int ioctl_exit(void *ctx)
{
    // Check PID filter (TGID = process ID)
    if (target_pid != 0)
    {
        __u32 current_tgid = bpf_get_current_pid_tgid() >> 32;
        if (current_tgid != target_pid)
        {
            return 0;
        }
    }

    __u32 tid = bpf_get_current_pid_tgid();
    struct ioctl_start_t *start_data = bpf_map_lookup_elem(&start_times, &tid);

    if (start_data)
    {
        __u64 delta_us = (bpf_ktime_get_ns() - start_data->ts) / 1000;
        __u64 init_val = 1;
        __u64 *count;

        count = bpf_map_lookup_elem(&ioctl_duration_us, &delta_us);
        if (count)
        {
            __sync_fetch_and_add(count, 1);
        }
        else
        {
            bpf_map_update_elem(&ioctl_duration_us, &delta_us, &init_val, BPF_ANY);
        }

        bpf_map_delete_elem(&start_times, &tid);
    }
    // Note: if start_data is NULL, the entry was either filtered out by PID
    // or the start_times map was full. This is expected and not an error.

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
