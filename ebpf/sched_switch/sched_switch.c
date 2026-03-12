// go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// sched_switch tracepoint args (from /sys/kernel/debug/tracing/events/sched/sched_switch/format)
struct sched_switch_args
{
    // Common tracepoint fields
    struct
    {
        unsigned short common_type;
        unsigned char common_flags;
        unsigned char common_preempt_count;
        int common_pid;
    } ent;

    char prev_comm[16];
    int prev_pid;
    int prev_prio;
    long prev_state;
    char next_comm[16];
    int next_pid;
    int next_prio;
};

// start_times stores the timestamp when a thread was switched out
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4096);
} start_times SEC(".maps");

// sched_offcpu_us: Histogram of off-CPU duration in microseconds
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 256);
} sched_offcpu_us SEC(".maps");

// target_pid: PID to filter (0 = trace all processes)
volatile const __u32 target_pid = 0;

SEC("tracepoint/sched/sched_switch")
int sched_switch_handler(struct sched_switch_args *ctx)
{
    __u64 now = bpf_ktime_get_ns();

    // --- Handle switch-out: record timestamp for the thread being switched away ---
    __u32 prev_tid = (__u32)ctx->prev_pid;

    if (target_pid == 0 || (bpf_get_current_pid_tgid() >> 32) == target_pid)
    {
        // Only record if the prev thread matches our filter
        // prev_pid in sched_switch is actually the kernel tid
        bpf_map_update_elem(&start_times, &prev_tid, &now, BPF_ANY);
    }

    // --- Handle switch-in: compute off-CPU duration for the thread being scheduled ---
    __u32 next_tid = (__u32)ctx->next_pid;

    __u64 *start_ts = bpf_map_lookup_elem(&start_times, &next_tid);
    if (start_ts)
    {
        __u64 delta_us = (now - *start_ts) / 1000;
        __u64 init_val = 1;
        __u64 *count;

        count = bpf_map_lookup_elem(&sched_offcpu_us, &delta_us);
        if (count)
        {
            __sync_fetch_and_add(count, 1);
        }
        else
        {
            bpf_map_update_elem(&sched_offcpu_us, &delta_us, &init_val, BPF_ANY);
        }

        bpf_map_delete_elem(&start_times, &next_tid);
    }

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
