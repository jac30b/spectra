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

// clone3_counts: Simple counter for clone3 syscalls
// Key: 0 (only one key for total count)
// Value: number of clone3 calls
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 256);
} clone3_counts SEC(".maps");

// target_pid: PID to filter (0 = trace all processes)
volatile const __u32 target_pid = 0;

SEC("tracepoint/syscalls/sys_enter_clone3")
int clone3_entry(struct trace_event_raw_sys_enter *ctx)
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

    // Use a fixed key (0) for counting
    __u64 key = 0;
    __u64 init_val = 1;
    __u64 *count;

    count = bpf_map_lookup_elem(&clone3_counts, &key);
    if (count)
    {
        __sync_fetch_and_add(count, 1);
    }
    else
    {
        bpf_map_update_elem(&clone3_counts, &key, &init_val, BPF_ANY);
    }

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
