// go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// page_fault_user tracepoint args
// (from /sys/kernel/debug/tracing/events/exceptions/page_fault_user/format)
struct page_fault_user_args
{
    struct
    {
        unsigned short common_type;
        unsigned char common_flags;
        unsigned char common_preempt_count;
        int common_pid;
    } ent;

    unsigned long address;
    unsigned long ip;
    unsigned long error_code;
};

// page_fault_count: Simple counter map
// key 0 = total fault count
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 256);
} page_fault_count SEC(".maps");

// target_pid: PID to filter (0 = trace all processes)
volatile const __u32 target_pid = 0;

SEC("tracepoint/exceptions/page_fault_user")
int page_fault_user_handler(struct page_fault_user_args *ctx)
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

    // Increment total fault count (key = 0)
    __u64 key = 0;
    __u64 init_val = 1;
    __u64 *count;

    count = bpf_map_lookup_elem(&page_fault_count, &key);
    if (count)
    {
        __sync_fetch_and_add(count, 1);
    }
    else
    {
        bpf_map_update_elem(&page_fault_count, &key, &init_val, BPF_ANY);
    }

    // Also bucket by error_code to distinguish read/write/exec faults
    __u64 err_key = ctx->error_code;
    count = bpf_map_lookup_elem(&page_fault_count, &err_key);
    if (count)
    {
        __sync_fetch_and_add(count, 1);
    }
    else
    {
        bpf_map_update_elem(&page_fault_count, &err_key, &init_val, BPF_ANY);
    }

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
