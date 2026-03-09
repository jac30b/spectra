// go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Define futex operations and masks
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_CMD_MASK 0x7f

// Define the generic tracepoint format for syscall entry
// This allows us to access the syscall arguments safely
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

// We now need to remember BOTH the timestamp and the command type
struct futex_start_t
{
    __u64 ts;
    int cmd;
};

// start_times stores the entry data for each thread ID
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct futex_start_t);
    __uint(max_entries, 1024);
} start_times SEC(".maps");

// futex_wait_us: Histogram of time spent SLEEPING on a lock
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 256);
} futex_wait_us SEC(".maps");

// futex_wake_us: Histogram of kernel overhead to WAKE other threads
// struct
// {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __type(key, __u64);
//     __type(value, __u64);
//     __uint(max_entries, 256);
// } futex_wake_us SEC(".maps");

// target_pid: PID to filter (0 = trace all processes)
// This is set from userspace before the program is loaded
volatile const __u32 target_pid = 0;

SEC("tracepoint/syscalls/sys_enter_futex")
int futex_entry(struct trace_event_raw_sys_enter *ctx)
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

    // args[1] corresponds to the 'op' parameter in the futex syscall
    int op = (int)ctx->args[1];

    // Mask out FUTEX_PRIVATE_FLAG and FUTEX_CLOCK_REALTIME
    int cmd = op & FUTEX_CMD_MASK;

    // Filter out requeues, cmp_requeues, etc. We only want WAIT and WAKE.
    if (cmd != FUTEX_WAIT && cmd != FUTEX_WAKE)
    {
        return 0;
    }

    __u32 tid = bpf_get_current_pid_tgid();

    struct futex_start_t start_data = {};
    start_data.ts = bpf_ktime_get_ns();
    start_data.cmd = cmd;

    bpf_map_update_elem(&start_times, &tid, &start_data, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_futex")
int futex_exit(void *ctx)
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
    struct futex_start_t *start_data = bpf_map_lookup_elem(&start_times, &tid);

    if (start_data)
    {
        __u64 delta_us = (bpf_ktime_get_ns() - start_data->ts) / 1000;
        __u64 init_val = 1;
        __u64 *count;

        // Route the delta to the correct histogram based on the saved command
        if (start_data->cmd == FUTEX_WAIT)
        {
            count = bpf_map_lookup_elem(&futex_wait_us, &delta_us);
            if (count)
            {
                __sync_fetch_and_add(count, 1);
            }
            else
            {
                bpf_map_update_elem(&futex_wait_us, &delta_us, &init_val, BPF_ANY);
            }
        }
        // else if (start_data->cmd == FUTEX_WAKE)
        // {
        //     count = bpf_map_lookup_elem(&futex_wake_us, &delta_us);
        //     if (count)
        //     {
        //         __sync_fetch_and_add(count, 1);
        //     }
        //     else
        //     {
        //         bpf_map_update_elem(&futex_wake_us, &delta_us, &init_val, BPF_ANY);
        //     }
        // }

        bpf_map_delete_elem(&start_times, &tid);
    }

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
