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

// openat_counts: Histogram of openat syscall counts by filename length bucket
// Key: filename length bucket (rounded to nearest power of 2 or range)
// Value: number of openat calls
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 256);
} openat_counts SEC(".maps");

// target_pid: PID to filter (0 = trace all processes)
volatile const __u32 target_pid = 0;

// Helper to round up to the next power of 2 bucket
static __u64 bucketize(__u64 value)
{
    if (value == 0)
        return 0;
    __u64 bucket = 1;
    while (bucket < value && bucket < (1ULL << 63))
    {
        bucket <<= 1;
    }
    return bucket;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int openat_entry(struct trace_event_raw_sys_enter *ctx)
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

    // args[1] is the filename pointer, args[2] is flags, args[0] is dirfd
    const char *filename = (const char *)ctx->args[1];

    // Calculate filename length (up to 256 chars max)
    __u64 len = 0;
    char ch;
    for (int i = 0; i < 256; i++)
    {
        if (bpf_probe_read_user(&ch, sizeof(ch), &filename[i]) != 0)
            break;
        if (ch == '\0')
            break;
        len++;
    }

    __u64 bucket = bucketize(len);
    __u64 init_val = 1;
    __u64 *count;

    count = bpf_map_lookup_elem(&openat_counts, &bucket);
    if (count)
    {
        __sync_fetch_and_add(count, 1);
    }
    else
    {
        bpf_map_update_elem(&openat_counts, &bucket, &init_val, BPF_ANY);
    }

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
