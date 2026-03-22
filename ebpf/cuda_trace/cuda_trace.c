// go:build ignore
// +build ignore

#define __TARGET_ARCH_x86 1
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stddef.h>

// BPF map to store the requested size per thread across uprobe to uretprobe
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, size_t);
    __uint(max_entries, 10240);
} alloc_args SEC(".maps");

// BPF map to store histogram of sizes (key is size in bytes, value is count)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 10240);
} cuda_allocs SEC(".maps");

volatile const __u32 target_pid = 0;

// Uprobe: Fires when cuMemAlloc is CALLED
SEC("uprobe/cuMemAlloc")
int BPF_UPROBE(uprobe_cuMemAlloc, void *dptr, size_t bytesize) {
    if (target_pid != 0) {
        __u32 current_tgid = bpf_get_current_pid_tgid() >> 32;
        if (current_tgid != target_pid) {
            return 0;
        }
    }

    __u32 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&alloc_args, &tid, &bytesize, BPF_ANY);
    return 0;
}

// Uretprobe: Fires when cuMemAlloc RETURNS
SEC("uretprobe/cuMemAlloc")
int BPF_URETPROBE(uretprobe_cuMemAlloc, int ret) {
    if (target_pid != 0) {
        __u32 current_tgid = bpf_get_current_pid_tgid() >> 32;
        if (current_tgid != target_pid) {
            return 0;
        }
    }

    __u32 tid = bpf_get_current_pid_tgid();
    size_t *bytesize_ptr = bpf_map_lookup_elem(&alloc_args, &tid);
    if (!bytesize_ptr) {
        return 0;
    }

    if (ret == 0) { // CUDA_SUCCESS
        __u64 size = *bytesize_ptr;
        __u64 init_val = 1;
        __u64 *count = bpf_map_lookup_elem(&cuda_allocs, &size);
        if (count) {
            __sync_fetch_and_add(count, 1);
        } else {
            bpf_map_update_elem(&cuda_allocs, &size, &init_val, BPF_ANY);
        }
    }

    bpf_map_delete_elem(&alloc_args, &tid);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
