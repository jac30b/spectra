//go:build linux

package main

import "github.com/cilium/ebpf/rlimit"

func removeMemlock() error {
	return rlimit.RemoveMemlock()
}
