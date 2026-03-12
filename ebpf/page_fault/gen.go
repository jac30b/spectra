package page_fault

//go:generate go tool bpf2go -tags linux page_fault_tracepoint page_fault.c
