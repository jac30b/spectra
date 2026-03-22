package cuda_trace

//go:generate go tool bpf2go -tags linux cuda_trace cuda_trace.c
