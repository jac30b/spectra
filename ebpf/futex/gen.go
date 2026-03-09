package futex

//go:generate go tool bpf2go -tags linux futex_tracepoint futex.c
