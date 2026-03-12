package sched_switch

//go:generate go tool bpf2go -tags linux sched_switch_tracepoint sched_switch.c
