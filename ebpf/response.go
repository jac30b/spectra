package ebpf

import (
	"fmt"
	"sort"
	"strings"

	"go.uber.org/zap/zapcore"
)

// ProcessMeta holds metadata about a traced process.
type ProcessMeta struct {
	PID     uint32 `json:"pid"`
	Name    string `json:"name"`
	Exe     string `json:"exe"`
	Cmdline string `json:"cmdline"`
}

// TracepointData wraps tracepoint histogram data with process metadata.
type TracepointData struct {
	Data    map[uint64]uint64 `json:"data"`
	Process ProcessMeta       `json:"process"`
}

// NewPullResponse creates a PullResponse with all map fields initialized.
func NewPullResponse() PullResponse {
	return PullResponse{
		Futex:       make(map[uint64]uint64),
		SchedSwitch: make(map[uint64]uint64),
		PageFault:   make(map[uint64]uint64),
		Ioctl:       make(map[uint64]uint64),
		Mmap:        make(map[uint64]uint64),
		Clone3:      make(map[uint64]uint64),
		Openat:      make(map[uint64]uint64),
		Cuda:        make(map[uint64]uint64),
	}
}

// PullResponse contains the latest data from all active tracepoints.
// Each field is a histogram-style map where the key is a latency bucket (in μs)
// or a count bucket, and the value is the number of events that fell into that bucket.
type PullResponse struct {
	// Futex maps latency buckets (μs) to the number of futex wait operations
	// that took that long. High values indicate lock contention.
	Futex map[uint64]uint64 `json:"futex,omitempty"`

	// SchedSwitch maps off-CPU duration buckets (μs) to the number of times the
	// traced process was scheduled out for that duration. High values suggest the
	// process is being preempted or voluntarily yielding frequently.
	SchedSwitch map[uint64]uint64 `json:"sched_switch,omitempty"`

	// PageFault maps fault-count buckets to the number of user-space page faults
	// observed. High counts may indicate memory pressure or working-set thrashing.
	PageFault map[uint64]uint64 `json:"page_fault,omitempty"`

	// Ioctl maps latency buckets (μs) to the number of ioctl syscalls that took
	// that long. High values can point to slow device drivers or kernel modules.
	Ioctl map[uint64]uint64 `json:"ioctl,omitempty"`

	// Mmap maps latency buckets (μs) to the number of mmap syscalls with PROT_EXEC
	// that took that long. High values indicate executable memory allocation activity
	// (e.g., JIT compilation, dynamic code loading).
	Mmap map[uint64]uint64 `json:"mmap,omitempty"`

	// Clone3 maps count buckets to the number of clone3 syscalls observed.
	// High counts indicate thread/process creation activity.
	Clone3 map[uint64]uint64 `json:"clone3,omitempty"`

	// Openat maps filename length buckets to the number of openat syscalls.
	// Shows file open patterns for library and data loading.
	Openat map[uint64]uint64 `json:"openat,omitempty"`

	// Cuda maps allocation sizes to the number of cuMemAlloc calls.
	// Shows GPU memory allocation patterns.
	Cuda map[uint64]uint64 `json:"cuda,omitempty"`
}

// MarshalLogObject implements zapcore.ObjectMarshaler so PullResponse can be
// logged with zap.Object("stats", &resp) without ANSI-escaping issues.
func (r PullResponse) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	marshalMap := func(name string, data map[uint64]uint64) {
		if len(data) == 0 {
			return
		}

		t := sectionThresholds[name]

		_ = enc.AddObject(name, zapcore.ObjectMarshalerFunc(func(inner zapcore.ObjectEncoder) error {
			inner.AddInt("entries", len(data))
			inner.AddString("unit", t.unit)

			keys := make([]uint64, 0, len(data))
			for k := range data {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

			_ = inner.AddArray("buckets", zapcore.ArrayMarshalerFunc(func(arr zapcore.ArrayEncoder) error {
				for _, k := range keys {
					_ = arr.AppendObject(zapcore.ObjectMarshalerFunc(func(item zapcore.ObjectEncoder) error {
						item.AddString("bucket", fmt.Sprintf("0x%x", k))
						item.AddUint64("value", data[k])
						return nil
					}))
				}
				return nil
			}))

			return nil
		}))
	}

	marshalMap("Futex", r.Futex)
	marshalMap("SchedSwitch", r.SchedSwitch)
	marshalMap("PageFault", r.PageFault)
	marshalMap("Ioctl", r.Ioctl)
	marshalMap("Mmap", r.Mmap)
	marshalMap("Clone3", r.Clone3)
	marshalMap("Openat", r.Openat)
	marshalMap("Cuda", r.Cuda)

	return nil
}

// ANSI color codes for terminal output.
const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

// severity thresholds per tracepoint type.
type thresholds struct {
	warn uint64 // above this → yellow
	crit uint64 // above this → red
	unit string // display unit
}

var sectionThresholds = map[string]thresholds{
	// Futex wait times in μs: >1ms concerning, >10ms high
	"Futex": {warn: 1_000, crit: 10_000, unit: "μs"},
	// Off-CPU time in μs: >5ms concerning, >50ms high
	"SchedSwitch": {warn: 5_000, crit: 50_000, unit: "μs"},
	// Page fault counts: >100 concerning, >1000 high
	"PageFault": {warn: 100, crit: 1_000, unit: "count"},
	// Ioctl duration in μs: >1ms concerning, >10ms high
	"Ioctl": {warn: 1_000, crit: 10_000, unit: "μs"},
	// Mmap EXEC duration in μs: >100μs concerning, >1ms high
	"Mmap": {warn: 100, crit: 1_000, unit: "μs"},
	// Clone3 counts: >10 concerning, >100 high
	"Clone3": {warn: 10, crit: 100, unit: "count"},
	// Openat filename length buckets
	"Openat": {warn: 100, crit: 1_000, unit: "count"},
	// Cuda allocation count buckets
	"Cuda": {warn: 50, crit: 500, unit: "allocs"},
}

func colorForValue(v uint64, t thresholds) string {
	switch {
	case v >= t.crit:
		return colorRed
	case v >= t.warn:
		return colorYellow
	default:
		return colorGreen
	}
}

// String returns a human-readable, color-coded representation of the PullResponse.
// Values are colored green (normal), yellow (concerning), or red (high) based on
// per-tracepoint severity thresholds.
func (r PullResponse) String() string {
	var sb strings.Builder

	formatSection := func(name string, data map[uint64]uint64) {
		if len(data) == 0 {
			return
		}

		t := sectionThresholds[name]

		keys := make([]uint64, 0, len(data))
		for k := range data {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

		sb.WriteString(fmt.Sprintf("%s%s── %s (%d entries) [%s] ──%s\n",
			colorBold, colorCyan, name, len(data), t.unit, colorReset))
		for _, k := range keys {
			c := colorForValue(data[k], t)
			sb.WriteString(fmt.Sprintf("  %s%#x%s → %s%d %s%s\n",
				colorDim, k, colorReset,
				c, data[k], t.unit, colorReset))
		}
		sb.WriteByte('\n')
	}

	sb.WriteString(fmt.Sprintf("%s%s╔══ PullResponse ══╗%s\n", colorBold, colorCyan, colorReset))
	formatSection("Futex", r.Futex)
	formatSection("SchedSwitch", r.SchedSwitch)
	formatSection("PageFault", r.PageFault)
	formatSection("Ioctl", r.Ioctl)
	formatSection("Mmap", r.Mmap)
	formatSection("Clone3", r.Clone3)
	formatSection("Openat", r.Openat)
	formatSection("Cuda", r.Cuda)
	sb.WriteString(fmt.Sprintf("%s%s╚══════════════════╝%s", colorBold, colorCyan, colorReset))

	return sb.String()
}
