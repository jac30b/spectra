package proc_monitor

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"
)

const (
	envVarName = "SPECTRA"
	// Size of our event structure: pid (4) + comm (16) = 20 bytes
	eventSize = 20
)

// ExecEvent represents a process execution event from eBPF
type ExecEvent struct {
	PID  uint32
	Comm [16]byte
}

// ProcessMonitor watches for process executions and detects those with SPECTRA env var
type ProcessMonitor struct {
	logger              *zap.Logger
	collection          *ebpf.Collection
	link                link.Link
	ringReader          *ringbuf.Reader
	discoveredPIDs      map[uint32]struct{}
	mu                  sync.RWMutex
	stopChan            chan struct{}
	wg                  sync.WaitGroup
	onProcessDiscovered func(pid uint32, comm string)
}

// NewProcessMonitor creates a new process monitor
func NewProcessMonitor(logger *zap.Logger, onProcessDiscovered func(pid uint32, comm string)) (*ProcessMonitor, error) {
	return &ProcessMonitor{
		logger:              logger,
		discoveredPIDs:      make(map[uint32]struct{}),
		stopChan:            make(chan struct{}),
		onProcessDiscovered: onProcessDiscovered,
	}, nil
}

// createEBPFProgram creates the eBPF program using assembly
func createEBPFProgram(eventsMap *ebpf.Map) (asm.Instructions, error) {
	// Load the map file descriptor
	fd := eventsMap.FD()

	progSpec := &ebpf.ProgramSpec{
		Type:         ebpf.TracePoint,
		License:      "Dual MIT/GPL",
		Instructions: asm.Instructions{},
	}

	// Build the eBPF program in assembly
	// This program:
	// 1. Allocates space on stack for the event structure
	// 2. Gets current PID using bpf_get_current_pid_tgid
	// 3. Stores PID in the event structure
	// 4. Gets current comm using bpf_get_current_comm
	// 5. Outputs the event to the ring buffer using bpf_ringbuf_output

	insns := asm.Instructions{
		// Reserve stack space for event structure (20 bytes)
		// We'll store the event at FP[-20] to FP[-1]
		asm.Mov.Reg(asm.R6, asm.RFP),
		asm.Add.Imm(asm.R6, -eventSize),

		// Get current PID/TGID using bpf_get_current_pid_tgid
		// Returns: u64 tgid << 32 | pid
		asm.FnGetCurrentPidTgid.Call(),

		// Store PID (TGID - process ID) at offset 0 of event
		// R0 contains tgid << 32 | pid
		// Shift right by 32 to get TGID (upper 32 bits)
		asm.RSh.Imm(asm.R0, 32),
		asm.StoreMem(asm.R6, 0, asm.R0, asm.Word),

		// Get current comm using bpf_get_current_comm
		// bpf_get_current_comm(void *buf, u32 size_of_buf)
		// R1 = pointer to buffer (R6 + 4)
		// R2 = size (16)
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Add.Imm(asm.R1, 4),
		asm.Mov.Imm(asm.R2, 16),
		asm.FnGetCurrentComm.Call(),

		// Output to ring buffer using bpf_ringbuf_output
		// bpf_ringbuf_output(void *ringbuf, void *data, u64 size, u64 flags)
		// R1 = pointer to ringbuf map
		// R2 = pointer to data
		// R3 = size
		// R4 = flags (0)
		asm.LoadMapPtr(asm.R1, fd),
		asm.Mov.Reg(asm.R2, asm.R6),
		asm.Mov.Imm(asm.R3, eventSize),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnRingbufOutput.Call(),

		// Return 0
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	progSpec.Instructions = insns
	return insns, nil
}

// Start begins monitoring for process executions
func (pm *ProcessMonitor) Start() error {
	// Create the events map (ring buffer)
	eventsMapSpec := &ebpf.MapSpec{
		Name:       "events",
		Type:       ebpf.RingBuf,
		MaxEntries: 256 * 1024, // 256KB
	}

	eventsMap, err := ebpf.NewMap(eventsMapSpec)
	if err != nil {
		return fmt.Errorf("failed to create events map: %w", err)
	}
	defer func() {
		if err != nil {
			eventsMap.Close()
		}
	}()

	// Create the eBPF program using assembly
	insns, err := createEBPFProgram(eventsMap)
	if err != nil {
		return fmt.Errorf("failed to create eBPF program: %w", err)
	}

	progSpec := &ebpf.ProgramSpec{
		Name:         "trace_sched_process_exec",
		Type:         ebpf.TracePoint,
		License:      "Dual MIT/GPL",
		Instructions: insns,
	}

	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		return fmt.Errorf("failed to create eBPF program: %w", err)
	}
	defer func() {
		if err != nil {
			prog.Close()
		}
	}()

	// Attach to the tracepoint
	tplink, err := link.Tracepoint("sched", "sched_process_exec", prog, nil)
	if err != nil {
		return fmt.Errorf("failed to attach to tracepoint: %w", err)
	}
	pm.link = tplink

	// Create ring buffer reader
	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return fmt.Errorf("failed to create ring buffer reader: %w", err)
	}
	pm.ringReader = reader

	// Store references for cleanup
	pm.collection = &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"trace_sched_process_exec": prog,
		},
		Maps: map[string]*ebpf.Map{
			"events": eventsMap,
		},
	}

	pm.logger.Info("process monitor started", zap.String("env_var", envVarName))

	// Start reading events
	pm.wg.Add(1)
	go pm.readEvents()

	return nil
}

// readEvents continuously reads from the ring buffer
func (pm *ProcessMonitor) readEvents() {
	defer pm.wg.Done()

	for {
		select {
		case <-pm.stopChan:
			return
		default:
		}

		// Set a read deadline to periodically check stopChan
		pm.ringReader.SetDeadline(time.Now().Add(100 * time.Millisecond))

		record, err := pm.ringReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			// Timeout errors are expected when no events are available
			// Don't log them as errors to avoid spam
			if os.IsTimeout(err) || err.Error() == "epoll wait: i/o timeout" {
				continue
			}
			pm.logger.Error("failed to read from ring buffer", zap.Error(err))
			continue
		}

		// Parse the event
		if len(record.RawSample) < eventSize {
			continue
		}

		event := ExecEvent{
			PID: binary.LittleEndian.Uint32(record.RawSample[0:4]),
		}
		copy(event.Comm[:], record.RawSample[4:20])

		// Get process name as string
		comm := string(event.Comm[:])
		if idx := strings.IndexByte(comm, 0); idx != -1 {
			comm = comm[:idx]
		}

		pm.logger.Debug("process exec detected",
			zap.Uint32("pid", event.PID),
			zap.String("comm", comm))

		// Check if this process has SPECTRA env var
		if pm.hasSpectraEnvVar(event.PID) {
			pm.mu.Lock()
			pm.discoveredPIDs[event.PID] = struct{}{}
			pm.mu.Unlock()

			pm.logger.Info("discovered process with SPECTRA env var",
				zap.Uint32("pid", event.PID),
				zap.String("comm", comm))

			if pm.onProcessDiscovered != nil {
				pm.onProcessDiscovered(event.PID, comm)
			}
		}
	}
}

// hasSpectraEnvVar checks if a process has the SPECTRA environment variable
func (pm *ProcessMonitor) hasSpectraEnvVar(pid uint32) bool {
	envPath := fmt.Sprintf("/proc/%d/environ", pid)

	// Read with timeout to avoid hanging on zombie processes
	data, err := pm.readFileWithTimeout(envPath, 100*time.Millisecond)
	if err != nil {
		pm.logger.Debug("failed to read environ",
			zap.Uint32("pid", pid),
			zap.Error(err))
		return false
	}

	// Environment variables are null-separated
	vars := strings.SplitSeq(string(data), "\x00")
	for v := range vars {
		if strings.HasPrefix(v, envVarName+"=") {
			return true
		}
	}

	return false
}

// readFileWithTimeout reads a file with a timeout
func (pm *ProcessMonitor) readFileWithTimeout(path string, timeout time.Duration) ([]byte, error) {
	type result struct {
		data []byte
		err  error
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ch := make(chan result, 1)

	go func() {
		data, err := os.ReadFile(path)
		ch <- result{data, err}
	}()

	select {
	case res := <-ch:
		return res.data, res.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// GetDiscoveredPIDs returns a copy of the currently discovered PIDs
func (pm *ProcessMonitor) GetDiscoveredPIDs() []uint32 {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	pids := make([]uint32, 0, len(pm.discoveredPIDs))
	for pid := range pm.discoveredPIDs {
		pids = append(pids, pid)
	}
	return pids
}

// RemovePID removes a PID from the discovered set (call when process exits)
func (pm *ProcessMonitor) RemovePID(pid uint32) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.discoveredPIDs, pid)
}

// Stop stops the process monitor
func (pm *ProcessMonitor) Stop() error {
	close(pm.stopChan)

	if pm.ringReader != nil {
		pm.ringReader.Close()
	}

	if pm.link != nil {
		pm.link.Close()
	}

	if pm.collection != nil {
		// Close programs and maps
		for _, prog := range pm.collection.Programs {
			prog.Close()
		}
		for _, m := range pm.collection.Maps {
			m.Close()
		}
	}

	// Wait for goroutines to finish with timeout
	done := make(chan struct{})
	go func() {
		pm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		pm.logger.Info("process monitor stopped")
	case <-time.After(5 * time.Second):
		pm.logger.Warn("process monitor stop timeout")
	}

	return nil
}
