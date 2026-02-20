package vmm

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/firecracker-microvm/firecracker-go-sdk"
	"github.com/firecracker-microvm/firecracker-go-sdk/client/models"

	"enclave/pkg/shared/logger"
)

var log = logger.New(os.Stdout)

type VMConfig struct {
	ID              string
	RootFSPath      string
	KernelPath      string
	FirecrackerPath string
	SocketPath      string
	VCPU            int64
	MemoryMB        int64
	Mounts          []Mount
}

type Mount struct {
	HostPath  string
	GuestPath string
	ReadOnly  bool
}

type Manager struct {
	vmmCtx    context.Context
	vmmCancel context.CancelFunc
	machine   *firecracker.Machine
	cfg       VMConfig
	guestMu   sync.RWMutex
	tetragon  bool
	tetraErr  string
}

func New(cfg VMConfig) *Manager {
	return &Manager{
		cfg: cfg,
		// Fail-safe default until guest health is observed.
		tetragon: false,
		tetraErr: "tetragon_status_unknown",
	}
}

func (m *Manager) Start(ctx context.Context) error {
	m.vmmCtx, m.vmmCancel = context.WithCancel(ctx)

	// Ensure cleanup of stale sockets before starting
	os.Remove(m.cfg.SocketPath)

	fcCfg := firecracker.Config{
		SocketPath:      m.cfg.SocketPath,
		KernelImagePath: m.cfg.KernelPath,
		LogPath:         filepath.Join(os.TempDir(), fmt.Sprintf("%s.log", m.cfg.ID)),
		Drives:          []models.Drive{}, // Initialize empty
		MachineCfg: models.MachineConfiguration{
			VcpuCount:  firecracker.Int64(2),
			MemSizeMib: firecracker.Int64(2048),
		},
		VsockDevices: []firecracker.VsockDevice{
			{
				Path: fmt.Sprintf("%s.vsock", m.cfg.SocketPath),
				CID:  3,
			},
		},
	}

	// Note: Virtio-FS is currently not used for JIT policy injection.
	// We use the ApplyPolicy RPC over Vsock instead for better compatibility and isolation.

	// Handle CPIO as Initrd
	if filepath.Ext(m.cfg.RootFSPath) == ".cpio" {
		fcCfg.InitrdPath = m.cfg.RootFSPath
		fcCfg.KernelArgs = "console=ttyS0 reboot=k panic=1 pci=off root=/dev/ram0 rdinit=/init bpf_jit_enable=1"
	} else {
		fcCfg.Drives = []models.Drive{
			{
				DriveID:      firecracker.String("1"),
				PathOnHost:   firecracker.String(m.cfg.RootFSPath),
				IsRootDevice: firecracker.Bool(true),
				IsReadOnly:   firecracker.Bool(true),
			},
		}
		fcCfg.KernelArgs = "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda bpf_jit_enable=1"
	}

	cmd := firecracker.VMCommandBuilder{}.
		WithBin(m.cfg.FirecrackerPath).
		WithSocketPath(m.cfg.SocketPath).
		Build(m.vmmCtx)

	// Tee guest console for visibility and runtime health parsing.
	stdoutR, stdoutW := io.Pipe()
	stderrR, stderrW := io.Pipe()
	cmd.Stdout = stdoutW
	cmd.Stderr = stderrW

	go m.consumeGuestLogs(stdoutR, os.Stdout)
	go m.consumeGuestLogs(stderrR, os.Stderr)

	machine, err := firecracker.NewMachine(m.vmmCtx, fcCfg, firecracker.WithProcessRunner(cmd))
	if err != nil {
		return fmt.Errorf("failed to create machine: %w", err)
	}
	m.machine = machine

	if err := m.machine.Start(m.vmmCtx); err != nil {
		return fmt.Errorf("failed to start machine: %w", err)
	}

	log.Info("VM %s started successfully", m.cfg.ID)
	return nil
}

func (m *Manager) consumeGuestLogs(r io.Reader, out io.Writer) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		fmt.Fprintln(out, line)
		m.observeGuestLogLine(line)
	}
}

func (m *Manager) observeGuestLogLine(line string) {
	l := strings.ToLower(line)
	m.guestMu.Lock()
	defer m.guestMu.Unlock()

	if strings.Contains(l, "tetragon pid file creation succeeded") {
		m.tetragon = true
		m.tetraErr = ""
		return
	}
	if strings.Contains(l, "failed to start tetragon") || strings.Contains(l, "tetragon exited with error") {
		m.tetragon = false
		switch {
		case strings.Contains(l, "btf search failed"):
			m.tetraErr = "tetragon_btf_missing"
		default:
			m.tetraErr = "tetragon_failed"
		}
	}
}

func (m *Manager) TetragonState() (ready bool, reason string) {
	m.guestMu.RLock()
	defer m.guestMu.RUnlock()
	return m.tetragon, m.tetraErr
}

func (m *Manager) Stop() error {
	if m.machine != nil {
		if err := m.machine.StopVMM(); err != nil {
			log.Error("Failed to stop VMM: %v", err)
		}
	}
	if m.vmmCancel != nil {
		m.vmmCancel()
	}
	os.Remove(m.cfg.SocketPath)
	os.Remove(fmt.Sprintf("%s.vsock", m.cfg.SocketPath))
	return nil
}

func (m *Manager) GetSocketPath() string {
	return m.cfg.SocketPath
}

func getKernelPath() string {
	// Expecting to find vmlinux in current dir or specific path
	// For this environment, we might need to assume a download or place it
	if k := os.Getenv("KERNEL_PATH"); k != "" {
		return k
	}
	return "vmlinux"
}

func getFirecrackerBinary() string {
	if b := os.Getenv("FIRECRACKER_BIN"); b != "" {
		return b
	}
	return "firecracker"
}
