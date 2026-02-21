package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"enclave/api/v1/agentv1connect"
	"enclave/cmd/enclave/bundle"
	"enclave/pkg/host/audit"
	"enclave/pkg/host/proxy"
	"enclave/pkg/host/vmm"
	"enclave/pkg/shared/logger"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
)

var log = logger.New(os.Stdout)
var uiColorEnabled = detectColorTTY()
var uiSpinnerEnabled = detectSpinnerTTY()

type runtimeStatus struct {
	mu                     sync.RWMutex
	RuntimeReady           bool     `json:"runtime_ready"`
	PolicyEnforcementReady bool     `json:"policy_enforcement_ready"`
	TelemetryReady         bool     `json:"telemetry_ready"`
	AuditPersistenceReady  bool     `json:"audit_persistence_ready"`
	DegradedReasons        []string `json:"degraded_reasons"`
}

func newRuntimeStatus() *runtimeStatus {
	return &runtimeStatus{
		PolicyEnforcementReady: false,
	}
}

func (s *runtimeStatus) addReason(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.DegradedReasons {
		if r == reason {
			return
		}
	}
	s.DegradedReasons = append(s.DegradedReasons, reason)
	sort.Strings(s.DegradedReasons)
}

func (s *runtimeStatus) clearReason(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make([]string, 0, len(s.DegradedReasons))
	for _, r := range s.DegradedReasons {
		if r != reason {
			next = append(next, r)
		}
	}
	s.DegradedReasons = next
}

func (s *runtimeStatus) setRuntimeReady(v bool) {
	s.mu.Lock()
	s.RuntimeReady = v
	s.mu.Unlock()
}

func (s *runtimeStatus) setAuditPersistenceReady(v bool) {
	s.mu.Lock()
	s.AuditPersistenceReady = v
	s.mu.Unlock()
}

func (s *runtimeStatus) setTelemetryReady(v bool) {
	s.mu.Lock()
	s.TelemetryReady = v
	s.mu.Unlock()
}

func (s *runtimeStatus) setPolicyEnforcementReady(v bool) {
	s.mu.Lock()
	s.PolicyEnforcementReady = v
	s.mu.Unlock()
}

func (s *runtimeStatus) snapshot() runtimeStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := *s
	out.DegradedReasons = append([]string(nil), s.DegradedReasons...)
	return out
}

func main() {
	if len(os.Args) == 1 {
		if err := runUp(nil); err != nil {
			log.Fatal("%v", err)
		}
		return
	}

	switch os.Args[1] {
	case "up":
		if err := runUp(os.Args[2:]); err != nil {
			log.Fatal("%v", err)
		}
	case "image":
		if err := runImage(os.Args[2:]); err != nil {
			log.Fatal("%v", err)
		}
	case "-h", "--help", "help":
		printUsage()
	default:
		// Backward compatibility with pre-subcommand flag-only invocation.
		if strings.HasPrefix(os.Args[1], "-") {
			if err := runUp(os.Args[1:]); err != nil {
				log.Fatal("%v", err)
			}
			return
		}
		printUsage()
		log.Fatal("unknown command %q", os.Args[1])
	}
}

func runUp(args []string) error {
	status := newRuntimeStatus()
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)

	cpu := fs.Int64("cpu", 1, "Number of vCPUs")
	mem := fs.Int64("mem", 2048, "Memory in MB")
	socket := fs.String("socket", "/tmp/enclave.sock", "Path to VSock socket")
	policyPath := fs.String("policy", "", "Path to policy YAML file")
	provider := fs.String("provider", "auto", "Runtime provider: auto|native|lima|wsl2")
	daemonize := fs.Bool("d", false, "Run in background as a daemon")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *daemonize {
		var childArgs []string
		for _, arg := range os.Args[1:] {
			if arg != "-d" && arg != "--d" { // filter out daemon flag
				childArgs = append(childArgs, arg)
			}
		}

		cmd := exec.Command(os.Args[0], childArgs...)
		cmd.Stdin = nil
		cmd.Stdout = nil
		cmd.Stderr = nil
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true, // create a new session
		}

		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start daemon: %w", err)
		}
		uiDone(fmt.Sprintf("Enclave started in background (PID: %d)", cmd.Process.Pid))
		return nil
	}

	selectedProvider, err := resolveProvider(*provider)
	if err != nil {
		return fmt.Errorf("invalid provider: %w", err)
	}
	if err := validateProviderRuntime(selectedProvider); err != nil {
		return fmt.Errorf("provider preflight failed: %w", err)
	}
	log.Info("Runtime provider: %s", selectedProvider)

	// 1. Hydrate Assets
	log.Info("Enclave Host v1.1.0-hardened (Build: %s)", time.Now().Format(time.RFC3339))
	log.Info("Checking runtime assets...")
	hydrator, err := bundle.NewHydrator("") // Default cache dir
	if err != nil {
		return fmt.Errorf("failed to initialize hydrator: %w", err)
	}

	if err := hydrator.EnsureAssets(); err != nil {
		log.Info("Assets missing or incomplete. Auto-hydrating from hub...")
		pullArgs := []string{
			"--install=true",
			"--verify=false",
			"--dest-dir", filepath.Join(os.TempDir(), "enclave-bootstrap"),
			"--cache-dir", hydrator.CacheDir,
		}
		if pullErr := runImagePull(pullArgs); pullErr != nil {
			return fmt.Errorf("auto-hydration failed: %w (original ensure error: %v)", pullErr, err) // Note: this calls image pull recursively basically but through the function directly
		}
		if checkErr := hydrator.EnsureAssets(); checkErr != nil {
			return fmt.Errorf("assets still missing after auto-hydration: %w", checkErr)
		}
	}

	// 2. Load Policy
	var mounts []vmm.Mount
	if *policyPath != "" {
		policy, err := LoadPolicy(*policyPath)
		if err != nil {
			return fmt.Errorf("failed to load policy: %w", err)
		}
		for _, m := range policy.Mounts {
			mounts = append(mounts, vmm.Mount{
				HostPath:  m.HostPath,
				GuestPath: m.GuestPath,
				ReadOnly:  m.ReadOnly,
			})
			log.Info("Policy: Mounting %s -> %s (ro=%v)", m.HostPath, m.GuestPath, m.ReadOnly)
		}
	}

	// 3. Configure VM
	// We use the hydrated assets from the cache
	cfg := vmm.VMConfig{
		ID:              "enclave-1",
		VCPU:            *cpu,
		MemoryMB:        *mem,
		SocketPath:      *socket,
		KernelPath:      hydrator.GetPath("vmlinux"),
		RootFSPath:      hydrator.GetPath("rootfs.cpio"),
		FirecrackerPath: hydrator.GetPath("firecracker"),
		Mounts:          mounts,
	}

	// 4. Start VM Manager
	mgr := vmm.New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Info("Starting Enclave VM...")
	if err := mgr.Start(ctx); err != nil {
		mgr.Stop() // Ensure cleanup on start failure
		return fmt.Errorf("failed to launch vm: %w", err)
	}
	status.setRuntimeReady(true)

	// 5. Start Proxy Server
	log.Info("Starting Proxy Server on :7337...")

	// Initialize Audit Writer
	dbURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if dbURL == "" && strings.TrimSpace(os.Getenv("POSTGRES_HOST")) != "" {
		dbUser := os.Getenv("POSTGRES_USER")
		if dbUser == "" {
			dbUser = "tensorpath"
		}
		dbPass := os.Getenv("POSTGRES_PASSWORD")
		if dbPass == "" {
			dbPass = "password"
		}
		dbHost := os.Getenv("POSTGRES_HOST")
		dbURL = fmt.Sprintf("postgres://%s:%s@%s:5432/reactor", dbUser, dbPass, dbHost)
	}
	if dbURL == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("resolve home dir for sqlite audit store: %w", err)
		}
		dbURL = "sqlite://" + filepath.Join(home, ".enclave", "audit.sqlite3")
		log.Info("No DATABASE_URL provided; using local sqlite audit store: %s", strings.TrimPrefix(dbURL, "sqlite://"))
	}
	logWriter := audit.NewAsyncLogWriter(dbURL)
	ctxLog, cancelLog := context.WithCancel(context.Background())
	defer cancelLog()

	go func() {
		if err := logWriter.Start(ctxLog); err != nil {
			log.Error("LogWriter failed: %v", err)
			status.addReason("audit_log_writer_error")
		}
	}()
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctxLog.Done():
				return
			case <-ticker.C:
				connected, lastErr := logWriter.ConnectionState()
				tetraReady, tetraReason := mgr.TetragonState()
				status.setAuditPersistenceReady(connected)
				status.setPolicyEnforcementReady(tetraReady)
				status.setTelemetryReady(connected && tetraReady)
				if !connected && lastErr != "" {
					status.addReason("audit_persistence_unavailable")
				} else if connected {
					status.clearReason("audit_persistence_unavailable")
				}
				if !tetraReady {
					if tetraReason == "" {
						tetraReason = "tetragon_failed"
					}
					status.addReason(tetraReason)
				} else {
					status.clearReason("tetragon_failed")
					status.clearReason("tetragon_btf_missing")
					status.clearReason("tetragon_status_unknown")
				}
			}
		}
	}()

	prox := proxy.New(mgr, 52, logWriter)
	path, handler := agentv1connect.NewAgentServiceHandler(prox)

	// Use logging middleware and raw mux
	mux := http.NewServeMux()
	log.Info("Registering gRPC handler at %s", path)
	mux.Handle(path, handler)
	log.Info("Registering WebSocket handler at /ws/audit")
	mux.HandleFunc("/ws/audit", prox.ServeHTTP)
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		log.Info("Ping handler executed")
		fmt.Fprintf(w, "pong\n")
	})
	mux.HandleFunc("/runtime/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Type", "application/json")
		snap := status.snapshot()
		if err := json.NewEncoder(w).Encode(snap); err != nil {
			log.Error("Failed to encode runtime status: %v", err)
		}
	})

	// Summary API (Bypass Protobuf/gRPC)
	mux.HandleFunc("/api/audit/summary", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.URL.Query().Get("session_id")
		summary, err := logWriter.GetSummary(r.Context(), sessionID)
		if err != nil {
			log.Error("Failed to fetch summary: %v", err)
			http.Error(w, "Failed to fetch summary", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		// Enable CORS for development

		if err := json.NewEncoder(w).Encode(summary); err != nil {
			log.Error("Failed to encode summary: %v", err)
		}
	})

	mux.HandleFunc("/api/policy/summary", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.URL.Query().Get("session_id")
		summary, err := logWriter.GetPolicyIntentSummary(r.Context(), sessionID)
		if err != nil {
			log.Error("Failed to fetch policy summary: %v", err)
			http.Error(w, "Failed to fetch policy summary", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(summary); err != nil {
			log.Error("Failed to encode policy summary: %v", err)
		}
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Info("Catch-all handler executed for %s", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Enclave Host Online\n")
	})

	srv := &http.Server{
		Addr:    ":7339",
		Handler: loggingMiddleware(mux),
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("Proxy server failed: %v", err)
		}
	}()

	// 6. Handle Signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	log.Info("Enclave running. Press Ctrl+C to stop.")
	<-sigCh

	log.Info("Shutting down...")

	// Shutdown Server
	ctxShut, cancelShut := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShut()
	if err := srv.Shutdown(ctxShut); err != nil {
		log.Error("Failed to shutdown proxy server: %v", err)
	}

	if err := mgr.Stop(); err != nil {
		log.Error("Error during stop: %v", err)
	}
	log.Info("Goodbye.")
	return nil
}

func runImage(args []string) error {
	if len(args) == 0 {
		return errors.New("missing image subcommand (expected pull|verify|install|status)")
	}

	switch args[0] {
	case "pull":
		return runImagePull(args[1:])
	case "verify":
		return runImageVerify(args[1:])
	case "install":
		return runImageInstall(args[1:])
	case "status":
		return runImageStatus(args[1:])
	default:
		return fmt.Errorf("unsupported image subcommand %q (expected pull|verify|install|status)", args[0])
	}
}

type hubIndex struct {
	Latest hubRelease `json:"latest"`
}

type hubRelease struct {
	Tag        string            `json:"tag"`
	Artifacts  map[string]string `json:"artifacts"`
	Components map[string]string `json:"components"`
}

type summaryRow struct {
	Artifact string
	Action   string
	Size     string
	Hash     string
	Status   string
}

func runImagePull(args []string) error {
	fs := flag.NewFlagSet("image pull", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	indexURL := fs.String("index-url", "https://hub.tensorpath.ai/index.json", "Hub release index URL")
	tag := fs.String("tag", "", "Expected release tag (defaults to latest)")
	destDir := fs.String("dest-dir", "./release", "Directory for downloaded artifacts")
	verify := fs.Bool("verify", true, "Verify checksums after download when available")
	install := fs.Bool("install", false, "Install artifacts to cache after download")
	cacheDir := fs.String("cache-dir", "", "Cache directory for --install (default: ~/.enclave/cache)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	uiBanner("IMAGE PULL")
	uiStep("Loading release index", *indexURL)
	release, err := fetchHubRelease(*indexURL)
	if err != nil {
		return err
	}
	if *tag != "" && release.Tag != *tag {
		return fmt.Errorf("release tag mismatch: requested=%s latest=%s", *tag, release.Tag)
	}
	uiOK("Release tag", release.Tag)

	if err := os.MkdirAll(*destDir, 0755); err != nil {
		return err
	}
	uiStep("Destination", *destDir)

	downloaded := 0
	var totalBytes int64
	rows := make([]summaryRow, 0, 8)
	for _, name := range []string{
		"enclave_linux_amd64",
		"vmlinux_linux_amd64",
		"rootfs.cpio",
		"rootfs.cpio.gz",
		"checksums.txt",
		"build_manifest.txt",
		"attestation_predicate.json",
		"attestation_statement.json",
	} {
		rawURL := strings.TrimSpace(release.Artifacts[name])
		if rawURL == "" {
			continue
		}
		artifactURL, err := resolveArtifactURL(*indexURL, rawURL)
		if err != nil {
			return fmt.Errorf("resolve %s url: %w", name, err)
		}
		dst := filepath.Join(*destDir, name)
		var n int64
		err = withProgress("Downloading", name, func(update func(current, total int64)) error {
			var dlErr error
			n, dlErr = downloadToFile(artifactURL, dst, update)
			return dlErr
		})
		if err != nil {
			return fmt.Errorf("download %s: %w", name, err)
		}
		totalBytes += n
		rows = append(rows, summaryRow{
			Artifact: name,
			Action:   "download",
			Size:     humanBytes(n),
			Status:   "ok",
		})
		downloaded++
	}
	if downloaded == 0 {
		return fmt.Errorf("no downloadable artifact URLs found in index %s", *indexURL)
	}
	uiOK("Artifacts downloaded", fmt.Sprintf("%d files (%s)", downloaded, humanBytes(totalBytes)))

	// Now pull dynamic components
	var componentBytes int64
	compDownloaded := 0
	for compName, compRawURL := range release.Components {
		if compRawURL == "" {
			continue
		}
		// Treat components as OCI targets
		var cmpBytes int64
		err = withProgress("Pulling", compName, func(update func(current, total int64)) error {
			var pullErr error
			cmpBytes, pullErr = downloadOCI(compRawURL, *destDir, update)
			return pullErr
		})
		if err != nil {
			return fmt.Errorf("pull %s: %w", compName, err)
		}
		totalBytes += cmpBytes
		componentBytes += cmpBytes
		rows = append(rows, summaryRow{
			Artifact: compName,
			Action:   "pull",
			Size:     humanBytes(cmpBytes),
			Status:   "ok",
		})
		compDownloaded++
	}
	if compDownloaded > 0 {
		uiOK("Components pulled", fmt.Sprintf("%d files (%s)", compDownloaded, humanBytes(componentBytes)))
	}

	if *verify {
		uiStep("Verification", "checksums")
		if _, err := os.Stat(filepath.Join(*destDir, "checksums.txt")); err == nil {
			if err := runImageVerify([]string{"--bundle-dir", *destDir}); err != nil {
				return err
			}
		} else {
			uiWarn("checksums.txt not present; skipping verification")
		}
	}
	printSummaryTable("PULL SUMMARY", rows)

	if *install {
		uiStep("Install", "cache")
		installArgs := []string{"--bundle-dir", *destDir}
		if *cacheDir != "" {
			installArgs = append(installArgs, "--cache-dir", *cacheDir)
		}
		if *verify {
			installArgs = append(installArgs, "--verify=true")
		} else {
			installArgs = append(installArgs, "--verify=false")
		}
		if err := runImageInstall(installArgs); err != nil {
			return err
		}
	}
	uiDone("image pull completed")
	return nil
}

func runImageVerify(args []string) error {
	fs := flag.NewFlagSet("image verify", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	bundleDir := fs.String("bundle-dir", ".", "Path to release artifact directory")
	checksumsPath := fs.String("checksums", "", "Path to checksums.txt (default: <bundle-dir>/checksums.txt)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	uiBanner("IMAGE VERIFY")

	sumFile := *checksumsPath
	if sumFile == "" {
		sumFile = filepath.Join(*bundleDir, "checksums.txt")
	}
	entries, err := parseChecksums(sumFile)
	if err != nil {
		return err
	}

	rows := make([]summaryRow, 0, len(entries))
	for name, want := range entries {
		p := filepath.Join(*bundleDir, name)
		uiStep("Hashing", name)
		var got string
		err := withProgress("Hashing", name, func(update func(c, t int64)) error {
			var hashErr error
			got, hashErr = sha256File(p)
			return hashErr
		})
		if err != nil {
			return fmt.Errorf("verify %s: %w", name, err)
		}
		if got != want {
			return fmt.Errorf("checksum mismatch for %s: got=%s want=%s", name, got, want)
		}
		rows = append(rows, summaryRow{
			Artifact: name,
			Action:   "verify",
			Hash:     shortHash(got),
			Status:   "ok",
		})
		uiOK(name, "sha256 verified")
	}
	printSummaryTable("VERIFY SUMMARY", rows)
	uiDone(fmt.Sprintf("all checksums verified (%d files)", len(entries)))
	return nil
}

func runImageInstall(args []string) error {
	fs := flag.NewFlagSet("image install", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	bundleDir := fs.String("bundle-dir", ".", "Path to release artifact directory")
	cacheDir := fs.String("cache-dir", "", "Cache directory (default: ~/.enclave/cache)")
	verify := fs.Bool("verify", true, "Verify checksums.txt before install when present")
	if err := fs.Parse(args); err != nil {
		return err
	}
	uiBanner("IMAGE INSTALL")

	h, err := bundle.NewHydrator(*cacheDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(h.CacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache dir: %w", err)
	}
	uiStep("Cache directory", h.CacheDir)

	sumPath := filepath.Join(*bundleDir, "checksums.txt")
	if *verify {
		if _, err := os.Stat(sumPath); err == nil {
			uiStep("Verification", "checksums")
			if err := runImageVerify([]string{"--bundle-dir", *bundleDir, "--checksums", sumPath}); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	kernelSrc := pickFirstExisting(*bundleDir, "vmlinux", "vmlinux_linux_amd64", "dist/vmlinux.release")
	if kernelSrc == "" {
		return fmt.Errorf("missing kernel artifact in %s (expected vmlinux, vmlinux_linux_amd64, or dist/vmlinux.release)", *bundleDir)
	}

	rootfsSrc := pickFirstExisting(*bundleDir, "rootfs.cpio", "rootfs.cpio.gz", "dist/rootfs-base.cpio.gz", "dist/rootfs-data-science.cpio.gz")
	if rootfsSrc == "" {
		return fmt.Errorf("missing rootfs artifact in %s", *bundleDir)
	}

	kernelDst := filepath.Join(h.CacheDir, "vmlinux")
	uiStep("Installing", "vmlinux")
	if err := withProgress("Installing", "vmlinux", func(update func(c, t int64)) error {
		return copyFile(kernelSrc, kernelDst)
	}); err != nil {
		return fmt.Errorf("install kernel: %w", err)
	}
	uiOK("vmlinux", kernelDst)
	kernelHash, _ := sha256File(kernelDst)

	rootfsDst := filepath.Join(h.CacheDir, "rootfs.cpio")
	uiStep("Installing", "rootfs.cpio")
	if strings.HasSuffix(rootfsSrc, ".gz") {
		if err := withProgress("Decompressing", "rootfs.cpio.gz", func(update func(c, t int64)) error {
			return gunzipFile(rootfsSrc, rootfsDst)
		}); err != nil {
			return fmt.Errorf("install rootfs: %w", err)
		}
	} else {
		if err := withProgress("Installing", "rootfs.cpio", func(update func(c, t int64)) error {
			return copyFile(rootfsSrc, rootfsDst)
		}); err != nil {
			return fmt.Errorf("install rootfs: %w", err)
		}
	}
	uiOK("rootfs.cpio", rootfsDst)
	rootfsHash, _ := sha256File(rootfsDst)

	printSummaryTable("INSTALL SUMMARY", []summaryRow{
		{
			Artifact: "vmlinux",
			Action:   "install",
			Size:     fileSizeHuman(kernelDst),
			Hash:     shortHash(kernelHash),
			Status:   "ok",
		},
		{
			Artifact: "rootfs.cpio",
			Action:   "install",
			Size:     fileSizeHuman(rootfsDst),
			Hash:     shortHash(rootfsHash),
			Status:   "ok",
		},
	})

	uiDone("image install completed")
	return nil
}

func runImageStatus(args []string) error {
	fs := flag.NewFlagSet("image status", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	cacheDir := fs.String("cache-dir", "", "Cache directory (default: ~/.enclave/cache)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	h, err := bundle.NewHydrator(*cacheDir)
	if err != nil {
		return err
	}
	log.Info("Cache dir: %s", h.CacheDir)
	for _, name := range []string{"firecracker", "vmlinux", "rootfs.cpio"} {
		p := filepath.Join(h.CacheDir, name)
		st, err := os.Stat(p)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				log.Info("%s: missing", name)
				continue
			}
			return err
		}
		sum, err := sha256File(p)
		if err != nil {
			return err
		}
		log.Info("%s: present size=%d sha256=%s", name, st.Size(), sum)
	}
	return nil
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  enclave up [--cpu=1 --mem=2048 --socket=/tmp/enclave.sock --policy=policy.yaml --provider=auto]")
	fmt.Println("  enclave image pull [--index-url=https://hub.tensorpath.ai/index.json --dest-dir=./release --verify=true --install=false]")
	fmt.Println("  enclave image verify --bundle-dir=./release")
	fmt.Println("  enclave image install --bundle-dir=./release [--verify=true]")
	fmt.Println("  enclave image status")
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("[DEBUG] HTTP Request: %s %s from %s\n", r.Method, r.URL.Path, r.RemoteAddr)
		log.Info("HTTP Request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

func resolveProvider(raw string) (string, error) {
	p := strings.ToLower(strings.TrimSpace(raw))
	switch p {
	case "", "auto":
		if isWSL() {
			return "wsl2", nil
		}
		if os.Getenv("LIMA_INSTANCE") != "" || os.Getenv("LIMA_CIDATA") != "" {
			return "lima", nil
		}
		return "native", nil
	case "native", "lima", "wsl2":
		return p, nil
	default:
		return "", fmt.Errorf("unsupported provider %q (expected auto|native|lima|wsl2)", raw)
	}
}

func validateProviderRuntime(provider string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("enclave host runtime requires Linux (current os=%s); for macOS/Windows run enclave inside a Linux guest via Lima/WSL2", runtime.GOOS)
	}

	if _, err := os.Stat("/dev/kvm"); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("/dev/kvm is unavailable; provider=%s requires KVM passthrough", provider)
		}
		return fmt.Errorf("failed to access /dev/kvm: %w", err)
	}
	if _, err := os.Stat("/dev/vhost-vsock"); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("/dev/vhost-vsock is unavailable; provider=%s requires vsock passthrough", provider)
		}
		return fmt.Errorf("failed to access /dev/vhost-vsock: %w", err)
	}

	if provider == "lima" {
		if os.Getenv("LIMA_INSTANCE") == "" && os.Getenv("LIMA_CIDATA") == "" {
			log.Info("Provider lima selected, but Lima environment markers are not present. Continuing because this may be a manually provisioned Linux guest.")
		}
	}
	if provider == "wsl2" && !isWSL() {
		log.Info("Provider wsl2 selected, but WSL markers are not present. Continuing because this may be a non-WSL Linux guest.")
	}
	return nil
}

func isWSL() bool {
	if os.Getenv("WSL_DISTRO_NAME") != "" || os.Getenv("WSL_INTEROP") != "" {
		return true
	}
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(data)), "microsoft")
}

func parseChecksums(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open checksums: %w", err)
	}
	defer f.Close()

	out := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid checksum line: %q", line)
		}
		name := strings.TrimPrefix(parts[1], "*")
		out[name] = parts[0]
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("checksums file is empty")
	}
	return out, nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func pickFirstExisting(dir string, names ...string) string {
	for _, name := range names {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

func gunzipFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	gzr, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	defer gzr.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, gzr); err != nil {
		return err
	}
	return out.Sync()
}

func fetchHubRelease(indexURL string) (*hubRelease, error) {
	resp, err := http.Get(indexURL)
	if err != nil {
		return nil, fmt.Errorf("fetch index: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch index: status=%s", resp.Status)
	}

	var idx hubIndex
	if err := json.NewDecoder(resp.Body).Decode(&idx); err != nil {
		return nil, fmt.Errorf("decode index: %w", err)
	}
	if idx.Latest.Tag == "" && len(idx.Latest.Artifacts) == 0 {
		return nil, errors.New("index has empty latest release metadata")
	}
	return &idx.Latest, nil
}

func downloadToFile(rawURL, dst string, update func(current, total int64)) (int64, error) {
	resp, err := http.Get(rawURL)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("status=%s", resp.Status)
	}

	tmp := dst + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return 0, err
	}

	tw := &trackingWriter{
		w:      out,
		update: update,
		total:  resp.ContentLength,
	}

	n, err := io.Copy(tw, resp.Body)
	if err != nil {
		out.Close()
		return 0, err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return 0, err
	}
	if err := out.Close(); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return 0, err
	}
	return n, nil
}

func downloadOCI(rawURL, destDir string, update func(current, total int64)) (int64, error) {
	ctx := context.Background()
	ref := strings.TrimPrefix(rawURL, "oci://") // optional prefix
	repo, err := remote.NewRepository(ref)
	if err != nil {
		return 0, fmt.Errorf("create repository: %w", err)
	}
	repo.PlainHTTP = false // GHCR requires HTTPS

	store, err := file.New(destDir)
	if err != nil {
		return 0, fmt.Errorf("create file store: %w", err)
	}
	defer store.Close()

	// 1. Resolve to get manifest descriptor
	desc, err := repo.Resolve(ctx, repo.Reference.ReferenceOrDefault())
	if err != nil {
		return 0, fmt.Errorf("oras resolve: %w", err)
	}

	// 2. Extract uncompressed sizes from Manifest (we read it from the remote first to count bytes accurately)
	_, manifestBytes, err := oras.FetchBytes(ctx, repo, desc.Digest.String(), oras.DefaultFetchBytesOptions)
	if err != nil {
		return desc.Size, nil // Fallback to manifest size if we can't extract layers
	}

	var m struct {
		Config struct {
			Size int64 `json:"size"`
		} `json:"config"`
		Layers []struct {
			Size int64 `json:"size"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return desc.Size, nil
	}

	total := m.Config.Size
	for _, l := range m.Layers {
		total += l.Size
	}
	if total == 0 {
		return desc.Size, nil
	}

	ts := &TrackingStore{
		Store:  store,
		update: update,
		total:  total,
	}

	// 3. Do the actual pull with tracked stream wrapper
	_, err = oras.Copy(ctx, repo, repo.Reference.ReferenceOrDefault(), ts, repo.Reference.ReferenceOrDefault(), oras.DefaultCopyOptions)
	if err != nil {
		return 0, fmt.Errorf("oras copy: %w", err)
	}
	
	return total, nil
}

func dirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

func resolveArtifactURL(indexURL, raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.IsAbs() {
		return raw, nil
	}
	base, err := url.Parse(indexURL)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(u).String(), nil
}

func uiBanner(title string) {
	fmt.Printf("\n%s\n", paint("== "+title+" ==", "bold"))
}

func uiStep(action, detail string) {
	fmt.Printf("%s %s: %s\n", paint("[..]", "dim"), action, detail)
}

func uiOK(label, detail string) {
	fmt.Printf("%s %s: %s\n", paint("[OK]", "green"), label, detail)
}

func uiWarn(msg string) {
	fmt.Printf("%s %s\n", paint("[!!]", "yellow"), msg)
}

func uiDone(msg string) {
	fmt.Printf("%s %s\n\n", paint("[DONE]", "cyan"), msg)
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for value := n / unit; value >= unit; value /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func fileSizeHuman(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		return "-"
	}
	return humanBytes(st.Size())
}

func withProgress(action, name string, fn func(update func(current, total int64)) error) error {
	if !uiSpinnerEnabled {
		return fn(func(c, t int64) {})
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)

	var currentBytes atomic.Int64
	var totalBytes atomic.Int64
	startTime := time.Now()

	updateFn := func(current, total int64) {
		currentBytes.Store(current)
		if total > 0 {
			totalBytes.Store(total)
		}
	}

	ticker := time.NewTicker(100 * time.Millisecond)

	go func() {
		defer wg.Done()
		defer ticker.Stop()
		frames := []string{"|", "/", "-", "\\"}
		i := 0
		for {
			select {
			case <-done:
				fmt.Print("\r\033[K")
				return
			case <-ticker.C:
				frame := frames[i%len(frames)]
				i++
				cur := currentBytes.Load()
				tot := totalBytes.Load()
				elapsed := time.Since(startTime).Seconds()
				rate := 0.0
				if elapsed > 0 {
					rate = float64(cur) / elapsed
				}

				if tot > 0 {
					fmt.Printf("\r\033[K%s %s: %s (%s / %s | %s/s)", paint(frame, "cyan"), action, paint(name, "bold"), humanBytes(cur), humanBytes(tot), humanBytes(int64(rate)))
				} else if cur > 0 {
					fmt.Printf("\r\033[K%s %s: %s (%s | %s/s)", paint(frame, "cyan"), action, paint(name, "bold"), humanBytes(cur), humanBytes(int64(rate)))
				} else {
					fmt.Printf("\r\033[K%s %s: %s", paint(frame, "cyan"), action, paint(name, "bold"))
				}
			}
		}
	}()

	err := fn(updateFn)
	close(done)
	wg.Wait()
	return err
}

type trackingWriter struct {
	w      io.Writer
	update func(current, total int64)
	total  int64
	cur    int64
}

func (tw *trackingWriter) Write(p []byte) (int, error) {
	n, err := tw.w.Write(p)
	tw.cur += int64(n)
	if tw.update != nil {
		tw.update(tw.cur, tw.total)
	}
	return n, err
}

type TrackingStore struct {
	*file.Store
	update func(current, total int64)
	total  int64
	cur    int64
}

func (s *TrackingStore) Push(ctx context.Context, expected ocispec.Descriptor, content io.Reader) error {
	tr := &trackingReader{
		r:      content,
		update: s.update,
		total:  s.total,
		cur:    &s.cur,
	}
	return s.Store.Push(ctx, expected, tr)
}

type trackingReader struct {
	r      io.Reader
	update func(current, total int64)
	total  int64
	cur    *int64
}

func (tr *trackingReader) Read(p []byte) (n int, err error) {
	n, err = tr.r.Read(p)
	if n > 0 {
		*tr.cur += int64(n)
		if tr.update != nil {
			tr.update(*tr.cur, tr.total)
		}
	}
	return
}

func detectColorTTY() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") == "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func detectSpinnerTTY() bool {
	if !uiColorEnabled {
		return false
	}
	if os.Getenv("CI") != "" {
		return false
	}
	return true
}

func paint(s, style string) string {
	if !uiColorEnabled {
		return s
	}
	switch style {
	case "bold":
		return "\033[1m" + s + "\033[0m"
	case "green":
		return "\033[32m" + s + "\033[0m"
	case "yellow":
		return "\033[33m" + s + "\033[0m"
	case "cyan":
		return "\033[36m" + s + "\033[0m"
	case "dim":
		return "\033[2m" + s + "\033[0m"
	default:
		return s
	}
}

func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}

func printSummaryTable(title string, rows []summaryRow) {
	if len(rows) == 0 {
		return
	}
	aw, cw, sw, hw, tw := len("artifact"), len("action"), len("size"), len("hash"), len("status")
	for _, r := range rows {
		if len(r.Artifact) > aw {
			aw = len(r.Artifact)
		}
		if len(r.Action) > cw {
			cw = len(r.Action)
		}
		if len(r.Size) > sw {
			sw = len(r.Size)
		}
		if len(r.Hash) > hw {
			hw = len(r.Hash)
		}
		if len(r.Status) > tw {
			tw = len(r.Status)
		}
	}

	fmt.Printf("%s\n", paint(title, "bold"))
	fmt.Printf("  %-*s  %-*s  %-*s  %-*s  %-*s\n", aw, "artifact", cw, "action", sw, "size", hw, "hash", tw, "status")
	for _, r := range rows {
		status := r.Status
		if status == "ok" {
			status = paint(status, "green")
		}
		fmt.Printf("  %-*s  %-*s  %-*s  %-*s  %-*s\n", aw, r.Artifact, cw, r.Action, sw, r.Size, hw, r.Hash, tw, status)
	}
	fmt.Println()
}
