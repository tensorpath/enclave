package bundle

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// Hydrator manages the runtime assets (kernel, rootfs, firecracker).
// In the "Thin Client" model, these are downloaded on demand or verified in the cache.
type Hydrator struct {
	CacheDir string
}

// NewHydrator creates a new Hydrator using the specified cache directory.
// If cacheDir is empty, it defaults to ~/.enclave/cache.
func NewHydrator(cacheDir string) (*Hydrator, error) {
	if cacheDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home dir: %w", err)
		}
		cacheDir = filepath.Join(home, ".enclave", "cache")
	}
	return &Hydrator{CacheDir: cacheDir}, nil
}

// EnsureAssets verifies that the required assets exist in the cache directory.
// It downloads missing standard components (Firecracker) and reports error for missing custom components.
func (h *Hydrator) EnsureAssets() error {
	if err := os.MkdirAll(h.CacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache dir: %w", err)
	}

	// 1. Firecracker (Public Download)
	if err := h.ensureFirecracker(); err != nil {
		return fmt.Errorf("failed to ensure firecracker: %w", err)
	}

	// 2. Kernel & Rootfs (Proprietary/Custom)
	// For now, we check existence. In the future, this would download from our private S3 bucket.
	required := []string{"vmlinux", "rootfs.cpio"}
	for _, name := range required {
		path := filepath.Join(h.CacheDir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return fmt.Errorf("missing asset %s: please install to %s or provide download URL", name, h.CacheDir)
		}
	}

	return nil
}

func (h *Hydrator) ensureFirecracker() error {
	const fcVersion = "v1.14.1"
	
	// Determine Architecture
	arch := runtime.GOARCH
	var fcArch string
	switch arch {
	case "amd64":
		fcArch = "x86_64"
	case "arm64":
		fcArch = "aarch64"
	default:
		return fmt.Errorf("unsupported architecture: %s", arch)
	}

	binName := "firecracker"
	destPath := filepath.Join(h.CacheDir, binName)

	// Check existence
	if _, err := os.Stat(destPath); err == nil {
		return nil // Already exists
	}

	// Download
	url := fmt.Sprintf("https://github.com/firecracker-microvm/firecracker/releases/download/%s/firecracker-%s-%s.tgz", fcVersion, fcVersion, fcArch)
	fmt.Printf("Downloading Firecracker %s (%s)...\n", fcVersion, fcArch)

	// Since it's a tarball, we need to download and extract.
	// For simplicity, let's stream it to a temp file then untar.
	// Or, to keep this code simple and strictly relying on 'tar' existing (linux):
	// actually, 'go' should handle it, but implementing a tar reader is verbose.
	// WE WILL USE A SIMPLER TRICK: Firecracker releases provide the binary inside the tar.
	// Let's defer to a helper or just execute 'curl | tar' if we are lazy, BUT we want pure Go if possible.
	// However, usually `tar` is present. Let's try to stick to pure Go logic for the download, 
	// but maybe relying on system `tar` is acceptable for this stage or we can implement a `untar` helper.
	// Let's assume system tar for MVP to save code lines, or implementing a quick untar.
	
	// Wait, the user specifically shared the release tag. 
	// The release assets are: firecracker-v1.14.1-x86_64.tgz
	// Inside is: release-v1.14.1-x86_64/firecracker-v1.14.1-x86_64
	
	// Let's implement a download + untar via shell invocation for robust simplicity in this environment,
	// OR do a quick download to file and simple native untar.
	// Going with 'download to temp file + tar -xf' via os/exec is safest/shortest.
	
	tmpTar := filepath.Join(h.CacheDir, "fc.tgz")
	if err := downloadFile(url, tmpTar); err != nil {
		return err
	}
	defer os.Remove(tmpTar)

	// Untar
	// We want to extract specifically the firecracker binary and rename it.
	// Tar content path: release-v1.14.1-{arch}/firecracker-v1.14.1-{arch}
	// internalPath := fmt.Sprintf("release-%s-%s/firecracker-%s-%s", fcVersion, fcArch, fcVersion, fcArch)
	
	// We'll use `tar -xzf FILE -O INTERNAL_PATH > OUT_FILE` to stream extraction
	// But standard tar might not support -O for renaming easily without shell redirection.
	
	// Let's just extract all, find the binary, move it, clean up.
	if err := runCmd(h.CacheDir, "tar", "-xzf", tmpTar, "--no-same-owner"); err != nil {
		return fmt.Errorf("failed to untar: %w", err)
	}
	
	extractedDir := filepath.Join(h.CacheDir, fmt.Sprintf("release-%s-%s", fcVersion, fcArch))
	defer os.RemoveAll(extractedDir)
	
	srcBin := filepath.Join(extractedDir, fmt.Sprintf("firecracker-%s-%s", fcVersion, fcArch))
	if err := os.Rename(srcBin, destPath); err != nil {
		return fmt.Errorf("failed to move binary: %w", err)
	}
	
	// Chmod
	return os.Chmod(destPath, 0755)
}

func downloadFile(url, filepath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func runCmd(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	// Capture output for debugging in case of failure? or just inherit?
	// Inherit is useful for "tar" verbose output if enabled, but let's keep it quiet unless error.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// GetPath returns the absolute path to a cached asset.
func (h *Hydrator) GetPath(name string) string {
	return filepath.Join(h.CacheDir, name)
}
