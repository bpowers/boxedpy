// Package boxedpy provides a Python sandboxing abstraction for secure execution
// of Python code in virtualenv environments. It wraps the sandbox package with
// Python-specific configuration and environment setup.
//
// Basic usage:
//
//	py, err := boxedpy.New(boxedpy.Config{
//	    VirtualEnv: "/path/to/venv",
//	    ReferenceDir: "/path/to/datasets/dir",
//	})
//	if err != nil {
//	    return err
//	}
//
//	policy := sandbox.DefaultPolicy()
//	policy.WorkDir = "/path/to/workdir"
//	cmd, err := py.Command(ctx, policy, boxedpy.ExecConfig{}, "-c", "print('hello')")
//	if err != nil {
//	    return err
//	}
//	output, err := cmd.CombinedOutput()
package boxedpy

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Python represents a configured Python virtualenv for sandboxed execution.
// It encapsulates the Python interpreter path, virtualenv location, optional
// project directory for data access, and configuration directory for Python
// library configs (matplotlib, jupyter, etc.).
//
// Python instances are safe for concurrent use - all fields are immutable after
// construction, and cleanup is protected by cleanupOnce.
//
// Call Close() when done to clean up auto-created temporary directories.
// For singleton instances that live for the process lifetime, Close() is
// optional - the OS will clean up temp directories on reboot.
type Python struct {
	venvRoot      string    // absolute path to virtualenv root
	referenceDir  string    // optional projects directory path
	configDir     string    // config directory for matplotlib, jupyter, etc.
	ownsConfigDir bool      // true if configDir was auto-created and should be cleaned up
	cleanupOnce   sync.Once // ensures cleanup happens at most once
}

// Config configures Python virtualenv discovery.
type Config struct {
	// VirtualEnv is the virtualenv root path.
	// Required. The Python interpreter at <VirtualEnv>/bin/python will be used.
	VirtualEnv string

	// ReferenceDir is mounted read-only for data access.
	// Optional. If empty, not mounted.
	ReferenceDir string

	// ConfigDir for Python library configs (matplotlib, jupyter, etc.).
	// Optional. If empty, a temporary directory is created in the system temp location.
	// Auto-created config directories are not explicitly cleaned up - they rely on periodic
	// OS temp directory cleanup (which is acceptable for config caches).
	// Mounted read-write.
	ConfigDir string
}

// New creates a Python environment from a virtualenv.
// Validates that <cfg.VirtualEnv>/bin/python exists.
// Returns an error if the virtualenv is invalid or the Python interpreter is not found.
func New(cfg Config) (*Python, error) {
	if cfg.VirtualEnv == "" {
		return nil, fmt.Errorf("VirtualEnv is required")
	}

	// Validate that the virtualenv exists and is a directory
	venvInfo, err := os.Stat(cfg.VirtualEnv)
	if err != nil {
		return nil, fmt.Errorf("virtualenv at %s: %w", cfg.VirtualEnv, err)
	}
	if !venvInfo.IsDir() {
		return nil, fmt.Errorf("virtualenv at %s is not a directory", cfg.VirtualEnv)
	}

	// Convert to absolute path
	venvRoot, err := filepath.Abs(cfg.VirtualEnv)
	if err != nil {
		return nil, fmt.Errorf("resolve virtualenv path: %w", err)
	}

	// Validate that the Python interpreter exists
	pythonPath := filepath.Join(venvRoot, "bin", "python")
	if _, err := os.Stat(pythonPath); err != nil {
		return nil, fmt.Errorf("python interpreter not found at %s: %w", pythonPath, err)
	}

	// If ReferenceDir is specified, validate it exists
	var referenceDir string
	if cfg.ReferenceDir != "" {
		projInfo, err := os.Stat(cfg.ReferenceDir)
		if err != nil {
			return nil, fmt.Errorf("projects directory at %s: %w", cfg.ReferenceDir, err)
		}
		if !projInfo.IsDir() {
			return nil, fmt.Errorf("projects directory at %s is not a directory", cfg.ReferenceDir)
		}

		referenceDir, err = filepath.Abs(cfg.ReferenceDir)
		if err != nil {
			return nil, fmt.Errorf("resolve projects directory path: %w", err)
		}
	}

	// Handle ConfigDir - create temp directory if not specified
	var configDir string
	var ownsConfigDir bool

	if cfg.ConfigDir == "" {
		tmpDir, err := os.MkdirTemp("", "boxedpy_config_*")
		if err != nil {
			return nil, fmt.Errorf("create config directory: %w", err)
		}
		configDir = tmpDir
		ownsConfigDir = true
	} else {
		// Validate that the specified ConfigDir exists
		info, err := os.Stat(cfg.ConfigDir)
		if err != nil {
			return nil, fmt.Errorf("config directory at %s: %w", cfg.ConfigDir, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("config directory at %s is not a directory", cfg.ConfigDir)
		}

		// Convert to absolute path
		configDir, err = filepath.Abs(cfg.ConfigDir)
		if err != nil {
			return nil, fmt.Errorf("resolve config directory path: %w", err)
		}
		ownsConfigDir = false
	}

	py := &Python{
		venvRoot:      venvRoot,
		referenceDir:  referenceDir,
		configDir:     configDir,
		ownsConfigDir: ownsConfigDir,
	}

	return py, nil
}

// InterpreterPath returns <venv>/bin/python.
func (p *Python) InterpreterPath() string {
	if p == nil {
		return ""
	}
	return filepath.Join(p.venvRoot, "bin", "python")
}

// VirtualEnvPath returns the virtualenv root path.
func (p *Python) VirtualEnvPath() string {
	if p == nil {
		return ""
	}
	return p.venvRoot
}

// ProjectsDir returns the projects directory path (may be empty).
func (p *Python) ProjectsDir() string {
	if p == nil {
		return ""
	}
	return p.referenceDir
}

// ConfigDir returns the config directory path for Python library configs.
func (p *Python) ConfigDir() string {
	if p == nil {
		return ""
	}
	return p.configDir
}

// Close removes the auto-created config directory if one was created.
// It's safe to call Close() multiple times - subsequent calls are no-ops.
// User-provided config directories are never removed.
//
// IMPORTANT: Close() should not be called while the Python instance is still
// in use by concurrent operations. The Python instance remains safe for concurrent
// use after Close(), but the config directory will no longer exist on disk.
func (p *Python) Close() error {
	if p == nil {
		return nil
	}
	return p.cleanup()
}

// cleanup removes the config directory if we own it.
// Uses sync.Once to ensure cleanup happens at most once, even if called concurrently.
func (p *Python) cleanup() error {
	if p == nil || !p.ownsConfigDir || p.configDir == "" {
		return nil
	}

	var cleanupErr error
	p.cleanupOnce.Do(func() {
		cleanupErr = os.RemoveAll(p.configDir)
	})
	return cleanupErr
}
