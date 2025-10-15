package boxedpy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/bpowers/boxedpy/sandbox"
)

// ExecConfig contains Python-specific execution configuration.
// Currently empty but reserved for future per-execution settings.
type ExecConfig struct{}

// Command creates a sandboxed exec.Cmd for running Python.
// The policy parameter is augmented with Python-specific mounts:
// - Virtualenv (read-only)
// - ProjectsDir (read-only, if configured)
// - ConfigDir (read-write, from Python instance)
// - Homebrew paths on macOS: /opt, /usr/local (read-only, if they exist)
//
// The policy's WorkDir, ReadOnlyMounts, ReadWriteMounts, Network settings, etc.
// are respected and used as the base configuration.
//
// IMPORTANT: On macOS, this function ALWAYS mounts Homebrew directories (/opt and /usr/local)
// if they exist. This is required for Python to access its dependencies installed via Homebrew.
// These mounts are read-only and do not grant write access to system directories.
//
// Example:
//
//	policy := sandbox.DefaultPolicy()
//	policy.WorkDir = "/path/to/workdir"
//	policy.AllowLocalhostOnly = true
//	cmd, err := py.Command(ctx, policy, ExecConfig{}, "-c", "print('hello')")
func (p *Python) Command(ctx context.Context, policy *sandbox.Policy, cfg ExecConfig, args ...string) (*exec.Cmd, error) {
	if p == nil {
		return nil, fmt.Errorf("Python instance is nil")
	}
	if policy == nil {
		return nil, fmt.Errorf("policy must not be nil")
	}

	// Create a deep copy of the policy to avoid modifying the caller's policy.
	// Shallow copy would share underlying slice arrays, causing data races.
	policyCopy := *policy
	policyCopy.ReadOnlyMounts = append([]sandbox.Mount(nil), policy.ReadOnlyMounts...)
	policyCopy.ReadWriteMounts = append([]sandbox.Mount(nil), policy.ReadWriteMounts...)
	policy = &policyCopy

	// Mount the virtualenv (read-only)
	policy.ReadOnlyMounts = append(policy.ReadOnlyMounts,
		sandbox.Mount{Source: p.venvRoot, Target: p.venvRoot},
	)

	// Mount the projects directory if configured (read-only)
	if p.referenceDir != "" {
		policy.ReadOnlyMounts = append(policy.ReadOnlyMounts,
			sandbox.Mount{Source: p.referenceDir, Target: p.referenceDir},
		)
	}

	// Mount the config directory (read-write, from Python instance)
	policy.ReadWriteMounts = append(policy.ReadWriteMounts,
		sandbox.Mount{Source: p.configDir, Target: p.configDir},
	)

	// On macOS, mount Homebrew paths if they exist
	if runtime.GOOS == "darwin" {
		homebrewPaths := []string{"/opt", "/usr/local"}
		for _, path := range homebrewPaths {
			if info, err := os.Stat(path); err == nil && info.IsDir() {
				policy.ReadOnlyMounts = append(policy.ReadOnlyMounts,
					sandbox.Mount{Source: path, Target: path},
				)
			}
		}
	}

	// Create the sandboxed command
	pythonPath := p.InterpreterPath()
	return policy.Command(ctx, pythonPath, args...)
}
