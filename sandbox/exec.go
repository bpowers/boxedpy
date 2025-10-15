// Package sandbox provides secure command execution by spawning child processes
// in isolated sandboxes. It does NOT use syscall.Exec (which would replace the
// current process), making it safe to use from long-running servers like HTTP handlers.
//
// Platform support:
//   - Linux: Uses bubblewrap (bwrap) with namespace isolation
//   - macOS: Uses Seatbelt (/usr/bin/sandbox-exec) with mandatory access control
//
// Security model:
//
// By default (zero-value Policy), the sandbox provides maximum isolation:
//   - No filesystem access (commands will fail to execute)
//   - Network is blocked
//   - No /tmp directory
//   - Linux: All namespaces are unshared
//   - Linux: Child processes die when the parent exits
//
// DefaultPolicy() provides a minimal baseline:
//   - System directories mounted read-only (/usr, /bin, /System, etc.)
//   - Working directory mounted read-write
//   - Isolated /tmp directory
//   - Network blocked by default
//
// Application-specific paths must be explicitly mounted by the caller.
//
// Usage examples:
//
// Example 1: Run a simple system command
//
//	policy := sandbox.DefaultPolicy()
//	cmd, err := policy.Command(context.Background(), "echo", "hello world")
//	if err != nil {
//	    return err
//	}
//	output, err := cmd.CombinedOutput()
//
// Example 2: Python with Homebrew (macOS) or system packages
//
//	policy := sandbox.DefaultPolicy()
//	// Add Homebrew paths on macOS
//	if _, err := os.Stat("/opt"); err == nil {
//	    policy.ReadOnlyMounts = append(policy.ReadOnlyMounts,
//	        sandbox.Mount{Source: "/opt", Target: "/opt"})
//	}
//	cmd, err := policy.Command(ctx, "python3", "-c", "print('Hello from Python')")
//
// Example 3: Python virtualenv with data processing
//
//	policy := sandbox.DefaultPolicy()
//	// Mount Python installation
//	policy.ReadOnlyMounts = append(policy.ReadOnlyMounts,
//	    sandbox.Mount{Source: "/opt", Target: "/opt"})  // Homebrew Python
//	// Mount virtualenv for packages (read-write for pip installs)
//	policy.ReadWriteMounts = append(policy.ReadWriteMounts,
//	    sandbox.Mount{Source: "/path/to/venv", Target: "/path/to/venv"})
//	// Mount data directory
//	policy.ReadWriteMounts = append(policy.ReadWriteMounts,
//	    sandbox.Mount{Source: "./projects/data", Target: "./projects/data"})
//
//	cmd, err := policy.Command(ctx, "/path/to/venv/bin/python", "analyze.py")
//
// Example 4: Localhost-only network (recommended for Jupyter/IPC)
//
//	policy := sandbox.DefaultPolicy()
//	policy.AllowLocalhostOnly = true  // Allows localhost, blocks internet
//	cmd, err := policy.Command(ctx, "jupyter", "nbconvert", "--execute", "notebook.ipynb")
//
// Example 5: Full network access (use sparingly)
//
//	policy := sandbox.DefaultPolicy()
//	policy.AllowNetwork = true  // Allows ALL network including internet
//	cmd, err := policy.Command(ctx, "curl", "https://api.example.com")
//
// Example 6: Concurrent usage in HTTP handler
//
//	// Create policy once, reuse across requests
//	var pythonPolicy = func() *sandbox.Policy {
//	    p := sandbox.DefaultPolicy()
//	    p.ReadOnlyMounts = append(p.ReadOnlyMounts,
//	        sandbox.Mount{Source: "/opt", Target: "/opt"})
//	    return p
//	}()
//
//	func handler(w http.ResponseWriter, r *http.Request) {
//	    // Safe to reuse pythonPolicy across concurrent requests
//	    cmd, err := pythonPolicy.Command(r.Context(), "python3", "-c", "print('hello')")
//	    if err != nil {
//	        http.Error(w, err.Error(), 500)
//	        return
//	    }
//	    output, _ := cmd.CombinedOutput()
//	    w.Write(output)
//	}
package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Command returns an *exec.Cmd configured to run the specified command
// inside a sandbox according to the Policy. The returned Cmd has not been started.
// The caller can configure Stdin, Stdout, Stderr and call Start(), Run(), or
// Output() as needed.
//
// The context is used for timeout and cancellation of the sandboxed process.
//
// Example (HTTP handler with timeout):
//
//	policy := sandbox.DefaultPolicy()
//	cmd, err := policy.Command(r.Context(), "python", "script.py")
//	if err != nil {
//	    return err
//	}
//	output, err := cmd.CombinedOutput()
//	w.Write(output)
func (p *Policy) Command(ctx context.Context, name string, arg ...string) (*exec.Cmd, error) {
	if p == nil {
		return nil, fmt.Errorf("sandbox: policy must not be nil")
	}
	if name == "" {
		return nil, fmt.Errorf("sandbox: command name must not be empty")
	}

	// Platform-specific implementations in exec_linux.go and exec_darwin.go
	return p.commandContext(ctx, name, arg...)
}

// Exec executes the command inside a sandbox and waits for completion.
// Stdin, stdout, stderr are inherited from the current process.
// This is a convenience wrapper for Command().Run().
func (p *Policy) Exec(ctx context.Context, name string, arg ...string) error {
	cmd, err := p.Command(ctx, name, arg...)
	if err != nil {
		return err
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// mountSet tracks mounted paths to prevent duplicates and check coverage.
// Used by both platform-specific implementations.
type mountSet struct {
	entries map[string]struct{}
	targets []string
}

func newMountSet() *mountSet {
	return &mountSet{entries: make(map[string]struct{})}
}

func (m *mountSet) key(flag, target string) string {
	return flag + "\x00" + target
}

func (m *mountSet) has(flag, target string) bool {
	if m == nil {
		return false
	}
	_, ok := m.entries[m.key(flag, target)]
	return ok
}

func (m *mountSet) add(flag, target string) {
	key := m.key(flag, target)
	if _, ok := m.entries[key]; ok {
		return
	}
	m.entries[key] = struct{}{}
	m.targets = append(m.targets, target)
}

// canonicalPath resolves a path to its canonical form by evaluating all symlinks.
// This ensures sandbox path matching works correctly on systems with symlinks:
// - macOS: /var -> /private/var, /etc -> /private/etc
// - Linux: /bin -> /usr/bin, /lib -> /usr/lib (on modern distros)
//
// We canonicalize paths when building sandbox policies to ensure the policy's
// path parameters match the actual filesystem paths the sandboxed process will use.
// For example, if a process writes to /private/var/tmp/foo but the policy only
// allows /var, the write would be denied without canonicalization.
//
// This is safe because canonicalization happens in the trusted parent process
// before sandboxing, using paths from the Policy struct (which is under our control).
func canonicalPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty path")
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("canonicalize %s: %w", path, err)
	}
	return canonical, nil
}
