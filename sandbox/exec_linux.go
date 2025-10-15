//go:build linux

package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

// Linux-specific types for bubblewrap mount handling
type mount struct {
	flag   string
	source string
	target string
}

// commandContext implements Linux sandboxing using bubblewrap.
func (p *Policy) commandContext(ctx context.Context, name string, arg ...string) (*exec.Cmd, error) {
	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, fmt.Errorf("sandbox: bwrap not found: %w", err)
	}

	// Build full argv (name + args)
	argv := append([]string{name}, arg...)

	// Get current environment (caller can override cmd.Env later)
	envv := os.Environ()

	// Generate bubblewrap arguments
	bwrapArgs, err := bubblewrapArgs(p, name, argv, envv)
	if err != nil {
		return nil, fmt.Errorf("sandbox: build bubblewrap args: %w", err)
	}

	// Create command: bwrap <bwrap-args> -- <command> <args>
	// bwrapArgs[0] is bwrapPath itself, skip it for exec.CommandContext
	cmd := exec.CommandContext(ctx, bwrapPath, bwrapArgs[1:]...)
	cmd.Env = envv

	return cmd, nil
}

// bubblewrapArgs builds the argument list for bwrap.
// Returns the full argv including bwrapPath at [0].
func bubblewrapArgs(policy *Policy, name string, argv, envv []string) ([]string, error) {
	// Use Policy.WorkDir if specified, otherwise current directory
	wd := policy.WorkDir
	if wd == "" {
		var err error
		wd, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("getwd: %w", err)
		}
	}

	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, fmt.Errorf("lookpath bwrap: %w", err)
	}

	args := []string{bwrapPath}
	seen := newMountSet()

	// Mount read-only paths from policy (with canonicalization)
	for _, m := range policy.ReadOnlyMounts {
		canonSrc, err := canonicalPath(m.Source)
		if err != nil {
			return nil, fmt.Errorf("canonicalize readonly mount %s: %w", m.Source, err)
		}
		canonTgt, err := canonicalPath(m.Target)
		if err != nil {
			return nil, fmt.Errorf("canonicalize readonly target %s: %w", m.Target, err)
		}
		args, err = appendMount(args, seen, mount{flag: "--ro-bind", source: canonSrc, target: canonTgt})
		if err != nil {
			return nil, err
		}
	}

	// Mount read-write paths from policy (with canonicalization)
	for _, m := range policy.ReadWriteMounts {
		canonSrc, err := canonicalPath(m.Source)
		if err != nil {
			return nil, fmt.Errorf("canonicalize readwrite mount %s: %w", m.Source, err)
		}
		canonTgt, err := canonicalPath(m.Target)
		if err != nil {
			return nil, fmt.Errorf("canonicalize readwrite target %s: %w", m.Target, err)
		}
		args, err = appendMount(args, seen, mount{flag: "--bind", source: canonSrc, target: canonTgt})
		if err != nil {
			return nil, err
		}
	}

	// Essential virtual filesystems (always required for process execution)
	args = append(args,
		"--proc", "/proc",
		"--dev", "/dev",
	)

	// Temp directory (isolated tmpfs if requested)
	if policy.ProvideTmp {
		args = append(args, "--tmpfs", "/tmp")
	}

	// On modern Linux systems, /bin, /lib, /lib64, and /sbin are symlinks to /usr subdirectories.
	// We need to recreate these symlinks in the sandbox for executables and libraries to be found.
	commonSymlinks := []struct {
		link   string
		target string
	}{
		{"/bin", "usr/bin"},
		{"/lib", "usr/lib"},
		{"/lib64", "usr/lib64"},
		{"/sbin", "usr/sbin"},
	}
	for _, sl := range commonSymlinks {
		if info, err := os.Lstat(sl.link); err == nil && info.Mode()&os.ModeSymlink != 0 {
			args = append(args, "--symlink", sl.target, sl.link)
		}
	}

	// Network and namespace isolation
	if !policy.AllowSharedNamespaces {
		// Unshare all namespaces (network, IPC, PID, UTS, cgroup)
		args = append(args, "--unshare-all")
	} else if !policy.AllowNetwork {
		// Shared namespaces allowed, but network specifically blocked
		args = append(args, "--unshare-net")
	}
	// else: both shared namespaces and network allowed - no unsharing

	// Process lifecycle control
	if !policy.AllowParentSurvival {
		args = append(args, "--die-with-parent")
	}
	if !policy.AllowSessionControl {
		args = append(args, "--new-session")
	}

	// Mount working directory as read-write (with canonicalization)
	workdir, err := canonicalPath(wd)
	if err != nil {
		return nil, fmt.Errorf("canonicalize working directory: %w", err)
	}
	args, err = appendMount(args, seen, mount{flag: "--bind", source: workdir, target: workdir})
	if err != nil {
		return nil, fmt.Errorf("bind working directory: %w", err)
	}
	args = append(args, "--chdir", workdir)

	// Append the separator and the actual command + arguments
	args = append(args, "--")
	args = append(args, argv...)

	return args, nil
}

// appendMount adds a mount entry to the bubblewrap args if not already present.
func appendMount(args []string, seen *mountSet, entry mount) ([]string, error) {
	if entry.source == "" || entry.target == "" {
		return nil, fmt.Errorf("sandbox: mount requires non-empty paths")
	}

	if seen.has(entry.flag, entry.target) {
		return args, nil
	}

	if err := ensurePath(entry.source); err != nil {
		return nil, fmt.Errorf("sandbox: stat %s: %w", entry.source, err)
	}

	seen.add(entry.flag, entry.target)
	args = append(args, entry.flag, entry.source, entry.target)
	return args, nil
}

// ensurePath verifies that a path exists.
func ensurePath(path string) error {
	if path == "" {
		return fmt.Errorf("sandbox: empty path")
	}
	if _, err := os.Stat(path); err != nil {
		return err
	}
	return nil
}
