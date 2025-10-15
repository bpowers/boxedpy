package sandbox

import (
	"os"
	"runtime"
)

// Policy defines the security boundaries for sandboxed command execution via bubblewrap.
// The zero value provides maximum security isolation: no mounts, all namespaces unshared,
// child dies with parent, and new session created.
//
// Security model:
//   - All processes run in isolated namespaces (network, IPC, PID, etc.) by default
//   - Only explicitly mounted paths are accessible inside the sandbox
//   - Read-only mounts prevent modification of system files
//   - Read-write mounts should be limited to working directories and necessary user data
//   - Child processes are terminated when the parent exits
//   - Processes cannot control the parent's terminal session
//
// To create a usable sandbox, at minimum add read-only system mounts and the working directory
// as a read-write mount. See DefaultPolicy() for a reasonable starting configuration.
//
// Concurrency: Policy instances are safe to reuse across concurrent calls to Command().
// The Command() method creates a deep copy of mount slices to prevent data races.
// This makes Policy ideal for use in HTTP handlers and other concurrent contexts where
// the same sandbox configuration is reused across multiple requests.
type Policy struct {
	// ReadOnlyMounts are mounted read-only inside the sandbox (e.g., /usr, /bin, /lib).
	// These allow the sandboxed process to execute system binaries and load libraries.
	ReadOnlyMounts []Mount

	// ReadWriteMounts are mounted read-write inside the sandbox (e.g., working directory).
	// Limit these to only what the sandboxed process needs to write.
	ReadWriteMounts []Mount

	// WorkDir specifies the working directory for the sandboxed command.
	// If empty, defaults to the current working directory (os.Getwd()).
	//
	// IMPORTANT: The working directory is automatically mounted read-write inside the sandbox.
	// You do NOT need to add it to ReadWriteMounts manually. The sandbox implementation
	// ensures WorkDir is accessible and sets it as the initial directory via --chdir (Linux)
	// or cmd.Dir (macOS).
	//
	// This design allows specifying the working directory without using os.Chdir(), which is
	// forbidden in library code as it affects global process state.
	WorkDir string

	// ProvideTmp controls whether /tmp is available inside the sandbox (default false = no /tmp).
	// - Linux: Creates isolated tmpfs mounted at /tmp (private to this sandbox, auto-cleaned on exit)
	// - macOS: Creates temporary directory on host and mounts it at /tmp inside sandbox.
	//   The temp directory is cleaned up via runtime.SetFinalizer when the *exec.Cmd is garbage
	//   collected. This is best-effort cleanup - finalizers are not guaranteed to run, but
	//   acceptable for temp directories in /tmp. Callers must hold the Cmd reference until
	//   after Wait() completes to ensure the temp directory exists during command execution.
	//   For explicit cleanup control, create your own temp directory and mount it with
	//   ReadWriteMounts instead of using ProvideTmp.
	ProvideTmp bool

	// AllowNetwork controls network access (default false = blocked).
	// - Linux: When false, --unshare-net isolates the network namespace
	// - macOS: When false, network-outbound/inbound Seatbelt rules are omitted
	//
	// Important: On macOS, AllowNetwork=true allows ALL network access including internet.
	// For localhost-only access (e.g., for Jupyter kernels), use AllowLocalhostOnly=true instead.
	AllowNetwork bool

	// AllowLocalhostOnly controls localhost-only network access (default false = blocked).
	// This is a safer alternative to AllowNetwork for applications that need IPC via TCP sockets
	// on localhost (127.0.0.1, ::1) but should not access external networks.
	//
	// - macOS: When true, Seatbelt rules allow network-outbound/inbound only for localhost
	// - Linux: When true, behaves the same as AllowNetwork=false (namespace isolation)
	//         Note: On Linux, localhost communication works even with network namespace isolation,
	//         so this flag has no additional effect beyond AllowNetwork=false.
	//
	// Typical use case: Jupyter notebook execution (kernel communication via localhost TCP)
	//
	// Security: This is the recommended setting for running untrusted code that needs IPC,
	// as it prevents the sandboxed process from accessing external internet while still
	// allowing local inter-process communication via TCP sockets.
	//
	// Note: If both AllowNetwork and AllowLocalhostOnly are true, AllowNetwork takes precedence
	// (full network access is granted).
	AllowLocalhostOnly bool

	// The following fields are Linux-specific and ignored on macOS:

	// AllowSharedNamespaces, when true, disables namespace isolation (skips --unshare-all).
	// The default (false) creates isolated namespaces for network, IPC, PID, etc.
	// Only set to true if the sandboxed process must communicate with the host system.
	// Ignored on macOS (Seatbelt doesn't use Linux namespaces).
	AllowSharedNamespaces bool

	// AllowParentSurvival, when true, allows the sandboxed process to outlive its parent
	// (skips --die-with-parent). The default (false) ensures child processes are cleaned up.
	// Only set to true if you need the sandbox to persist after the parent exits.
	// Ignored on macOS (Seatbelt doesn't have this concept).
	AllowParentSurvival bool

	// AllowSessionControl, when true, allows the sandboxed process to control the terminal
	// session (skips --new-session). The default (false) creates a new session.
	// Only set to true if the sandboxed process needs terminal control.
	// Ignored on macOS (Seatbelt doesn't have this concept).
	AllowSessionControl bool
}

// Mount represents a filesystem path binding into the sandbox.
// All mounts are required; if a mount source doesn't exist, the sandbox will fail to start.
// This ensures deterministic and predictable security boundaries.
type Mount struct {
	// Source is the absolute path on the host filesystem to mount.
	Source string

	// Target is the absolute path inside the sandbox where Source will appear.
	// Typically this is the same as Source to maintain path consistency.
	Target string
}

// DefaultPolicy returns a policy that provides a reasonable baseline for running
// basic commands in a sandbox. It includes minimal system directories mounted read-only
// and provides an isolated /tmp directory.
//
// System mounts (Linux):
//   - Always mounted: /usr, /bin, /lib, /etc
//   - Mounted if they exist: /sbin, /lib64, /run
//
// System mounts (macOS):
//   - Always mounted: /usr, /bin, /System, /Library, /etc
//   - Mounted if exists: /sbin
//
// Temp directory:
//   - ProvideTmp is enabled, providing isolated /tmp on both platforms
//
// Security settings:
//   - Network is blocked by default (AllowNetwork: false, AllowLocalhostOnly: false)
//   - For applications needing IPC via TCP (like Jupyter), use AllowLocalhostOnly: true
//     to allow localhost communication while blocking external internet
//   - All Linux isolation flags enabled (namespace isolation, die-with-parent, new session)
//   - Working directory is automatically mounted read-write at execution time
//
// Application-specific mounts (like /opt for Homebrew, virtualenv paths, user data directories)
// must be added explicitly by the caller. See package examples for common use cases.
func DefaultPolicy() *Policy {
	policy := &Policy{
		ReadOnlyMounts:  make([]Mount, 0, 10),
		ReadWriteMounts: make([]Mount, 0, 5),
		ProvideTmp:      true,
		// AllowNetwork defaults to false (network blocked)
		// All other security bools default to false (maximum security)
	}

	var required, optional []string

	if runtime.GOOS == "darwin" {
		// macOS system directories required for basic utilities
		required = []string{"/usr", "/bin", "/System", "/Library", "/etc"}
		optional = []string{"/sbin"}
	} else if runtime.GOOS == "linux" {
		// Linux system directories
		required = []string{"/usr", "/bin", "/lib", "/etc"}
		optional = []string{"/sbin", "/lib64", "/run"}
	}

	for _, path := range required {
		if pathExists(path) {
			policy.ReadOnlyMounts = append(policy.ReadOnlyMounts, Mount{
				Source: path,
				Target: path,
			})
		}
	}

	for _, path := range optional {
		if pathExists(path) {
			policy.ReadOnlyMounts = append(policy.ReadOnlyMounts, Mount{
				Source: path,
				Target: path,
			})
		}
	}

	return policy
}

// pathExists checks if a path exists. Returns false for any error, including permission denied.
func pathExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}
