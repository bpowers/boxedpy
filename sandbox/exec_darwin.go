//go:build darwin

package sandbox

import (
	"context"
	"crypto/rand"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

//go:embed seatbelt_base_policy.sbpl
var seatbeltBasePolicy string

const seatbeltPath = "/usr/bin/sandbox-exec"

// commandContext implements macOS sandboxing using Seatbelt.
func (p *Policy) commandContext(ctx context.Context, name string, arg ...string) (*exec.Cmd, error) {
	// Build full argv
	argv := append([]string{name}, arg...)

	// Get current environment (caller can override cmd.Env later)
	envv := os.Environ()

	// Generate seatbelt arguments
	// Returns (args, tmpDir, workDir, error) where tmpDir is non-empty if a temp directory was created
	seatbeltArgs, tmpDir, workDir, err := seatbeltArgs(p, name, argv, envv)
	if err != nil {
		return nil, fmt.Errorf("seatbelt: build args: %w", err)
	}

	// Create command: /usr/bin/sandbox-exec -p <policy> -D... -- <command> <args>
	// seatbeltArgs[0] is seatbeltPath itself, skip it for exec.CommandContext
	cmd := exec.CommandContext(ctx, seatbeltPath, seatbeltArgs[1:]...)
	cmd.Env = envv
	// Set the working directory to match Linux's --chdir behavior
	// This allows code to use relative paths inside the sandbox
	cmd.Dir = workDir

	// If a temp directory was created, set TMPDIR to point to it
	// This provides isolation similar to Linux's tmpfs
	if tmpDir != "" {
		cmd.Env = append(cmd.Env, "TMPDIR="+tmpDir)

		// Set up finalizer to clean up temp directory when Cmd is garbage collected.
		// This is best-effort cleanup - finalizers are not guaranteed to run, but
		// acceptable for temp directories that the OS will eventually clean up.
		// IMPORTANT: Callers must hold the Cmd reference until after Wait() completes
		// to ensure the temp directory exists during command execution.
		runtime.SetFinalizer(cmd, func(c *exec.Cmd) {
			os.RemoveAll(tmpDir)
		})
	}

	return cmd, nil
}

// seatbeltArgs builds the argument list for sandbox-exec.
// Returns (args, tmpDir, workDir, error) where:
// - args: full argv including seatbeltPath at [0]
// - tmpDir: path to created temp directory (empty string if none)
// - workDir: canonicalized working directory path
// - error: any error that occurred
func seatbeltArgs(policy *Policy, name string, argv, envv []string) ([]string, string, string, error) {
	// Use Policy.WorkDir if specified, otherwise current directory
	wd := policy.WorkDir
	if wd == "" {
		var err error
		wd, err = os.Getwd()
		if err != nil {
			return nil, "", "", fmt.Errorf("getwd: %w", err)
		}
	}

	// Collect all paths that should be readable (deduplicated)
	readableSet := newMountSet()
	var readablePaths []string

	// Add all ReadOnlyMounts to readable set
	for _, m := range policy.ReadOnlyMounts {
		canonSrc, err := canonicalPath(m.Source)
		if err != nil {
			return nil, "", "", fmt.Errorf("canonicalize readonly mount %s: %w", m.Source, err)
		}
		if !readableSet.has("", canonSrc) {
			readableSet.add("", canonSrc)
			readablePaths = append(readablePaths, canonSrc)
		}
	}

	// Collect all paths that should be writable (deduplicated)
	// Note: writable implies readable, so we add these to both sets
	writableSet := newMountSet()
	var writablePaths []string

	// Add all ReadWriteMounts to both readable and writable sets
	for _, m := range policy.ReadWriteMounts {
		canonSrc, err := canonicalPath(m.Source)
		if err != nil {
			return nil, "", "", fmt.Errorf("canonicalize readwrite mount %s: %w", m.Source, err)
		}
		if !writableSet.has("", canonSrc) {
			writableSet.add("", canonSrc)
			writablePaths = append(writablePaths, canonSrc)
		}
		if !readableSet.has("", canonSrc) {
			readableSet.add("", canonSrc)
			readablePaths = append(readablePaths, canonSrc)
		}
	}

	// Add working directory to writable (and readable)
	workdir, err := canonicalPath(wd)
	if err != nil {
		return nil, "", "", fmt.Errorf("canonicalize working directory: %w", err)
	}
	if !writableSet.has("", workdir) {
		writableSet.add("", workdir)
		writablePaths = append(writablePaths, workdir)
	}
	if !readableSet.has("", workdir) {
		readableSet.add("", workdir)
		readablePaths = append(readablePaths, workdir)
	}

	// Create and add temporary directory if requested
	var tmpDir string
	if policy.ProvideTmp {
		tmpDir, err = os.MkdirTemp("", "boxedpy-sandbox-*")
		if err != nil {
			return nil, "", "", fmt.Errorf("create temp directory: %w", err)
		}
		// Canonicalize tmpDir to handle macOS symlinks (/var -> /private/var)
		canonTmpDir, err := canonicalPath(tmpDir)
		if err != nil {
			return nil, "", "", fmt.Errorf("canonicalize temp directory %s: %w", tmpDir, err)
		}
		// Allow read-write access to the temp directory
		// The sandboxed process will access it via TMPDIR env var
		if !writableSet.has("", canonTmpDir) {
			writableSet.add("", canonTmpDir)
			writablePaths = append(writablePaths, canonTmpDir)
		}
		if !readableSet.has("", canonTmpDir) {
			readableSet.add("", canonTmpDir)
			readablePaths = append(readablePaths, canonTmpDir)
		}
		// Use canonicalized path for TMPDIR env var
		tmpDir = canonTmpDir
	}

	// Generate unique log tag for violation tracking
	logTag := fmt.Sprintf("boxedpy-%d-%s", time.Now().Unix(), randomString(8))

	// Inject log tag into base policy
	fullPolicy := strings.ReplaceAll(seatbeltBasePolicy, "boxedpy-LOGTAG", logTag)

	// Build Seatbelt policy string
	var policyBuilder strings.Builder
	policyBuilder.WriteString(fullPolicy)
	policyBuilder.WriteString("\n")

	// Add read access rules (restricted to explicitly mounted paths)
	if len(readablePaths) > 0 {
		policyBuilder.WriteString("(allow file-read*\n")
		for i := range readablePaths {
			policyBuilder.WriteString(fmt.Sprintf("  (subpath (param \"READABLE_ROOT_%d\"))\n", i))
		}
		policyBuilder.WriteString(fmt.Sprintf("  (with message \"%s-read\"))\n", logTag))
	}

	// Add write access rules
	if len(writablePaths) > 0 {
		policyBuilder.WriteString("(allow file-write*\n")
		for i := range writablePaths {
			policyBuilder.WriteString(fmt.Sprintf("  (subpath (param \"WRITABLE_ROOT_%d\"))\n", i))
		}
		policyBuilder.WriteString(fmt.Sprintf("  (with message \"%s-write\"))\n", logTag))
	}

	// Add network access rules based on policy
	if policy.AllowNetwork {
		// Full network access (includes localhost and internet)
		policyBuilder.WriteString("(allow network-outbound)\n")
		policyBuilder.WriteString("(allow network-inbound)\n")
	} else if policy.AllowLocalhostOnly {
		// Localhost-only network access (blocks internet)
		// Note: Seatbelt requires "localhost:*" syntax, not "127.0.0.1:*"
		// The system will resolve localhost to 127.0.0.1 and ::1
		policyBuilder.WriteString("(allow network-outbound\n")
		policyBuilder.WriteString("  (remote ip \"localhost:*\"))\n")

		policyBuilder.WriteString("(allow network-inbound\n")
		policyBuilder.WriteString("  (local ip \"localhost:*\"))\n")
	}
	// If both are false, no network rules are added (network is blocked)

	fullPolicy = policyBuilder.String()

	// Build command-line arguments
	args := []string{seatbeltPath, "-p", fullPolicy}

	// Add -D parameter definitions for readable paths
	for i, path := range readablePaths {
		args = append(args, fmt.Sprintf("-DREADABLE_ROOT_%d=%s", i, path))
	}

	// Add -D parameter definitions for writable paths
	for i, path := range writablePaths {
		args = append(args, fmt.Sprintf("-DWRITABLE_ROOT_%d=%s", i, path))
	}

	// Add separator and command
	args = append(args, "--")
	args = append(args, argv...)

	return args, tmpDir, workdir, nil
}

// randomString generates a random alphanumeric string of length n.
// Used for generating unique log tags for sandbox violation tracking.
func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based suffix if crypto/rand fails
		return fmt.Sprintf("%d", time.Now().UnixNano()%100000000)
	}
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}
