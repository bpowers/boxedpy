package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommandReturnsCmd(t *testing.T) {
	policy := DefaultPolicy()

	cmd, err := policy.Command(context.Background(), "echo", "hello")
	require.NoError(t, err)
	require.NotNil(t, cmd)

	// Should be able to set stdout
	cmd.Stdout = os.Stdout
}

func TestCommandContextWithTimeout(t *testing.T) {
	policy := DefaultPolicy()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// sleep is in /usr/bin on macOS and /bin on Linux, both should be in DefaultPolicy
	cmd, err := policy.Command(ctx, "sleep", "10")
	require.NoError(t, err)

	err = cmd.Run()
	assert.Error(t, err)
	// Should have timed out or been killed
	// On Linux: "signal: killed", on macOS: "signal: abort trap" or "signal: killed"
	errMsg := err.Error()
	assert.True(t, contains(errMsg, "signal"), "expected signal error, got: %s", errMsg)
}

func TestCommandNilPolicy(t *testing.T) {
	var policy *Policy
	cmd, err := policy.Command(context.Background(), "echo", "hi")
	require.Error(t, err)
	assert.Nil(t, cmd)
	assert.Contains(t, err.Error(), "policy must not be nil")
}

func TestCommandEmptyName(t *testing.T) {
	policy := DefaultPolicy()
	cmd, err := policy.Command(context.Background(), "", "arg")
	require.Error(t, err)
	assert.Nil(t, cmd)
	assert.Contains(t, err.Error(), "command name must not be empty")
}

func TestIntegrationEchoCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	policy := DefaultPolicy()

	cmd, err := policy.Command(context.Background(), "echo", "hello", "from", "sandbox")
	require.NoError(t, err)

	output, err := cmd.CombinedOutput()
	require.NoError(t, err)
	assert.Contains(t, string(output), "hello from sandbox")
}

func TestIntegrationNetworkBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	// Python3 is required for tests (minimum 3.11)
	pythonPath, err := findPython()
	require.NoError(t, err, "python3 is required for integration tests (minimum 3.11)")

	policy := pythonPolicy()
	policy.AllowNetwork = false

	// Try to make a network request
	cmd, err := policy.Command(context.Background(), pythonPath, "-c",
		"import urllib.request; urllib.request.urlopen('http://example.com', timeout=1)")
	require.NoError(t, err)

	output, err := cmd.CombinedOutput()
	assert.Error(t, err, "network request should fail when network is blocked")

	// The exact error varies by platform, but should contain some network-related error
	outputStr := string(output)
	t.Logf("Output: %s", outputStr)
	// Either URLError, connection error, or other network-related failure
}

func TestIntegrationSSHWriteBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	homeDir, err := os.UserHomeDir()
	require.NoError(t, err, "failed to get home directory")
	sshDir := filepath.Join(homeDir, ".ssh")

	// Ensure ~/.ssh exists for this test
	err = os.MkdirAll(sshDir, 0o700)
	require.NoError(t, err, "failed to create ~/.ssh directory")

	pythonPath, err := findPython()
	require.NoError(t, err, "python3 is required for integration tests (minimum 3.11)")

	// Use Python policy but do NOT mount ~/.ssh directory.
	// This tests that the sandbox properly blocks write access to sensitive paths.
	policy := pythonPolicy()

	testFile := filepath.Join(sshDir, "test_sandbox_write.txt")

	cmd, err := policy.Command(context.Background(), pythonPath, "-c",
		"with open('"+testFile+"', 'w') as f: f.write('test')")
	require.NoError(t, err)

	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	// The sandbox MUST block write access to ~/.ssh as it's not mounted
	require.Error(t, err, "Sandbox must block write access to %s (~/.ssh not mounted)", testFile)

	// Verify we get a sandbox denial error
	// macOS: "not permitted" or "unable to load libxcrun"
	// Linux: "FileNotFoundError" or "No such file or directory"
	require.Truef(t,
		strings.Contains(outputStr, "not permitted") ||
			strings.Contains(outputStr, "unable to load libxcrun") ||
			strings.Contains(outputStr, "FileNotFoundError") ||
			strings.Contains(outputStr, "No such file or directory"),
		"Expected sandbox denial when writing to unmounted path %s, got: %s",
		testFile, outputStr,
	)

	// Verify the file was NOT created
	_, statErr := os.Stat(testFile)
	require.True(t, os.IsNotExist(statErr), "Security failure: file was created in unmounted path %s", testFile)
}

func TestIntegrationWorkingDirectory(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("hello world"), 0o644))

	policy := DefaultPolicy()
	// Set working directory for the sandboxed command using Policy.WorkDir
	// This tests that the sandbox properly sets the working directory
	policy.WorkDir = tmpDir

	// Read the file we created using a relative path
	cmd, err := policy.Command(context.Background(), "cat", "test.txt")
	require.NoError(t, err)

	output, err := cmd.CombinedOutput()
	require.NoError(t, err)
	assert.Equal(t, "hello world", string(output))
}

func TestExecWithInheritedStdio(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	policy := DefaultPolicy()

	// This should succeed with no output captured (goes to os.Stdout)
	err := policy.Exec(context.Background(), "echo", "test")
	require.NoError(t, err)
}

// Helper functions

func findPython() (string, error) {
	for _, name := range []string{"python3", "python"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("python not found in PATH")
}

// pythonPolicy returns a Policy configured to run Python interpreters.
// On macOS: mounts Homebrew paths for Python dependencies.
// On Linux: uses system Python (no additional mounts needed).
func pythonPolicy() *Policy {
	policy := DefaultPolicy()

	if runtime.GOOS == "darwin" {
		// Homebrew on macOS installs to /opt/homebrew (Apple Silicon) or /usr/local (Intel)
		// These paths must be mounted for Python to find its libraries and modules.
		policy.ReadOnlyMounts = append(policy.ReadOnlyMounts,
			Mount{Source: "/opt", Target: "/opt"},
			Mount{Source: "/usr/local", Target: "/usr/local"},
		)
	}
	// On Linux: system Python is already available via DefaultPolicy's system mounts

	return policy
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			indexOf(s, substr) >= 0))
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func TestSandboxPolicyGeneration(t *testing.T) {
	policy := DefaultPolicy()

	// Verify policy defaults
	assert.True(t, policy.ProvideTmp)
	assert.False(t, policy.AllowNetwork)
	assert.NotEmpty(t, policy.ReadOnlyMounts)

	// Create a command to inspect generated args
	cmd, err := policy.Command(context.Background(), "echo", "hello")
	require.NoError(t, err)
	require.NotNil(t, cmd)

	// Verify appropriate sandbox tool is being used (platform-dependent)
	// On macOS: sandbox-exec, on Linux: bwrap
	if _, err := exec.LookPath("sandbox-exec"); err == nil {
		// macOS
		assert.Equal(t, "/usr/bin/sandbox-exec", cmd.Path)

		// Find and log the policy string (3rd argument after sandbox-exec and -p)
		if len(cmd.Args) >= 3 && cmd.Args[1] == "-p" {
			policyStr := cmd.Args[2]
			t.Logf("Generated policy:\n%s", policyStr)
		}

		// Count -D parameters (macOS-specific)
		dParamCount := 0
		for _, arg := range cmd.Args {
			if len(arg) > 2 && arg[:2] == "-D" {
				dParamCount++
			}
		}

		// Should have parameters for all mounts plus working dir plus temp dir
		expectedMin := len(policy.ReadOnlyMounts) + 1 + 1 // mounts + workdir + tmpdir
		assert.GreaterOrEqual(t, dParamCount, expectedMin,
			"Should have at least %d -D parameters for mounts", expectedMin)
	} else if _, err := exec.LookPath("bwrap"); err == nil {
		// Linux
		assert.Contains(t, cmd.Path, "bwrap")
		t.Logf("Using bubblewrap with args: %v", cmd.Args)
	} else {
		require.Fail(t, "No sandbox tool available - need either sandbox-exec (macOS) or bwrap (Linux)")
	}
}

func TestIntegrationReadAccessScope(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	pythonPath, err := findPython()
	require.NoError(t, err, "python3 is required for integration tests (minimum 3.11)")

	homeDir, err := os.UserHomeDir()
	require.NoError(t, err, "failed to get home directory")

	// Create a test file in home directory (not in working dir)
	testFile := filepath.Join(homeDir, ".sandbox_read_test.txt")
	testContent := "secret content for read test"
	require.NoError(t, os.WriteFile(testFile, []byte(testContent), 0o644))
	defer os.Remove(testFile)

	// Use Python policy but explicitly NOT mount HOME directory.
	// This tests that the sandbox properly blocks access to unmounted paths.
	policy := pythonPolicy()

	// Try to read the file from home directory
	cmd, err := policy.Command(context.Background(), pythonPath, "-c",
		"with open('"+testFile+"', 'r') as f: print(f.read())")
	require.NoError(t, err)

	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	// The sandbox MUST block read access to files outside explicitly mounted directories.
	// Home directory is not in the mount list, so reading from it must fail.
	require.Error(t, err, "Sandbox must block read access to %s (home directory not mounted)", testFile)

	// Verify we get a sandbox denial error. The exact message depends on the platform:
	// - macOS (Seatbelt): "Operation not permitted" or "unable to load libxcrun"
	// - Linux (bubblewrap): "FileNotFoundError" or "No such file or directory"
	// We require that at least one of these specific errors is present.
	require.Truef(t,
		strings.Contains(outputStr, "not permitted") ||
			strings.Contains(outputStr, "unable to load libxcrun") ||
			strings.Contains(outputStr, "FileNotFoundError") ||
			strings.Contains(outputStr, "No such file or directory"),
		"Expected sandbox denial when reading unmounted path %s, got: %s",
		testFile, outputStr,
	)

	// Ensure the actual content is NOT accessible
	require.False(t, contains(outputStr, testContent),
		"SECURITY FAILURE: Sandbox allowed reading file content from unmounted path %s", testFile)
}
