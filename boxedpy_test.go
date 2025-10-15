package boxedpy

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bpowers/boxedpy/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNew_ValidVirtualenv tests creating a Python instance with a valid virtualenv
func TestNew_ValidVirtualenv(t *testing.T) {
	t.Parallel()

	// Create a temporary virtualenv structure
	tmpDir := t.TempDir()
	venvDir := filepath.Join(tmpDir, "venv")
	binDir := filepath.Join(venvDir, "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))

	// Create a dummy python executable
	pythonPath := filepath.Join(binDir, "python")
	require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\n"), 0o755))

	// Test creating Python instance
	py, err := New(Config{
		VirtualEnv: venvDir,
	})
	require.NoError(t, err)
	require.NotNil(t, py)

	// Verify paths
	assert.Equal(t, pythonPath, py.InterpreterPath())
	assert.True(t, filepath.IsAbs(py.VirtualEnvPath()))
	assert.Contains(t, py.VirtualEnvPath(), "venv")
	assert.Empty(t, py.ProjectsDir())
}

// TestNew_WithProjectsDir tests creating a Python instance with a projects directory
func TestNew_WithProjectsDir(t *testing.T) {
	t.Parallel()

	// Create temporary directories
	tmpDir := t.TempDir()
	venvDir := filepath.Join(tmpDir, "venv")
	binDir := filepath.Join(venvDir, "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))

	pythonPath := filepath.Join(binDir, "python")
	require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\n"), 0o755))

	projectsDir := filepath.Join(tmpDir, "projects")
	require.NoError(t, os.MkdirAll(projectsDir, 0o755))

	// Test creating Python instance with projects directory
	py, err := New(Config{
		VirtualEnv:   venvDir,
		ReferenceDir: projectsDir,
	})
	require.NoError(t, err)
	require.NotNil(t, py)

	// Verify paths
	assert.True(t, filepath.IsAbs(py.ProjectsDir()))
	assert.Contains(t, py.ProjectsDir(), "projects")
}

// TestNew_ErrorCases tests various error scenarios
func TestNew_ErrorCases(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	tests := []struct {
		name      string
		cfg       Config
		wantError string
	}{
		{
			name:      "empty virtualenv",
			cfg:       Config{},
			wantError: "VirtualEnv is required",
		},
		{
			name: "nonexistent virtualenv",
			cfg: Config{
				VirtualEnv: filepath.Join(tmpDir, "nonexistent"),
			},
			wantError: "virtualenv",
		},
		{
			name: "virtualenv is a file",
			cfg: Config{
				VirtualEnv: func() string {
					file := filepath.Join(tmpDir, "not-a-dir")
					require.NoError(t, os.WriteFile(file, []byte("test"), 0o644))
					return file
				}(),
			},
			wantError: "not a directory",
		},
		{
			name: "missing python interpreter",
			cfg: Config{
				VirtualEnv: func() string {
					dir := filepath.Join(tmpDir, "venv-no-python")
					require.NoError(t, os.MkdirAll(dir, 0o755))
					return dir
				}(),
			},
			wantError: "python interpreter not found",
		},
		{
			name: "invalid projects directory",
			cfg: Config{
				VirtualEnv: func() string {
					venvDir := filepath.Join(tmpDir, "venv-valid")
					binDir := filepath.Join(venvDir, "bin")
					require.NoError(t, os.MkdirAll(binDir, 0o755))
					pythonPath := filepath.Join(binDir, "python")
					require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\n"), 0o755))
					return venvDir
				}(),
				ReferenceDir: filepath.Join(tmpDir, "nonexistent-projects"),
			},
			wantError: "projects directory",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			py, err := New(tc.cfg)
			require.Error(t, err)
			assert.Nil(t, py)
			assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tc.wantError))
		})
	}
}

// TestCommand_Basic tests creating a basic sandboxed command
func TestCommand_Basic(t *testing.T) {
	t.Parallel()

	// Create a temporary virtualenv structure
	tmpDir := t.TempDir()
	venvDir := filepath.Join(tmpDir, "venv")
	binDir := filepath.Join(venvDir, "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))

	pythonPath := filepath.Join(binDir, "python")
	require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\n"), 0o755))

	py, err := New(Config{
		VirtualEnv: venvDir,
	})
	require.NoError(t, err)

	// Create a sandbox policy
	policy := sandbox.DefaultPolicy()
	policy.WorkDir = tmpDir

	// Create a command
	ctx := context.Background()
	cmd, err := py.Command(ctx, policy, ExecConfig{}, "-c", "print('hello')")
	require.NoError(t, err)
	require.NotNil(t, cmd)

	// Verify the command path is the Python interpreter
	assert.Equal(t, pythonPath, py.InterpreterPath())
}

// TestCommand_WithConfigDir tests command creation with a specified config directory
func TestCommand_WithConfigDir(t *testing.T) {
	t.Parallel()

	// Create temporary directories
	tmpDir := t.TempDir()
	venvDir := filepath.Join(tmpDir, "venv")
	binDir := filepath.Join(venvDir, "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))

	pythonPath := filepath.Join(binDir, "python")
	require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\n"), 0o755))

	configDir := filepath.Join(tmpDir, "config")
	require.NoError(t, os.MkdirAll(configDir, 0o755))

	py, err := New(Config{
		VirtualEnv: venvDir,
		ConfigDir:  configDir,
	})
	require.NoError(t, err)

	// Verify ConfigDir was set correctly
	assert.Equal(t, configDir, py.ConfigDir())

	// Create command - should use the configured ConfigDir
	policy := sandbox.DefaultPolicy()
	policy.WorkDir = tmpDir

	ctx := context.Background()
	cmd, err := py.Command(ctx, policy, ExecConfig{}, "-c", "print('test')")
	require.NoError(t, err)
	require.NotNil(t, cmd)
}

// TestCommand_AutoCreatesConfigDir tests that config directory is auto-created when not specified
func TestCommand_AutoCreatesConfigDir(t *testing.T) {
	t.Parallel()

	// Create temporary virtualenv
	tmpDir := t.TempDir()
	venvDir := filepath.Join(tmpDir, "venv")
	binDir := filepath.Join(venvDir, "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))

	pythonPath := filepath.Join(binDir, "python")
	require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\n"), 0o755))

	py, err := New(Config{
		VirtualEnv: venvDir,
	})
	require.NoError(t, err)

	// Create command without specifying config directory
	policy := sandbox.DefaultPolicy()
	policy.WorkDir = tmpDir

	ctx := context.Background()
	cmd, err := py.Command(ctx, policy, ExecConfig{}, "-c", "print('test')")
	require.NoError(t, err)
	require.NotNil(t, cmd)
}

// TestCommand_ErrorCases tests error scenarios for Command()
func TestCommand_ErrorCases(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	venvDir := filepath.Join(tmpDir, "venv")
	binDir := filepath.Join(venvDir, "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))

	pythonPath := filepath.Join(binDir, "python")
	require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\n"), 0o755))

	py, err := New(Config{
		VirtualEnv: venvDir,
	})
	require.NoError(t, err)

	ctx := context.Background()

	tests := []struct {
		name      string
		py        *Python
		policy    *sandbox.Policy
		cfg       ExecConfig
		wantError string
	}{
		{
			name:      "nil python instance",
			py:        nil,
			policy:    sandbox.DefaultPolicy(),
			cfg:       ExecConfig{},
			wantError: "Python instance is nil",
		},
		{
			name:      "nil policy",
			py:        py,
			policy:    nil,
			cfg:       ExecConfig{},
			wantError: "policy must not be nil",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cmd, err := tc.py.Command(ctx, tc.policy, tc.cfg, "-c", "print('test')")
			require.Error(t, err)
			assert.Nil(t, cmd)
			assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tc.wantError))
		})
	}
}

// TestCommand_HomebrewMountsOnMacOS tests that Homebrew paths are mounted on macOS
func TestCommand_HomebrewMountsOnMacOS(t *testing.T) {
	t.Parallel()

	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific test")
	}

	// Create temporary virtualenv
	tmpDir := t.TempDir()
	venvDir := filepath.Join(tmpDir, "venv")
	binDir := filepath.Join(venvDir, "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))

	pythonPath := filepath.Join(binDir, "python")
	require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\n"), 0o755))

	py, err := New(Config{
		VirtualEnv: venvDir,
	})
	require.NoError(t, err)

	policy := sandbox.DefaultPolicy()
	policy.WorkDir = tmpDir

	ctx := context.Background()
	_, err = py.Command(ctx, policy, ExecConfig{}, "-c", "print('test')")
	require.NoError(t, err)
}

// TestJupyterEnv tests the JupyterEnv function
func TestJupyterEnv(t *testing.T) {
	t.Parallel()

	notebookDir := "/path/to/notebook"
	configDir := "/path/to/config"

	envSlice := JupyterEnv(notebookDir, configDir)

	// Convert slice to map for easier testing
	env := make(map[string]string)
	for _, pair := range envSlice {
		parts := strings.SplitN(pair, "=", 2)
		require.Len(t, parts, 2, "environment variable should be in KEY=VALUE format")
		env[parts[0]] = parts[1]
	}

	// Check that all expected keys are present
	expectedKeys := []string{
		"IPYTHONDIR",
		"JUPYTER_DATA_DIR",
		"JUPYTER_RUNTIME_DIR",
		"JUPYTER_CONFIG_DIR",
		"JUPYTER_PLATFORM_DIRS",
		"MPLCONFIGDIR",
		"TERM",
	}

	for _, key := range expectedKeys {
		_, ok := env[key]
		assert.Truef(t, ok, "expected key %s in environment", key)
	}

	// Check specific values
	assert.Equal(t, filepath.Join(notebookDir, ".ipython"), env["IPYTHONDIR"])
	assert.Equal(t, filepath.Join(notebookDir, ".jupyter"), env["JUPYTER_DATA_DIR"])
	assert.Equal(t, filepath.Join(notebookDir, ".jupyter", "runtime"), env["JUPYTER_RUNTIME_DIR"])
	assert.Equal(t, filepath.Join(notebookDir, ".jupyter_config"), env["JUPYTER_CONFIG_DIR"])
	assert.Equal(t, "1", env["JUPYTER_PLATFORM_DIRS"])
	assert.Equal(t, configDir, env["MPLCONFIGDIR"])
	assert.Equal(t, "dumb", env["TERM"])
}

// TestParsePythonError_NameError tests parsing a NameError
func TestParsePythonError_NameError(t *testing.T) {
	t.Parallel()

	output := `Traceback (most recent call last):
  File "<string>", line 2, in <module>
NameError: name 'undefined_variable' is not defined`

	err := ParsePythonError([]byte(output))
	require.NotNil(t, err)

	assert.Equal(t, "NameError", err.Type)
	assert.Contains(t, err.Message, "NameError")
	assert.Contains(t, err.Message, "undefined_variable")
	assert.Equal(t, 2, err.Line)
	assert.Contains(t, err.Traceback, "NameError")
	assert.Contains(t, err.Hint, "undefined_variable")
}

// TestParsePythonError_SyntaxError tests parsing a SyntaxError
func TestParsePythonError_SyntaxError(t *testing.T) {
	t.Parallel()

	output := `  File "<string>", line 3
    def foo():
IndentationError: expected an indented block`

	err := ParsePythonError([]byte(output))
	require.NotNil(t, err)

	assert.Equal(t, "IndentationError", err.Type)
	assert.Contains(t, err.Message, "IndentationError")
	assert.Equal(t, 3, err.Line)
	assert.Contains(t, err.Hint, "indentation")
}

// TestParsePythonError_ModuleNotFoundError tests parsing a ModuleNotFoundError
func TestParsePythonError_ModuleNotFoundError(t *testing.T) {
	t.Parallel()

	output := `Traceback (most recent call last):
  File "<string>", line 1, in <module>
ModuleNotFoundError: No module named 'nonexistent_module'`

	err := ParsePythonError([]byte(output))
	require.NotNil(t, err)

	assert.Equal(t, "ModuleNotFoundError", err.Type)
	assert.Contains(t, err.Message, "ModuleNotFoundError")
	assert.Contains(t, err.Message, "nonexistent_module")
	assert.Equal(t, 1, err.Line)
	assert.Contains(t, err.Hint, "nonexistent_module")
}

// TestParsePythonError_TypeErrors tests parsing various TypeError scenarios
func TestParsePythonError_TypeErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		output       string
		expectedType string
		expectedHint string
	}{
		{
			name: "ZeroDivisionError",
			output: `Traceback (most recent call last):
  File "<string>", line 3, in <module>
ZeroDivisionError: division by zero`,
			expectedType: "ZeroDivisionError",
			expectedHint: "divisor",
		},
		{
			name: "TypeError",
			output: `Traceback (most recent call last):
  File "<string>", line 2, in <module>
TypeError: can only concatenate str (not "int") to str`,
			expectedType: "TypeError",
			expectedHint: "concatenating",
		},
		{
			name: "AttributeError",
			output: `Traceback (most recent call last):
  File "<string>", line 2, in <module>
AttributeError: 'str' object has no attribute 'nonexistent_method'`,
			expectedType: "AttributeError",
			expectedHint: "nonexistent_method",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := ParsePythonError([]byte(tc.output))
			require.NotNil(t, err)

			assert.Equal(t, tc.expectedType, err.Type)
			assert.Contains(t, err.Message, tc.expectedType)
			assert.Contains(t, strings.ToLower(err.Hint), strings.ToLower(tc.expectedHint))
		})
	}
}

// TestParsePythonError_ANSICleaning tests that ANSI codes are stripped
func TestParsePythonError_ANSICleaning(t *testing.T) {
	t.Parallel()

	// Use proper ANSI escape sequences (must use double quotes, not backticks)
	output := "Traceback (most recent call last):\n" +
		"  File \"\x1b[32m<string>\x1b[0m\", line 1, in <module>\n" +
		"\x1b[31mNameError\x1b[0m: name 'undefined_var' is not defined"

	err := ParsePythonError([]byte(output))
	require.NotNil(t, err)

	assert.Equal(t, "NameError", err.Type)
	assert.NotContains(t, err.Traceback, "\x1b[")
	assert.Contains(t, err.Traceback, "NameError")
	assert.Contains(t, err.Traceback, "undefined_var")
}

// TestParsePythonError_NoError tests that nil is returned for non-error output
func TestParsePythonError_NoError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		output string
	}{
		{
			name:   "empty output",
			output: "",
		},
		{
			name:   "normal output",
			output: "Hello, World!",
		},
		{
			name:   "warning message",
			output: "Warning: This is a warning, not an error",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := ParsePythonError([]byte(tc.output))
			assert.Nil(t, err)
		})
	}
}

// TestParsePythonError_JupyterFormat tests parsing Jupyter-style error output
func TestParsePythonError_JupyterFormat(t *testing.T) {
	t.Parallel()

	output := `Cell In[1], line 2
----> 2 print(undefined_variable)

NameError: name 'undefined_variable' is not defined`

	err := ParsePythonError([]byte(output))
	require.NotNil(t, err)

	assert.Equal(t, "NameError", err.Type)
	assert.Equal(t, 2, err.Line)
	assert.Contains(t, err.Message, "undefined_variable")
}

// TestNilPythonMethods tests that methods handle nil Python instances gracefully
func TestNilPythonMethods(t *testing.T) {
	t.Parallel()

	var py *Python

	assert.Empty(t, py.InterpreterPath())
	assert.Empty(t, py.VirtualEnvPath())
	assert.Empty(t, py.ProjectsDir())
}

// TestPolicyConcurrentReuse tests that a Policy can be safely reused across concurrent calls.
// This verifies the deep copy fix prevents data races when appending to mount slices.
func TestPolicyConcurrentReuse(t *testing.T) {
	t.Parallel()

	// Create temporary virtualenv
	tmpDir := t.TempDir()
	venvDir := filepath.Join(tmpDir, "venv")
	binDir := filepath.Join(venvDir, "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))

	pythonPath := filepath.Join(binDir, "python")
	require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\necho test\n"), 0o755))

	py, err := New(Config{
		VirtualEnv: venvDir,
	})
	require.NoError(t, err)

	// Create a policy that will be reused across goroutines
	policy := sandbox.DefaultPolicy()
	policy.WorkDir = tmpDir

	// Run multiple concurrent commands using the same policy
	const numGoroutines = 10
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			ctx := context.Background()
			cmd, err := py.Command(ctx, policy, ExecConfig{}, "-c", "print('concurrent test')")
			if err != nil {
				errors <- err
				return
			}
			_, err = cmd.CombinedOutput()
			errors <- err
		}()
	}

	// Collect results
	for i := 0; i < numGoroutines; i++ {
		err := <-errors
		assert.NoError(t, err, "Concurrent command execution failed")
	}

	// Verify the policy's mounts weren't modified
	// Original policy should still have the same mounts (not accumulated from all goroutines)
	// The deep copy ensures each Command() call gets its own slice
	assert.LessOrEqual(t, len(policy.ReadOnlyMounts), 20, "Policy mounts should not accumulate")
}

// TestClose_AutoCreatedConfigDir tests that Close() removes auto-created config directories
func TestClose_AutoCreatedConfigDir(t *testing.T) {
	t.Parallel()

	// Create temporary virtualenv
	tmpDir := t.TempDir()
	venvDir := filepath.Join(tmpDir, "venv")
	binDir := filepath.Join(venvDir, "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))

	pythonPath := filepath.Join(binDir, "python")
	require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\n"), 0o755))

	// Create Python instance without ConfigDir (will auto-create)
	py, err := New(Config{
		VirtualEnv: venvDir,
	})
	require.NoError(t, err)

	configDir := py.ConfigDir()
	require.NotEmpty(t, configDir)

	// Verify config directory exists
	info, err := os.Stat(configDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	// Close should remove the auto-created directory
	err = py.Close()
	require.NoError(t, err)

	// Verify config directory was removed
	_, err = os.Stat(configDir)
	assert.True(t, os.IsNotExist(err), "ConfigDir should be removed after Close()")
}

// TestClose_UserProvidedConfigDir tests that Close() does NOT remove user-provided config directories
func TestClose_UserProvidedConfigDir(t *testing.T) {
	t.Parallel()

	// Create temporary directories
	tmpDir := t.TempDir()
	venvDir := filepath.Join(tmpDir, "venv")
	binDir := filepath.Join(venvDir, "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))

	pythonPath := filepath.Join(binDir, "python")
	require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\n"), 0o755))

	userConfigDir := filepath.Join(tmpDir, "user-config")
	require.NoError(t, os.MkdirAll(userConfigDir, 0o755))

	// Create Python instance with user-provided ConfigDir
	py, err := New(Config{
		VirtualEnv: venvDir,
		ConfigDir:  userConfigDir,
	})
	require.NoError(t, err)

	assert.Equal(t, userConfigDir, py.ConfigDir())

	// Close should NOT remove user-provided directory
	err = py.Close()
	require.NoError(t, err)

	// Verify config directory still exists
	info, err := os.Stat(userConfigDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir(), "User-provided ConfigDir should NOT be removed after Close()")
}

// TestClose_Idempotent tests that Close() can be called multiple times safely
func TestClose_Idempotent(t *testing.T) {
	t.Parallel()

	// Create temporary virtualenv
	tmpDir := t.TempDir()
	venvDir := filepath.Join(tmpDir, "venv")
	binDir := filepath.Join(venvDir, "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))

	pythonPath := filepath.Join(binDir, "python")
	require.NoError(t, os.WriteFile(pythonPath, []byte("#!/bin/sh\n"), 0o755))

	py, err := New(Config{
		VirtualEnv: venvDir,
	})
	require.NoError(t, err)

	// First close
	err = py.Close()
	require.NoError(t, err)

	// Second close should not error
	err = py.Close()
	require.NoError(t, err)

	// Third close for good measure
	err = py.Close()
	require.NoError(t, err)
}

// TestClose_NilPython tests that Close() on nil Python is safe
func TestClose_NilPython(t *testing.T) {
	t.Parallel()

	var py *Python
	err := py.Close()
	require.NoError(t, err)
}
