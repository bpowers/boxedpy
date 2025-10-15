# boxedpy

Safe Python code execution for AI agents with cross-platform sandboxing.

## Overview

`boxedpy` is a Go library for safely executing Python code in isolated sandboxes. It's designed for AI agent frameworks that need to run untrusted Python code with strict security boundaries.

**Key Features:**
- **Sandboxed execution** on Linux (bubblewrap) and macOS (Seatbelt)
- **Virtualenv support** with automatic environment configuration
- **Jupyter integration** for notebook execution
- **Network isolation** with optional localhost-only access
- **Python error parsing** with helpful debugging hints
- **Concurrent-safe** - reuse policies across goroutines

## Installation

```bash
go get github.com/bpowers/boxedpy
```

### Platform Requirements

**Linux:**
- `bubblewrap` (bwrap) must be installed
- Available in most package managers: `apt install bubblewrap` or `dnf install bubblewrap`

**macOS:**
- Uses built-in `sandbox-exec` (Seatbelt) - no additional installation required

## Quick Start

### Basic Python Execution

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/bpowers/boxedpy"
    "github.com/bpowers/boxedpy/sandbox"
)

func main() {
    // Create Python instance from virtualenv
    py, err := boxedpy.New(boxedpy.Config{
        VirtualEnv: "/path/to/venv",
    })
    if err != nil {
        log.Fatal(err)
    }
    defer py.Close()

    // Create sandbox policy
    policy := sandbox.DefaultPolicy()
    policy.WorkDir = "/path/to/workdir"

    // Execute Python code
    ctx := context.Background()
    cmd, err := py.Command(ctx, policy, boxedpy.ExecConfig{},
        "-c", "print('Hello from sandbox')")
    if err != nil {
        log.Fatal(err)
    }

    output, err := cmd.CombinedOutput()
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(string(output))
}
```

### Running Python Scripts with Data Access

```go
// Create Python instance with read-only data access
py, err := boxedpy.New(boxedpy.Config{
    VirtualEnv:   "/path/to/venv",
    ReferenceDir: "/path/to/datasets",  // Mounted read-only
})
if err != nil {
    log.Fatal(err)
}
defer py.Close()

policy := sandbox.DefaultPolicy()
policy.WorkDir = "/path/to/workdir"  // Automatically mounted read-write

// Run script with access to datasets and workdir
cmd, err := py.Command(ctx, policy, boxedpy.ExecConfig{},
    "/path/to/workdir/analyze.py")
```

### Jupyter Notebook Execution

```go
py, err := boxedpy.New(boxedpy.Config{
    VirtualEnv: "/path/to/venv",
})
if err != nil {
    log.Fatal(err)
}
defer py.Close()

policy := sandbox.DefaultPolicy()
policy.WorkDir = "/path/to/notebooks"
policy.AllowLocalhostOnly = true  // Required for Jupyter kernel communication

cmd, err := py.Command(ctx, policy, boxedpy.ExecConfig{},
    "-m", "jupyter", "nbconvert", "--execute", "notebook.ipynb")
if err != nil {
    log.Fatal(err)
}

// Configure Jupyter environment
jupyterEnv := boxedpy.JupyterEnv(policy.WorkDir, py.ConfigDir())
cmd.Env = append(os.Environ(), jupyterEnv...)

output, err := cmd.CombinedOutput()
```

### Error Handling with Hints

```go
output, err := cmd.CombinedOutput()
if err != nil {
    // Parse Python errors for helpful debugging hints
    if pyErr := boxedpy.ParsePythonError(output); pyErr != nil {
        fmt.Printf("Python %s at line %d: %s\n",
            pyErr.Type, pyErr.Line, pyErr.Message)
        fmt.Printf("Hint: %s\n", pyErr.Hint)
    }
    return err
}
```

## Architecture

### Package Structure

- **`boxedpy`** - High-level Python virtualenv wrapper
  - `Config`, `Python` - Virtualenv configuration and management
  - `JupyterEnv()` - Jupyter environment configuration
  - `ParsePythonError()` - Python error parsing with hints

- **`boxedpy/sandbox`** - Low-level cross-platform sandboxing
  - `Policy` - Sandbox configuration (mounts, network, etc.)
  - `DefaultPolicy()` - Safe defaults for common use cases
  - Platform-specific implementations (Linux/macOS)

### Security Model

The sandbox provides defense-in-depth security:

1. **Filesystem Isolation**
   - Only explicitly mounted paths are accessible
   - System directories mounted read-only by default
   - Working directory mounted read-write
   - Home directory and other user paths blocked unless explicitly mounted

2. **Network Isolation**
   - Network blocked by default
   - `AllowLocalhostOnly` for IPC via TCP (e.g., Jupyter kernels)
   - `AllowNetwork` for full internet access (use sparingly)

3. **Process Isolation** (Linux)
   - Isolated namespaces (network, IPC, PID)
   - Child processes die with parent
   - New session prevents terminal control

4. **Resource Isolation**
   - Isolated `/tmp` directory
   - Config directory for Python library state

## Advanced Usage

### Custom Mounts

```go
policy := sandbox.DefaultPolicy()
policy.WorkDir = "/workdir"

// Add read-only data mount
policy.ReadOnlyMounts = append(policy.ReadOnlyMounts,
    sandbox.Mount{Source: "/data", Target: "/data"},
)

// Add read-write output mount
policy.ReadWriteMounts = append(policy.ReadWriteMounts,
    sandbox.Mount{Source: "/output", Target: "/output"},
)
```

### Network Configuration

```go
policy := sandbox.DefaultPolicy()

// Option 1: Block all network (default)
policy.AllowNetwork = false
policy.AllowLocalhostOnly = false

// Option 2: Allow localhost only (recommended for Jupyter)
policy.AllowLocalhostOnly = true

// Option 3: Allow full network access (use with caution)
policy.AllowNetwork = true
```

### Concurrent Usage

Policies are safe to reuse across concurrent goroutines:

```go
// Create policy once
pythonPolicy := sandbox.DefaultPolicy()
pythonPolicy.ReadOnlyMounts = append(pythonPolicy.ReadOnlyMounts,
    sandbox.Mount{Source: "/opt", Target: "/opt"},
)

// Reuse across concurrent HTTP requests
http.HandleFunc("/execute", func(w http.ResponseWriter, r *http.Request) {
    cmd, err := pythonPolicy.Command(r.Context(), "python3", "-c", code)
    // ... execute command
})
```

### Custom Config Directory

```go
// Specify config directory for Python library state
py, err := boxedpy.New(boxedpy.Config{
    VirtualEnv: "/path/to/venv",
    ConfigDir:  "/persistent/config",  // For matplotlib, jupyter, etc.
})
```

If `ConfigDir` is not specified, a temporary directory is created automatically and cleaned up when `Close()` is called.

## API Documentation

Full API documentation is available on [pkg.go.dev](https://pkg.go.dev/github.com/bpowers/boxedpy).

### Core Types

#### `boxedpy.Config`
Configuration for creating a Python instance:
- `VirtualEnv` (required) - Path to Python virtualenv
- `ReferenceDir` (optional) - Read-only data directory
- `ConfigDir` (optional) - Config directory for Python libraries

#### `boxedpy.Python`
Represents a configured Python virtualenv:
- `Command()` - Create sandboxed exec.Cmd
- `InterpreterPath()` - Get Python interpreter path
- `Close()` - Clean up resources

#### `sandbox.Policy`
Sandbox configuration:
- `ReadOnlyMounts` - Read-only filesystem mounts
- `ReadWriteMounts` - Read-write filesystem mounts
- `WorkDir` - Working directory (auto-mounted read-write)
- `ProvideTmp` - Isolated /tmp directory
- `AllowNetwork` - Allow full network access
- `AllowLocalhostOnly` - Allow localhost only (for IPC)

## Platform-Specific Notes

### Linux
- Uses `bubblewrap` for sandboxing
- All isolation features available
- Install: `apt install bubblewrap` or `dnf install bubblewrap`

### macOS
- Uses built-in `sandbox-exec` (Seatbelt)
- Filesystem and network isolation supported
- Some Linux-specific flags (like `AllowSharedNamespaces`) are ignored
- Homebrew paths (`/opt`, `/usr/local`) must be explicitly mounted for Homebrew Python

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Limitations

The sandbox does not enforce CPU/memory limits. Also this is hillariously fresh code.