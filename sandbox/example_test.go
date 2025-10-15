package sandbox_test

import (
	"context"
	"fmt"
	"log"

	"github.com/bpowers/boxedpy/sandbox"
)

// This example demonstrates creating a default sandbox policy.
func ExampleDefaultPolicy() {
	policy := sandbox.DefaultPolicy()

	// The default policy includes:
	// - System directories mounted read-only
	// - Isolated /tmp directory
	// - Network blocked
	// - Working directory mounted read-write

	ctx := context.Background()
	cmd, err := policy.Command(ctx, "echo", "Hello from sandbox")
	if err != nil {
		log.Fatal(err)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(output))
}

// This example demonstrates running a sandboxed command.
func ExamplePolicy_Command() {
	policy := sandbox.DefaultPolicy()
	policy.WorkDir = "/path/to/workdir"

	ctx := context.Background()
	cmd, err := policy.Command(ctx, "ls", "-la")
	if err != nil {
		log.Fatal(err)
	}

	// Execute the command
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(output))
}

// This example demonstrates adding custom read-only and read-write mounts.
func ExamplePolicy_Command_withMounts() {
	policy := sandbox.DefaultPolicy()
	policy.WorkDir = "/path/to/workdir"

	// Mount a data directory as read-only
	policy.ReadOnlyMounts = append(policy.ReadOnlyMounts,
		sandbox.Mount{Source: "/path/to/data", Target: "/path/to/data"},
	)

	// Mount an output directory as read-write
	policy.ReadWriteMounts = append(policy.ReadWriteMounts,
		sandbox.Mount{Source: "/path/to/output", Target: "/path/to/output"},
	)

	ctx := context.Background()
	cmd, err := policy.Command(ctx, "python3", "process_data.py")
	if err != nil {
		log.Fatal(err)
	}

	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
}

// This example demonstrates allowing localhost-only network access.
// This is useful for applications that need inter-process communication via TCP sockets
// (like Jupyter kernels) but should not access the internet.
func ExamplePolicy_Command_localhostOnly() {
	policy := sandbox.DefaultPolicy()
	policy.WorkDir = "/path/to/notebook"
	policy.AllowLocalhostOnly = true // Allow localhost, block internet

	ctx := context.Background()
	cmd, err := policy.Command(ctx, "jupyter", "nbconvert", "--execute", "notebook.ipynb")
	if err != nil {
		log.Fatal(err)
	}

	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
}

// This example demonstrates running a command with inherited stdio.
func ExamplePolicy_Exec() {
	policy := sandbox.DefaultPolicy()
	policy.WorkDir = "/path/to/workdir"

	ctx := context.Background()

	// Exec runs the command and waits for it to complete
	// stdout and stderr are inherited from the current process
	err := policy.Exec(ctx, "python3", "script.py")
	if err != nil {
		log.Fatal(err)
	}
}
