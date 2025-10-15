package boxedpy_test

import (
	"context"
	"fmt"
	"log"

	"github.com/bpowers/boxedpy"
	"github.com/bpowers/boxedpy/sandbox"
)

// This example demonstrates creating a Python instance from a virtualenv.
func ExampleNew() {
	// Create a Python instance pointing to your virtualenv
	py, err := boxedpy.New(boxedpy.Config{
		VirtualEnv: "/path/to/venv",
	})
	if err != nil {
		log.Fatal(err)
	}
	defer py.Close()

	fmt.Println("Python interpreter:", py.InterpreterPath())
}

// This example demonstrates running sandboxed Python code.
func ExamplePython_Command() {
	// Setup: create a Python instance
	py, err := boxedpy.New(boxedpy.Config{
		VirtualEnv: "/path/to/venv",
	})
	if err != nil {
		log.Fatal(err)
	}
	defer py.Close()

	// Create a sandbox policy with safe defaults
	policy := sandbox.DefaultPolicy()
	policy.WorkDir = "/path/to/workdir"

	// Create a sandboxed Python command
	ctx := context.Background()
	cmd, err := py.Command(ctx, policy, boxedpy.ExecConfig{}, "-c", "print('Hello from sandbox')")
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

// ExampleJupyterEnv demonstrates configuring Jupyter environment variables.
func ExampleJupyterEnv() {
	notebookDir := "/path/to/notebook"
	configDir := "/path/to/config"

	// Get Jupyter environment variables
	jupyterEnv := boxedpy.JupyterEnv(notebookDir, configDir)

	// Add to command environment
	// cmd.Env = append(os.Environ(), jupyterEnv...)

	// Print the environment variables (for demonstration)
	for _, envVar := range jupyterEnv {
		fmt.Println(envVar)
	}
	// Output will include:
	// IPYTHONDIR=/path/to/notebook/.ipython
	// JUPYTER_DATA_DIR=/path/to/notebook/.jupyter
	// ... and other Jupyter-related environment variables
}

// ExampleParsePythonError demonstrates parsing Python error output.
func ExampleParsePythonError() {
	// Simulated Python error output
	output := []byte(`Traceback (most recent call last):
  File "<string>", line 2, in <module>
NameError: name 'undefined_variable' is not defined`)

	// Parse the error
	pyErr := boxedpy.ParsePythonError(output)
	if pyErr != nil {
		fmt.Printf("Error Type: %s\n", pyErr.Type)
		fmt.Printf("Line: %d\n", pyErr.Line)
		fmt.Printf("Hint: %s\n", pyErr.Hint)
	}
	// Output:
	// Error Type: NameError
	// Line: 2
	// Hint: Variable 'undefined_variable' is not defined. Check for typos or ensure it's defined before use.
}
