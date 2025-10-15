package boxedpy

import (
	"path/filepath"
)

// JupyterEnv returns environment variables for Jupyter/IPython execution.
// Configures all Jupyter paths to use notebookDir, avoiding home directory writes.
// The configDir is used for MPLCONFIGDIR.
//
// Returns a slice of "KEY=VALUE" strings suitable for appending to cmd.Env.
// The environment variables include: IPYTHONDIR, JUPYTER_DATA_DIR, JUPYTER_RUNTIME_DIR,
// JUPYTER_CONFIG_DIR, JUPYTER_PLATFORM_DIRS, MPLCONFIGDIR, TERM.
//
// These environment variables ensure that Jupyter and related tools write their
// configuration, data, and runtime files to the specified directories rather than
// to the user's home directory, which is important for sandboxed execution.
//
// Example usage:
//
//	env := boxedpy.JupyterEnv("/path/to/notebook/dir", "/path/to/config")
//	cmd.Env = append(os.Environ(), env...)
func JupyterEnv(notebookDir, configDir string) []string {
	jupyterData := filepath.Join(notebookDir, ".jupyter")

	return []string{
		"IPYTHONDIR=" + filepath.Join(notebookDir, ".ipython"),
		"JUPYTER_DATA_DIR=" + jupyterData,
		"JUPYTER_RUNTIME_DIR=" + filepath.Join(jupyterData, "runtime"),
		"JUPYTER_CONFIG_DIR=" + filepath.Join(notebookDir, ".jupyter_config"),
		"JUPYTER_PLATFORM_DIRS=1",
		"MPLCONFIGDIR=" + configDir,
		"TERM=dumb",
	}
}
