# boxedpy

Safe Python code execution for AI agents with cross-platform sandboxing.

## Why boxedpy?

Running untrusted Python code safely requires robust sandboxing across different platforms. boxedpy solves this by providing:

- **Unified sandbox API**: Write your code once, runs on Linux (bubblewrap) and macOS (Seatbelt) without changes
- **Security by default**: Network isolation, filesystem restrictions, and process isolation built-in
- **Python-focused**: Virtualenv integration, Jupyter support, and helpful error parsing
- **Production-ready**: Comprehensive test coverage, concurrent-safe implementations, and battle-tested across platforms

## Repository Layout

```
sandbox/            # Cross-platform sandboxing primitives
  policy.go         # Sandbox policy configuration
  exec_linux.go     # Linux bubblewrap implementation
  exec_darwin.go    # macOS Seatbelt implementation
  exec.go           # Common sandbox interface
boxedpy.go          # Python virtualenv wrapper
policy.go           # Python-specific command creation
jupyter.go          # Jupyter environment configuration
errors.go           # Python error parsing with hints
```

## Commit Message Style

- Initial-line format: component: description
- Component prefix: Use the module/directory name (e.g., sandbox, boxedpy, errors)
- Description: Start with lowercase, present tense verb, no period
- Length: Keep the initial line concise, typically under 60 characters
- Examples:
  - sandbox: add localhost-only network isolation
  - boxedpy: fix virtualenv path resolution
  - errors: improve ModuleNotFoundError hints
- Add 1 to 2 paragraphs of the "why" of the change in the body of the commit message. Especially highlight any assumptions you made or non-obvious pieces of the change.
- DO NOT use any emoji in the commit message.


## Development Workflow

It is CRITICAL that you NEVER use the `--no-verify` flag with `git commit`.

When working on this codebase, follow this systematic approach:

### 0. Problem-Solving Philosophy

- **Write high-quality, general-purpose solutions**: Implement solutions that work correctly for all valid inputs, not just test cases. Do not hard-code values or create solutions that only work for specific test inputs.
- **Prioritize the right approach over the first approach**: Research the proper way to implement features rather than implementing workarounds. For example, check platform documentation before implementing sandbox features.
- **Keep implementations simple and maintainable**: Start with the simplest solution that meets requirements. Only add complexity when the simple approach demonstrably fails.
- **No special casing in tests**: Tests should hold all implementations to the same standard. Never add conditional logic in tests that allows certain implementations to skip requirements.
- **Complete all aspects of a task**: When fixing bugs or implementing features, ensure the fix works for all code paths, not just the primary one. Continue making progress until all aspects of the user's task are done, including newly discovered but necessary work and rework along the way.

### 1. Understanding Requirements
- Read relevant code and documentation (including for libraries via `go doc`) and build a plan based on the user's task.
- ultrathink: if there are important and ambiguous high-level architecture decisions or "trapdoor" choices, stop and ask the user.
- All implementations must work consistently across platforms (Linux and macOS) unless platform-specific by nature.
- Start by adding tests to validate assumptions before making changes.
- Remember: we want to build the simplest interfaces and abstractions possible while fully addressing the intrinsic complexity of the problem domain.

### 2. Test-First Development
When fixing bugs or adding features:
1. **Write tests first** that validate the expected behavior
2. **Run tests to confirm the issue** exists across platforms (where applicable)
3. **Fix implementations** one component at a time
4. **Run gofumpt** after each change: `gofumpt -w <modified files>`
5. **Ensure all tests pass** before committing
6. **Commit with descriptive messages** strictly following the commit message style from above

### 3. Multi-Step Task Execution
For complex tasks with multiple components:
1. **Break down into discrete tasks** and track with a todo list
2. **Complete each task fully** including tests and formatting before moving to the next
3. **Commit each logical change separately** with clear commit messages
4. **Boldly refactor** when needed - there's no legacy code to preserve
5. **Address the root cause** if you find that a problem is due to a bad abstraction or deficiency in the current code, stop and create a plan to directly address it. Do not work around it by skipping tests or leaving part of the user's task unaddressed. Use the same "Problem-Solving Philosophy", "Understanding Requirements" steps and "Multi-Step Task Execution" approach when this happens - it is much more important that we are systematically improving this codebase than completing tasks as quickly as possible.


## Development Guide

This section contains important details for how developers and AI agents working on this codebase should structure their code and solutions.

### Go Development Standards

#### Code Style and Safety
- You MUST write concurrency-safe code by default. Favor immutability; use mutexes for shared mutable state.
- Prefer sync.Mutex over sync.RWMutex unless explicitly instructed otherwise: nothing at the level of abstraction of this problem domain is performance sensitive enough to need separate read + write locks.
- ALWAYS call Unlock()/RUnlock() in a defer statement, never synchronously
- Remember: Go mutexes are not reentrant. If you need to call logic that requires holding a lock from callers that both already have the lock held and ones that don't, split the functionality in two: e.g. add a `GetTokens()` method that obtains a lock (and defers the unlock), and then a (non-exported) `getTokensLocked()` method with the actual logic, called both from `GetTokens` and any other package-internal callers who themselves hold the lock. The function's godoc comment should detail _which_ lock is expected to be held, and `*Locked` variants should NEVER be visible to callers outside the package. The package's public API should not expose the intricacies of locking to users: it should just work.
- Use `go doc` to inspect and understand third-party APIs before implementing
- Run `gofumpt -w .` before committing to ensure proper formatting
- Use `omitzero` instead of `omitempty` in JSON struct tags


#### Testing
- Run tests with `go test -race ./...` to verify correctness and race-freedom.
- Use `github.com/stretchr/testify/assert` and `require` for test assertions.
  - Use `require` for fatal errors that should stop the test immediately (like setup failures).
  - Use `assert` for non-fatal assertions that allow the test to continue gathering information.
  - The default error messages are clear enough, avoid adding custom messages to assertions.
- Write table-driven tests with `t.Run()` to test all variations comprehensively.
- Use `t.Parallel()` for tests that can run concurrently (most tests).
- Platform-specific tests should use `runtime.GOOS` checks and `t.Skip()` when appropriate.


#### Project Conventions
- This is a standalone library package with no external dependencies beyond the Go standard library and testify
- When introducing a new abstraction, migrate all users to it and completely remove the old one
- Be bold in refactoring - there's no "legacy code" to preserve


### Sandbox Implementation Patterns

When implementing features across platforms, follow these established patterns:

#### Platform-Specific Sandboxing
Each platform uses different sandboxing technologies:

**Linux (bubblewrap)**:
- Full namespace isolation (network, IPC, PID, mount)
- Fine-grained filesystem control with bind mounts
- Process dies with parent via `--die-with-parent`
- New session prevents terminal control
- Explicit mount specification (nothing accessible unless mounted)
- Network can be completely blocked or fully allowed

**macOS (Seatbelt)**:
- Profile-based sandboxing with declarative rules
- Filesystem access controlled via `(allow file-read*)` and `(allow file-write*)` rules
- Network isolation via IP-based rules (supports localhost-only filtering)
- Requires canonicalized paths (handles /var -> /private/var symlinks)
- System directories accessible by default unless explicitly denied
- Less strict process isolation than Linux

**Key differences**:
- Linux requires explicit mounts; macOS requires explicit restrictions
- Linux blocks all network by default; macOS allows all by default
- Linux uses namespaces; macOS uses profile evaluation
- Path canonicalization critical on macOS for symlink handling

#### Mount Management & Isolation

Mount handling follows these patterns:

**Read-Only Mounts**:
- Virtualenv directories (never writable)
- Reference/data directories (for input data access)
- System libraries and binaries (implicit on Linux, explicit on macOS)
- Mounted at the same path inside and outside the sandbox

**Read-Write Mounts**:
- Working directory (where user code runs)
- Config directory (for matplotlib, jupyter, etc. state)
- Output directories (for results)
- Must be carefully controlled to prevent escape

**Mount Deduplication**:
- Both platforms track mounts to avoid duplicates
- `mountSet` helper prevents redundant entries
- Critical for performance and correctness

**Path Resolution**:
- All mount paths must be absolute (no relative paths)
- macOS requires canonicalization via `filepath.EvalSymlinks`
- Validation ensures paths exist before mounting
- Deep copying policies prevents mount accumulation across concurrent uses

**Temporary Directory Isolation**:
- Linux: tmpfs mount provides completely isolated /tmp
- macOS: temp directory created in host OS, mounted read-write, cleanup via finalizer
- Both set TMPDIR environment variable to isolated location

#### Platform-Specific Quirks

**Linux**:
- Requires bubblewrap (`bwrap`) installed system-wide
- Needs `/proc` mounted for process introspection
- Requires explicit device mounts (`/dev/null`, `/dev/random`, etc.)
- `--die-with-parent` prevents orphaned processes
- Namespace creation may fail without sufficient privileges

**macOS**:
- Seatbelt policies use S-expression syntax
- Must canonicalize all paths to handle system symlinks
- Homebrew paths (`/opt`, `/usr/local`) must be explicitly mounted
- `AllowLocalhostOnly` uses `(remote ip "localhost:*")` syntax
- `AllowSharedNamespaces` flag is ignored (not applicable to Seatbelt)
- System directories like `/System`, `/usr` accessible by default

**Both**:
- Working directory must exist before creating command
- Environment variables inherited from parent by default
- Command context cancellation propagates to sandboxed process
- Cleanup of temp directories is best-effort (finalizers not guaranteed to run)

#### Common Pitfalls to Avoid

**Mount Configuration**:
- Forgetting to mount the virtualenv on any platform
- Not mounting Homebrew paths on macOS (leads to import errors)
- Using relative paths instead of absolute paths
- Mounting the same path as both read-only and read-write (behavior undefined)
- Not validating paths exist before mounting

**Path Handling**:
- Not canonicalizing paths on macOS (breaks with symlinks)
- Assuming paths inside sandbox differ from outside (they're the same)
- Forgetting that macOS resolves `/var` to `/private/var`

**Policy Reuse**:
- Modifying shared Policy instances (causes data races)
- Not deep-copying mount slices when creating commands
- Accumulating mounts across multiple Command() calls

**Network Isolation**:
- Assuming network is blocked by default on macOS (it's not)
- Not setting `AllowLocalhostOnly` for Jupyter (kernel communication fails)
- Using `AllowNetwork` unnecessarily (security risk)

**Cleanup & Lifecycle**:
- Not calling `Close()` on Python instances (leaks temp directories)
- Calling `Close()` while Python instance still in use
- Assuming finalizers will always run (they won't)
- Not handling command cancellation properly

**Platform Assumptions**:
- Writing Linux-specific code without macOS equivalent
- Not testing on both platforms
- Assuming features work the same on both platforms


### Project Maintenance

- Keep platform-specific logic in `exec_linux.go` and `exec_darwin.go`
- Shared sandbox interface stays in `policy.go` and `exec.go`
- Python-specific logic stays in `boxedpy.go` and `policy.go` (main package)
- Update tests when adding new features
- Maintain backward compatibility for the public API
- Test on both Linux and macOS when changing sandbox behavior
