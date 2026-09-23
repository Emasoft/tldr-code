# Tools Commands

Miscellaneous tools for development workflow integration.

## doctor

**Alias:** `doc`

**Purpose:** Check and install diagnostic tools for each language.

**Implementation:** `crates/tldr-cli/src/commands/doctor.rs`

**How it works:**
1. Detects installed tools per language
2. Reports missing tools
3. Optionally installs via `--install`

**Example:**
```bash
tldr doctor

# Install tools
tldr doctor --install python
tldr doctor --install rust
tldr doctor --install go
```

**Supported languages and tools** (type checker, linter — from `get_tool_info()` in the implementation):
- Python: pyright, ruff
- TypeScript: tsc
- JavaScript: eslint (linter only)
- Go: go, golangci-lint
- Rust: cargo, cargo-clippy
- Java: javac, checkstyle
- C: gcc, cppcheck
- C++: g++, cppcheck
- Ruby: rubocop
- PHP: phpstan
- Kotlin: kotlinc, ktlint
- Swift: swiftc, swiftlint
- C#: dotnet (type checker only)
- Scala: scalac (type checker only)
- Elixir: elixir, mix
- Lua: luacheck

`--install` auto-installs for a subset of languages (python, go, rust, ruby, kotlin, swift, lua); other languages only report install instructions.

---

## diagnostics

**Alias:** `diag`

**Purpose:** Run type checking and linting using external tools.

**Implementation:** `crates/tldr-cli/src/commands/diagnostics.rs`

**Example:**
```bash
tldr diagnostics src/

# Specific tools
tldr diagnostics src/ --tools pyright,ruff

# Skip type checking (linters only)
tldr diagnostics src/ --no-typecheck

# Skip linting (type checkers only)
tldr diagnostics src/ --no-lint

# Minimum severity (error|warning|info|hint; default hint)
tldr diagnostics src/ -s warning

# Ignore specific error codes
tldr diagnostics src/ --ignore E501,F401

# Fail on warnings, not just errors
tldr diagnostics src/ --strict

# Baseline workflow: show only new issues / save current results as baseline
tldr diagnostics src/ --baseline .tldr/diagnostics-baseline.json
tldr diagnostics src/ --save-baseline .tldr/diagnostics-baseline.json

# Output for GitHub Actions
tldr diagnostics src/ --output github-actions
```

---

## fix

**Alias:** `fx`

**Purpose:** Diagnose and auto-fix errors from compiler/runtime output.

**Subcommands:**

### fix diagnose

Parse error output and produce a structured diagnosis with optional fix. `--source <SOURCE>` is **required** (the source file to analyze for tree-sitter based analysis); the error text itself is passed via `-e/--error`, `--error-file`, or `--stdin` — it is never a positional argument.

```bash
# Inline error text (-e/--error; mutually exclusive with --error-file)
tldr fix diagnose --source src/main.ts -e "TS2339: Property 'foo' does not exist on type 'Bar'."

# Error text from a file
tldr fix diagnose --source src/main.ts --error-file build.log

# Error text from stdin (when neither --error nor --error-file is given)
cat build.log | tldr fix diagnose --source src/main.ts --stdin

# Enhance analysis with an API surface JSON (e.g. TS2339 property suggestions)
tldr fix diagnose --source src/main.ts -e "TS2339: ..." --api-surface surface.json
```

### fix apply

Apply fix edits to source code and write the patched result. `--source <SOURCE>` is **required**; the error text is passed via `-e/--error`, `--error-file`, or `--stdin` (same contract as `fix diagnose` — stdin carries error text, never a fixes JSON). The patched source goes to **stdout** by default; write it with `-o/--output <FILE>` or `-i/--in-place`, and preview with `-d/--diff` (unified diff instead of the full patched source).

```bash
# Patched source to stdout
tldr fix apply --source src/main.ts -e "TS2339: Property 'foo' does not exist on type 'Bar'."

# Error text from a file, patched in place
tldr fix apply --source src/main.ts --error-file build.log --in-place

# Preview as a unified diff
tldr fix apply --source src/main.ts --error-file build.log --diff

# Write the patched result to a different file
tldr fix apply --source src/main.ts --error-file build.log -o src/main.fixed.ts

# Enhanced analysis with an API surface JSON (e.g. TS2339 property suggestions)
tldr fix apply --source src/main.ts -e "TS2339: ..." --api-surface surface.json
```

### fix check

Run test command, diagnose failures, apply fixes, and re-run in a loop. Requires `--file <FILE>` (the source file to fix) and `--test-cmd <TEST_CMD>` (the test command as a single quoted string); `--max-attempts` caps the loop (default: 5).

```bash
tldr fix check --file src/app.py --test-cmd "pytest tests/test_app.py"

# Cap the fix loop at 3 attempts
tldr fix check --file src/index.ts --test-cmd "npm test" --max-attempts 3
```

---

## bugbot

**Purpose:** Automated bug detection on code changes.

**Subcommands:**

### bugbot check

Run bugbot check on uncommitted changes (or against a base ref).

```bash
tldr bugbot check

# Staged files only
tldr bugbot check --staged

# Diff against a specific base ref (default: HEAD)
tldr bugbot check --base-ref origin/main

# Cap findings, don't fail the build, skip commodity tools
tldr bugbot check --max-findings 20 --no-fail --no-tools
```

Flags: `--base-ref <BASE_REF>` (default `HEAD`), `--staged`, `--max-findings <N>` (default 50, `0` = unlimited), `--no-fail`, `--no-tools` (disable L1 commodity tool analysis), `--tool-timeout <SECONDS>` (default 60). There is no `--uncommitted` flag.

**Checks performed:**
- Syntax errors introduced
- Type errors from changes
- API contract violations
- Known bug patterns

---

## diff

**Alias:** `df`

**Purpose:** AST-aware structural diff between two files.

**Implementation:** `crates/tldr-cli/src/commands/remaining/diff.rs`

**Granularity levels:**
- `token` (L1) — Token-level diff
- `expression` (L2) — Expression-level diff
- `statement` (L3) — Statement-level diff
- `function` (L4) — Function-level diff (default)
- `class` (L5) — Class-level diff
- `file` (L6) — File-level diff
- `module` (L7) — Module-level diff
- `architecture` (L8) — Architecture-level diff

**Example:**
```bash
tldr diff src/v1/utils.py src/v2/utils.py

# Expression-level diff
tldr diff src/v1/main.py src/v2/main.py -g expression

# Exclude formatting-only changes
tldr diff src/v1/main.py src/v2/main.py --semantic-only
```

---

## surface

**Alias:** `surf`

**Purpose:** Extract machine-readable API surface for a library/package.

**Example:**
```bash
tldr surface requests

# Lookup specific API
tldr surface requests --lookup requests.Session

# Include private APIs
tldr surface mylib --include-private

# Cap the number of APIs extracted (default: unlimited)
tldr surface requests --limit 50

# Rust crate resolution via a specific manifest
tldr surface . --manifest-path crates/mylib/Cargo.toml
```

---

## deps

**Alias:** `dep`

**Purpose:** Analyze module dependencies.

**Example:**
```bash
tldr deps src/

# Include external deps
tldr deps src/ --include-external

# Show cycles only
tldr deps src/ --show-cycles

# Cap reported cycle length (default 10)
tldr deps src/ --max-cycle-length 5

# Collapse files into package-level nodes
tldr deps src/ --collapse-packages

# Limit depth
tldr deps src/ -d 3
```

---

## change-impact

**Alias:** `ci`

**Purpose:** Find tests affected by code changes.

**Example:**
```bash
tldr change-impact src/

# Explicit changed files
tldr change-impact src/ -F src/main.py,src/utils.py

# Base branch
tldr change-impact src/ -b origin/main

# Staged only (pre-commit) / all uncommitted changes
tldr change-impact src/ --staged
tldr change-impact src/ --uncommitted

# Bound call-graph traversal (default 10) and include the import graph
tldr change-impact src/ -d 5 --include-imports

# Custom test-file globs (comma-separated)
tldr change-impact src/ --test-patterns "tests/**/*_test.py,tests/**/test_*.py"

# pytest format
tldr change-impact src/ --runner pytest-k

# Jest format
tldr change-impact src/ --runner jest
```

---

## todo

**Purpose:** Aggregate improvement suggestions.

**Aggregates from:**
- `dead` — Dead code
- `complexity` — High complexity functions
- `cohesion` — Low cohesion classes
- `similar` — Similar code fragments

**Example:**
```bash
tldr todo src/

# Quick mode
tldr todo src/ --quick

# Cap displayed items (default 20; 0 = show all)
tldr todo src/ --max-items 50

# Specific detail
tldr todo src/ --detail dead_code
```
