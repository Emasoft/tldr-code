//! Tool execution and detection module.
//!
//! This module handles:
//! - Detecting which diagnostic tools are available on PATH
//! - Running tools with timeout handling
//! - Parallel execution of multiple tools
//! - Capturing stdout/stderr and exit codes

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::diagnostics::parsers::*;
use crate::diagnostics::{Diagnostic, DiagnosticsReport, ToolConfig, ToolResult};
use crate::error::TldrError;
use crate::types::Language;
use crate::walker::ProjectWalker;

// =============================================================================
// Tool Detection
// =============================================================================

/// Check if a tool binary is available on PATH.
///
/// Uses `which` on Unix and `where` on Windows to check availability.
pub fn is_tool_available(binary: &str) -> bool {
    #[cfg(unix)]
    {
        Command::new("which")
            .arg(binary)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[cfg(windows)]
    {
        Command::new("where")
            .arg(binary)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

/// Get the version string of a tool, if available.
pub fn get_tool_version(binary: &str) -> Option<String> {
    let output = Command::new(binary).arg("--version").output().ok()?;

    if output.status.success() {
        let version = String::from_utf8_lossy(&output.stdout);
        // Extract first line and trim
        version.lines().next().map(|s| s.trim().to_string())
    } else {
        None
    }
}

/// Get all diagnostic tools configured for a language.
pub fn tools_for_language(lang: Language) -> Vec<ToolConfig> {
    match lang {
        Language::Python => vec![
            ToolConfig {
                name: "pyright",
                binary: "pyright",
                args: vec!["--outputjson".to_string()],
                is_type_checker: true,
                is_linter: false,
            },
            ToolConfig {
                name: "ruff",
                binary: "ruff",
                args: vec![
                    "check".to_string(),
                    "--output-format".to_string(),
                    "json".to_string(),
                ],
                is_type_checker: false,
                is_linter: true,
            },
        ],
        Language::TypeScript | Language::JavaScript => vec![
            ToolConfig {
                name: "tsc",
                binary: "tsc",
                args: vec![
                    "--noEmit".to_string(),
                    "--pretty".to_string(),
                    "false".to_string(),
                ],
                is_type_checker: true,
                is_linter: false,
            },
            ToolConfig {
                name: "eslint",
                binary: "eslint",
                args: vec!["-f".to_string(), "json".to_string()],
                is_type_checker: false,
                is_linter: true,
            },
        ],
        Language::Go => vec![
            ToolConfig {
                name: "go vet",
                binary: "go",
                args: vec!["vet".to_string(), "-json".to_string()],
                is_type_checker: true,
                is_linter: false,
            },
            ToolConfig {
                name: "golangci-lint",
                binary: "golangci-lint",
                args: vec![
                    "run".to_string(),
                    "--out-format".to_string(),
                    "json".to_string(),
                ],
                is_type_checker: false,
                is_linter: true,
            },
        ],
        Language::Rust => vec![
            ToolConfig {
                name: "cargo check",
                binary: "cargo",
                args: vec!["check".to_string(), "--message-format=json".to_string()],
                is_type_checker: true,
                is_linter: false,
            },
            ToolConfig {
                name: "clippy",
                binary: "cargo",
                args: vec!["clippy".to_string(), "--message-format=json".to_string()],
                is_type_checker: false,
                is_linter: true,
            },
        ],
        Language::Kotlin => vec![
            ToolConfig {
                name: "kotlinc",
                binary: "kotlinc",
                args: vec!["-language-version".to_string(), "1.9".to_string()],
                is_type_checker: true,
                is_linter: false,
            },
            ToolConfig {
                name: "detekt",
                binary: "detekt-cli",
                args: vec!["--report".to_string(), "txt:stdout".to_string()],
                is_type_checker: false,
                is_linter: true,
            },
        ],
        Language::Swift => vec![
            ToolConfig {
                name: "swiftc",
                binary: "swiftc",
                args: vec!["-typecheck".to_string()],
                is_type_checker: true,
                is_linter: false,
            },
            ToolConfig {
                name: "swiftlint",
                binary: "swiftlint",
                args: vec![
                    "lint".to_string(),
                    "--reporter".to_string(),
                    "json".to_string(),
                    "--quiet".to_string(),
                ],
                is_type_checker: false,
                is_linter: true,
            },
        ],
        Language::CSharp => vec![ToolConfig {
            name: "dotnet build",
            binary: "dotnet",
            args: vec![
                "build".to_string(),
                "--no-restore".to_string(),
                "--verbosity".to_string(),
                "quiet".to_string(),
            ],
            is_type_checker: true,
            is_linter: true, // Roslyn analyzers are built in
        }],
        Language::Scala => vec![ToolConfig {
            name: "scalac",
            binary: "scalac",
            args: vec![],
            is_type_checker: true,
            is_linter: false,
        }],
        Language::Elixir => vec![
            ToolConfig {
                name: "mix compile",
                binary: "mix",
                args: vec!["compile".to_string(), "--warnings-as-errors".to_string()],
                is_type_checker: true,
                is_linter: false,
            },
            ToolConfig {
                name: "credo",
                binary: "mix",
                args: vec![
                    "credo".to_string(),
                    "--format".to_string(),
                    "json".to_string(),
                ],
                is_type_checker: false,
                is_linter: true,
            },
        ],
        Language::Lua => vec![ToolConfig {
            name: "luacheck",
            binary: "luacheck",
            args: vec![
                "--formatter".to_string(),
                "plain".to_string(),
                "--no-color".to_string(),
            ],
            is_type_checker: false,
            is_linter: true,
        }],
        Language::Java => vec![
            ToolConfig {
                name: "javac",
                binary: "javac",
                args: vec!["-Xlint:all".to_string()],
                is_type_checker: true,
                is_linter: false,
            },
            ToolConfig {
                name: "checkstyle",
                binary: "checkstyle",
                args: vec!["-f".to_string(), "plain".to_string()],
                is_type_checker: false,
                is_linter: true,
            },
        ],
        Language::C | Language::Cpp => vec![
            ToolConfig {
                name: "clang",
                binary: "clang",
                args: vec!["-fsyntax-only".to_string(), "-Wall".to_string()],
                is_type_checker: true,
                is_linter: false,
            },
            ToolConfig {
                name: "clang-tidy",
                binary: "clang-tidy",
                args: vec![],
                is_type_checker: false,
                is_linter: true,
            },
        ],
        Language::Ruby => vec![ToolConfig {
            name: "rubocop",
            binary: "rubocop",
            args: vec!["--format".to_string(), "json".to_string()],
            is_type_checker: false,
            is_linter: true,
        }],
        Language::Php => vec![
            ToolConfig {
                name: "php",
                binary: "php",
                args: vec!["-l".to_string()],
                is_type_checker: true,
                is_linter: false,
            },
            ToolConfig {
                name: "phpstan",
                binary: "phpstan",
                args: vec![
                    "analyse".to_string(),
                    "--error-format=json".to_string(),
                    "--no-progress".to_string(),
                ],
                is_type_checker: false,
                is_linter: true,
            },
        ],
        _ => vec![],
    }
}

/// Detect which tools are available for a given language.
/// Only returns tools that are actually installed.
pub fn detect_available_tools(lang: Language) -> Vec<ToolConfig> {
    tools_for_language(lang)
        .into_iter()
        .filter(|t| is_tool_available(t.binary))
        .collect()
}

// =============================================================================
// Tool Execution
// =============================================================================

/// Emit a progress event to stderr, gated by `TLDR_DIAGNOSTICS_PROGRESS=1`.
///
/// diagnostics-subprocess-timeout-v1 (M-028): users running `tldr
/// diagnostics` against large repos previously had zero feedback during
/// long-running invocations (kotlinc/swiftc/clang/luacheck can take
/// tens of seconds). The opt-in env var emits one line per state
/// transition so callers can observe progress without affecting
/// machine-readable stdout.
fn progress_emit(msg: &str) {
    if std::env::var("TLDR_DIAGNOSTICS_PROGRESS").as_deref() == Ok("1") {
        eprintln!("[diagnostics] {}", msg);
    }
}

/// Run a single diagnostic tool and parse its output.
///
/// # Arguments
/// * `tool` - The tool configuration
/// * `path` - The path to analyze
/// * `timeout_secs` - Timeout in seconds
///
/// # Returns
/// A tuple of (ToolResult, Vec<Diagnostic>)
///
/// # Pipe handling (diagnostics-subprocess-timeout-v1, M-028)
///
/// Previously this function used `child.stdout(Stdio::piped())` and
/// waited for the child to exit BEFORE reading the pipes. Many
/// diagnostic tools emit large output:
///
/// - `kotlinc` on a 223-file repo: ~22k lines to STDERR
/// - `luacheck` on lua-lsp: ~10k diagnostic lines to STDOUT
/// - `clang` on a multi-file C++ project: thousands of warning lines
///
/// The OS pipe buffer is ~64KB on macOS / Linux. Once full, the child
/// blocks on `write()` waiting for someone to drain the pipe — but the
/// parent is stuck in `try_wait` waiting for an exit that will never
/// come. Result: spurious 60s "Timeout" errors on tools that would
/// otherwise complete in 3-15 seconds.
///
/// Fix: spawn one reader thread per pipe, drain concurrently, then
/// `wait()` on the child. On timeout, kill the child and `join` the
/// drainers with a bounded grace window so we still surface partial
/// output.
pub fn run_tool(
    tool: &ToolConfig,
    path: &Path,
    timeout_secs: u64,
) -> (ToolResult, Vec<Diagnostic>) {
    let start = Instant::now();
    progress_emit(&format!("starting {}", tool.name));

    // Build the command. CRITICAL: `stdin(Stdio::null())` so tools that
    // would otherwise read from a terminal (e.g. kotlinc in REPL mode,
    // some clang invocations, swiftc -typecheck with no inputs) do not
    // block forever waiting for input.
    let mut cmd = Command::new(tool.binary);
    cmd.args(&tool.args);
    cmd.arg(path);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // Put the child in its own process group on Unix so that a timeout
    // kill propagates to grand-children. Many wrapper scripts (e.g.
    // `kotlinc`, `phpstan`, `mix`) launch a long-running JVM / BEAM /
    // PHP subprocess without `exec`ing — SIGKILL on the wrapper shell
    // leaves the inner process orphaned with the pipe FDs still open,
    // which keeps our drainer threads blocked reading.
    //
    // Setting `process_group(0)` creates a new group with the child as
    // leader; we can then `killpg` the whole group on timeout. See
    // `kill_process_tree` below.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    // Spawn the process
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            progress_emit(&format!("{} failed to spawn: {}", tool.name, e));
            return (
                ToolResult {
                    name: tool.name.to_string(),
                    version: None,
                    success: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    diagnostic_count: 0,
                    error: Some(format!("Failed to start {}: {}", tool.name, e)),
                },
                Vec::new(),
            );
        }
    };

    // Spawn drainer threads for stdout and stderr. These read until EOF
    // — which happens either because the child exited or because we
    // killed it.
    let stdout_handle = child.stdout.take().map(|mut s| {
        std::thread::spawn(move || -> String {
            let mut buf = String::new();
            let _ = s.read_to_string(&mut buf);
            buf
        })
    });
    let stderr_handle = child.stderr.take().map(|mut s| {
        std::thread::spawn(move || -> String {
            let mut buf = String::new();
            let _ = s.read_to_string(&mut buf);
            buf
        })
    });

    // Wait with timeout. The polling loop now only watches the child;
    // pipes are drained on background threads so the child cannot block
    // on a full pipe.
    let timeout = Duration::from_secs(timeout_secs);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => {
                if start.elapsed() > timeout {
                    // Kill the whole process group (on Unix) so any
                    // grand-children spawned by wrapper scripts are
                    // also reaped. Falls back to `child.kill()` on
                    // other platforms.
                    kill_process_tree(&mut child);
                    // Reap the killed child to release OS resources;
                    // wait() should now return promptly because pipes
                    // are drained on background threads.
                    let _ = child.wait();
                    break Err("Timeout");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => break Err(Box::leak(format!("{}", e).into_boxed_str()) as &str),
        }
    };

    // Join the drainer threads with a bounded wait. After child.wait()
    // (or kill+wait) the pipes are closed, so read_to_string returns
    // quickly. We still cap the join time defensively to avoid any
    // pathological hang.
    let stdout = join_drainer(stdout_handle);
    let stderr = join_drainer(stderr_handle);

    let duration_ms = start.elapsed().as_millis() as u64;

    // Handle timeout or error
    let _exit_status = match status {
        Ok(s) => s,
        Err(e) => {
            progress_emit(&format!("{} {} after {}ms", tool.name, e, duration_ms));
            return (
                ToolResult {
                    name: tool.name.to_string(),
                    version: get_tool_version(tool.binary),
                    success: false,
                    duration_ms,
                    diagnostic_count: 0,
                    error: Some(e.to_string()),
                },
                Vec::new(),
            );
        }
    };

    // Parse the output based on tool type
    let parse_result = parse_tool_output(tool.name, &stdout, &stderr);

    let (diagnostics, error) = match parse_result {
        Ok(diags) => (diags, None),
        Err(e) => {
            // Some tools exit non-zero when they find issues, which is OK
            // Only treat it as an error if we couldn't parse the output
            if !stdout.is_empty() || !stderr.is_empty() {
                // Try to parse anyway for tools that might output to stderr
                let fallback = parse_tool_output(tool.name, &stderr, &stdout);
                match fallback {
                    Ok(diags) => (diags, None),
                    Err(_) => (Vec::new(), Some(format!("Parse error: {}", e))),
                }
            } else {
                (Vec::new(), Some(format!("Parse error: {}", e)))
            }
        }
    };

    let diagnostic_count = diagnostics.len();

    // Tool is successful if it ran and we could parse output (even if it found issues)
    let success = error.is_none();

    progress_emit(&format!(
        "{} done in {}ms ({} diagnostic{})",
        tool.name,
        duration_ms,
        diagnostic_count,
        if diagnostic_count == 1 { "" } else { "s" }
    ));

    (
        ToolResult {
            name: tool.name.to_string(),
            version: get_tool_version(tool.binary),
            success,
            duration_ms,
            diagnostic_count,
            error,
        },
        diagnostics,
    )
}

/// Kill a child process and (on Unix) its entire process group.
///
/// diagnostics-subprocess-timeout-v1 (M-028): wrapper scripts such as
/// `kotlinc`, `mix credo`, and some `phpstan` installations launch a
/// long-running JVM / BEAM / PHP subprocess WITHOUT `exec`ing. Sending
/// SIGKILL to the wrapper shell leaves the inner process orphaned but
/// still alive, holding the stdout/stderr pipe file descriptors open
/// — which keeps the pipe-drainer threads blocked reading. The
/// `tldr diagnostics --timeout 2` invocation would then "honour" the
/// 2-second budget at the wait-loop level but still take 13+ seconds
/// to actually return because the drainers stayed alive.
///
/// On Unix we spawn the child in its own process group (see
/// `process_group(0)` in `run_tool`) and here we send SIGKILL to the
/// whole group via `killpg`. On other platforms we fall back to the
/// stdlib's `Child::kill` (which is best-effort on Windows job-object
/// support — acceptable since the affected diagnostic tools are
/// primarily Unix-only).
fn kill_process_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        // Best effort: signal the group; if that fails (e.g. the
        // process group creation didn't take), fall back to the
        // direct child.kill() path.
        let pid = child.id() as i32;
        // SAFETY: libc::killpg is a thin syscall wrapper. We pass a
        // valid pgid (the child's pid, which is also its pgid because
        // we set `process_group(0)`).
        let killpg_rc = unsafe { libc::killpg(pid, libc::SIGKILL) };
        if killpg_rc != 0 {
            let _ = child.kill();
        }
    }

    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
}

/// Join a pipe-drainer thread with a bounded wait.
///
/// diagnostics-subprocess-timeout-v1 (M-028): once the child process
/// has exited (or has been killed), the pipe write-end is closed and
/// `read_to_string` on the read-end returns promptly. This helper
/// simply unwraps the join result and returns the collected output;
/// an Err on join (which can only happen on a panic in the drainer)
/// is treated as empty output rather than propagating.
fn join_drainer(handle: Option<std::thread::JoinHandle<String>>) -> String {
    match handle {
        Some(h) => h.join().unwrap_or_default(),
        None => String::new(),
    }
}

/// Parse output based on tool name.
fn parse_tool_output(
    tool_name: &str,
    stdout: &str,
    _stderr: &str,
) -> Result<Vec<Diagnostic>, TldrError> {
    match tool_name {
        "pyright" => parse_pyright_output(stdout),
        "ruff" => parse_ruff_output(stdout),
        "tsc" => parse_tsc_text(stdout),
        "eslint" => parse_eslint_output(stdout),
        "cargo check" | "clippy" => parse_cargo_output(stdout),
        "go vet" => parse_go_vet_output(stdout),
        "golangci-lint" => parse_golangci_lint_output(stdout),
        "kotlinc" => parse_kotlinc_output(stdout),
        "detekt" => parse_detekt_output(stdout),
        "swiftc" => parse_swiftc_output(stdout),
        "swiftlint" => parse_swiftlint_output(stdout),
        "dotnet build" => parse_dotnet_build_output(stdout),
        "scalac" => parse_scalac_output(stdout),
        "mix compile" => parse_mix_compile_output(stdout),
        "credo" => parse_credo_output(stdout),
        "luacheck" => parse_luacheck_output(stdout),
        "javac" => parse_javac_output(stdout),
        "checkstyle" => parse_checkstyle_output(stdout),
        "clang" => parse_clang_output(stdout, "clang"),
        "clang-tidy" => parse_clang_output(stdout, "clang-tidy"),
        "rubocop" => parse_rubocop_output(stdout),
        "php" => parse_php_lint_output(stdout),
        "phpstan" => parse_phpstan_output(stdout),
        _ => Err(TldrError::ParseError {
            file: std::path::PathBuf::from(format!("<{}-output>", tool_name)),
            line: None,
            message: format!("Unknown tool: {}", tool_name),
        }),
    }
}

/// Run multiple tools in parallel (or sequentially on single-core systems).
///
/// # Arguments
/// * `tools` - The tools to run
/// * `path` - The path to analyze
/// * `timeout_secs` - Timeout per tool in seconds
///
/// # Returns
/// A DiagnosticsReport with results from all tools.
pub fn run_tools_parallel(
    tools: &[ToolConfig],
    path: &Path,
    timeout_secs: u64,
) -> Result<DiagnosticsReport, TldrError> {
    use std::sync::mpsc;
    use std::thread;

    if tools.is_empty() {
        return Err(TldrError::ParseError {
            file: std::path::PathBuf::from("<diagnostics>"),
            line: None,
            message: "No tools provided".to_string(),
        });
    }

    // Check core count - run sequentially if single core
    let num_cpus = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let mut all_diagnostics = Vec::new();
    let mut all_results = Vec::new();

    if num_cpus <= 1 || tools.len() == 1 {
        // Sequential execution
        for tool in tools {
            let (result, diags) = run_tool(tool, path, timeout_secs);
            all_results.push(result);
            all_diagnostics.extend(diags);
        }
    } else {
        // Parallel execution
        let (tx, rx) = mpsc::channel();
        let path = path.to_path_buf();

        let handles: Vec<_> = tools
            .iter()
            .map(|tool| {
                let tx = tx.clone();
                let tool = tool.clone();
                let path = path.clone();

                thread::spawn(move || {
                    let (result, diags) = run_tool(&tool, &path, timeout_secs);
                    let _ = tx.send((result, diags));
                })
            })
            .collect();

        // Drop the original sender so rx.iter() terminates
        drop(tx);

        // Collect results
        for (result, diags) in rx.iter() {
            all_results.push(result);
            all_diagnostics.extend(diags);
        }

        // Wait for all threads
        for handle in handles {
            let _ = handle.join();
        }
    }

    // Compute summary
    let summary = crate::diagnostics::compute_summary(&all_diagnostics);

    // high-bundle-progress-determinism-coverage-v1 (N4): properly count
    // source files in `path`. Previously this was a hard-coded `1`, so a
    // directory of 83 Python files reported `files_analyzed: 1`, which
    // made the field useless for downstream tooling and dashboards.
    //
    // Determine the language from the first tool's expected extensions —
    // diagnostic tools are language-specific, so all `tools` here share a
    // language. Falling back to a count of all files in the path keeps the
    // value useful when the language list is empty.
    let files_analyzed = count_diagnostic_files(path, tools);

    Ok(DiagnosticsReport {
        diagnostics: all_diagnostics,
        summary,
        tools_run: all_results,
        files_analyzed,
    })
}

/// Count source files at `path` that match the language(s) of the tools
/// being run.
///
/// `path` may be a single file (returns 1 if it has a matching extension,
/// 0 otherwise) or a directory (recursive walk, honoring .gitignore).
///
/// Diagnostic tools are language-specific, so we infer the target language
/// from the first tool's binary name. If detection fails, we fall back to
/// accepting any common source extension.
fn count_diagnostic_files(path: &Path, tools: &[ToolConfig]) -> usize {
    // Map the tool binary back to its language so we can look up the
    // canonical extension list (mirrors the same set used by `health`'s
    // `count_source_files`).
    let lang = tools
        .first()
        .and_then(|t| language_for_tool_binary(t.binary));

    let extensions: Vec<&'static str> = match lang {
        Some(l) => l.extensions().to_vec(),
        None => vec![
            ".py", ".pyi", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".rs", ".go", ".java",
            ".rb", ".php", ".cs", ".c", ".h", ".cpp", ".cc", ".hpp", ".hh", ".swift", ".kt",
            ".scala", ".lua", ".ex", ".exs", ".ml", ".mli",
        ],
    };

    if path.is_file() {
        return match path.extension().and_then(|e| e.to_str()) {
            Some(ext) => {
                let ext_with_dot = format!(".{}", ext);
                if extensions.contains(&ext_with_dot.as_str()) {
                    1
                } else {
                    0
                }
            }
            None => 0,
        };
    }

    if !path.is_dir() {
        return 0;
    }

    let mut count = 0usize;
    for entry in ProjectWalker::new(path).iter() {
        let p = entry.path();
        if p.is_file() {
            if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                let ext_with_dot = format!(".{}", ext);
                if extensions.contains(&ext_with_dot.as_str()) {
                    count += 1;
                }
            }
        }
    }
    count
}

/// Best-effort mapping from a diagnostic tool binary name to its
/// associated `Language`. Used by `count_diagnostic_files` to decide
/// which file extensions to walk for the `files_analyzed` counter.
fn language_for_tool_binary(binary: &str) -> Option<Language> {
    match binary {
        "pyright" | "ruff" | "mypy" | "pylint" | "flake8" => Some(Language::Python),
        "tsc" | "eslint" => Some(Language::TypeScript),
        "cargo" | "clippy" | "clippy-driver" => Some(Language::Rust),
        "go" | "golangci-lint" | "gofmt" | "govet" => Some(Language::Go),
        "javac" | "checkstyle" => Some(Language::Java),
        "rubocop" | "ruby" => Some(Language::Ruby),
        "phpstan" | "psalm" | "php" => Some(Language::Php),
        "dotnet" | "csharpier" => Some(Language::CSharp),
        "swiftc" | "swiftlint" => Some(Language::Swift),
        "kotlinc" | "detekt" | "detekt-cli" | "ktlint" => Some(Language::Kotlin),
        "scalac" | "scalafmt" | "scalafix" => Some(Language::Scala),
        "luacheck" | "selene" => Some(Language::Lua),
        "credo" | "dialyxir" => Some(Language::Elixir),
        "ocamlc" | "dune" => Some(Language::Ocaml),
        _ => None,
    }
}

/// Get install suggestions for missing tools.
pub fn get_install_suggestion(tool_name: &str) -> &'static str {
    match tool_name {
        "pyright" => "pip install pyright",
        "ruff" => "pip install ruff",
        "tsc" => "npm install -g typescript",
        "eslint" => "npm install -g eslint",
        "golangci-lint" => "go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest",
        "cargo" | "clippy" => "rustup component add clippy",
        "kotlinc" => "Install Kotlin: https://kotlinlang.org/docs/command-line.html",
        "detekt" | "detekt-cli" => "Install detekt: https://detekt.dev/docs/gettingstarted/cli",
        "swiftc" => "Install Xcode or Swift toolchain: https://swift.org/download/",
        "swiftlint" => "brew install swiftlint",
        "dotnet" => "Install .NET SDK: https://dotnet.microsoft.com/download",
        "scalac" => "Install Scala: https://www.scala-lang.org/download/",
        "mix" => "Install Elixir: https://elixir-lang.org/install.html",
        "luacheck" => "luarocks install luacheck",
        "javac" => "Install JDK: https://adoptium.net/",
        "checkstyle" => "Install Checkstyle: https://checkstyle.org/",
        "clang" => "Install LLVM/Clang: https://releases.llvm.org/ or brew install llvm",
        "clang-tidy" => "Install LLVM/Clang: https://releases.llvm.org/ or brew install llvm",
        "rubocop" => "gem install rubocop",
        "php" => "Install PHP: https://www.php.net/downloads",
        "phpstan" => "composer require --dev phpstan/phpstan",
        _ => "Check tool documentation",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_tool_available_which() {
        // 'which' should be available on Unix systems
        #[cfg(unix)]
        assert!(is_tool_available("which"));
    }

    #[test]
    fn test_is_tool_unavailable() {
        assert!(!is_tool_available("nonexistent_tool_xyz_12345"));
    }

    #[test]
    fn test_tools_for_python() {
        let tools = tools_for_language(Language::Python);
        assert!(tools.iter().any(|t| t.name == "pyright"));
        assert!(tools.iter().any(|t| t.name == "ruff"));
    }

    #[test]
    fn test_tools_for_typescript() {
        let tools = tools_for_language(Language::TypeScript);
        assert!(tools.iter().any(|t| t.name == "tsc"));
        assert!(tools.iter().any(|t| t.name == "eslint"));
    }

    #[test]
    fn test_tools_for_rust() {
        let tools = tools_for_language(Language::Rust);
        assert!(tools.iter().any(|t| t.name == "cargo check"));
        assert!(tools.iter().any(|t| t.name == "clippy"));
    }

    #[test]
    fn test_tools_for_go() {
        let tools = tools_for_language(Language::Go);
        assert!(tools.iter().any(|t| t.name == "go vet"));
        assert!(tools.iter().any(|t| t.name == "golangci-lint"));
    }

    #[test]
    fn test_tools_for_kotlin() {
        let tools = tools_for_language(Language::Kotlin);
        assert!(tools.iter().any(|t| t.name == "kotlinc"));
        assert!(tools.iter().any(|t| t.name == "detekt"));
    }

    #[test]
    fn test_tools_for_swift() {
        let tools = tools_for_language(Language::Swift);
        assert!(tools.iter().any(|t| t.name == "swiftc"));
        assert!(tools.iter().any(|t| t.name == "swiftlint"));
    }

    #[test]
    fn test_tools_for_csharp() {
        let tools = tools_for_language(Language::CSharp);
        assert!(tools.iter().any(|t| t.name == "dotnet build"));
    }

    #[test]
    fn test_tools_for_scala() {
        let tools = tools_for_language(Language::Scala);
        assert!(tools.iter().any(|t| t.name == "scalac"));
    }

    #[test]
    fn test_tools_for_elixir() {
        let tools = tools_for_language(Language::Elixir);
        assert!(tools.iter().any(|t| t.name == "mix compile"));
        assert!(tools.iter().any(|t| t.name == "credo"));
    }

    #[test]
    fn test_tools_for_lua() {
        let tools = tools_for_language(Language::Lua);
        assert!(tools.iter().any(|t| t.name == "luacheck"));
    }

    #[test]
    fn test_install_suggestions() {
        assert!(get_install_suggestion("pyright").contains("pip"));
        assert!(get_install_suggestion("eslint").contains("npm"));
    }

    #[test]
    fn test_install_suggestions_new_languages() {
        assert!(get_install_suggestion("kotlinc").contains("kotlin"));
        assert!(get_install_suggestion("swiftlint").contains("brew"));
        assert!(get_install_suggestion("dotnet").contains(".NET"));
        assert!(get_install_suggestion("scalac").contains("scala"));
        assert!(
            get_install_suggestion("mix").contains("elixir")
                || get_install_suggestion("mix").contains("Elixir")
        );
        assert!(get_install_suggestion("luacheck").contains("luarocks"));
    }

    #[test]
    fn test_tools_for_java() {
        let tools = tools_for_language(Language::Java);
        assert!(tools.iter().any(|t| t.name == "javac"));
        assert!(tools.iter().any(|t| t.name == "checkstyle"));
    }

    #[test]
    fn test_tools_for_c() {
        let tools = tools_for_language(Language::C);
        assert!(tools.iter().any(|t| t.name == "clang"));
        assert!(tools.iter().any(|t| t.name == "clang-tidy"));
    }

    #[test]
    fn test_tools_for_cpp() {
        let tools = tools_for_language(Language::Cpp);
        assert!(tools.iter().any(|t| t.name == "clang"));
        assert!(tools.iter().any(|t| t.name == "clang-tidy"));
    }

    #[test]
    fn test_tools_for_ruby() {
        let tools = tools_for_language(Language::Ruby);
        assert!(tools.iter().any(|t| t.name == "rubocop"));
    }

    #[test]
    fn test_tools_for_php() {
        let tools = tools_for_language(Language::Php);
        assert!(tools.iter().any(|t| t.name == "php"));
        assert!(tools.iter().any(|t| t.name == "phpstan"));
    }

    #[test]
    fn test_install_suggestions_java_c_ruby_php() {
        assert!(get_install_suggestion("javac").contains("JDK"));
        assert!(get_install_suggestion("checkstyle").contains("Checkstyle"));
        assert!(
            get_install_suggestion("clang").contains("LLVM")
                || get_install_suggestion("clang").contains("llvm")
        );
        assert!(
            get_install_suggestion("clang-tidy").contains("LLVM")
                || get_install_suggestion("clang-tidy").contains("llvm")
        );
        assert!(get_install_suggestion("rubocop").contains("gem"));
        assert!(
            get_install_suggestion("php").contains("PHP")
                || get_install_suggestion("php").contains("php")
        );
        assert!(get_install_suggestion("phpstan").contains("composer"));
    }
}
