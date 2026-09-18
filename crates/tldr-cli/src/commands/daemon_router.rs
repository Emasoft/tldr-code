//! Daemon Router - Auto-route CLI commands through daemon cache
//!
//! This module provides transparent routing of CLI commands through the daemon
//! when it's running, falling back to direct compute when the daemon is unavailable.
//!
//! # Design
//!
//! Each command can call `try_daemon_route()` before doing direct compute.
//! If the daemon is running and responds successfully, the cached result is returned.
//! Otherwise, the command falls back to computing the result directly.
//!
//! # Fallback observability (issue #67)
//!
//! Every `return None` after the IPC attempt appends a `fallback` line to
//! the project's persistent daemon log (`<project>/.tldr/cache/daemon.log`)
//! through the shared [`crate::commands::daemon::logging`] helper — the
//! daemon-to-local fallback is never silent. The helper is best-effort and
//! never creates the log file itself: projects that never ran a daemon gain
//! no new state from a plain direct-compute command.
//!
//! # Performance
//!
//! The daemon maintains Salsa-style query memoization, providing ~35x speedup
//! on cache hits compared to direct computation.

use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;

use crate::commands::daemon::error::DaemonError;
use crate::commands::daemon::ipc::send_raw_command;
use crate::commands::daemon::logging::log_client_fallback;

// =============================================================================
// Core Router Function
// =============================================================================

/// Try to route a command through the daemon.
///
/// Returns `Some(result)` if the daemon is running and responds successfully.
/// Returns `None` if the daemon is not running or an error occurs (caller should fallback).
///
/// # Arguments
///
/// * `project` - Project root directory (used to find the correct daemon)
/// * `endpoint` - Command name (e.g., "calls", "impact", "structure")
/// * `params` - Additional JSON parameters for the command
///
/// # Example
///
/// ```ignore
/// if let Some(result) = try_daemon_route::<CallGraphOutput>(
///     &self.path,
///     "calls",
///     json!({"language": language.to_string()})
/// ) {
///     return writer.write(&result);
/// }
/// // Fallback to direct compute...
/// ```
pub fn try_daemon_route<T: DeserializeOwned>(
    project: &Path,
    endpoint: &str,
    params: serde_json::Value,
) -> Option<T> {
    // Use blocking runtime for sync commands
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return None,
    };

    runtime.block_on(try_daemon_route_async(project, endpoint, params))
}

/// Async version of try_daemon_route.
///
/// Used internally and can be called directly from async contexts.
pub async fn try_daemon_route_async<T: DeserializeOwned>(
    project: &Path,
    endpoint: &str,
    params: serde_json::Value,
) -> Option<T> {
    // Resolve project path to absolute
    let project = project.canonicalize().unwrap_or_else(|_| {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(project)
    });

    // Build command JSON
    let mut cmd_obj = serde_json::json!({
        "cmd": endpoint.to_lowercase()
    });

    // Merge additional parameters
    if let serde_json::Value::Object(params_obj) = params {
        if let serde_json::Value::Object(ref mut cmd_map) = cmd_obj {
            for (key, value) in params_obj {
                cmd_map.insert(key, value);
            }
        }
    }

    let command_json = match serde_json::to_string(&cmd_obj) {
        Ok(json) => json,
        Err(_) => return None,
    };

    // Send to daemon
    //
    // Issue #67: every failure of the daemon route is a CLIENT-side
    // fallback to direct compute, and it must not be silent. Each
    // `return None` below appends a `fallback` line to the project's
    // persistent daemon log (`<project>/.tldr/cache/daemon.log`) through
    // the shared daemon/CLI helper — best-effort, and only when the log
    // already exists (the helper never creates daemon state in projects
    // that never ran a daemon).
    let response = match send_raw_command(&project, &command_json).await {
        Ok(resp) => resp,
        Err(DaemonError::NotRunning) => {
            log_client_fallback(&project, endpoint, "daemon not running");
            return None;
        }
        Err(DaemonError::ConnectionRefused) => {
            log_client_fallback(&project, endpoint, "daemon connection refused");
            return None;
        }
        Err(e) => {
            log_client_fallback(&project, endpoint, &format!("daemon ipc error: {}", e));
            return None;
        }
    };

    // Parse response - check for error response first
    let response_value: serde_json::Value = match serde_json::from_str(&response) {
        Ok(v) => v,
        Err(e) => {
            log_client_fallback(
                &project,
                endpoint,
                &format!("unparseable daemon response: {}", e),
            );
            return None;
        }
    };

    // Check if response is an error
    if let Some(status) = response_value.get("status") {
        if status == "error" {
            log_client_fallback(&project, endpoint, "daemon returned an error response");
            return None;
        }
    }

    // If the response has a "result" field, extract it (daemon wraps results)
    let result_value = if response_value.get("result").is_some() {
        response_value
            .get("result")
            .cloned()
            .unwrap_or(response_value)
    } else {
        response_value
    };

    // Deserialize to target type
    match serde_json::from_value(result_value) {
        Ok(v) => Some(v),
        Err(e) => {
            log_client_fallback(
                &project,
                endpoint,
                &format!("daemon response did not deserialize: {}", e),
            );
            None
        }
    }
}

/// Check if the daemon is running for a project.
///
/// This is a lightweight check that doesn't send a command.
pub fn is_daemon_running(project: &Path) -> bool {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return false,
    };

    runtime.block_on(is_daemon_running_async(project))
}

/// Async version of is_daemon_running.
pub async fn is_daemon_running_async(project: &Path) -> bool {
    use crate::commands::daemon::ipc::check_socket_alive;
    check_socket_alive(project).await
}

// =============================================================================
// Convenience Builders
// =============================================================================

/// Build JSON params with optional path.
pub fn params_with_path(path: Option<&Path>) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    if let Some(p) = path {
        obj.insert("path".to_string(), serde_json::json!(p));
    }
    serde_json::Value::Object(obj)
}

/// Build JSON params with file path.
pub fn params_with_file(file: &Path) -> serde_json::Value {
    serde_json::json!({
        "file": file
    })
}

/// Build JSON params with file path and optional language hint.
///
/// Used by commands (e.g. `imports`) that accept `--lang` and route through the
/// daemon. JSON key is `"language"` to match the daemon handler's
/// `ImportsRequest.language` field (handlers/ast.rs:L164) — there is no
/// `#[serde(rename)]` on that field, so a `"lang"` key would be silently
/// ignored and the bug would still ship.
pub fn params_with_file_lang(file: &Path, lang: Option<&str>) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("file".to_string(), serde_json::json!(file));
    if let Some(l) = lang {
        obj.insert("language".to_string(), serde_json::json!(l));
    }
    serde_json::Value::Object(obj)
}

/// Build JSON params with file and function.
pub fn params_with_file_function(file: &Path, function: &str) -> serde_json::Value {
    serde_json::json!({
        "file": file,
        "function": function
    })
}

/// Build JSON params with file, function, and line.
pub fn params_with_file_function_line(file: &Path, function: &str, line: u32) -> serde_json::Value {
    serde_json::json!({
        "file": file,
        "function": function,
        "line": line
    })
}

/// Build JSON params with function name and optional depth.
///
/// issue-83-daemon-language-v1: `lang` threads the CLI-side detected
/// language into the daemon `Impact` request. The daemon handler used to
/// resolve a missing language to `Language::Python`, silently analyzing
/// non-Python projects as Python; see `resolve_language_from_root`
/// (commands/daemon/daemon.rs). The JSON key is the canonical `"language"`
/// (the `DaemonCommand::Impact` field name; the legacy `"lang"` spelling is
/// still accepted server-side via serde alias, but `"language"` is what the
/// wire contract documents).
pub fn params_with_func_depth(
    func: &str,
    depth: Option<usize>,
    lang: Option<&str>,
) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("func".to_string(), serde_json::json!(func));
    if let Some(d) = depth {
        obj.insert("depth".to_string(), serde_json::json!(d));
    }
    if let Some(l) = lang {
        obj.insert("language".to_string(), serde_json::json!(l));
    }
    serde_json::Value::Object(obj)
}

/// Build JSON params with module and optional path.
///
/// issue-83-daemon-language-v1: `lang` threads the CLI-side detected
/// language into the daemon `Importers` request (same rationale as
/// [`params_with_func_depth`]). The module string itself reaches the daemon
/// VERBATIM — the doc-target rewrite stays a direct-compute concern.
pub fn params_with_module(
    module: &str,
    path: Option<&Path>,
    lang: Option<&str>,
) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("module".to_string(), serde_json::json!(module));
    if let Some(p) = path {
        obj.insert("path".to_string(), serde_json::json!(p));
    }
    if let Some(l) = lang {
        obj.insert("language".to_string(), serde_json::json!(l));
    }
    serde_json::Value::Object(obj)
}

/// Build JSON params with pattern and max_results.
pub fn params_with_pattern(pattern: &str, max_results: Option<usize>) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("pattern".to_string(), serde_json::json!(pattern));
    if let Some(m) = max_results {
        obj.insert("max_results".to_string(), serde_json::json!(m));
    }
    serde_json::Value::Object(obj)
}

/// Build JSON params with entry point and depth.
///
/// issue-83-daemon-language-v1: `lang` threads the CLI-side detected
/// language into the daemon `Context` request (same rationale as
/// [`params_with_func_depth`]).
pub fn params_with_entry_depth(
    entry: &str,
    depth: Option<usize>,
    lang: Option<&str>,
) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("entry".to_string(), serde_json::json!(entry));
    if let Some(d) = depth {
        obj.insert("depth".to_string(), serde_json::json!(d));
    }
    if let Some(l) = lang {
        obj.insert("language".to_string(), serde_json::json!(l));
    }
    serde_json::Value::Object(obj)
}

/// Build JSON params with path and lang.
///
/// issue-83-daemon-language-v1: the key was renamed `"lang"` →
/// `"language"`. `"language"` is the canonical field name on BOTH daemon
/// command shapes that consume this builder (`Structure.lang` is
/// `#[serde(rename = "language", alias = "lang")]`; `Calls.language` uses
/// the same spelling), so the emitted params now work against the plain
/// field name everywhere instead of relying on the alias.
pub fn params_with_path_lang(path: &Path, lang: Option<&str>) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("path".to_string(), serde_json::json!(path));
    if let Some(l) = lang {
        obj.insert("language".to_string(), serde_json::json!(l));
    }
    serde_json::Value::Object(obj)
}

/// Build JSON params for the `smells` command.
///
/// v0.2.3 (#1.D): the smells command supports a repeatable `--files` flag and
/// an `--include-tests` flag. Both are forwarded to the daemon handler so the
/// daemon can produce identical output to direct-compute mode. `files` is only
/// emitted when non-empty so the daemon can detect "default" vs "scoped" mode.
pub fn params_for_smells(
    path: Option<&Path>,
    files: &[PathBuf],
    include_tests: bool,
) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    if let Some(p) = path {
        obj.insert("path".to_string(), serde_json::json!(p));
    }
    if !files.is_empty() {
        obj.insert("files".to_string(), serde_json::json!(files));
    }
    obj.insert(
        "include_tests".to_string(),
        serde_json::Value::Bool(include_tests),
    );
    serde_json::Value::Object(obj)
}

/// Build JSON params for dead code analysis.
///
/// issue-83-daemon-language-v1: `lang` threads the CLI-side detected
/// language into the daemon `Dead` request (same rationale as
/// [`params_with_func_depth`]).
pub fn params_for_dead(
    path: Option<&Path>,
    entry: Option<&[String]>,
    lang: Option<&str>,
) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    if let Some(p) = path {
        obj.insert("path".to_string(), serde_json::json!(p));
    }
    if let Some(e) = entry {
        obj.insert("entry".to_string(), serde_json::json!(e));
    }
    if let Some(l) = lang {
        obj.insert("language".to_string(), serde_json::json!(l));
    }
    serde_json::Value::Object(obj)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_params_with_path() {
        let params = params_with_path(Some(Path::new("/test/path")));
        assert_eq!(params.get("path").unwrap(), "/test/path");
    }

    #[test]
    fn test_params_with_path_none() {
        let params = params_with_path(None);
        assert!(params.get("path").is_none());
    }

    #[test]
    fn test_params_with_file_function() {
        let params = params_with_file_function(Path::new("/test/file.py"), "my_func");
        assert_eq!(params.get("file").unwrap(), "/test/file.py");
        assert_eq!(params.get("function").unwrap(), "my_func");
    }

    #[test]
    fn test_params_with_file_function_line() {
        let params = params_with_file_function_line(Path::new("/test/file.py"), "my_func", 42);
        assert_eq!(params.get("file").unwrap(), "/test/file.py");
        assert_eq!(params.get("function").unwrap(), "my_func");
        assert_eq!(params.get("line").unwrap(), 42);
    }

    #[test]
    fn test_params_with_func_depth() {
        let params = params_with_func_depth("process_data", Some(5), None);
        assert_eq!(params.get("func").unwrap(), "process_data");
        assert_eq!(params.get("depth").unwrap(), 5);
    }

    /// issue-83-daemon-language-v1: builders that take a language hint must
    /// emit the canonical `"language"` key, and omit it entirely when no
    /// hint exists (so the daemon's auto-detect fallback applies).
    #[test]
    fn test_language_params_emit_canonical_language_key() {
        let params = params_with_func_depth("process_data", Some(5), Some("rust"));
        assert_eq!(params["language"], "rust");
        assert_eq!(params["func"], "process_data");

        let params = params_with_entry_depth("main", Some(3), Some("rust"));
        assert_eq!(params["language"], "rust");
        assert_eq!(params["entry"], "main");

        let params = params_for_dead(Some(Path::new("/proj")), None, Some("rust"));
        assert_eq!(params["language"], "rust");
        assert_eq!(params["path"], "/proj");

        let params = params_with_module("util", Some(Path::new("/proj")), Some("rust"));
        assert_eq!(params["language"], "rust");
        assert_eq!(params["module"], "util");

        let params = params_with_path_lang(Path::new("/proj"), Some("rust"));
        assert_eq!(params["language"], "rust");
        assert_eq!(params["path"], "/proj");
    }

    #[test]
    fn test_language_params_omitted_when_none() {
        let params = params_with_func_depth("process_data", Some(5), None);
        assert!(params.get("language").is_none());

        let params = params_with_entry_depth("main", Some(3), None);
        assert!(params.get("language").is_none());

        let params = params_for_dead(Some(Path::new("/proj")), None, None);
        assert!(params.get("language").is_none());

        let params = params_with_module("util", Some(Path::new("/proj")), None);
        assert!(params.get("language").is_none());

        let params = params_with_path_lang(Path::new("/proj"), None);
        assert!(params.get("language").is_none());
    }

    #[test]
    fn test_params_with_pattern() {
        let params = params_with_pattern("fn main", Some(100));
        assert_eq!(params.get("pattern").unwrap(), "fn main");
        assert_eq!(params.get("max_results").unwrap(), 100);
    }

    #[test]
    fn test_is_daemon_running_no_daemon() {
        let temp = TempDir::new().unwrap();
        assert!(!is_daemon_running(temp.path()));
    }

    #[test]
    fn test_try_daemon_route_no_daemon() {
        let temp = TempDir::new().unwrap();
        let result: Option<serde_json::Value> =
            try_daemon_route(temp.path(), "ping", serde_json::json!({}));
        assert!(result.is_none());
    }

    #[test]
    fn test_params_with_file_lang_includes_language_key() {
        let params = params_with_file_lang(Path::new("/tmp/myscript"), Some("python"));
        assert_eq!(params["language"], "python");
        assert_eq!(params["file"], "/tmp/myscript");
    }

    #[test]
    fn test_params_with_file_lang_omits_language_when_none() {
        let params = params_with_file_lang(Path::new("/tmp/myscript"), None);
        assert!(params.get("language").is_none());
        assert_eq!(params["file"], "/tmp/myscript");
    }
}
