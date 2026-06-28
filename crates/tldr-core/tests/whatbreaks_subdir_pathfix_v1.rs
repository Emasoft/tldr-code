//! whatbreaks-subdir-pathfix-v1 (v0.5.0 BACKLOG B-whatbreaks-subdir)
//!
//! Reproduces and locks the subdir path-prefix DOUBLING bug at the core
//! `whatbreaks_analysis` boundary (the same path the `tldr whatbreaks` CLI
//! drives).
//!
//! Symptom: `whatbreaks <file> <subdir>` run from the repo root passes
//! `changed_files = [project_path.join(target)]` — a CWD-relative path that
//! already carries the subdir prefix. `change_impact` then re-joined
//! `project_root`, producing a DOUBLED path (`bin/bin/target.ml`,
//! `Ast/Ast/src/Ast.cpp`, `Src/X/Src/X/...`). AST extraction failed with
//! "Path not found" and `affected_functions` degenerated to 0.
//!
//! Generalization: the symptom class spans every language. This exercises the
//! three backlog corpora's languages — OCaml, the C++ luau corpus, and C# —
//! and asserts both the subdir target AND the repo-root (`.`) control return
//! real, non-zero `affected_functions`.

use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, OnceLock};

use tldr_core::analysis::whatbreaks::{whatbreaks_analysis, WhatbreaksOptions};
use tldr_core::Language;

/// `std::env::set_current_dir` mutates process-global state. Serialize the
/// CWD-sensitive sections so the three language cases never interleave.
fn cwd_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

/// Restore the previous CWD when dropped, even on panic.
struct CwdGuard {
    prev: std::path::PathBuf,
}

impl CwdGuard {
    fn enter(dir: &Path) -> Self {
        let prev = std::env::current_dir().expect("read cwd");
        std::env::set_current_dir(dir).expect("set cwd");
        Self { prev }
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.prev);
    }
}

fn affected_functions(report: &tldr_core::analysis::whatbreaks::WhatbreaksReport) -> u64 {
    let ci = report
        .sub_results
        .get("change-impact")
        .unwrap_or_else(|| panic!("missing 'change-impact' sub-result"));
    assert!(
        ci.success,
        "change-impact sub-analysis must succeed; error={:?}",
        ci.error
    );
    ci.data
        .as_ref()
        .and_then(|d| d.get("affected_functions"))
        .and_then(|n| n.as_u64())
        .unwrap_or_else(|| panic!("missing change-impact.data.affected_functions: {ci:?}"))
}

/// Build a fixture (root marker + nested source file) and assert that BOTH the
/// relative-subdir target and the repo-root control yield real affected
/// functions. Runs entirely inside a CWD guard.
fn assert_no_doubling(lang: Language, marker: &str, subdir: &str, file_name: &str, body: &str) {
    let _g = cwd_lock();
    let temp = tempfile::TempDir::new().unwrap();
    let root = temp.path();
    fs::write(root.join(marker), "").unwrap();
    let dir = root.join(subdir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(file_name), body).unwrap();

    // Canonicalize so we compare against the real path even through the
    // /var -> /private/var symlink on macOS temp dirs.
    let canonical_root = root.canonicalize().unwrap();
    let _cwd = CwdGuard::enter(&canonical_root);

    let opts = WhatbreaksOptions {
        depth: 3,
        quick: false,
        language: Some(lang),
        force_type: None,
    };

    // BUG path: project is a RELATIVE subdir; target is relative to it. This is
    // the invocation that doubled the prefix and returned 0.
    let subdir_report = whatbreaks_analysis(file_name, Path::new(subdir), &opts)
        .unwrap_or_else(|e| panic!("[{lang:?}] subdir whatbreaks_analysis failed: {e}"));
    let subdir_n = affected_functions(&subdir_report);
    assert!(
        subdir_n > 0,
        "[{lang:?}] subdir target must report real affected_functions (no path-doubling); got {subdir_n}"
    );

    // CONTROL: repo-root (`.`) target must keep working.
    let root_target = format!("{subdir}/{file_name}");
    let root_report = whatbreaks_analysis(&root_target, Path::new("."), &opts)
        .unwrap_or_else(|e| panic!("[{lang:?}] repo-root whatbreaks_analysis failed: {e}"));
    let root_n = affected_functions(&root_report);
    assert!(
        root_n > 0,
        "[{lang:?}] repo-root target must still report real affected_functions; got {root_n}"
    );
}

#[test]
fn whatbreaks_subdir_no_path_doubling_ocaml() {
    assert_no_doubling(
        Language::Ocaml,
        "dune-project",
        "bin",
        "target.ml",
        "let helper x = x + 1\n\nlet main () = helper 2\n",
    );
}

#[test]
fn whatbreaks_subdir_no_path_doubling_cpp_luau() {
    // The audit's `luau` corpus is the Luau interpreter, written in C++.
    assert_no_doubling(
        Language::Cpp,
        "CMakeLists.txt",
        "Ast/src",
        "Ast.cpp",
        "int helper(int x) { return x + 1; }\n\nint run() { return helper(2); }\n",
    );
}

#[test]
fn whatbreaks_subdir_no_path_doubling_csharp() {
    assert_no_doubling(
        Language::CSharp,
        "App.sln",
        "Src/App",
        "Token.cs",
        "namespace App\n{\n    public class Token\n    {\n        public int Helper(int x) { return x + 1; }\n        public int Run() { return Helper(2); }\n    }\n}\n",
    );
}
