//! path-and-schema-cleanup-v3 — regression tests for 5 bugs:
//!
//! - **P3.BUG-N1**: `tldr slice`/`chop` on Python `__init__` (and other
//!   functions with multi-line def signatures) returned empty/zero
//!   output even when the criterion line fell inside the function's
//!   signature range. Root cause: the CFG entry block's line range was
//!   set to body-start, so signature lines were not in any block. Fix:
//!   pre-seed the entry block to the def line so the entry block
//!   covers the whole signature.
//!
//! - **P3.BUG-N2**: 5 commands (`chop`, `cohesion`, `coupling`,
//!   `interface`, `contracts`) emitted `/private/tmp/...` instead of
//!   the user-supplied `/tmp/...` path on macOS. Mirrors the M2 BUG-8
//!   fix already applied to halstead/cognitive/reaching-defs/
//!   dead-stores/resources. Fix: keep canonicalisation for I/O safety
//!   but echo `self.path` in the JSON `file` field.
//!
//! - **P3.BUG-N3**: `from __future__ import annotations` was silently
//!   dropped by `tldr imports` because tree-sitter Python emits a
//!   dedicated `future_import_statement` node (not the regular
//!   `import_from_statement`) and the extractor did not handle it.
//!   Fix: add a match arm for `future_import_statement` that emits
//!   the same `ImportInfo { module: "__future__", names, is_from }`
//!   shape any other from-import would.
//!
//! - **P3.BUG-N4**: `tldr structure`'s `definitions` field was elided
//!   from the JSON when empty (via
//!   `skip_serializing_if = "Vec::is_empty"`), forcing schema
//!   consumers to handle an absent key. Fix: remove the skip-if so
//!   `definitions: []` is always present.
//!
//! - **P3.BUG-N5**: `tldr calls` `truncated` field was elided when
//!   the output was not truncated (via
//!   `skip_serializing_if = "is_false"`). Fix: remove the skip-if so
//!   `truncated: false` is always present.

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn write(p: &Path, body: &str) {
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).expect("mkdir -p");
    }
    fs::write(p, body).expect("write fixture");
}

fn run_json(args: &[&str]) -> Value {
    let out = tldr_cmd()
        .args(args)
        .args(["--format", "json", "-q"])
        .output()
        .unwrap_or_else(|e| panic!("spawn {:?}: {}", args, e));
    assert!(
        out.status.success(),
        "tldr {:?} failed: stderr={}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "tldr {:?} JSON parse failed: {}\nstdout={}",
            args,
            e,
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

// =============================================================================
// P3.BUG-N1: __init__ resolves in slice/chop
// =============================================================================

/// Build a Python file with a class whose `__init__` has a multi-line
/// def signature. This is the exact shape that triggered the bug in
/// flask's `Flask.__init__` (line 310 `def __init__(` with the body
/// not starting until line 323).
fn build_class_with_multiline_init() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(
        &root.join("model.py"),
        // Lines:
        //  1: ""
        //  2: class Foo:
        //  3:     def __init__(
        //  4:         self,
        //  5:         a,
        //  6:         b,
        //  7:         c=None,
        //  8:     ):
        //  9:         self.a = a
        // 10:         self.b = b
        // 11:         self.c = c
        // 12:         for i in range(5):
        // 13:             self.a += i
        // 14:         return None
        r#"
class Foo:
    def __init__(
        self,
        a,
        b,
        c=None,
    ):
        self.a = a
        self.b = b
        self.c = c
        for i in range(5):
            self.a += i
        return None
"#,
    );
    dir
}

#[test]
fn slice_resolves_python_init_dunder() {
    // P3.BUG-N1: criterion line on the multi-line signature (line 5,
    // `a,`) must resolve to the function's CFG entry block and produce
    // a non-empty slice. Pre-fix this returned line_count=0.
    let dir = build_class_with_multiline_init();
    let file = dir.path().join("model.py");
    let v = run_json(&["slice", file.to_str().unwrap(), "__init__", "5"]);
    let line_count = v
        .get("line_count")
        .and_then(|x| x.as_u64())
        .expect("slice JSON must have line_count");
    assert!(
        line_count > 0,
        "P3.BUG-N1: slice on __init__ at signature line 5 must \
         produce non-empty slice (got line_count={})",
        line_count
    );
}

#[test]
fn chop_resolves_python_init_dunder() {
    // P3.BUG-N1: chop with source/target inside __init__ (signature
    // line 3 -> body line 9) must resolve to a non-empty result.
    let dir = build_class_with_multiline_init();
    let file = dir.path().join("model.py");
    let v = run_json(&["chop", file.to_str().unwrap(), "__init__", "3", "9"]);
    let line_count = v
        .get("line_count")
        .and_then(|x| x.as_u64())
        .expect("chop JSON must have line_count");
    assert!(
        line_count > 0,
        "P3.BUG-N1: chop on __init__ from signature to body must \
         produce non-empty chop (got line_count={})",
        line_count
    );
}

#[test]
fn slice_other_dunders_still_work() {
    // Sanity: dunders that already worked before the fix continue to
    // work. `__init_subclass__` was the example in the bug report.
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("klass.py");
    write(
        &file,
        r#"
class K:
    def __init_subclass__(cls, **kw):
        cls.x = 1
        cls.y = 2
        for i in range(3):
            cls.x += i
        return None
"#,
    );
    let v = run_json(&["slice", file.to_str().unwrap(), "__init_subclass__", "5"]);
    let line_count = v
        .get("line_count")
        .and_then(|x| x.as_u64())
        .expect("slice JSON must have line_count");
    assert!(
        line_count > 0,
        "regression: __init_subclass__ slice must still work \
         (got line_count={})",
        line_count
    );
}

// =============================================================================
// P3.BUG-N2: path preservation for chop/cohesion/coupling/interface/contracts
// =============================================================================

/// Build a tiny Python file under `/tmp/<unique>/` so we can verify
/// that the user-supplied `/tmp/...` path is preserved (not rewritten
/// to `/private/tmp/...` on macOS). We deliberately bypass tempfile's
/// `/var/folders/...` location because that path is already canonical
/// — we need a path that DIFFERS from its canonical form to detect
/// the regression.
fn build_tmp_path_fixture(suffix: &str) -> std::path::PathBuf {
    let unique = format!(
        "tldr_p3_n2_{}_{}_{}",
        suffix,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let dir = std::path::PathBuf::from("/tmp").join(unique);
    fs::create_dir_all(&dir).expect("mkdir /tmp/<unique>");
    let file = dir.join("mod.py");
    write(
        &file,
        r#"
class Service:
    def __init__(self, name):
        self.name = name
        self.count = 0
    def increment(self):
        self.count += 1
        return self.count
    def label(self):
        return self.name + ":" + str(self.count)
"#,
    );
    file
}

fn build_tmp_path_fixture_b(suffix: &str) -> std::path::PathBuf {
    let unique = format!(
        "tldr_p3_n2_b_{}_{}_{}",
        suffix,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let dir = std::path::PathBuf::from("/tmp").join(unique);
    fs::create_dir_all(&dir).expect("mkdir /tmp/<unique>");
    let file = dir.join("client.py");
    write(
        &file,
        r#"
from .mod import Service

def boot():
    s = Service("x")
    s.increment()
    s.label()
    return s
"#,
    );
    file
}

fn assert_no_private_prefix(actual: &str, label: &str, user_path: &str) {
    assert!(
        !actual.starts_with("/private/"),
        "P3.BUG-N2: {} must not rewrite /tmp/... to /private/tmp/... \
         (user passed {}, got {})",
        label,
        user_path,
        actual
    );
    assert!(
        actual.starts_with("/tmp/"),
        "P3.BUG-N2: {} must echo the user-supplied /tmp/... path \
         (user passed {}, got {})",
        label,
        user_path,
        actual
    );
}

#[test]
fn chop_path_preserves_user_supplied() {
    // P3.BUG-N2: `tldr chop /tmp/.../mod.py __init__ 3 5` must emit
    // `file: /tmp/.../mod.py` (not /private/tmp/...).
    let file = build_tmp_path_fixture("chop");
    let file_str = file.to_str().unwrap().to_string();
    let v = run_json(&["chop", &file_str, "__init__", "3", "5"]);
    let f = v
        .get("file")
        .and_then(|x| x.as_str())
        .expect("chop JSON must have file");
    assert_no_private_prefix(f, "chop", &file_str);
    let _ = fs::remove_dir_all(file.parent().unwrap());
}

#[test]
fn cohesion_path_preserves_user_supplied() {
    // P3.BUG-N2: cohesion's per-class `file_path` must echo the
    // user-supplied path.
    let file = build_tmp_path_fixture("cohesion");
    let file_str = file.to_str().unwrap().to_string();
    let v = run_json(&["cohesion", &file_str, "--include-dunder"]);
    let classes = v
        .get("classes")
        .and_then(|x| x.as_array())
        .expect("cohesion must emit classes array");
    assert!(!classes.is_empty(), "cohesion must find Service class");
    let fp = classes[0]
        .get("file_path")
        .and_then(|x| x.as_str())
        .expect("cohesion class must have file_path");
    assert_no_private_prefix(fp, "cohesion", &file_str);
    let _ = fs::remove_dir_all(file.parent().unwrap());
}

#[test]
fn coupling_path_preserves_user_supplied() {
    // P3.BUG-N2: coupling's `path_a` and `path_b` must echo the
    // user-supplied paths.
    let file_a = build_tmp_path_fixture("coupling_a");
    let file_b = build_tmp_path_fixture_b("coupling_b");
    let a_str = file_a.to_str().unwrap().to_string();
    let b_str = file_b.to_str().unwrap().to_string();
    let v = run_json(&["coupling", &a_str, &b_str]);
    let pa = v
        .get("path_a")
        .and_then(|x| x.as_str())
        .expect("coupling JSON must have path_a");
    let pb = v
        .get("path_b")
        .and_then(|x| x.as_str())
        .expect("coupling JSON must have path_b");
    assert_no_private_prefix(pa, "coupling.path_a", &a_str);
    assert_no_private_prefix(pb, "coupling.path_b", &b_str);
    let _ = fs::remove_dir_all(file_a.parent().unwrap());
    let _ = fs::remove_dir_all(file_b.parent().unwrap());
}

#[test]
fn interface_path_preserves_user_supplied() {
    // P3.BUG-N2: interface's `file` field must echo the user-supplied
    // path.
    let file = build_tmp_path_fixture("interface");
    let file_str = file.to_str().unwrap().to_string();
    let v = run_json(&["interface", &file_str]);
    let f = v
        .get("file")
        .and_then(|x| x.as_str())
        .expect("interface JSON must have file");
    assert_no_private_prefix(f, "interface", &file_str);
    let _ = fs::remove_dir_all(file.parent().unwrap());
}

#[test]
fn contracts_path_preserves_user_supplied() {
    // P3.BUG-N2: contracts' `file` field must echo the user-supplied
    // path.
    let file = build_tmp_path_fixture("contracts");
    let file_str = file.to_str().unwrap().to_string();
    let v = run_json(&["contracts", &file_str, "increment"]);
    let f = v
        .get("file")
        .and_then(|x| x.as_str())
        .expect("contracts JSON must have file");
    assert_no_private_prefix(f, "contracts", &file_str);
    let _ = fs::remove_dir_all(file.parent().unwrap());
}

// =============================================================================
// P3.BUG-N3: __future__ imports
// =============================================================================

#[test]
fn python_imports_includes_future() {
    // P3.BUG-N3: `from __future__ import annotations` must surface in
    // `tldr imports` output. Pre-fix the future_import_statement node
    // was unhandled and the import was silently dropped.
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("future.py");
    write(
        &file,
        "from __future__ import annotations\n\
         import os\n\
         from typing import Optional\n",
    );
    let v = run_json(&["imports", file.to_str().unwrap()]);
    let imports = v
        .get("imports")
        .and_then(|x| x.as_array())
        .expect("imports JSON must have imports array");
    let has_future = imports
        .iter()
        .any(|imp| imp.get("module").and_then(|m| m.as_str()) == Some("__future__"));
    assert!(
        has_future,
        "P3.BUG-N3: imports must include {{module: __future__}}, \
         got: {}",
        serde_json::to_string_pretty(imports).unwrap()
    );
}

// =============================================================================
// P3.BUG-N4: structure.definitions always present
// =============================================================================

#[test]
fn structure_definitions_always_present_even_on_empty() {
    // P3.BUG-N4: `structure` on an empty Python file must still
    // emit `definitions: []`. Pre-fix the field was elided via
    // `skip_serializing_if = "Vec::is_empty"`.
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("empty.py");
    fs::write(&file, "").expect("write empty file");
    let v = run_json(&["structure", file.to_str().unwrap()]);
    let files = v
        .get("files")
        .and_then(|x| x.as_array())
        .expect("structure JSON must have files array");
    assert!(
        !files.is_empty(),
        "structure must emit at least one file entry"
    );
    let defs = files[0].get("definitions");
    assert!(
        defs.is_some(),
        "P3.BUG-N4: definitions key must always be present, even on \
         empty files; got file entry keys = {:?}",
        files[0]
            .as_object()
            .map(|o| o.keys().cloned().collect::<Vec<_>>())
    );
    let arr = defs.unwrap().as_array().expect("definitions must be array");
    assert!(
        arr.is_empty(),
        "P3.BUG-N4: definitions on an empty file must be the empty \
         array, got {} entries",
        arr.len()
    );
}

// =============================================================================
// P3.BUG-N5: calls.truncated always present
// =============================================================================

#[test]
fn calls_truncated_field_always_present() {
    // P3.BUG-N5: `tldr calls` on a small project (well under
    // max_items) must still emit `truncated: false`. Pre-fix the
    // field was elided when false.
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(
        &root.join("a.py"),
        r#"
def foo():
    return bar()

def bar():
    return 42
"#,
    );
    let v = run_json(&["calls", root.to_str().unwrap()]);
    let truncated = v.get("truncated");
    assert!(
        truncated.is_some(),
        "P3.BUG-N5: truncated key must always be present, got top-level \
         keys = {:?}",
        v.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>())
    );
    assert_eq!(
        truncated.and_then(|t| t.as_bool()),
        Some(false),
        "P3.BUG-N5: truncated must be `false` on a small project"
    );
}
