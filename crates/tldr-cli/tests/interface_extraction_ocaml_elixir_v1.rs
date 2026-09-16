//! interface-extraction-ocaml-elixir-v1 — regression tests for two
//! Phase-11 audit bugs (P11.BUG-AGG-8, P11.BUG-AGG-9):
//!
//! * BUG-AGG-8 (MED): `tldr interface` returned empty `name`/`signature`
//!   strings for all OCaml functions. The walker matched
//!   `value_definition` nodes but never reached into the inner
//!   `let_binding > pattern (value_name)` to pull out the identifier.
//!
//! * BUG-AGG-9 (MED): `tldr interface` returned empty exports for
//!   Elixir modules. The visitor's "call" dispatch overlapped between
//!   `func_kinds` and `class_kinds`, dropped `defmodule`, and never
//!   walked the module body where the public `def`s live.
//!
//! Real-repo tests are gated on the upstream corpus
//! (`/tmp/repos/ocaml-dune`, `/tmp/repos/elixir-plug`) and are no-ops
//! otherwise.

use assert_cmd::Command;
use serde_json::Value;
use std::path::Path;

fn run_tldr_json(args: &[&str]) -> Value {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    cmd.args(args).arg("--format").arg("json");
    let output = cmd.output().expect("failed to execute tldr");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "tldr {:?} failed: stdout={} stderr={}",
        args,
        stdout,
        stderr,
    );
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("non-JSON output for {:?}: {} — stdout={}", args, e, stdout))
}

fn write_temp(name: &str, body: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir();
    let path = dir.join(name);
    std::fs::write(&path, body).expect("write temp file");
    path
}

// =============================================================================
// BUG-AGG-8: OCaml — let-binding name extraction populates `name`/`signature`
// =============================================================================

#[test]
fn test_interface_ocaml_function_names_populated() {
    let src = "\
let create size = ()\n\
let length t = t\n\
let add (x : int) (y : int) : int = x + y\n";
    let path = write_temp("iface_ocaml_v1.ml", src);

    let v = run_tldr_json(&["interface", path.to_str().unwrap()]);
    let funcs = v
        .get("functions")
        .and_then(|f| f.as_array())
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        funcs.len(),
        3,
        "expected 3 OCaml functions, got {} (output: {})",
        funcs.len(),
        serde_json::to_string(&v).unwrap_or_default(),
    );

    let names: Vec<String> = funcs
        .iter()
        .map(|f| {
            f.get("name")
                .and_then(|n| n.as_str())
                .unwrap_or_default()
                .to_string()
        })
        .collect();

    let empty = names.iter().filter(|n| n.is_empty()).count();
    assert_eq!(
        empty, 0,
        "expected 0 empty names, got {} (names={:?})",
        empty, names,
    );
    assert!(
        names.contains(&"create".to_string()),
        "missing `create`: {:?}",
        names
    );
    assert!(
        names.contains(&"length".to_string()),
        "missing `length`: {:?}",
        names
    );
    assert!(
        names.contains(&"add".to_string()),
        "missing `add`: {:?}",
        names
    );
}

#[test]
fn test_interface_ocaml_real_repo() {
    let f = "/tmp/repos/ocaml-dune/src/rpc/io_buffer.ml";
    if !Path::new(f).exists() {
        return;
    }
    let v = run_tldr_json(&["interface", f]);
    let funcs = v
        .get("functions")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let non_empty: Vec<&str> = funcs
        .iter()
        .filter_map(|f| f.get("name").and_then(|n| n.as_str()))
        .filter(|s| !s.is_empty())
        .collect();
    assert!(
        non_empty.len() >= 10,
        "expected >=10 named OCaml functions, got {} (names={:?})",
        non_empty.len(),
        non_empty,
    );
    let empty = funcs
        .iter()
        .filter(|f| {
            f.get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .is_empty()
        })
        .count();
    assert_eq!(empty, 0, "expected 0 empty OCaml names, got {}", empty);
}

// =============================================================================
// BUG-AGG-9: Elixir — `def` is exported, `defp` is not
// =============================================================================

#[test]
fn test_interface_elixir_def_exported() {
    let src = "\
defmodule Demo do\n\
  def public_fn(x), do: x + 1\n\
  defp private_fn(x), do: x + 2\n\
  def another_pub(a, b), do: a + b\n\
end\n";
    let path = write_temp("iface_elixir_v1.ex", src);
    let v = run_tldr_json(&["interface", path.to_str().unwrap()]);

    let funcs = v
        .get("functions")
        .and_then(|f| f.as_array())
        .cloned()
        .unwrap_or_default();
    let names: Vec<String> = funcs
        .iter()
        .filter_map(|f| f.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect();

    assert!(
        names.contains(&"public_fn".to_string()),
        "missing public_fn (names={:?})",
        names,
    );
    assert!(
        names.contains(&"another_pub".to_string()),
        "missing another_pub (names={:?})",
        names,
    );
    assert!(
        !names.contains(&"private_fn".to_string()),
        "private_fn should NOT be exported (names={:?})",
        names,
    );

    // all_exports: should contain public names and exclude private.
    let exports: Vec<String> = v
        .get("all_exports")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|n| n.as_str().map(String::from))
        .collect();
    assert!(
        exports.contains(&"public_fn".to_string()),
        "all_exports missing public_fn (got {:?})",
        exports,
    );
    assert!(
        !exports.contains(&"private_fn".to_string()),
        "all_exports must not include private_fn (got {:?})",
        exports,
    );
}

#[test]
fn test_interface_elixir_real_repo() {
    let f = "/tmp/repos/elixir-plug/lib/plug/conn.ex";
    if !Path::new(f).exists() {
        return;
    }
    let v = run_tldr_json(&["interface", f]);
    let funcs = v
        .get("functions")
        .and_then(|f| f.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        funcs.len() >= 10,
        "expected >=10 Elixir functions for Plug.Conn, got {}",
        funcs.len(),
    );
    let exports = v
        .get("all_exports")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        exports.len() >= 10,
        "expected >=10 exports for Plug.Conn, got {}",
        exports.len(),
    );

    // Spot-check well-known Plug.Conn public APIs.
    let names: Vec<String> = funcs
        .iter()
        .filter_map(|f| f.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect();
    for expected in &["assign", "halt", "put_session"] {
        assert!(
            names.contains(&expected.to_string()),
            "Plug.Conn must export `{}` (names sample: {:?})",
            expected,
            &names[..names.len().min(20)],
        );
    }
}

// =============================================================================
// Regression: Python visibility unchanged
// =============================================================================

#[test]
fn test_interface_python_unchanged() {
    let src = "\
def foo(x):\n\
    return x\n\
\n\
def _bar(y):\n\
    return y\n";
    let path = write_temp("iface_py_v1.py", src);
    let v = run_tldr_json(&["interface", path.to_str().unwrap()]);

    let funcs = v
        .get("functions")
        .and_then(|f| f.as_array())
        .cloned()
        .unwrap_or_default();
    let names: Vec<String> = funcs
        .iter()
        .filter_map(|f| f.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect();

    assert!(
        names.contains(&"foo".to_string()),
        "missing `foo`: {:?}",
        names
    );
    assert!(
        !names.contains(&"_bar".to_string()),
        "_bar must not be exported (names={:?})",
        names,
    );

    let exports: Vec<String> = v
        .get("all_exports")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|n| n.as_str().map(String::from))
        .collect();
    assert!(
        exports.contains(&"foo".to_string()),
        "exports missing foo: {:?}",
        exports
    );
    assert!(
        !exports.contains(&"_bar".to_string()),
        "exports must not contain _bar: {:?}",
        exports,
    );
}
