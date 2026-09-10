//! elixir-method-infos-v1: populate `method_infos` for Elixir defmodule blocks.
//!
//! Bug: `structure-method-infos-all-langs-v1` ensured the field is ALWAYS
//! serialized (never `skip_serializing_if`), but for Elixir the field was
//! still emitted as `[]` because `try_elixir_call_definition` always tagged
//! `def`/`defp` with `kind: "function"` regardless of whether the call sat
//! inside a `defmodule … do … end` block. The downstream filter
//! `definitions.filter(|d| d.kind == "method")` therefore returned an empty
//! `Vec<MethodInfo>` for every Elixir file.
//!
//! Fix: classify `def`/`defp` whose ancestor chain contains a `defmodule`
//! call as `kind: "method"`. Top-level `def`/`defp` (rare, only legal in
//! Mix scripts and `iex`) remain `kind: "function"`.
//!
//! These tests pin both invariants:
//! 1. `method_infos` is populated for `def`/`defp` inside `defmodule`.
//! 2. `method_infos.length == methods.length` for the same fixture (the
//!    legacy `methods: [String]` array stays additive — we don't break it).

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

const FIXTURE: &str = "defmodule Foo do\n  def bar(x) do\n    x + 1\n  end\n\n  defp baz do\n    :ok\n  end\nend\n";

fn run_structure(dir: &TempDir) -> Value {
    let mut cmd = tldr_cmd();
    cmd.args([
        "structure",
        dir.path().to_str().unwrap(),
        "--lang",
        "elixir",
        "-q",
    ]);
    let out = cmd.assert().success().get_output().stdout.clone();
    serde_json::from_slice(&out).expect("structure output is JSON")
}

/// elixir-method-infos-v1: a synthetic Elixir module with one `def` and one
/// `defp` MUST surface both inside `method_infos` with their `line` and
/// `signature` populated. The `methods: [String]` array MUST also contain
/// both names (additive contract — legacy consumers keep working).
#[test]
fn test_structure_elixir_method_infos_populated() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("foo.ex");
    fs::write(&path, FIXTURE).unwrap();

    let v = run_structure(&temp);
    let files = v
        .get("files")
        .and_then(Value::as_array)
        .expect("structure.files present");
    assert_eq!(files.len(), 1, "exactly one elixir file expected");
    let f0 = &files[0];

    // `methods: [String]` is suppressed on the wire (schema-cleanup-v1
    // BUG-13, see types.rs FileStructure) — read the same information from
    // `definitions[]` where `kind == "method"` instead of the legacy key.
    let definitions = f0
        .get("definitions")
        .and_then(Value::as_array)
        .expect("definitions array present");
    let method_names: Vec<&str> = definitions
        .iter()
        .filter(|d| d.get("kind").and_then(Value::as_str) == Some("method"))
        .filter_map(|d| d.get("name").and_then(Value::as_str))
        .collect();
    assert!(
        method_names.contains(&"bar"),
        "definitions[] kind==method must contain `bar`, got {:?}",
        method_names
    );
    assert!(
        method_names.contains(&"baz"),
        "definitions[] kind==method must contain `baz`, got {:?}",
        method_names
    );

    let mi = f0
        .get("method_infos")
        .and_then(Value::as_array)
        .expect("method_infos array present");
    assert_eq!(
        mi.len(),
        2,
        "method_infos must have exactly 2 entries (bar + baz), got {}: {:?}",
        mi.len(),
        mi
    );

    let mi_names: Vec<&str> = mi
        .iter()
        .filter_map(|m| m.get("name").and_then(Value::as_str))
        .collect();
    assert!(
        mi_names.contains(&"bar"),
        "method_infos must contain `bar`, got {:?}",
        mi_names
    );
    assert!(
        mi_names.contains(&"baz"),
        "method_infos must contain `baz`, got {:?}",
        mi_names
    );

    // Each entry must carry a non-zero line and a non-empty signature.
    for entry in mi {
        let name = entry.get("name").and_then(Value::as_str).unwrap_or("");
        let line = entry.get("line").and_then(Value::as_u64).unwrap_or(0);
        let sig = entry.get("signature").and_then(Value::as_str).unwrap_or("");
        assert!(line > 0, "method_infos[{}].line must be 1-indexed positive, got {}", name, line);
        assert!(
            !sig.is_empty(),
            "method_infos[{}].signature must be non-empty",
            name
        );
        assert!(
            sig.starts_with("def ") || sig.starts_with("defp "),
            "method_infos[{}].signature must start with `def ` / `defp `, got {:?}",
            name,
            sig
        );
    }
}

/// elixir-method-infos-v1: count parity invariant. For an Elixir source file
/// where every `def`/`defp` lives inside a single `defmodule`, the
/// `definitions[]` entries tagged `kind == "method"` and the new
/// `method_infos: [MethodInfo]` field MUST report the same length — they
/// describe the same set of declarations from two angles (structured-list
/// view vs dedicated-record view). `methods: [String]` is suppressed on the
/// wire (schema-cleanup-v1 BUG-13), so `definitions[]` stands in for it.
#[test]
fn test_structure_elixir_method_infos_count_matches_methods() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("foo.ex");
    fs::write(&path, FIXTURE).unwrap();

    let v = run_structure(&temp);
    let f0 = &v.get("files").and_then(Value::as_array).unwrap()[0];

    let methods_len = f0
        .get("definitions")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .filter(|d| d.get("kind").and_then(Value::as_str) == Some("method"))
        .count();
    let mi_len = f0
        .get("method_infos")
        .and_then(Value::as_array)
        .unwrap()
        .len();

    assert_eq!(
        methods_len, mi_len,
        "elixir-method-infos-v1: definitions[kind==method].len() ({}) must equal method_infos.len() ({}); they describe the same defmodule-scoped declarations",
        methods_len, mi_len
    );
}
