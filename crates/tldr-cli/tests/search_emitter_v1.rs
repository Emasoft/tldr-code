//! search-emitter-v1 (M-027): tests for `tldr search` emitter correctness.
//!
//! Covers:
//! - kind classification per language (function vs method vs module vs class)
//! - signature must NOT include attributes / decorators / annotations
//! - callers/callees populated by joining with the call-graph index
//!
//! These tests are real-repo tests: they generate small fixtures per language
//! in a tempdir, invoke the release binary, and inspect the JSON output.

use std::fs;
use std::process::Command;
use serde_json::Value;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Run `tldr search <query> <path>` (BM25, no-callgraph to keep tests fast
/// unless callgraph is the thing being tested) and parse JSON output.
fn run_search_no_cg(path: &std::path::Path, query: &str) -> Value {
    let out = tldr_cmd()
        .args(["search", query, path.to_str().unwrap(), "--no-callgraph"])
        .output()
        .expect("invoke tldr search");
    assert!(
        out.status.success(),
        "search failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse search JSON")
}

fn run_search_with_cg(path: &std::path::Path, query: &str) -> Value {
    let out = tldr_cmd()
        .args(["search", query, path.to_str().unwrap()])
        .output()
        .expect("invoke tldr search");
    assert!(
        out.status.success(),
        "search failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse search JSON")
}

fn results(v: &Value) -> &Vec<Value> {
    v.get("results").and_then(|r| r.as_array()).expect("results array")
}

fn find_named<'a>(rs: &'a [Value], name: &str) -> Option<&'a Value> {
    rs.iter().find(|r| r.get("name").and_then(|n| n.as_str()) == Some(name))
}

// ---------------------------------------------------------------------------
// 1. Go: method (receiver) must be kind="method", not "function".
// ---------------------------------------------------------------------------
#[test]
fn go_method_with_receiver_is_classified_as_method() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("users.go"),
        r#"package main

type User struct { Name string }

func FindUser(name string) *User { return &User{Name: name} }

func (u *User) SaveUser() error { return nil }

func main() { _ = FindUser("alice") }
"#,
    )
    .unwrap();

    let v = run_search_no_cg(dir.path(), "SaveUser");
    let rs = results(&v);
    let save = find_named(rs, "SaveUser").expect("SaveUser in results");
    assert_eq!(
        save.get("kind").and_then(|k| k.as_str()),
        Some("method"),
        "Go method with receiver must be kind=method, got: {:?}",
        save.get("kind")
    );
}

// ---------------------------------------------------------------------------
// 2. OCaml: top-level `let foo x = ...` must surface as function, name=foo,
//    NOT as a file-level "module" with filename-as-name.
// ---------------------------------------------------------------------------
#[test]
fn ocaml_let_binding_is_classified_as_function() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("lib.ml"),
        r#"let find_user name =
  Printf.printf "find %s\n" name;
  name

let save_user u =
  let _ = find_user u in
  ()
"#,
    )
    .unwrap();

    let v = run_search_no_cg(dir.path(), "find_user");
    let rs = results(&v);
    // The result must contain a function named "find_user", not the filename "lib".
    let f = find_named(rs, "find_user").expect("find_user as result name");
    assert_eq!(
        f.get("kind").and_then(|k| k.as_str()),
        Some("function"),
        "OCaml let-binding must be kind=function, got: {:?}",
        f.get("kind")
    );
    // The filename must NOT appear as a result name when a function name is available.
    assert!(
        find_named(rs, "lib").is_none(),
        "filename 'lib' must not appear as result name when a function is matched"
    );
}

// ---------------------------------------------------------------------------
// 3. Swift: signature must NOT be the attribute line "@inlinable".
// ---------------------------------------------------------------------------
#[test]
fn swift_signature_strips_attribute_modifier() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("users.swift"),
        r#"import Foundation

class User {
    var name: String
    init(name: String) { self.name = name }

    @inlinable
    func saveUser() -> Bool { return true }
}
"#,
    )
    .unwrap();

    let v = run_search_no_cg(dir.path(), "saveUser");
    let rs = results(&v);
    let save = find_named(rs, "saveUser").expect("saveUser in results");
    let sig = save.get("signature").and_then(|s| s.as_str()).unwrap_or("");
    assert!(
        !sig.starts_with('@'),
        "Swift signature must not start with attribute '@...', got: {sig:?}"
    );
    assert!(
        sig.contains("func saveUser"),
        "Swift signature should contain the func line, got: {sig:?}"
    );
}

// ---------------------------------------------------------------------------
// 4. PHP: signature must NOT be `#[Attribute]` line (attribute_list stripped).
// ---------------------------------------------------------------------------
#[test]
fn php_signature_strips_attribute_list() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("users.php"),
        r#"<?php

class User {
    public string $name;
    public function __construct(string $name) { $this->name = $name; }

    #[Attribute]
    public function saveUser(): bool { return true; }
}
"#,
    )
    .unwrap();

    let v = run_search_no_cg(dir.path(), "saveUser");
    let rs = results(&v);
    let save = find_named(rs, "saveUser").expect("saveUser in results");
    let sig = save.get("signature").and_then(|s| s.as_str()).unwrap_or("");
    assert!(
        !sig.starts_with("#["),
        "PHP signature must not be the attribute line `#[...]`, got: {sig:?}"
    );
    assert!(
        sig.contains("saveUser"),
        "PHP signature should contain function name, got: {sig:?}"
    );
}

// ---------------------------------------------------------------------------
// 5. Ruby: `def save_user ... end` must classify as method/function, not a
//    file-level "module" with filename-as-name.
// ---------------------------------------------------------------------------
#[test]
fn ruby_def_is_classified_as_function_or_method() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("users.rb"),
        r#"class User
  def save_user
    puts "save"
    true
  end
end

def find_user(name)
  User.new
end
"#,
    )
    .unwrap();

    let v = run_search_no_cg(dir.path(), "save_user");
    let rs = results(&v);
    let f = find_named(rs, "save_user").expect("save_user as result name");
    let k = f.get("kind").and_then(|k| k.as_str()).unwrap_or("");
    assert!(
        k == "method" || k == "function",
        "Ruby def must be method or function, got: {k:?}"
    );
    assert!(
        find_named(rs, "users").is_none(),
        "filename 'users' must not appear as a result name"
    );
}

// ---------------------------------------------------------------------------
// 6. Elixir: `def foo do ... end` must surface as function, not "module".
// ---------------------------------------------------------------------------
#[test]
fn elixir_def_is_classified_as_function() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("users.ex"),
        r#"defmodule Users do
  @moduledoc """
  Users module.
  """

  @doc "Find a user by name."
  def find_user(name) do
    IO.puts(name)
    name
  end

  def save_user(u) do
    find_user(u)
    :ok
  end
end
"#,
    )
    .unwrap();

    let v = run_search_no_cg(dir.path(), "find_user");
    let rs = results(&v);
    let f = find_named(rs, "find_user").expect("find_user as result name");
    let k = f.get("kind").and_then(|k| k.as_str()).unwrap_or("");
    assert!(
        k == "function" || k == "method",
        "Elixir def must be function/method, got: {k:?}"
    );
    let sig = f.get("signature").and_then(|s| s.as_str()).unwrap_or("");
    assert!(
        !sig.starts_with("@doc") && !sig.starts_with("@moduledoc"),
        "Elixir signature must not be @doc line, got: {sig:?}"
    );
}

// ---------------------------------------------------------------------------
// 7. Call-graph join: Go FindUser called by main → callers must contain "main".
// ---------------------------------------------------------------------------
#[test]
fn go_callgraph_populates_callers() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("users.go"),
        r#"package main

type User struct { Name string }

func FindUser(name string) *User { return &User{Name: name} }

func main() { _ = FindUser("alice") }
"#,
    )
    .unwrap();

    let v = run_search_with_cg(dir.path(), "FindUser");
    let rs = results(&v);
    let f = find_named(rs, "FindUser").expect("FindUser in results");
    let callers = f
        .get("callers")
        .and_then(|c| c.as_array())
        .expect("callers array")
        .iter()
        .filter_map(|c| c.as_str().map(|s| s.to_string()))
        .collect::<Vec<_>>();
    assert!(
        callers.contains(&"main".to_string()),
        "Go FindUser callers should contain 'main', got: {callers:?}"
    );
}

// ---------------------------------------------------------------------------
// 8. Kotlin: signature must contain `fun NAME`, no annotation leakage.
// ---------------------------------------------------------------------------
#[test]
fn kotlin_signature_is_fun_line() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("users.kt"),
        r#"package com.example

class User(val name: String) {
    @JvmStatic
    fun saveUser(): Boolean { return true }
}

fun findUser(name: String): User = User(name)
"#,
    )
    .unwrap();

    let v = run_search_no_cg(dir.path(), "saveUser");
    let rs = results(&v);
    let f = find_named(rs, "saveUser").expect("saveUser in results");
    let sig = f.get("signature").and_then(|s| s.as_str()).unwrap_or("");
    assert!(
        !sig.starts_with('@'),
        "Kotlin signature must not start with annotation `@...`, got: {sig:?}"
    );
    assert!(
        sig.contains("fun saveUser"),
        "Kotlin signature should contain 'fun saveUser', got: {sig:?}"
    );
}
