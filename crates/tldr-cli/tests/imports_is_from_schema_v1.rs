//! imports-is-from-schema-v1: per-lang sense for `is_from` field (v0.4.2 M-021).
//!
//! The `is_from` field on `ImportInfo` was borrowed from Python's `from X import Y`
//! distinction. Several adapters either set it uniformly (Lua, Swift) or repurposed
//! it for an unrelated lang-specific concept (C system-vs-local, Kotlin wildcard,
//! Ruby relative-path). In both cases the field as named carried no useful signal
//! for non-`from`-style languages — pure Python-leakage.
//!
//! Fix: the field is now `Option<bool>` with `#[serde(skip_serializing_if =
//! "Option::is_none")]`. Adapters set it ONLY for languages whose import syntax
//! has a genuine "from X import Y" / "use Foo::bar" distinction (Python, Rust,
//! TypeScript/JavaScript ESM, Java static, C# static/global, Scala wildcard,
//! Elixir import-vs-alias, OCaml open, PHP use-vs-require). For C, C++, Kotlin,
//! Lua, Ruby, Swift the field is OMITTED from JSON output entirely.
//!
//! These tests pin the schema: for the five affected languages the `is_from`
//! key must be absent from every emitted import entry.

use assert_cmd::Command;
use serde_json::Value;
use std::io::Write;
use tempfile::NamedTempFile;

/// Write `content` to a temp file with the given extension and return the handle.
fn write_temp(content: &str, ext: &str) -> NamedTempFile {
    let mut file = tempfile::Builder::new()
        .suffix(&format!(".{}", ext))
        .tempfile()
        .expect("create temp file");
    file.write_all(content.as_bytes()).expect("write content");
    file.flush().expect("flush");
    file
}

/// Run `tldr imports <path> --lang <lang> -q` and return the parsed JSON envelope.
fn run_imports(path: &str, lang: &str) -> Value {
    let out = Command::cargo_bin("tldr")
        .expect("tldr binary")
        .args(["imports", path, "--lang", lang, "-q"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&out).expect("imports output is JSON")
}

/// Assert that every import entry in `imports` lacks the `is_from` key.
fn assert_no_is_from(imports: &[Value], lang: &str) {
    for (i, imp) in imports.iter().enumerate() {
        let obj = imp.as_object().unwrap_or_else(|| {
            panic!("{} import [{}] is not an object: {:?}", lang, i, imp);
        });
        assert!(
            !obj.contains_key("is_from"),
            "{} import [{}] should not contain `is_from` key, got: {:?}",
            lang,
            i,
            imp
        );
    }
}

// =============================================================================
// C: #include <stdio.h> and #include "local.h"
// =============================================================================
//
// Pre-fix: `is_from=true` for system headers, `false` for local. The field was
// repurposed for a system-vs-local distinction that has nothing to do with
// Python's `from`-import syntax. Now: omitted entirely.
#[test]
fn c_imports_omit_is_from_field() {
    let src = r#"
#include <stdio.h>
#include "local.h"
#include <stdlib.h>
"#;
    let file = write_temp(src, "c");
    let v = run_imports(file.path().to_str().unwrap(), "c");
    let imports = v["imports"].as_array().expect("imports array");
    assert!(imports.len() >= 3, "expected 3 C includes, got {:?}", imports);
    assert_no_is_from(imports, "c");
}

// =============================================================================
// C++: same #include semantics as C
// =============================================================================
#[test]
fn cpp_imports_omit_is_from_field() {
    let src = r#"
#include <iostream>
#include "myheader.hpp"
"#;
    let file = write_temp(src, "cpp");
    let v = run_imports(file.path().to_str().unwrap(), "cpp");
    let imports = v["imports"].as_array().expect("imports array");
    assert!(!imports.is_empty(), "expected at least 1 C++ include");
    assert_no_is_from(imports, "cpp");
}

// =============================================================================
// Kotlin: import kotlin.collections.List (.* wildcard)
// =============================================================================
//
// Pre-fix: `is_from=true` for wildcards (`.*`), false otherwise. The field was
// repurposed for a wildcard signal. Kotlin's `import` is a top-level statement,
// not a `from`-style binding. Now: omitted.
#[test]
fn kotlin_imports_omit_is_from_field() {
    let src = r#"
package foo

import kotlin.collections.List
import kotlin.collections.*
import foo.bar.Baz as B
"#;
    let file = write_temp(src, "kt");
    let v = run_imports(file.path().to_str().unwrap(), "kotlin");
    let imports = v["imports"].as_array().expect("imports array");
    assert!(imports.len() >= 3, "expected 3 Kotlin imports, got {:?}", imports);
    assert_no_is_from(imports, "kotlin");
}

// =============================================================================
// Lua: require('module')
// =============================================================================
//
// Pre-fix: uniform `is_from=false` (Python-leakage, zero info). Lua has no
// from-style import syntax — `require` is a function call returning a value.
// Now: omitted.
#[test]
fn lua_imports_omit_is_from_field() {
    let src = r#"
local socket = require("socket")
local http = require "http"
local mime = require("mime")
"#;
    let file = write_temp(src, "lua");
    let v = run_imports(file.path().to_str().unwrap(), "lua");
    let imports = v["imports"].as_array().expect("imports array");
    assert!(imports.len() >= 3, "expected 3 Lua requires, got {:?}", imports);
    assert_no_is_from(imports, "lua");
}

// =============================================================================
// Ruby: require / require_relative
// =============================================================================
//
// Pre-fix: `is_from=true` for relative paths (./, ../, require_relative), false
// for absolute. The field was repurposed for a relative-path signal. Ruby's
// `require` is a function call, not a from-style binding. Now: omitted.
#[test]
fn ruby_imports_omit_is_from_field() {
    let src = r#"
require 'json'
require_relative './helper'
require './local'
"#;
    let file = write_temp(src, "rb");
    let v = run_imports(file.path().to_str().unwrap(), "ruby");
    let imports = v["imports"].as_array().expect("imports array");
    assert!(imports.len() >= 3, "expected 3 Ruby requires, got {:?}", imports);
    assert_no_is_from(imports, "ruby");
}

// =============================================================================
// Swift: import Foundation
// =============================================================================
//
// Pre-fix: uniform `is_from=false` (Python-leakage, zero info). Swift's `import`
// is a top-level module declaration with no from-style binding. Now: omitted.
#[test]
fn swift_imports_omit_is_from_field() {
    let src = r#"
import Foundation
import UIKit
@testable import MyModule
"#;
    let file = write_temp(src, "swift");
    let v = run_imports(file.path().to_str().unwrap(), "swift");
    let imports = v["imports"].as_array().expect("imports array");
    assert!(imports.len() >= 3, "expected 3 Swift imports, got {:?}", imports);
    assert_no_is_from(imports, "swift");
}

// =============================================================================
// Python: `from X import Y` — is_from MUST still be present (genuine semantics)
// =============================================================================
#[test]
fn python_imports_keep_is_from_field() {
    let src = r#"
import os
from typing import List, Dict
import sys as system
"#;
    let file = write_temp(src, "py");
    let v = run_imports(file.path().to_str().unwrap(), "python");
    let imports = v["imports"].as_array().expect("imports array");
    assert!(imports.len() >= 3, "expected 3 Python imports, got {:?}", imports);

    // At least one entry must have is_from=true (the `from typing import ...`)
    let from_entry = imports
        .iter()
        .find(|i| i["is_from"].as_bool() == Some(true))
        .expect("python: at least one is_from=true entry for `from X import Y`");
    assert_eq!(
        from_entry["module"].as_str(),
        Some("typing"),
        "the `from typing import ...` entry should appear; got: {:?}",
        from_entry
    );
}

// =============================================================================
// Rust: `use crate::foo::bar` — is_from MUST still be present (use-decl)
// =============================================================================
#[test]
fn rust_imports_keep_is_from_field() {
    let src = r#"
use std::collections::HashMap;
mod helper;
"#;
    let file = write_temp(src, "rs");
    let v = run_imports(file.path().to_str().unwrap(), "rust");
    let imports = v["imports"].as_array().expect("imports array");
    assert!(!imports.is_empty(), "expected at least one Rust import");
    // The `use` entry must carry is_from=true.
    let use_entry = imports
        .iter()
        .find(|i| i["module"].as_str().map(|m| m.contains("collections")).unwrap_or(false))
        .expect("rust: `use std::collections::...` entry present");
    assert_eq!(
        use_entry["is_from"].as_bool(),
        Some(true),
        "rust `use` should keep is_from=true, got: {:?}",
        use_entry
    );
}
