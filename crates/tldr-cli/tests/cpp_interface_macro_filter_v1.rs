//! cpp-interface-macro-filter-v1 — regression tests for the cpp interface
//! export-macro mis-detection bug (BUG-CPP-P20-02 / VAL-CPP-IFACE).
//!
//! Background: tree-sitter-cpp 0.23.x misparses `class TINYXML2_LIB XMLDocument
//! { ... };` as a `function_definition` wrapping a `class_specifier` (whose
//! `name` field points at the macro `TINYXML2_LIB`), a sibling `identifier`
//! (the real class name `XMLDocument`), and a sibling `compound_statement`
//! (the class body). The pre-fix `tldr interface` walker:
//!
//! * surfaced the EXPORT MACRO (`TINYXML2_LIB`, `_LIB`, `_EXPORT`, …) as the
//!   class name, producing ~14 duplicate `TINYXML2_LIB` entries in
//!   `classes[]` for tinyxml2.h.
//! * returned `methods: []` (empty) for those entries because
//!   `find_body_node` only looks at the class_specifier's own children
//!   (which contain neither the field_declaration_list nor the
//!   compound_statement sibling holding the actual member declarations).
//!
//! This file pins:
//!   1. The macro is filtered out of `classes[]`.
//!   2. The real class names (`XMLDocument`, `XMLElement`, `XMLNode`, …)
//!      surface in `classes[]`.
//!   3. The classes have non-empty `methods[]` populated from the
//!      compound_statement member declarations.
//!
//! Real-repo cases are gated on `/tmp/repos/cpp-tinyxml2/tinyxml2.h` and
//! become no-ops when the corpus is absent.

use serde_json::Value;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn tldr_bin() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn run_tldr_json(args: &[&str]) -> Value {
    let mut cmd = tldr_bin();
    cmd.args(args).arg("--format").arg("json");
    let out = cmd.output().expect("spawn tldr");
    assert!(
        out.status.success(),
        "tldr {:?} failed: stdout={} stderr={}",
        args,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("non-JSON output for {:?}: {}", args, e))
}

fn class_names(v: &Value) -> Vec<String> {
    v.get("classes")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| {
                    c.get("name")
                        .and_then(|n| n.as_str())
                        .map(|s| s.to_string())
                })
                .collect()
        })
        .unwrap_or_default()
}

// =============================================================================
// Synthetic fixture: hermetic, always-on
// =============================================================================

/// Minimal reproducer for the macro-misparse: `class <MACRO> <Name> { ... };`.
/// The export macro `TINYXML2_LIB`-style identifier must not be reported as
/// the class name.
#[test]
fn cpp_interface_excludes_export_macros_synthetic() {
    let tmp = TempDir::new().unwrap();
    // .hpp is unambiguously C++ regardless of sibling files; `.h` would be
    // mis-classified as C in a hermetic TempDir.
    let path = tmp.path().join("macro_class.hpp");
    std::fs::write(
        &path,
        r#"
class TINYXML2_LIB XMLDocument {
public:
    XMLDocument();
    ~XMLDocument();
    int Parse(const char* xml);
    const char* Name() const;
};

class MYLIB_EXPORT Widget {
public:
    Widget();
    void Render();
    int Width() const;
};
"#,
    )
    .unwrap();

    let v = run_tldr_json(&["interface", path.to_str().unwrap()]);
    let names = class_names(&v);

    // The export-macro names must be filtered out.
    assert!(
        !names.iter().any(|n| n == "TINYXML2_LIB"),
        "TINYXML2_LIB leaked into classes[] as a class name: {:?}",
        names
    );
    assert!(
        !names.iter().any(|n| n == "MYLIB_EXPORT"),
        "MYLIB_EXPORT leaked into classes[] as a class name: {:?}",
        names
    );

    // The real class names must be present.
    assert!(
        names.iter().any(|n| n == "XMLDocument"),
        "XMLDocument missing from classes[]: {:?}",
        names
    );
    assert!(
        names.iter().any(|n| n == "Widget"),
        "Widget missing from classes[]: {:?}",
        names
    );
}

/// The methods inside the misparsed compound_statement body must be
/// extracted and reported on the corrected class entry. Each member
/// function declaration becomes a method.
#[test]
fn cpp_interface_classes_have_methods_synthetic() {
    let tmp = TempDir::new().unwrap();
    // .hpp ensures unambiguous C++ classification in a hermetic TempDir.
    let path = tmp.path().join("macro_class_methods.hpp");
    std::fs::write(
        &path,
        r#"
class TINYXML2_LIB XMLDocument {
public:
    XMLDocument();
    ~XMLDocument();
    int Parse(const char* xml);
    const char* Name() const;
    void SetValue(const char* val);
};
"#,
    )
    .unwrap();

    let v = run_tldr_json(&["interface", path.to_str().unwrap()]);
    let classes = v
        .get("classes")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();
    let xml_doc = classes
        .iter()
        .find(|c| c.get("name").and_then(|n| n.as_str()) == Some("XMLDocument"))
        .unwrap_or_else(|| panic!("XMLDocument class not found in {:?}", classes));
    let methods = xml_doc
        .get("methods")
        .and_then(|m| m.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        !methods.is_empty(),
        "XMLDocument.methods is empty; expected method declarations from compound_statement body; got class={:?}",
        xml_doc
    );

    let method_names: Vec<String> = methods
        .iter()
        .filter_map(|m| m.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect();
    // At least one of the non-constructor/destructor methods should surface.
    let has_real_method = method_names
        .iter()
        .any(|n| n == "Parse" || n == "Name" || n == "SetValue");
    assert!(
        has_real_method,
        "no member function name (Parse/Name/SetValue) surfaced in methods: {:?}",
        method_names
    );
}

// =============================================================================
// Real-repo gated: /tmp/repos/cpp-tinyxml2/tinyxml2.h
// =============================================================================

const TINYXML2_HEADER: &str = "/tmp/repos/cpp-tinyxml2/tinyxml2.h";

fn skip_if_no_tinyxml2() -> bool {
    !Path::new(TINYXML2_HEADER).exists()
}

#[test]
fn cpp_interface_excludes_export_macros_tinyxml2() {
    if skip_if_no_tinyxml2() {
        return;
    }
    let v = run_tldr_json(&["interface", TINYXML2_HEADER]);
    let names = class_names(&v);

    // BUG-CPP-P20-02: pre-fix output contained 14+ TINYXML2_LIB entries.
    let macro_count = names.iter().filter(|n| n.as_str() == "TINYXML2_LIB").count();
    assert_eq!(
        macro_count, 0,
        "TINYXML2_LIB still surfaces as a class name {} times in tinyxml2.h interface; \
         the export-macro qualifier must be filtered: {:?}",
        macro_count, names
    );
}

#[test]
fn cpp_interface_includes_real_classes_tinyxml2() {
    if skip_if_no_tinyxml2() {
        return;
    }
    let v = run_tldr_json(&["interface", TINYXML2_HEADER]);
    let names = class_names(&v);

    // The real public class identities defined in tinyxml2.h (see grep at
    // lines 133, 476, 546, 669, 992, 1032, 1071, 1106, 1141, …):
    for expected in &[
        "XMLDocument",
        "XMLElement",
        "XMLNode",
        "XMLAttribute",
        "XMLText",
        "XMLComment",
        "XMLDeclaration",
        "XMLUnknown",
        "XMLPrinter",
        "XMLVisitor",
        "XMLUtil",
        "StrPair",
    ] {
        assert!(
            names.iter().any(|n| n == expected),
            "real class {} missing from tinyxml2.h interface; got {:?}",
            expected,
            names
        );
    }
}

#[test]
fn cpp_interface_classes_have_methods_tinyxml2() {
    if skip_if_no_tinyxml2() {
        return;
    }
    let v = run_tldr_json(&["interface", TINYXML2_HEADER]);
    let classes = v
        .get("classes")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();

    // At least one of the macro-prefixed real classes must have a
    // non-empty methods array.
    let target_classes = [
        "XMLDocument",
        "XMLElement",
        "XMLNode",
        "XMLAttribute",
    ];
    let mut populated = 0usize;
    let mut per_class: Vec<(String, usize)> = Vec::new();
    for c in &classes {
        let name = match c.get("name").and_then(|n| n.as_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if !target_classes.contains(&name.as_str()) {
            continue;
        }
        let m_len = c
            .get("methods")
            .and_then(|m| m.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        per_class.push((name, m_len));
        if m_len > 0 {
            populated += 1;
        }
    }
    assert!(
        populated > 0,
        "no macro-prefixed real class in tinyxml2.h has non-empty methods; \
         per-class method counts: {:?}",
        per_class
    );
}
