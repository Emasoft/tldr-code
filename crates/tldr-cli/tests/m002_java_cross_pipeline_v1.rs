//! m002-java-cross-pipeline-drift-v1 (v0.4.2 M-109)
//!
//! Regression test for the cross-pipeline line-attribution drift in Java
//! identified by Phase-22 iter-2.
//!
//! ## Background
//!
//! `extract-slice-explain-decl-keyword-span-v1` (M-002) introduced the
//! `decl_keyword_line_from_node` AST normaliser in `ast::extract` so that
//! Java/Kotlin/Scala/Swift function and class extractors report the line of
//! the decl keyword (`class` / `public` / `void Foo` etc.) rather than the
//! line of a leading `@Annotation` / `modifiers` child. `extract` and
//! `explain` adopted the helper, and `cfg::extractor::extract_function_cfg`
//! (consumed by `slice`/`chop`) was updated alongside.
//!
//! However the audit identified that
//! `ast::extractor::collect_definitions` (which feeds `DefinitionInfo`
//! consumed by `structure`, `interface`, `contracts`, `verify`,
//! `definition`, and `cohesion`) still used the bare
//! `node.start_position().row as u32 + 1` for the decl line — so the SAME
//! Java class/method could report two different lines depending on which
//! pipeline reads it (`extract` says line N, `structure` says line N-2).
//!
//! ## What this test pins
//!
//! For an annotation-decorated Java class with annotation-decorated
//! methods, the line reported by `get_code_structure` (structure pipeline)
//! must match the line reported by `extract_file_with_lang` (extract
//! pipeline) for the same symbol. Equivalent assertions cover
//! constructors and fields (constants).
//!
//! Other languages (Rust, Python, Go) MUST keep their existing behavior —
//! the helper is gated on `language == Language::Java` so non-Java
//! grammars are not touched.

use std::fs;
use std::path::Path;
use tempfile::TempDir;

use tldr_core::ast::extract::extract_file_with_lang;
use tldr_core::ast::get_code_structure;
use tldr_core::types::Language;

/// Annotation-decorated Java class with mixed annotation and non-annotation
/// methods + a constructor + a field with annotations + a static-final
/// constant with annotation. Designed so that EVERY decl-keyword line
/// differs from the outer tree-sitter node's start line.
const ANNOTATED_JAVA: &str = "\
package com.example;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

@Entity
@Table(name = \"things\")
public class Thing {

    @Deprecated
    public static final String CONST_VALUE = \"x\";

    @Column
    private String name;

    @Autowired
    public Thing(String n) {
        this.name = n;
    }

    @Override
    public String toString() {
        return name;
    }

    public String getName() {
        return name;
    }
}
";

// Expected (1-indexed) decl-keyword lines for the fixture above.
//   line  5  `@Entity`                ← outer class_declaration node
//   line  6  `@Table(...)`
//   line  7  `public class Thing {`   ← DECL-KEYWORD line for class Thing
//   line  9  `@Deprecated`
//   line 10  `public static final ...` ← DECL-KEYWORD line for CONST_VALUE
//   line 12  `@Column`
//   line 13  `private String name;`    ← DECL-KEYWORD line for field name
//   line 15  `@Autowired`
//   line 16  `public Thing(String n)`  ← DECL-KEYWORD line for constructor
//   line 20  `@Override`
//   line 21  `public String toString()`← DECL-KEYWORD line for toString
//   line 25  `public String getName()` ← non-annotated; agrees both ways
const EXPECTED_CLASS_LINE: u32 = 7;
const EXPECTED_CONSTRUCTOR_LINE: u32 = 16;
const EXPECTED_TOSTRING_LINE: u32 = 21;
const EXPECTED_GETNAME_LINE: u32 = 25;

fn write_fixture(name: &str, src: &str) -> (TempDir, std::path::PathBuf) {
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join(name);
    fs::write(&file, src).unwrap();
    (tmp, file)
}

// =============================================================================
// CORE: structure-vs-extract parity for Java
// =============================================================================

#[test]
fn test_m109_java_class_line_matches_extract_and_structure() {
    let (_tmp, file) = write_fixture("Thing.java", ANNOTATED_JAVA);

    // --- extract side (source of truth) ---
    let ext = extract_file_with_lang(&file, None, Some(Language::Java))
        .expect("extract_file_with_lang ok");
    assert_eq!(ext.classes.len(), 1, "expected one class from extract");
    let extract_class_line = ext.classes[0].line_number;

    // --- structure side (must agree) ---
    let st = get_code_structure(&file, Language::Java, 1000, None)
        .expect("get_code_structure ok");
    assert_eq!(st.files.len(), 1, "expected one file in structure");
    let f = &st.files[0];

    let struct_class_def = f
        .definitions
        .iter()
        .find(|d| d.name == "Thing" && d.kind == "class")
        .unwrap_or_else(|| panic!(
            "expected `Thing` class in definitions[]; got {:?}",
            f.definitions.iter().map(|d| (&d.name, &d.kind)).collect::<Vec<_>>()
        ));

    assert_eq!(
        struct_class_def.line_start, extract_class_line,
        "DRIFT: structure says Thing line_start={}, extract says line={}",
        struct_class_def.line_start, extract_class_line
    );
    assert_eq!(
        struct_class_def.line_start, EXPECTED_CLASS_LINE,
        "expected class Thing on the `public class` decl-keyword line"
    );
}

#[test]
fn test_m109_java_constructor_line_reports_decl_keyword_line() {
    // Java constructors surface in `structure` definitions[] via
    // `constructor_declaration` (classified as `is_func` in
    // `classify_definition_node`). They do NOT currently surface in
    // `extract`'s `classes[].methods[]` (extract recurses only on
    // `method_declaration`), so direct extract↔structure parity isn't
    // possible without widening extract — out of scope for M-109.
    //
    // We pin the structure-side line to the decl-keyword line (where
    // `public Thing(...)` is) — which is the post-fix behavior and the
    // line a future extract widening would converge on.
    let (_tmp, file) = write_fixture("Thing.java", ANNOTATED_JAVA);

    let st = get_code_structure(&file, Language::Java, 1000, None)
        .expect("structure ok");
    let f = &st.files[0];
    let ctor_def = f
        .definitions
        .iter()
        .find(|d| d.name == "Thing" && d.kind == "method")
        .unwrap_or_else(|| panic!(
            "expected Thing constructor with kind=\"method\" in definitions[]; got {:?}",
            f.definitions.iter().map(|d| (&d.name, &d.kind, d.line_start)).collect::<Vec<_>>()
        ));

    assert_eq!(
        ctor_def.line_start, EXPECTED_CONSTRUCTOR_LINE,
        "expected constructor on the `public Thing(String n)` decl-keyword line, \
         not on the leading `@Autowired` annotation line"
    );
}

#[test]
fn test_m109_java_annotated_method_line_matches_extract_and_structure() {
    let (_tmp, file) = write_fixture("Thing.java", ANNOTATED_JAVA);

    let ext = extract_file_with_lang(&file, None, Some(Language::Java))
        .expect("extract ok");
    let cls = &ext.classes[0];
    let tostring = cls
        .methods
        .iter()
        .find(|m| m.name == "toString")
        .expect("toString method in extract");
    let extract_tostring_line = tostring.line_number;

    let st = get_code_structure(&file, Language::Java, 1000, None)
        .expect("structure ok");
    let f = &st.files[0];
    let tostring_def = f
        .definitions
        .iter()
        .find(|d| d.name == "toString" && d.kind == "method")
        .expect("toString in structure definitions[]");

    assert_eq!(
        tostring_def.line_start, extract_tostring_line,
        "DRIFT: structure toString line_start={}, extract line={}",
        tostring_def.line_start, extract_tostring_line
    );
    assert_eq!(
        tostring_def.line_start, EXPECTED_TOSTRING_LINE,
        "expected toString on the `public String toString()` decl-keyword line"
    );
}

#[test]
fn test_m109_java_unannotated_method_line_unchanged() {
    // Regression guard: non-annotated method must still report the same line
    // from both extract and structure (the fix must not move methods that
    // weren't annotated).
    let (_tmp, file) = write_fixture("Thing.java", ANNOTATED_JAVA);

    let ext = extract_file_with_lang(&file, None, Some(Language::Java))
        .expect("extract ok");
    let cls = &ext.classes[0];
    let getname = cls
        .methods
        .iter()
        .find(|m| m.name == "getName")
        .expect("getName method in extract");
    assert_eq!(getname.line_number, EXPECTED_GETNAME_LINE);

    let st = get_code_structure(&file, Language::Java, 1000, None)
        .expect("structure ok");
    let f = &st.files[0];
    let getname_def = f
        .definitions
        .iter()
        .find(|d| d.name == "getName" && d.kind == "method")
        .expect("getName in structure");
    assert_eq!(
        getname_def.line_start, EXPECTED_GETNAME_LINE,
        "non-annotated method line must not move"
    );
}

#[test]
fn test_m109_java_interface_line_matches_extract_and_structure() {
    // Interface with leading annotation.
    let src = "\
package com.example;

@FunctionalInterface
public interface Doer {
    void doIt();
}
";
    let (_tmp, file) = write_fixture("Doer.java", src);

    let ext = extract_file_with_lang(&file, None, Some(Language::Java))
        .expect("extract ok");
    assert_eq!(ext.classes.len(), 1, "interface surfaces in classes[]");
    let extract_iface_line = ext.classes[0].line_number;

    let st = get_code_structure(&file, Language::Java, 1000, None)
        .expect("structure ok");
    let f = &st.files[0];
    let iface_def = f
        .definitions
        .iter()
        .find(|d| d.name == "Doer" && d.kind == "interface")
        .expect("Doer in structure definitions[]");

    assert_eq!(
        iface_def.line_start, extract_iface_line,
        "DRIFT: structure interface line_start={}, extract line={}",
        iface_def.line_start, extract_iface_line
    );
    // `public interface Doer {` is at line 4 (line 3 is `@FunctionalInterface`).
    assert_eq!(iface_def.line_start, 4);
}

#[test]
fn test_m109_java_static_final_constant_parity_preserved() {
    // PARITY-PRESERVATION test (NOT a structural fix in M-109 scope).
    //
    // The extract pipeline anchors Java field/constant lines to the bare
    // tree-sitter `field_declaration` node start (which begins at the
    // `modifiers` child for annotated fields → reports the annotation
    // line). The structure pipeline does the same. The two agree.
    //
    // The M-109 audit listed the field/constant call sites as nominal
    // bug candidates, but realigning structure to the decl-keyword line
    // here without coordinating the extract side would NEWLY drift these
    // pipelines — making the cross-pipeline picture worse. We therefore
    // leave the parity intact and pin it here so a future change that
    // touches one side without the other is caught.
    let (_tmp, file) = write_fixture("Thing.java", ANNOTATED_JAVA);

    let ext = extract_file_with_lang(&file, None, Some(Language::Java))
        .expect("extract ok");
    let cls = &ext.classes[0];
    let const_field = cls
        .fields
        .iter()
        .find(|f| f.name == "CONST_VALUE")
        .expect("CONST_VALUE field in extract");
    let extract_const_line = const_field.line_number;

    let st = get_code_structure(&file, Language::Java, 1000, None)
        .expect("structure ok");
    let f = &st.files[0];
    let const_def = f
        .definitions
        .iter()
        .find(|d| d.name == "CONST_VALUE")
        .expect("CONST_VALUE in structure definitions[]");

    assert_eq!(
        const_def.line_start, extract_const_line,
        "PARITY: structure CONST_VALUE line_start={}, extract line={}",
        const_def.line_start, extract_const_line
    );
    // Pre-M109 behavior pin: both pipelines report the leading `@Deprecated`
    // annotation row (line 9), not the `public static final` row (line 10).
    assert_eq!(const_def.line_start, 9);
}

#[test]
fn test_m109_java_annotated_field_parity_preserved() {
    // PARITY-PRESERVATION test for annotated fields. See the
    // `_static_final_constant_parity_preserved` test above for rationale.
    // Both `extract_java_class_fields` and `try_field_definition` anchor
    // to the bare node start; aligning one without the other would create
    // new drift.
    let (_tmp, file) = write_fixture("Thing.java", ANNOTATED_JAVA);

    let ext = extract_file_with_lang(&file, None, Some(Language::Java))
        .expect("extract ok");
    let cls = &ext.classes[0];
    let field = cls
        .fields
        .iter()
        .find(|f| f.name == "name")
        .expect("name field in extract");
    let extract_field_line = field.line_number;

    let st = get_code_structure(&file, Language::Java, 1000, None)
        .expect("structure ok");
    let f = &st.files[0];
    let field_def = f
        .definitions
        .iter()
        .find(|d| d.name == "name" && d.kind == "field")
        .expect("name in structure definitions[]");

    assert_eq!(
        field_def.line_start, extract_field_line,
        "PARITY: structure field name line_start={}, extract line={}",
        field_def.line_start, extract_field_line
    );
    // Pre-M109 behavior pin: both pipelines report the `@Column` row (12).
    assert_eq!(field_def.line_start, 12);
}

// =============================================================================
// REGRESSION: other languages unchanged
// =============================================================================

#[test]
fn test_m109_rust_pub_fn_line_unchanged() {
    // tree-sitter-rust emits `visibility_modifier` as the first child of
    // `function_item` for `pub fn`. Our helper's `ANNOTATION_LIKE_KINDS`
    // includes `visibility_modifier` (because Kotlin uses it). The Java
    // gate must prevent the helper from being applied here, so a
    // multi-line `pub\nfn foo()` keeps its pre-fix `start_position().row`
    // behavior in structure output for Rust.
    let src = "pub fn one() {}\n\
               \n\
               pub\n\
               fn two() {}\n";
    let (_tmp, file) = write_fixture("regress.rs", src);

    let st = get_code_structure(&file, Language::Rust, 1000, None)
        .expect("structure ok");
    let f = &st.files[0];

    let one = f
        .definitions
        .iter()
        .find(|d| d.name == "one")
        .expect("`one` in defs");
    let two = f
        .definitions
        .iter()
        .find(|d| d.name == "two")
        .expect("`two` in defs");

    assert_eq!(one.line_start, 1, "rust `pub fn one()` stays on its node start line");
    // For multi-line `pub\nfn two()`, the rust function_item node starts on
    // line 3 (where `pub` is). Pre-fix behavior reports line 3. We must
    // keep this exact behavior — DO NOT advance to line 4.
    assert_eq!(two.line_start, 3, "rust multi-line pub fn must report node start, not fn keyword");
}

#[test]
fn test_m109_python_decorated_function_line_unchanged() {
    // Python decorators wrap functions in `decorated_definition`. Recursion
    // descends into the wrapper and visits the inner `function_definition`,
    // whose first child IS `def` — `ANNOTATION_LIKE_KINDS` does NOT touch
    // python kinds. But the test pins this so anyone widening the gate
    // sees the breakage.
    let src = "@staticmethod\n\
               def decorated():\n\
                   pass\n\
               \n\
               def plain():\n\
                   pass\n";
    let (_tmp, file) = write_fixture("regress.py", src);

    let st = get_code_structure(&file, Language::Python, 1000, None)
        .expect("structure ok");
    let f = &st.files[0];

    let decorated = f
        .definitions
        .iter()
        .find(|d| d.name == "decorated")
        .expect("`decorated` in defs");
    let plain = f
        .definitions
        .iter()
        .find(|d| d.name == "plain")
        .expect("`plain` in defs");

    // tree-sitter-python's `function_definition` for the decorated symbol
    // starts at the `def` line — line 2. The wrapping `decorated_definition`
    // starts at line 1 (the decorator), but `classify_definition_node`
    // matches `function_definition`, NOT the wrapper. Pre-fix behavior is
    // line 2. Must remain line 2.
    assert_eq!(decorated.line_start, 2);
    assert_eq!(plain.line_start, 5);
}

#[test]
fn test_m109_go_function_line_unchanged() {
    let src = "package main\n\
               \n\
               func one() {}\n\
               \n\
               func two() int { return 0 }\n";
    let (_tmp, file) = write_fixture("regress.go", src);

    let st = get_code_structure(&file, Language::Go, 1000, None)
        .expect("structure ok");
    let f = &st.files[0];

    let one = f
        .definitions
        .iter()
        .find(|d| d.name == "one")
        .expect("`one` in defs");
    let two = f
        .definitions
        .iter()
        .find(|d| d.name == "two")
        .expect("`two` in defs");

    assert_eq!(one.line_start, 3);
    assert_eq!(two.line_start, 5);
}

// =============================================================================
// REAL-WORLD: petclinic Owner.java (guarded by filesystem existence)
// =============================================================================

#[test]
fn test_m109_petclinic_owner_class_parity() {
    let path = Path::new(
        "/tmp/repos/java-petclinic/src/main/java/org/springframework/samples/petclinic/owner/Owner.java",
    );
    if !path.exists() {
        eprintln!("skipping: petclinic Owner.java not present at {:?}", path);
        return;
    }

    let ext = extract_file_with_lang(path, None, Some(Language::Java))
        .expect("extract ok");
    assert!(!ext.classes.is_empty(), "Owner class present");
    let extract_owner_line = ext
        .classes
        .iter()
        .find(|c| c.name == "Owner")
        .expect("Owner class")
        .line_number;

    let st = get_code_structure(path, Language::Java, 1000, None)
        .expect("structure ok");
    let f = &st.files[0];
    let owner_def = f
        .definitions
        .iter()
        .find(|d| d.name == "Owner" && d.kind == "class")
        .expect("Owner in structure defs[]");

    assert_eq!(
        owner_def.line_start, extract_owner_line,
        "petclinic Owner.java drift: structure={} extract={}",
        owner_def.line_start, extract_owner_line
    );

    // toString in Owner.java is @Override-decorated — known drift site.
    let tostring_extract = ext
        .classes
        .iter()
        .flat_map(|c| c.methods.iter())
        .find(|m| m.name == "toString")
        .expect("toString in extract")
        .line_number;
    let tostring_struct = f
        .definitions
        .iter()
        .find(|d| d.name == "toString" && d.kind == "method")
        .expect("toString in structure")
        .line_start;
    assert_eq!(
        tostring_struct, tostring_extract,
        "petclinic Owner.toString drift: structure={} extract={}",
        tostring_struct, tostring_extract
    );
}
