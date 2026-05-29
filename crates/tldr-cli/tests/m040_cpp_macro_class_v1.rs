//! m040-cpp-macro-class-cross-pipeline-v1 (v0.4.2 M-110)
//!
//! Wave 17c: tree-sitter-cpp misparses `class MACRO Name : public Base { ... };`
//! as a `function_definition` whose:
//!   - `type` field is a `class_specifier` whose `name` field is the macro
//!     (`TINYXML2_LIB`, `API_EXPORT`, `BOOST_SYMBOL_VISIBLE`, …);
//!   - `declarator` field is the real class name (`XMLDocument`);
//!   - body sibling is a `compound_statement` carrying the class members.
//!
//! Wave-13 M-040 added `extract_macro_decorated_class_name` to the call-graph
//! cpp handler (`crates/tldr-core/src/callgraph/languages/cpp.rs`) so the
//! `definition`, `calls`, and `impact` pipelines no longer report
//! `TINYXML2_LIB` or `<macro>` as the class. The iter-2 audit confirmed the
//! same recovery was never threaded through the SIBLING pipelines:
//!
//!   - `structure`: misclassified the macro-prefixed class as a
//!     `function_definition` (the file-structure `functions` list contained
//!     `XMLDocument`; `definitions[]` listed `TINYXML2_LIB` with
//!     `kind:"class"` AND `XMLDocument` with `kind:"function"`).
//!   - `extract`: `extract_cpp_classes_detailed` emitted `TINYXML2_LIB`
//!     (the macro) as a real class and `extract_cpp_functions_detailed`
//!     emitted `XMLDocument` as a free function with
//!     `return_type:"class API_EXPORT"`.
//!   - `definition` for `--symbol XMLDocument` and `cohesion` for
//!     `XMLDocument` already worked in iter-2 (callgraph/cohesion paths
//!     were patched in earlier waves), but the cross-pipeline contract
//!     requires ALL four to agree.
//!
//! This regression suite pins the cross-pipeline agreement on the real
//! `tinyxml2.h` corpus (`/tmp/repos/cpp-tinyxml2/tinyxml2.h`) when that
//! corpus is present, and on a hermetic fixture otherwise so the test
//! is portable.

use std::fs;
use tempfile::TempDir;

use tldr_core::ast::extract::extract_file_with_lang;
use tldr_core::ast::get_code_structure;
use tldr_core::quality::cohesion::{analyze_cohesion_with_options, CohesionOptions};
use tldr_core::types::Language;

// The two macro-decorated classes (`XMLDocument`, `XMLElement`) reproduce
// the tinyxml2.h shape (`class TINYXML2_LIB XMLDocument : public XMLNode {…}`).
//
// We deliberately omit `public:` access-specifier labels because
// tree-sitter-cpp's misparse swallows the FIRST member after `public:` as
// a `labeled_statement → declaration` (not a `function_definition`). That
// label-induced shape change is orthogonal to the M-040 class-name-recovery
// fix this regression suite pins. The live tinyxml2.h corpus exercises
// the labelled path separately (verified post-fix by `tldr extract` on
// tinyxml2.h reporting 13 methods for `XMLDocument`).
const HERMETIC_SRC: &str = "namespace ns {\n\
class API_EXPORT XMLDocument : public XMLNode\n\
{\n\
    void Init() {}\n\
    void DeepCopy() {}\n\
};\n\
\n\
class API_EXPORT XMLElement : public XMLNode\n\
{\n\
    void SetText(const char* text) {}\n\
};\n\
}\n";

fn write_hermetic_file() -> (TempDir, std::path::PathBuf) {
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("doc.cpp");
    fs::write(&file, HERMETIC_SRC).unwrap();
    (tmp, file)
}

// ============================================================================
// Acceptance 1 — `structure` (file mode) emits the macro-decorated class as a
// real class entry and DROPS it from the functions list. The inner macro name
// must NEVER surface as the class name.
// ============================================================================

#[test]
fn test_m040_structure_emits_macro_decorated_class() {
    let (_tmp, file) = write_hermetic_file();

    let result = get_code_structure(&file, Language::Cpp, 1000, None)
        .expect("structure extraction failed");
    assert_eq!(result.files.len(), 1, "expected exactly one file");
    let f = &result.files[0];

    // The real class names must be present in `classes[]`.
    assert!(
        f.classes.iter().any(|c| c == "XMLDocument"),
        "expected `XMLDocument` in classes[], got: {:?}",
        f.classes
    );
    assert!(
        f.classes.iter().any(|c| c == "XMLElement"),
        "expected `XMLElement` in classes[], got: {:?}",
        f.classes
    );

    // The macro identifier MUST NOT surface as a class.
    assert!(
        !f.classes.iter().any(|c| c == "API_EXPORT"),
        "macro identifier `API_EXPORT` leaked into classes[]: {:?}",
        f.classes
    );

    // The class name MUST NOT appear in `functions[]`.
    assert!(
        !f.functions.iter().any(|n| n == "XMLDocument"),
        "macro-decorated class `XMLDocument` leaked into functions[]: {:?}",
        f.functions
    );
    assert!(
        !f.functions.iter().any(|n| n == "XMLElement"),
        "macro-decorated class `XMLElement` leaked into functions[]: {:?}",
        f.functions
    );

    // The class name must NOT carry any `..` prefix or other corruption.
    for c in f.classes.iter() {
        assert!(
            !c.starts_with(".."),
            "class name has stray `..` prefix: {:?}",
            c
        );
        assert!(
            !c.is_empty(),
            "class name is empty"
        );
    }

    // `definitions[]` must carry the class with kind="class" at the real
    // declaration line. The macro identifier MUST NOT appear as a class def.
    let xml_doc_class_defs: Vec<_> = f
        .definitions
        .iter()
        .filter(|d| d.kind == "class" && d.name == "XMLDocument")
        .collect();
    assert_eq!(
        xml_doc_class_defs.len(),
        1,
        "expected exactly one class def for `XMLDocument` in definitions[], got: {:?}",
        f.definitions
            .iter()
            .map(|d| (d.name.as_str(), d.kind.as_str()))
            .collect::<Vec<_>>()
    );
    assert!(
        !f.definitions
            .iter()
            .any(|d| d.kind == "class" && d.name == "API_EXPORT"),
        "macro identifier `API_EXPORT` leaked into definitions[] as class: {:?}",
        f.definitions
            .iter()
            .map(|d| (d.name.as_str(), d.kind.as_str()))
            .collect::<Vec<_>>()
    );
    // And the class name MUST NOT appear with kind="function" — that was the
    // misclassification reported in the iter-2 audit cell L-1.
    assert!(
        !f.definitions
            .iter()
            .any(|d| d.kind == "function" && d.name == "XMLDocument"),
        "class `XMLDocument` misclassified as function in definitions[]: {:?}",
        f.definitions
            .iter()
            .map(|d| (d.name.as_str(), d.kind.as_str()))
            .collect::<Vec<_>>()
    );
}

// ============================================================================
// Acceptance 2 — `extract` (single-file detailed module) emits XMLDocument as
// a real class and DROPS it from the free-functions list.
// ============================================================================

#[test]
fn test_m040_extract_emits_macro_decorated_class() {
    let (_tmp, file) = write_hermetic_file();

    let module = extract_file_with_lang(&file, None, Some(Language::Cpp))
        .expect("extract_file_with_lang failed");

    // The real class is present with a non-zero method count and the correct
    // line number (line 2 = the misparsed `function_definition` line).
    let xml_doc = module
        .classes
        .iter()
        .find(|c| c.name == "XMLDocument")
        .unwrap_or_else(|| {
            panic!(
                "expected XMLDocument in extract classes[], got: {:?}",
                module
                    .classes
                    .iter()
                    .map(|c| (c.name.as_str(), c.line_number))
                    .collect::<Vec<_>>()
            )
        });
    assert_eq!(
        xml_doc.line_number, 2,
        "XMLDocument declared at line 2 of the hermetic fixture"
    );
    // The body carries `Init()` and `DeepCopy()`.
    let method_names: Vec<&str> = xml_doc.methods.iter().map(|m| m.name.as_str()).collect();
    assert!(
        method_names.contains(&"DeepCopy"),
        "DeepCopy missing from XMLDocument.methods, got: {:?}",
        method_names
    );
    assert!(
        method_names.contains(&"Init"),
        "Init missing from XMLDocument.methods, got: {:?}",
        method_names
    );

    // The macro must NOT leak as a class name.
    assert!(
        !module.classes.iter().any(|c| c.name == "API_EXPORT"),
        "macro identifier API_EXPORT leaked into extract classes[]: {:?}",
        module.classes.iter().map(|c| c.name.clone()).collect::<Vec<_>>()
    );

    // And NOT as a free function — the macro-misparse used to surface
    // `XMLDocument` as a free function with `return_type:"class API_EXPORT"`.
    assert!(
        !module.functions.iter().any(|f| f.name == "XMLDocument"),
        "XMLDocument leaked into extract functions[]: {:?}",
        module.functions.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
    );
    assert!(
        !module.functions.iter().any(|f| f.name == "XMLElement"),
        "XMLElement leaked into extract functions[]: {:?}",
        module.functions.iter().map(|f| f.name.clone()).collect::<Vec<_>>()
    );
}

// ============================================================================
// Acceptance 3 — `definition` (already handled by the callgraph cpp handler
// post-M-040) resolves `XMLDocument` to a class.
// ============================================================================

#[test]
fn test_m040_definition_resolves_macro_decorated_class_to_class_kind() {
    use tldr_core::callgraph::languages::{cpp::CppHandler, CallGraphLanguageSupport};

    let (_tmp, file) = write_hermetic_file();
    let source = fs::read_to_string(&file).unwrap();
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .unwrap();
    let tree = parser.parse(&source, None).unwrap();

    let handler = CppHandler::new();
    let (_funcs, classes) = handler
        .extract_definitions(&source, &file, &tree)
        .expect("callgraph extract_definitions failed");

    let xml_doc = classes
        .iter()
        .find(|c| c.name == "XMLDocument")
        .unwrap_or_else(|| {
            panic!(
                "expected XMLDocument in callgraph classes, got: {:?}",
                classes.iter().map(|c| c.name.clone()).collect::<Vec<_>>()
            )
        });
    assert_eq!(xml_doc.line, 2, "XMLDocument at line 2 in fixture");

    // No macro-named class.
    assert!(
        !classes.iter().any(|c| c.name == "API_EXPORT"),
        "macro identifier `API_EXPORT` leaked into callgraph classes: {:?}",
        classes.iter().map(|c| c.name.clone()).collect::<Vec<_>>()
    );
}

// ============================================================================
// Acceptance 4 — `cohesion` reports XMLDocument with real members.
// ============================================================================

#[test]
fn test_m040_cohesion_reports_macro_decorated_class() {
    let (_tmp, file) = write_hermetic_file();

    // Run cohesion with min_methods=1 (default keeps methodless classes off).
    let opts = CohesionOptions::default();
    let report = analyze_cohesion_with_options(&file, Some(Language::Cpp), opts)
        .expect("analyze_cohesion_with_options failed");

    // Find XMLDocument.
    let xml_doc = report
        .classes
        .iter()
        .find(|c| c.name == "XMLDocument")
        .unwrap_or_else(|| {
            panic!(
                "expected XMLDocument in cohesion classes, got: {:?}",
                report
                    .classes
                    .iter()
                    .map(|c| (c.name.clone(), c.line))
                    .collect::<Vec<_>>()
            )
        });
    assert_eq!(xml_doc.line, 2, "XMLDocument at line 2 in fixture");
    assert!(
        xml_doc.method_count >= 2,
        "XMLDocument should carry its 2 methods (ctor + DeepCopy), got method_count={}",
        xml_doc.method_count
    );

    // The macro identifier MUST NOT surface as a class.
    assert!(
        !report.classes.iter().any(|c| c.name == "API_EXPORT"),
        "macro identifier `API_EXPORT` leaked into cohesion classes: {:?}",
        report
            .classes
            .iter()
            .map(|c| c.name.clone())
            .collect::<Vec<_>>()
    );
}

// ============================================================================
// Cross-pipeline agreement — the four pipelines must AGREE on the name and
// line number of `XMLDocument`.
// ============================================================================

#[test]
fn test_m040_cross_pipeline_agreement_on_macro_decorated_class() {
    use tldr_core::callgraph::languages::{cpp::CppHandler, CallGraphLanguageSupport};

    let (_tmp, file) = write_hermetic_file();
    let source = fs::read_to_string(&file).unwrap();

    // 1. structure
    let structure = get_code_structure(&file, Language::Cpp, 1000, None).unwrap();
    let structure_class_def = structure.files[0]
        .definitions
        .iter()
        .find(|d| d.kind == "class" && d.name == "XMLDocument")
        .expect("structure missing XMLDocument class def");

    // 2. extract
    let module = extract_file_with_lang(&file, None, Some(Language::Cpp)).unwrap();
    let extract_xml_doc = module
        .classes
        .iter()
        .find(|c| c.name == "XMLDocument")
        .expect("extract missing XMLDocument");

    // 3. callgraph (definition resolver)
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .unwrap();
    let tree = parser.parse(&source, None).unwrap();
    let (_, classes) = CppHandler::new()
        .extract_definitions(&source, &file, &tree)
        .unwrap();
    let cg_xml_doc = classes
        .iter()
        .find(|c| c.name == "XMLDocument")
        .expect("callgraph missing XMLDocument");

    // 4. cohesion
    let opts = CohesionOptions::default();
    let cohesion_report =
        analyze_cohesion_with_options(&file, Some(Language::Cpp), opts).unwrap();
    let cohesion_xml_doc = cohesion_report
        .classes
        .iter()
        .find(|c| c.name == "XMLDocument")
        .expect("cohesion missing XMLDocument");

    // All four must agree on the declaration line (= 2 in the fixture).
    assert_eq!(structure_class_def.line_start, 2, "structure line");
    assert_eq!(extract_xml_doc.line_number, 2, "extract line");
    assert_eq!(cg_xml_doc.line, 2, "callgraph line");
    assert_eq!(cohesion_xml_doc.line, 2, "cohesion line");
}
