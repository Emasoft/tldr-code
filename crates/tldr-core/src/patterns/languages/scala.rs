use std::path::Path;

use tree_sitter::Node;

use super::super::language_profile::{
    node_text, LanguageNodeMap, LanguageProfile, LanguageSemantics, SignalAction, SignalTarget,
};
use super::super::signals::{detect_naming_case, PatternSignals};
use crate::types::Evidence;

/// Semantic extractor for Scala.
pub struct ScalaSemantics;

impl LanguageSemantics for ScalaSemantics {
    fn process_node(
        &self,
        node: Node,
        node_type: &str,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        match node_type {
            "class_definition" | "object_definition" | "trait_definition" => {
                self.detect_class_like(node, source, file_path, signals)
            }
            "function_definition" => self.detect_function(node, source, file_path, signals),
            "val_definition" => self.detect_val(node, source, file_path, signals),
            "import_declaration" => self.detect_import(node, source, file_path, signals),
            // R7 cluster[9] #cl9: the file root is the only node that can see
            // ALL top-level declarations at once, which is required for the
            // two inherently cross-declaration Scala detectors (sealed-trait
            // ADT join + companion-object Factory/Singleton pairing). Mirrors
            // the OCaml file-level precedent (`ocaml.rs` `source_file` arm).
            // Scala's tree-sitter root kind is `compilation_unit`; the other
            // two are harmless belt-and-suspenders / future-proofing.
            "compilation_unit" | "source_file" | "implementation" => {
                self.detect_design_patterns(node, source, file_path, signals)
            }
            _ => {}
        }
    }
}

impl ScalaSemantics {
    fn detect_class_like(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = node_text(name_node, source);
            let case = detect_naming_case(&name);
            signals
                .naming
                .class_names
                .push((name, case, file_path.display().to_string(), node.start_position().row as u32 + 1));
        }
    }

    fn detect_function(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = node_text(name_node, source);
            let case = detect_naming_case(&name);
            signals.naming.function_names.push((
                name.clone(),
                case,
                file_path.display().to_string(),
                node.start_position().row as u32 + 1,
            ));
            if name.starts_with("test") {
                signals.test_idioms.test_function_count += 1;
            }
        }
    }

    fn detect_val(&self, node: Node, source: &str, file_path: &Path, signals: &mut PatternSignals) {
        let text = node_text(node, source);
        if text.starts_with("val ") {
            let name = text
                .trim_start_matches("val ")
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_end_matches(':')
                .to_string();
            if !name.is_empty() {
                let case = detect_naming_case(&name);
                signals
                    .naming
                    .constant_names
                    .push((name, case, file_path.display().to_string(), node.start_position().row as u32 + 1));
            }
        }
    }

    fn detect_import(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let text = node_text(node, source);
        let module = text
            .trim_start_matches("import")
            .trim()
            .trim_end_matches(';')
            .to_string();
        if !module.is_empty() {
            signals
                .import_patterns
                .absolute_imports
                .push((module, file_path.display().to_string()));
        }

        // R7 cluster[9] #226: a Scala wildcard import (`import x._`) is a
        // star import. tree-sitter-scala exposes the trailing `_` as a
        // `namespace_wildcard` child of the `import_declaration`. A
        // SELECTIVE brace import (`import x.{a, b}`) produces a
        // `namespace_selectors` child instead and is NOT a star import, so
        // we match strictly on `namespace_wildcard` (AST node kind, not a
        // substring of the raw text). Pre-fix scala.rs only filled
        // `absolute_imports` and never surfaced star_imports, so a repo
        // with hundreds of `import zio._` lines reported `star_imports:
        // none`.
        if subtree_has_kind(node, "namespace_wildcard") {
            let line = node.start_position().row as u32 + 1;
            let snippet = text.lines().next().unwrap_or(&text).to_string();
            signals
                .import_patterns
                .star_imports
                .push(Evidence::new(file_path.display().to_string(), line, snippet));
        }
    }

    /// R7 cluster[9] #cl9 — file-level Scala GoF / idiomatic design-pattern
    /// detection. Runs once per file (dispatched on the `compilation_unit`
    /// root) because the two highest-value Scala signals are inherently
    /// cross-declaration:
    ///
    /// - **Sealed-trait ADT**: `case class Circle extends Shape` is a separate
    ///   top-level declaration from `sealed trait Shape`; the parent→variant
    ///   edge only exists via the `extends_clause`.
    /// - **Companion Factory/Singleton**: the `object` and its same-name
    ///   `class`/`trait` are separate declarations paired by name.
    ///
    /// All structural navigation (sealed/case modifiers, `extends_clause`
    /// parents, companion `apply`) is AST-only — no source-span/regex scan.
    fn detect_design_patterns(
        &self,
        root: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        use std::collections::{HashMap, HashSet};

        let file = file_path.display().to_string();

        // PASS 1 — collect every class/trait/object/enum declaration in the
        // file, descending `template_body` so variants nested inside a
        // companion `object` (R2: play-json #502 idiom) and a companion
        // `def apply` are seen.
        let mut decls: Vec<ScalaDecl> = Vec::new();
        collect_scala_decls(root, source, &mut decls);

        // Index sealed parents (by simple name) and all class/trait names
        // (for companion pairing).
        let mut sealed_parents: HashSet<String> = HashSet::new();
        let mut type_names: HashSet<String> = HashSet::new();
        for d in &decls {
            if matches!(d.kind, ScalaDeclKind::Class | ScalaDeclKind::Trait) {
                type_names.insert(d.name.clone());
                if d.is_sealed {
                    sealed_parents.insert(d.name.clone());
                }
            }
        }

        // PASS 2a — sealed-trait ADT join. Attach every declaration that
        // extends a sealed parent (rightmost identifier of each parent type,
        // generics/qualifier already stripped) as a variant of that parent.
        let mut variants: HashMap<String, Vec<String>> = HashMap::new();
        for d in &decls {
            for parent in &d.parents {
                if sealed_parents.contains(parent) {
                    variants
                        .entry(parent.clone())
                        .or_default()
                        .push(d.name.clone());
                }
            }
        }

        for d in &decls {
            match d.kind {
                ScalaDeclKind::Class | ScalaDeclKind::Trait if d.is_sealed => {
                    if let Some(vs) = variants.get(&d.name) {
                        // Fire at >=1 resolved variant; a bare sealed trait
                        // (0 variants) is SUPPRESSED (SC-W1079 / E145).
                        if !vs.is_empty() {
                            signals.design_patterns.push_pattern(
                                "ADT",
                                "structural",
                                "scala",
                                d.name.clone(),
                                file.clone(),
                                d.line,
                                format!(
                                    "sealed `{}` with {} case variant(s): {}",
                                    d.name,
                                    vs.len(),
                                    vs.join(", ")
                                ),
                            );
                        }
                    }
                }
                ScalaDeclKind::Enum => {
                    // Scala 3 `enum` is an intrinsic ADT (cases are part of
                    // the definition; scalac E145 guarantees >=1).
                    signals.design_patterns.push_pattern(
                        "ADT",
                        "structural",
                        "scala",
                        d.name.clone(),
                        file.clone(),
                        d.line,
                        format!("enum `{}` with intrinsic case variants", d.name),
                    );
                }
                _ => {}
            }
        }

        // PASS 2b — companion Factory / Singleton (disjoint branches, mirrors
        // php.rs `if construct-evidence { Factory } else { Singleton }`).
        for d in &decls {
            if !matches!(d.kind, ScalaDeclKind::Object) {
                continue;
            }
            // FACTORY: a companion `def apply` whose body shows CONSTRUCTION
            // evidence of the companion type (an `instance_expression`, a
            // `call_expression` on the companion name, or a return type ==
            // companion). Evidence over name — the php.rs lesson.
            if let Some(apply) = find_companion_apply(d.node, source) {
                if apply_constructs(apply, source, &d.name) {
                    signals.design_patterns.push_pattern(
                        "Factory",
                        "creational",
                        "scala",
                        d.name.clone(),
                        file.clone(),
                        d.line,
                        format!("companion object `{}` builds `{}` in `apply`", d.name, d.name),
                    );
                    continue;
                }
            }
            // SINGLETON (else-branch): only fire for an object that is a real
            // global instance — i.e. the companion of a same-name class/trait.
            // A bare package object (no same-name type) is NOT flagged, which
            // keeps creational precision high (avoids the 966-object swamp).
            if type_names.contains(&d.name) {
                signals.design_patterns.push_pattern(
                    "Singleton",
                    "creational",
                    "scala",
                    d.name.clone(),
                    file.clone(),
                    d.line,
                    format!("object `{}` is the single companion instance of type `{}`", d.name, d.name),
                );
            }
        }
    }
}

/// Which kind of Scala declaration a [`ScalaDecl`] records.
enum ScalaDeclKind {
    Class,
    Trait,
    Object,
    Enum,
}

/// A single Scala type declaration collected during the file-level Pass 1.
struct ScalaDecl<'a> {
    kind: ScalaDeclKind,
    name: String,
    line: u32,
    node: Node<'a>,
    is_sealed: bool,
    /// Parent type simple-names from the `extends_clause` (generics/qualifier
    /// already stripped to the rightmost identifier).
    parents: Vec<String>,
}

/// Recursively collect class/trait/object/enum declarations, descending into
/// `template_body` so companion-nested variants and `def apply` are seen.
fn collect_scala_decls<'a>(node: Node<'a>, source: &str, out: &mut Vec<ScalaDecl<'a>>) {
    let kind = match node.kind() {
        "class_definition" => Some(ScalaDeclKind::Class),
        "trait_definition" => Some(ScalaDeclKind::Trait),
        "object_definition" => Some(ScalaDeclKind::Object),
        "enum_definition" => Some(ScalaDeclKind::Enum),
        _ => None,
    };

    if let Some(kind) = kind {
        if let Some(name_node) = node
            .child_by_field_name("name")
            .or_else(|| first_child_of_kind(node, "identifier"))
        {
            let name = node_text(name_node, source).to_string();
            let line = node.start_position().row as u32 + 1;
            let is_sealed = scala_has_modifier(node, source, "sealed");
            let parents = node
                .child_by_field_name("extend")
                .map(|e| scala_extends_parents(e, source))
                .unwrap_or_default();
            out.push(ScalaDecl {
                kind,
                name,
                line,
                node,
                is_sealed,
                parents,
            });
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_scala_decls(child, source, out);
    }
}

/// First direct child of `node` whose kind equals `kind`.
fn first_child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    let found = node.children(&mut cursor).find(|c| c.kind() == kind);
    found
}

/// Find a `def apply` function in an object's `template_body` (the companion
/// Factory signal). Returns the `function_definition` node.
fn find_companion_apply<'a>(obj: Node<'a>, source: &str) -> Option<Node<'a>> {
    let body = first_child_of_kind(obj, "template_body")?;
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        if child.kind() == "function_definition" {
            if let Some(name_node) = child.child_by_field_name("name") {
                if node_text(name_node, source) == "apply" {
                    return Some(child);
                }
            }
        }
    }
    None
}

/// True when an `apply` body shows AST evidence of constructing the companion
/// type `name`: a return type == `name`, an `instance_expression` of `name`
/// (`new Name(...)`), or a `call_expression` on `name`. Evidence over name —
/// a transforming `apply` (e.g. `def apply(s): Int = s.length`) does NOT fire.
fn apply_constructs(apply: Node, source: &str, name: &str) -> bool {
    // Return type appears as a direct `type_identifier` child of the
    // `function_definition` (after `parameters`, before `=`).
    let mut cursor = apply.walk();
    for child in apply.children(&mut cursor) {
        if child.kind() == "type_identifier" && node_text(child, source) == name {
            return true;
        }
    }
    construction_evidence(apply, source, name)
}

/// Recursively scan a subtree for an `instance_expression` constructing `name`
/// or a `call_expression` whose callee is `name`.
fn construction_evidence(node: Node, source: &str, name: &str) -> bool {
    match node.kind() {
        "instance_expression" => {
            if let Some(t) = first_descendant_type_identifier(node, source) {
                if t == name {
                    return true;
                }
            }
        }
        "call_expression" => {
            if let Some(callee) = node
                .child_by_field_name("function")
                .or_else(|| node.named_child(0))
            {
                if node_text(callee, source) == name {
                    return true;
                }
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if construction_evidence(child, source, name) {
            return true;
        }
    }
    false
}

/// Text of the first `type_identifier` anywhere under `node` (handles
/// `new Name(...)` and `new Name[T](...)`).
fn first_descendant_type_identifier(node: Node, source: &str) -> Option<String> {
    if node.kind() == "type_identifier" {
        return Some(node_text(node, source).to_string());
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(t) = first_descendant_type_identifier(child, source) {
            return Some(t);
        }
    }
    None
}

// --- AST navigation duplicated (pure `(Node,&str)->…` reducers) from
// `inheritance/scala.rs` so the pattern miner has no cross-module coupling.
// Same forms pinned to tree-sitter-scala =0.24.0 (sealed inside `modifiers`
// wrapper, `case` a bare sibling; `extends_clause` parents as type_identifier
// / generic_type / stable_type_identifier).

/// Extract parent type simple-names from an `extends_clause`.
fn scala_extends_parents(node: Node, source: &str) -> Vec<String> {
    let mut bases = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "type_identifier" => bases.push(node_text(child, source).to_string()),
            "generic_type" => {
                if let Some(name) = scala_generic_base(child, source) {
                    bases.push(name);
                }
            }
            "stable_type_identifier" => {
                if let Some(name) = scala_last_identifier(child, source) {
                    bases.push(name);
                }
            }
            _ => {}
        }
    }
    bases
}

/// Base type name of a `generic_type` (`Generic[T]` -> `Generic`).
fn scala_generic_base(node: Node, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    let base = node
        .children(&mut cursor)
        .find(|c| c.kind() == "type_identifier")
        .map(|c| node_text(c, source).to_string());
    base
}

/// Last identifier of a qualified `stable_type_identifier` (`pkg.Class` ->
/// `Class`).
fn scala_last_identifier(node: Node, source: &str) -> Option<String> {
    let mut last = None;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "identifier" || child.kind() == "type_identifier" {
            last = Some(node_text(child, source).to_string());
        }
    }
    last
}

/// True when a declaration carries `modifier` (e.g. `sealed`, `case`). Handles
/// both the `modifiers` wrapper child and the bare keyword sibling.
fn scala_has_modifier(node: Node, source: &str, modifier: &str) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "modifiers" {
            if scala_modifier_recursive(child, source, modifier) {
                return true;
            }
        }
        if child.kind() == modifier {
            return true;
        }
    }
    false
}

/// Recursively text-match a keyword inside a `modifiers` node.
fn scala_modifier_recursive(node: Node, source: &str, modifier: &str) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if node_text(child, source) == modifier {
            return true;
        }
        if scala_modifier_recursive(child, source, modifier) {
            return true;
        }
    }
    false
}

/// True when `node` (or any descendant) has the given tree-sitter kind.
fn subtree_has_kind(node: Node, kind: &str) -> bool {
    if node.kind() == kind {
        return true;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if subtree_has_kind(child, kind) {
            return true;
        }
    }
    false
}

/// Build the Scala language profile.
pub fn profile() -> LanguageProfile {
    let mut map = LanguageNodeMap::new();
    map.dispatch
        .insert("class_definition", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("object_definition", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("trait_definition", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("function_definition", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("val_definition", vec![SignalAction::CallSemantics]);
    map.dispatch.insert(
        "try_expression",
        vec![SignalAction::PushEvidence(SignalTarget::TryCatchBlocks)],
    );
    map.dispatch
        .insert("import_declaration", vec![SignalAction::CallSemantics]);
    // R7 cluster[9] #cl9: dispatch the file root so the cross-declaration
    // design-pattern detectors run once with the whole tree in hand
    // (`compilation_unit` is Scala's tree-sitter root; the other two are
    // belt-and-suspenders / future-proofing — mirrors ocaml.rs).
    map.dispatch
        .insert("compilation_unit", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("source_file", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("implementation", vec![SignalAction::CallSemantics]);

    LanguageProfile {
        node_map: map,
        semantics: Box::new(ScalaSemantics),
    }
}
