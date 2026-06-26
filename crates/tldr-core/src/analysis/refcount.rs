//! Reference counting for dead code rescue
//!
//! Counts how many times each identifier appears across the codebase
//! using tree-sitter AST parsing. Used to "rescue" functions from dead
//! code reports when they are referenced multiple times (indicating
//! they are used, just not through call-graph edges).
//!
//! # Algorithm
//! 1. Walk each file's AST using TreeCursor
//! 2. Collect all identifier nodes appropriate for the language
//! 3. Count occurrences of each identifier name
//! 4. A function with ref_count > 1 and name length >= 3 is "rescued"

use std::collections::HashMap;

use tree_sitter::Tree;

use crate::types::Language;

/// Returns the tree-sitter node type names that represent identifiers for the given language.
///
/// Each language has different AST node types for identifiers. This function
/// maps our `Language` enum to the relevant tree-sitter node type strings.
pub fn identifier_node_types(language: Language) -> &'static [&'static str] {
    match language {
        Language::Python => &["identifier"],
        Language::TypeScript | Language::JavaScript => &[
            "identifier",
            "property_identifier",
            "shorthand_property_identifier",
            "type_identifier",
        ],
        Language::Go => &["identifier", "field_identifier", "type_identifier"],
        Language::Rust => &["identifier", "field_identifier", "type_identifier"],
        Language::Java => &["identifier", "type_identifier"],
        Language::C | Language::Cpp => &["identifier", "field_identifier", "type_identifier"],
        Language::Ruby => &["identifier", "constant"],
        Language::Php => &["name"],
        Language::Kotlin => &["identifier"],
        Language::Swift => &["simple_identifier", "type_identifier"],
        Language::CSharp => &["identifier"],
        Language::Scala => &["identifier"],
        Language::Elixir => &["identifier"],
        Language::Lua | Language::Luau => &["identifier"],
        Language::Ocaml => &[
            "value_name",
            "type_constructor",
            // Operator USE/DEF leaf tokens (tree-sitter-ocaml 0.24.2, verified
            // against node-types.json). `a >>= b` exposes the operator at
            // `infix_expression.operator` as one of the `*_operator` leaves, and
            // `let+`/`and+`/`let*` appear as bare `let_operator`/`let_and_operator`
            // under `value_definition`. Without these, every operator USE is
            // invisible to the refcount tally (RC6). We add ONLY the concrete
            // leaf tokens — NOT the `parenthesized_operator` DEF wrapper (which
            // would re-introduce the `( >>= )` source-slice form) nor the hidden
            // `_infix_operator` alias / `indexing_operator_path` path wrapper.
            "prefix_operator",
            "sign_operator",
            "hash_operator",
            "pow_operator",
            "mult_operator",
            "add_operator",
            "concat_operator",
            "rel_operator",
            "and_operator",
            "or_operator",
            "assign_operator",
            "indexing_operator",
            "let_operator",
            "let_and_operator",
            "match_operator",
        ],
        // v0.5.0 SOL-001 Solidity foundation. Solidity uses a plain
        // `identifier` for variable/function names and
        // `type_identifier` for declared type names (verified via
        // node-types.json on tree-sitter-solidity 1.2.13).
        Language::Solidity => &["identifier", "type_identifier"],
    }
}

/// Elixir-specific structural recognizer: if `atom_node` is the function token
/// of a canonical MFA reference, return the bare function name to credit.
///
/// We deliberately do NOT add `atom` to the blanket Elixir identifier set —
/// that would import the much larger map-key / tag-atom collision surface and
/// re-rescue genuinely dead functions that merely share a name with a config
/// atom or message tag. Instead we credit an `atom` as a runtime reference ONLY
/// when the surrounding shape is an unambiguous Module/Function/Args form:
///
///   * MFA tuple   `{Mod, :fun, [args]}` / `{__MODULE__, :fun, [args]}` /
///                 `{Mod, :fun}` — atom is the 2nd named child, the 1st is an
///                 `alias` (module) or the `__MODULE__` identifier, the tuple has
///                 2 or 3 named children, and (when 3) the 3rd is a `list`.
///   * apply/spawn `apply(Mod, :fun, [args])` / `spawn(Mod, :fun, [args])` etc.
///                 — same shape inside an `arguments` node whose enclosing
///                 `call` targets `apply`/`spawn`/`spawn_link`/`spawn_monitor`.
///
/// All node-kinds verified against tree-sitter-elixir 0.3.4 node-types.json.
/// This excludes `{:via, Registry, name}` (1st named child is an atom),
/// `{state, :fun, []}` (1st is a plain variable identifier), keyword-shorthand
/// map/list keys (which are `keyword`, not `atom`), and standalone `:tag`
/// atoms (parent is `binary_operator`/`list`/`pair`, not a qualifying shape).
fn elixir_mfa_atom_credit(atom_node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    // Bare function name = atom text with exactly one leading ':' stripped.
    let start = atom_node.start_byte();
    let end = atom_node.end_byte();
    if start > end || end > source.len() {
        return None;
    }
    let raw = std::str::from_utf8(&source[start..end]).ok()?;
    let bare = raw.strip_prefix(':')?;
    if bare.is_empty() || bare.starts_with('"') {
        return None;
    }

    let parent = atom_node.parent()?;

    // Helper: among `container`'s NAMED children, validate the MFA shape and
    // confirm `atom_node` is the 2nd (index 1) named child.
    let shape_ok = |container: &tree_sitter::Node| -> bool {
        let named: Vec<tree_sitter::Node> = {
            let mut c = container.walk();
            container.named_children(&mut c).collect()
        };
        if named.len() != 2 && named.len() != 3 {
            return false;
        }
        // atom must be the 2nd named child.
        if named.get(1).map(|n| n.id()) != Some(atom_node.id()) {
            return false;
        }
        // 1st named child: alias (module) OR `__MODULE__` identifier.
        let head = match named.first() {
            Some(h) => h,
            None => return false,
        };
        let head_ok = match head.kind() {
            "alias" => true,
            "identifier" => {
                let hs = head.start_byte();
                let he = head.end_byte();
                hs <= he
                    && he <= source.len()
                    && std::str::from_utf8(&source[hs..he]).ok() == Some("__MODULE__")
            }
            _ => false,
        };
        if !head_ok {
            return false;
        }
        // If 3 named children, the 3rd must be the args `list`.
        if named.len() == 3 && named[2].kind() != "list" {
            return false;
        }
        true
    };

    match parent.kind() {
        "tuple" => {
            if shape_ok(&parent) {
                return Some(bare.to_string());
            }
        }
        "arguments" => {
            // enclosing call must target apply/spawn/spawn_link/spawn_monitor
            if let Some(call) = parent.parent() {
                if call.kind() == "call" {
                    if let Some(target) = call.child_by_field_name("target") {
                        let ts = target.start_byte();
                        let te = target.end_byte();
                        if ts <= te && te <= source.len() {
                            if let Ok(t) = std::str::from_utf8(&source[ts..te]) {
                                if matches!(t, "apply" | "spawn" | "spawn_link" | "spawn_monitor")
                                    && shape_ok(&parent)
                                {
                                    return Some(bare.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }

    None
}

/// Walk the tree-sitter AST and count all identifier occurrences.
///
/// # Arguments
/// * `tree` - Parsed tree-sitter AST
/// * `source` - Source code bytes (used to extract identifier text)
/// * `language` - Programming language (determines which node types to count)
///
/// # Returns
/// HashMap mapping identifier name to occurrence count.
pub fn count_identifiers_in_tree(
    tree: &Tree,
    source: &[u8],
    language: Language,
) -> HashMap<String, usize> {
    let id_types = identifier_node_types(language);
    let mut counts: HashMap<String, usize> = HashMap::new();

    // Use TreeCursor for efficient depth-first traversal
    let mut cursor = tree.walk();
    let mut reached_root = false;

    loop {
        let node = cursor.node();

        // Check if this node is an identifier type we care about
        if id_types.contains(&node.kind()) {
            // Extract text from source bytes
            let start = node.start_byte();
            let end = node.end_byte();
            if start <= end && end <= source.len() {
                if let Ok(text) = std::str::from_utf8(&source[start..end]) {
                    if !text.is_empty() {
                        *counts.entry(text.to_string()).or_insert(0) += 1;
                    }
                }
            }
        }

        // Elixir MFA runtime references: `{Mod, :fun, [args]}` and
        // `apply(Mod, :fun, [args])` reference `fun` via an `atom` node-kind,
        // which is intentionally NOT in the blanket identifier set. Credit it
        // only when the strict MFA shape holds (RC6, Fix 2).
        if language == Language::Elixir && node.kind() == "atom" {
            if let Some(fun) = elixir_mfa_atom_credit(&node, source) {
                *counts.entry(fun).or_insert(0) += 1;
            }
        }

        // Depth-first traversal: try going to first child, then next sibling,
        // then walk back up to parent and try next sibling, etc.
        if cursor.goto_first_child() {
            continue;
        }
        if cursor.goto_next_sibling() {
            continue;
        }

        // Walk back up until we find a node with a next sibling or reach root
        loop {
            if !cursor.goto_parent() {
                reached_root = true;
                break;
            }
            if cursor.goto_next_sibling() {
                break;
            }
        }

        if reached_root {
            break;
        }
    }

    counts
}

/// Check if a function name is "rescued" by reference counting.
///
/// A name is rescued if:
/// - It appears more than once in the ref_counts (ref_count > 1)
/// - The name is at least 3 characters long (short names are too collision-prone)
/// - For qualified names like "MyClass.method", checks the bare name after the last "."
///
/// # Arguments
/// * `name` - Function/method name to check
/// * `ref_counts` - Map of identifier name to occurrence count
///
/// # Returns
/// `true` if the name should be rescued from dead code reports
pub fn is_rescued_by_refcount(name: &str, ref_counts: &HashMap<String, usize>) -> bool {
    // Extract the bare name (after the last "." or ":") for qualified names
    // Supports: "MyClass.method" (Python, JS, etc.) and "module:method" (Lua)
    let bare_name = if name.contains('.') {
        name.rsplit('.').next().unwrap_or(name)
    } else if name.contains(':') {
        name.rsplit(':').next().unwrap_or(name)
    } else {
        name
    };

    // Names shorter than 3 characters need a higher refcount threshold to avoid
    // false rescues from collision-prone names (i, j, x, id, etc.).
    // But very high refcounts (>= 5) indicate genuine usage even for short names.
    let min_refs = if bare_name.len() < 3 { 5 } else { 2 };

    // Check bare name first (covers both qualified and unqualified cases)
    if let Some(&count) = ref_counts.get(bare_name) {
        if count >= min_refs {
            return true;
        }
    }

    // If the full qualified name differs from the bare name, also check it
    if bare_name != name {
        if let Some(&count) = ref_counts.get(name) {
            if count >= min_refs {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::parser::parse;

    /// T1: Parse Python source and verify identifier counts
    #[test]
    fn test_count_identifiers_python() {
        let source = "def hello():\n    x = 1\n    return hello()\n";
        let tree = parse(source, Language::Python).unwrap();
        let counts = count_identifiers_in_tree(&tree, source.as_bytes(), Language::Python);

        // "hello" appears as function def name + recursive call = at least 2
        assert!(
            counts.get("hello").copied().unwrap_or(0) >= 2,
            "Expected 'hello' count >= 2, got {:?}",
            counts.get("hello")
        );
        // "x" appears as assignment target = at least 1
        assert!(
            counts.get("x").copied().unwrap_or(0) >= 1,
            "Expected 'x' count >= 1, got {:?}",
            counts.get("x")
        );
    }

    /// T2: Short names (< 3 chars) should NOT be rescued even with high ref count
    #[test]
    fn test_is_rescued_short_name_low_count() {
        let mut ref_counts = HashMap::new();
        ref_counts.insert("fn".to_string(), 3);
        assert!(
            !is_rescued_by_refcount("fn", &ref_counts),
            "Short name 'fn' (2 chars) with count=3 should not be rescued (needs >= 5)"
        );
    }

    #[test]
    fn test_is_rescued_short_name_high_count() {
        let mut ref_counts = HashMap::new();
        ref_counts.insert("cn".to_string(), 50);
        assert!(
            is_rescued_by_refcount("cn", &ref_counts),
            "Short name 'cn' (2 chars) with count=50 should be rescued (>= 5)"
        );
    }

    /// T3: Names with ref_count > 1 and length >= 3 should be rescued
    #[test]
    fn test_is_rescued_referenced() {
        let mut ref_counts = HashMap::new();
        ref_counts.insert("handle_signal".to_string(), 3);
        assert!(
            is_rescued_by_refcount("handle_signal", &ref_counts),
            "handle_signal with count=3 should be rescued"
        );
    }

    /// T4: Names with ref_count == 1 (only definition, never used) should NOT be rescued
    #[test]
    fn test_is_rescued_only_definition() {
        let mut ref_counts = HashMap::new();
        ref_counts.insert("unused_helper".to_string(), 1);
        assert!(
            !is_rescued_by_refcount("unused_helper", &ref_counts),
            "unused_helper with count=1 should not be rescued"
        );
    }

    /// T5: Qualified names like "MyClass.process" should check the bare name "process"
    #[test]
    fn test_class_method_bare_name() {
        let mut ref_counts = HashMap::new();
        ref_counts.insert("process".to_string(), 5);
        assert!(
            is_rescued_by_refcount("MyClass.process", &ref_counts),
            "MyClass.process should be rescued via bare name 'process' with count=5"
        );
    }

    /// T6: Every Language variant should return a non-empty identifier node types slice
    #[test]
    fn test_identifier_node_types_all_languages() {
        let languages = [
            Language::Python,
            Language::TypeScript,
            Language::JavaScript,
            Language::Go,
            Language::Rust,
            Language::Java,
            Language::C,
            Language::Cpp,
            Language::Ruby,
            Language::Kotlin,
            Language::Swift,
            Language::CSharp,
            Language::Scala,
            Language::Php,
            Language::Lua,
            Language::Luau,
            Language::Elixir,
            Language::Ocaml,
        ];
        for lang in &languages {
            let types = identifier_node_types(*lang);
            assert!(
                !types.is_empty(),
                "identifier_node_types({:?}) returned empty slice",
                lang
            );
        }
    }

    /// JSX element names are type_identifier in tree-sitter TSX.
    /// Verify they are counted for refcount rescue.
    #[test]
    fn test_jsx_element_name_refcount() {
        let source = r#"
function Comp(props) {
    return <div>hello</div>;
}
function App() {
    return <Comp foo="bar" />;
}
"#;
        let tree = parse(source, Language::TypeScript).unwrap();
        let counts = count_identifiers_in_tree(&tree, source.as_bytes(), Language::TypeScript);
        let comp_count = counts.get("Comp").copied().unwrap_or(0);

        // Comp appears as: function declaration identifier + JSX type_identifier
        assert!(
            comp_count >= 2,
            "Expected Comp refcount >= 2 (definition + JSX usage), got {}",
            comp_count
        );
    }

    /// Java: type_identifier is used for class names in type positions (generics, variable types).
    /// e.g. `List<MyService>` parses MyService as type_identifier, not identifier.
    #[test]
    fn test_java_type_identifier_refcount() {
        let source = r#"
class MyService {
    public void run() {}
}
class App {
    private MyService svc;
    public void start(MyService service) {}
}
"#;
        let tree = parse(source, Language::Java).unwrap();
        let counts = count_identifiers_in_tree(&tree, source.as_bytes(), Language::Java);
        let svc_count = counts.get("MyService").copied().unwrap_or(0);

        // MyService appears as: class declaration identifier + field type + parameter type
        assert!(
            svc_count >= 3,
            "Expected MyService refcount >= 3 (class def + field type + param type), got {}",
            svc_count
        );
    }

    /// Kotlin: tree-sitter-kotlin-ng uses `identifier` as the leaf node type
    /// e.g. `val x: MyType` parses MyType as type_identifier.
    #[test]
    fn test_kotlin_type_identifier_refcount() {
        let source = r#"
class MyHelper {
    fun run() {}
}
fun main() {
    val helper: MyHelper = MyHelper()
}
"#;
        let tree = parse(source, Language::Kotlin).unwrap();
        let counts = count_identifiers_in_tree(&tree, source.as_bytes(), Language::Kotlin);
        let helper_count = counts.get("MyHelper").copied().unwrap_or(0);

        // MyHelper appears as: class def + type annotation + constructor call
        assert!(
            helper_count >= 2,
            "Expected MyHelper refcount >= 2 (class def + type annotation or constructor), got {}",
            helper_count
        );
    }

    /// Swift: type_identifier is used for type annotations.
    /// e.g. `let x: MyType` parses MyType as type_identifier.
    #[test]
    fn test_swift_type_identifier_refcount() {
        let source = r#"
class MyManager {
    func run() {}
}
func setup() {
    let mgr: MyManager = MyManager()
}
"#;
        let tree = parse(source, Language::Swift).unwrap();
        let counts = count_identifiers_in_tree(&tree, source.as_bytes(), Language::Swift);
        let mgr_count = counts.get("MyManager").copied().unwrap_or(0);

        // MyManager appears as: class def + type annotation + constructor call
        assert!(
            mgr_count >= 2,
            "Expected MyManager refcount >= 2 (class def + type annotation or constructor), got {}",
            mgr_count
        );
    }

    /// RC6 Fix 3 (OCaml operators) — POS: a defined-and-used infix operator is
    /// tallied at both its `parenthesized_operator` DEF and its
    /// `infix_expression.operator` USE, so its count reaches >= 2 and it is
    /// rescued.
    #[test]
    fn test_ocaml_operator_refcount_rescued() {
        let source = "let ( >>= ) a b = a + b\nlet r = 1 >>= 2\n";
        let tree = parse(source, Language::Ocaml).unwrap();
        let counts = count_identifiers_in_tree(&tree, source.as_bytes(), Language::Ocaml);
        let c = counts.get(">>=").copied().unwrap_or(0);
        assert!(
            c >= 2,
            "Expected '>>=' refcount >= 2 (def + use), got {} (counts: {:?})",
            c,
            counts
        );
        assert!(
            is_rescued_by_refcount(">>=", &counts),
            "'>>=' with count {} should be rescued (len 3 >= 3 => min_refs 2)",
            c
        );
    }

    /// RC6 Fix 3 (OCaml) — let-operator (`let+`) USE appears as a bare
    /// `let_operator` under a `value_definition` let-header; it must be tallied.
    #[test]
    fn test_ocaml_let_operator_refcount() {
        let source = "let ( let+ ) x f = f x\nlet result =\n  let+ y = 1 in\n  y\n";
        let tree = parse(source, Language::Ocaml).unwrap();
        let counts = count_identifiers_in_tree(&tree, source.as_bytes(), Language::Ocaml);
        let c = counts.get("let+").copied().unwrap_or(0);
        assert!(
            c >= 2,
            "Expected 'let+' refcount >= 2 (def + use), got {} (counts: {:?})",
            c,
            counts
        );
    }

    /// RC6 Fix 3 (OCaml) — NEG FP-guard: an operator that is DEFINED but never
    /// USED stays at count 1 and is NOT rescued.
    #[test]
    fn test_ocaml_operator_defined_unused_not_rescued() {
        let source = "let ( <?> ) a b = a + b\n";
        let tree = parse(source, Language::Ocaml).unwrap();
        let counts = count_identifiers_in_tree(&tree, source.as_bytes(), Language::Ocaml);
        assert_eq!(
            counts.get("<?>").copied().unwrap_or(0),
            1,
            "defined-but-unused operator should have count 1, counts: {:?}",
            counts
        );
        assert!(
            !is_rescued_by_refcount("<?>", &counts),
            "defined-but-unused '<?>' must NOT be rescued"
        );
    }

    /// RC6 Fix 2 (Elixir MFA-atom) — POS: `{__MODULE__, :start_pooled, [a]}`
    /// and `apply(Mod, :start_pooled, [a])` each credit the function atom.
    #[test]
    fn test_elixir_mfa_tuple_atom_credited() {
        let source = "def go(ref, i) do\n  {__MODULE__, :start_pooled, [ref, i]}\nend\n";
        let tree = parse(source, Language::Elixir).unwrap();
        let counts = count_identifiers_in_tree(&tree, source.as_bytes(), Language::Elixir);
        assert!(
            counts.get("start_pooled").copied().unwrap_or(0) >= 1,
            "MFA-tuple atom :start_pooled should credit 'start_pooled', counts: {:?}",
            counts
        );
    }

    #[test]
    fn test_elixir_apply_atom_credited() {
        let source = "def go(a) do\n  apply(MyMod, :start_pooled, [a])\nend\n";
        let tree = parse(source, Language::Elixir).unwrap();
        let counts = count_identifiers_in_tree(&tree, source.as_bytes(), Language::Elixir);
        assert!(
            counts.get("start_pooled").copied().unwrap_or(0) >= 1,
            "apply/3 atom :start_pooled should credit 'start_pooled', counts: {:?}",
            counts
        );
    }

    /// RC6 Fix 2 (Elixir) — NEG FP-guards: the structural gate must NOT credit
    /// atoms outside the strict MFA shape.
    #[test]
    fn test_elixir_mfa_atom_fp_guards() {
        // {:via, Registry, name} — 1st named child is an atom, not alias/__MODULE__.
        let src_via = "def f(name) do\n  {:via, Registry, name}\nend\n";
        let t = parse(src_via, Language::Elixir).unwrap();
        let c = count_identifiers_in_tree(&t, src_via.as_bytes(), Language::Elixir);
        assert_eq!(
            c.get("via").copied().unwrap_or(0),
            0,
            "{{:via, Registry, name}} must NOT credit 'via', counts: {:?}",
            c
        );
        assert_eq!(
            c.get("Registry").copied().unwrap_or(0),
            0,
            "atom rule must NOT credit 'Registry', counts: {:?}",
            c
        );

        // {state, :start_pooled, []} — 1st named child is a variable identifier.
        let src_var = "def f(state) do\n  {state, :start_pooled, []}\nend\n";
        let t = parse(src_var, Language::Elixir).unwrap();
        let c = count_identifiers_in_tree(&t, src_var.as_bytes(), Language::Elixir);
        assert_eq!(
            c.get("start_pooled").copied().unwrap_or(0),
            0,
            "variable head must NOT credit 'start_pooled', counts: {:?}",
            c
        );

        // %{start_pooled: 1} — keyword key, not an atom node.
        let src_map = "def f do\n  %{start_pooled: 1}\nend\n";
        let t = parse(src_map, Language::Elixir).unwrap();
        let c = count_identifiers_in_tree(&t, src_map.as_bytes(), Language::Elixir);
        assert_eq!(
            c.get("start_pooled").copied().unwrap_or(0),
            0,
            "keyword key must NOT credit 'start_pooled', counts: {:?}",
            c
        );

        // standalone atom assignment — parent is binary_operator, not a tuple.
        let src_tag = "def f do\n  x = :start_pooled\n  x\nend\n";
        let t = parse(src_tag, Language::Elixir).unwrap();
        let c = count_identifiers_in_tree(&t, src_tag.as_bytes(), Language::Elixir);
        assert_eq!(
            c.get("start_pooled").copied().unwrap_or(0),
            0,
            "standalone atom must NOT credit 'start_pooled', counts: {:?}",
            c
        );
    }
}
