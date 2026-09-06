//! Inheritance Module Integration Tests
//!
//! Tests for inheritance analysis modules:
//! - python: Python class extraction
//! - typescript: TypeScript/JavaScript class extraction
//! - go: Go struct embedding extraction
//! - rust: Rust trait extraction
//! - patterns: ABC/Protocol, mixin, diamond detection
//! - resolve: Base class resolution
//! - filter: Class filtering with depth limits
//! - format: DOT and text output formatting

use std::path::PathBuf;
use tempfile::TempDir;

use tldr_core::inheritance::resolve::BaseOrigin;
use tldr_core::inheritance::{
    detect_abc_protocol, detect_diamonds, detect_mixins, escape_dot_string, extract_inheritance,
    filter_by_class, format_dot, format_text, get_fuzzy_suggestions, is_stdlib_class, resolve_base,
    InheritanceOptions,
};
use tldr_core::types::{InheritanceGraph, InheritanceNode, Language};

// =============================================================================
// Test Fixtures
// =============================================================================

fn create_test_graph() -> InheritanceGraph {
    let mut graph = InheritanceGraph::new();

    // Create a simple hierarchy: Animal -> Dog, Cat
    let animal = InheritanceNode::new(
        "Animal".to_string(),
        PathBuf::from("animals.py"),
        1,
        Language::Python,
    );

    let mut dog = InheritanceNode::new(
        "Dog".to_string(),
        PathBuf::from("animals.py"),
        10,
        Language::Python,
    );
    dog.bases = vec!["Animal".to_string()];

    let mut cat = InheritanceNode::new(
        "Cat".to_string(),
        PathBuf::from("animals.py"),
        20,
        Language::Python,
    );
    cat.bases = vec!["Animal".to_string()];

    graph.add_node(animal);
    graph.add_node(dog);
    graph.add_node(cat);

    graph.add_edge("Dog", "Animal");
    graph.add_edge("Cat", "Animal");

    graph
}

fn create_diamond_graph() -> InheritanceGraph {
    let mut graph = InheritanceGraph::new();

    // Diamond pattern: A <- B, C <- D
    // B and C both inherit from A, D inherits from both B and C
    let a = InheritanceNode::new(
        "A".to_string(),
        PathBuf::from("test.py"),
        1,
        Language::Python,
    );

    let mut b = InheritanceNode::new(
        "B".to_string(),
        PathBuf::from("test.py"),
        2,
        Language::Python,
    );
    b.bases = vec!["A".to_string()];

    let mut c = InheritanceNode::new(
        "C".to_string(),
        PathBuf::from("test.py"),
        3,
        Language::Python,
    );
    c.bases = vec!["A".to_string()];

    let mut d = InheritanceNode::new(
        "D".to_string(),
        PathBuf::from("test.py"),
        4,
        Language::Python,
    );
    d.bases = vec!["B".to_string(), "C".to_string()];

    graph.add_node(a);
    graph.add_node(b);
    graph.add_node(c);
    graph.add_node(d);

    graph.add_edge("B", "A");
    graph.add_edge("C", "A");
    graph.add_edge("D", "B");
    graph.add_edge("D", "C");

    graph
}

fn create_mixin_graph() -> InheritanceGraph {
    let mut graph = InheritanceGraph::new();

    // TimestampMixin used as secondary base by multiple classes
    let timestamp_mixin = InheritanceNode::new(
        "TimestampMixin".to_string(),
        PathBuf::from("mixins.py"),
        1,
        Language::Python,
    );

    let base = InheritanceNode::new(
        "Base".to_string(),
        PathBuf::from("models.py"),
        1,
        Language::Python,
    );

    let mut user = InheritanceNode::new(
        "User".to_string(),
        PathBuf::from("models.py"),
        10,
        Language::Python,
    );
    user.bases = vec!["Base".to_string(), "TimestampMixin".to_string()];

    let mut post = InheritanceNode::new(
        "Post".to_string(),
        PathBuf::from("models.py"),
        20,
        Language::Python,
    );
    post.bases = vec!["Base".to_string(), "TimestampMixin".to_string()];

    let mut comment = InheritanceNode::new(
        "Comment".to_string(),
        PathBuf::from("models.py"),
        30,
        Language::Python,
    );
    comment.bases = vec!["Base".to_string(), "TimestampMixin".to_string()];

    graph.add_node(timestamp_mixin);
    graph.add_node(base);
    graph.add_node(user);
    graph.add_node(post);
    graph.add_node(comment);

    graph.add_edge("User", "Base");
    graph.add_edge("User", "TimestampMixin");
    graph.add_edge("Post", "Base");
    graph.add_edge("Post", "TimestampMixin");
    graph.add_edge("Comment", "Base");
    graph.add_edge("Comment", "TimestampMixin");

    graph
}

fn create_test_file(dir: &TempDir, name: &str, content: &str) -> PathBuf {
    let path = dir.path().join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, content).unwrap();
    path
}

// =============================================================================
// Options Tests
// =============================================================================

#[test]
fn test_inheritance_options_default() {
    let options = InheritanceOptions::default();

    assert!(options.class_filter.is_none());
    assert!(options.depth.is_none());
    assert!(!options.no_external);
    assert!(!options.no_patterns);
    assert!(options.max_nodes.is_none());
    assert!(!options.cluster_by_file);
}

#[test]
fn test_inheritance_options_validate_depth_without_class() {
    let options = InheritanceOptions {
        depth: Some(3),
        class_filter: None,
        ..Default::default()
    };

    let result = options.validate();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("requires --class"));
}

#[test]
fn test_inheritance_options_validate_depth_with_class() {
    let options = InheritanceOptions {
        depth: Some(3),
        class_filter: Some("MyClass".to_string()),
        ..Default::default()
    };

    assert!(options.validate().is_ok());
}

#[test]
fn test_inheritance_options_validate_valid() {
    let options = InheritanceOptions {
        class_filter: Some("MyClass".to_string()),
        depth: None,
        no_external: true,
        no_patterns: true,
        max_nodes: Some(100),
        cluster_by_file: true,
    };

    assert!(options.validate().is_ok());
}

// =============================================================================
// Python Class Extraction Tests
// =============================================================================

#[test]
fn test_extract_inheritance_python_empty() {
    let temp_dir = TempDir::new().unwrap();
    let options = InheritanceOptions::default();

    let result = extract_inheritance(temp_dir.path(), Some(Language::Python), &options);

    assert!(result.is_ok());
    let report = result.unwrap();
    assert_eq!(report.count, 0);
    assert!(report.nodes.is_empty());
    assert!(report.edges.is_empty());
}

#[test]
fn test_extract_inheritance_python_simple_class() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.py",
        r#"
class Animal:
    pass
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Python), &options);

    assert!(result.is_ok());
    let report = result.unwrap();
    assert_eq!(report.count, 1);
    assert!(report.nodes.iter().any(|n| n.name == "Animal"));
}

#[test]
fn test_extract_inheritance_python_single_inheritance() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.py",
        r#"
class Animal:
    pass

class Dog(Animal):
    pass
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Python), &options);

    assert!(result.is_ok());
    let report = result.unwrap();
    assert_eq!(report.count, 2);

    let dog = report.nodes.iter().find(|n| n.name == "Dog").unwrap();
    assert_eq!(dog.bases, vec!["Animal"]);
}

#[test]
fn test_extract_inheritance_python_multiple_inheritance() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.py",
        r#"
class Base:
    pass

class Mixin:
    pass

class Child(Base, Mixin):
    pass
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Python), &options);

    assert!(result.is_ok());
    let report = result.unwrap();

    let child = report.nodes.iter().find(|n| n.name == "Child").unwrap();
    assert_eq!(child.bases.len(), 2);
    assert!(child.bases.contains(&"Base".to_string()));
    assert!(child.bases.contains(&"Mixin".to_string()));
}

#[test]
fn test_extract_inheritance_python_abc() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.py",
        r#"
from abc import ABC

class Animal(ABC):
    pass
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Python), &options);

    assert!(result.is_ok());
    let report = result.unwrap();

    let animal = report.nodes.iter().find(|n| n.name == "Animal").unwrap();
    assert!(animal.bases.contains(&"ABC".to_string()));
}

#[test]
fn test_extract_inheritance_python_protocol() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.py",
        r#"
from typing import Protocol

class Serializable(Protocol):
    pass
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Python), &options);

    assert!(result.is_ok());
    let report = result.unwrap();

    let serializable = report
        .nodes
        .iter()
        .find(|n| n.name == "Serializable")
        .unwrap();
    assert!(serializable.bases.contains(&"Protocol".to_string()));
}

#[test]
fn test_extract_inheritance_python_metaclass() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.py",
        r#"
class Singleton(metaclass=SingletonMeta):
    pass
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Python), &options);

    assert!(result.is_ok());
    let report = result.unwrap();

    let singleton = report.nodes.iter().find(|n| n.name == "Singleton").unwrap();
    assert_eq!(singleton.metaclass, Some("SingletonMeta".to_string()));
}

#[test]
fn test_extract_inheritance_python_generic() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.py",
        r#"
from typing import Generic, TypeVar

T = TypeVar('T')

class Container(Generic[T]):
    pass
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Python), &options);

    assert!(result.is_ok());
    let report = result.unwrap();

    let container = report.nodes.iter().find(|n| n.name == "Container").unwrap();
    assert!(container.bases.contains(&"Generic".to_string()));
}

// =============================================================================
// TypeScript Class Extraction Tests
// =============================================================================

#[test]
fn test_extract_inheritance_typescript_simple_class() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.ts",
        r#"
class Animal {
    speak(): string {
        return "...";
    }
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::TypeScript), &options);

    assert!(result.is_ok());
    let report = result.unwrap();
    // why: `let _ = report;` discarded the extraction result and only checked
    // parsing didn't error — it never verified the class was actually found.
    assert!(
        report.nodes.iter().any(|n| n.name == "Animal"),
        "extraction should find the `Animal` class: {:?}",
        report.nodes
    );
}

#[test]
fn test_extract_inheritance_typescript_extends() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.ts",
        r#"
class Animal {}

class Dog extends Animal {
    speak(): string {
        return "woof";
    }
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::TypeScript), &options);

    assert!(result.is_ok());
}

#[test]
fn test_extract_inheritance_typescript_interface() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.ts",
        r#"
interface Serializable {
    serialize(): string;
}

class Dog implements Serializable {
    serialize(): string {
        return "{}";
    }
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::TypeScript), &options);

    assert!(result.is_ok());
}

#[test]
fn test_extract_inheritance_typescript_abstract() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.ts",
        r#"
abstract class Animal {
    abstract speak(): string;
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::TypeScript), &options);

    assert!(result.is_ok());
}

// =============================================================================
// Go Struct Extraction Tests
// =============================================================================

#[test]
fn test_extract_inheritance_go_simple_struct() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.go",
        r#"
package main

type Animal struct {
    Name string
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Go), &options);

    assert!(result.is_ok());
}

#[test]
fn test_extract_inheritance_go_struct_embedding() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.go",
        r#"
package main

type Animal struct {
    Name string
}

type Dog struct {
    Animal
    Breed string
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Go), &options);

    assert!(result.is_ok());
    let report = result.unwrap();

    // Dog should have Animal as base
    if let Some(dog) = report.nodes.iter().find(|n| n.name == "Dog") {
        assert!(dog.bases.contains(&"Animal".to_string()));
    }
}

#[test]
fn test_extract_inheritance_go_interface() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.go",
        r#"
package main

type Reader interface {
    Read(p []byte) (n int, err error)
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Go), &options);

    assert!(result.is_ok());
}

// =============================================================================
// Rust Trait Extraction Tests
// =============================================================================

#[test]
fn test_extract_inheritance_rust_struct() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.rs",
        r#"
struct Animal {
    name: String,
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Rust), &options);

    assert!(result.is_ok());
}

#[test]
fn test_extract_inheritance_rust_trait() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.rs",
        r#"
trait Animal {
    fn speak(&self) -> String;
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Rust), &options);

    assert!(result.is_ok());
}

#[test]
fn test_extract_inheritance_rust_impl() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.rs",
        r#"
trait Animal {
    fn speak(&self) -> String;
}

struct Dog {
    name: String,
}

impl Animal for Dog {
    fn speak(&self) -> String {
        "woof".to_string()
    }
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Rust), &options);

    assert!(result.is_ok());
}

// =============================================================================
// Pattern Detection Tests
// =============================================================================

#[test]
fn test_detect_abc_protocol() {
    let mut graph = create_test_graph();

    // Add ABC base
    if let Some(animal) = graph.nodes.get_mut("Animal") {
        animal.bases = vec!["ABC".to_string()];
    }

    detect_abc_protocol(&mut graph);

    let animal = graph.nodes.get("Animal").unwrap();
    assert_eq!(animal.is_abstract, Some(true));
}

#[test]
fn test_detect_protocol() {
    let mut graph = create_test_graph();

    // Add Protocol base
    if let Some(animal) = graph.nodes.get_mut("Animal") {
        animal.bases = vec!["Protocol".to_string()];
    }

    detect_abc_protocol(&mut graph);

    let animal = graph.nodes.get("Animal").unwrap();
    assert_eq!(animal.protocol, Some(true));
}

#[test]
fn test_detect_mixins_by_name() {
    let mut graph = create_mixin_graph();

    detect_mixins(&mut graph);

    let timestamp_mixin = graph.nodes.get("TimestampMixin").unwrap();
    assert_eq!(timestamp_mixin.mixin, Some(true));
}

#[test]
#[ignore = "Test needs fixing: HashMap key doesn't update when node.name changes"]
fn test_detect_mixins_by_usage() {
    // BUG DOCUMENTATION: The test setup has an issue where renaming a node
    // doesn't update the HashMap key, causing lookup to fail.
    // This tests the mixin detection by usage pattern (class used as secondary
    // base 2+ times with no bases itself).
    let mut graph = create_mixin_graph();

    // Rename to not end with "Mixin"
    if let Some(node) = graph.nodes.get_mut("TimestampMixin") {
        node.name = "Auditable".to_string();
    }

    // Update references
    for (_, node) in graph.nodes.iter_mut() {
        for base in &mut node.bases {
            if base == "TimestampMixin" {
                *base = "Auditable".to_string();
            }
        }
    }

    detect_mixins(&mut graph);

    // The node lookup may fail due to key mismatch
    if let Some(auditable) = graph.nodes.get("Auditable") {
        assert_eq!(auditable.mixin, Some(true));
    }
}

#[test]
fn test_detect_diamonds() {
    let graph = create_diamond_graph();

    let diamonds = detect_diamonds(&graph);

    assert_eq!(diamonds.len(), 1);
    assert_eq!(diamonds[0].class_name, "D");
    assert_eq!(diamonds[0].common_ancestor, "A");
    assert_eq!(diamonds[0].paths.len(), 2);
}

#[test]
fn test_no_diamond_single_inheritance() {
    let graph = create_test_graph();

    let diamonds = detect_diamonds(&graph);

    assert!(diamonds.is_empty());
}

#[test]
fn test_no_diamond_disjoint_parents() {
    let mut graph = InheritanceGraph::new();

    // D has two parents with no common ancestor
    let a = InheritanceNode::new(
        "A".to_string(),
        PathBuf::from("test.py"),
        1,
        Language::Python,
    );
    let b = InheritanceNode::new(
        "B".to_string(),
        PathBuf::from("test.py"),
        2,
        Language::Python,
    );

    let mut d = InheritanceNode::new(
        "D".to_string(),
        PathBuf::from("test.py"),
        3,
        Language::Python,
    );
    d.bases = vec!["A".to_string(), "B".to_string()];

    graph.add_node(a);
    graph.add_node(b);
    graph.add_node(d);

    graph.add_edge("D", "A");
    graph.add_edge("D", "B");

    let diamonds = detect_diamonds(&graph);
    assert!(diamonds.is_empty());
}

// =============================================================================
// Resolution Tests
// =============================================================================

#[test]
fn test_is_stdlib_class_python() {
    assert!(is_stdlib_class("Exception", Language::Python));
    assert!(is_stdlib_class("ABC", Language::Python));
    assert!(is_stdlib_class("Protocol", Language::Python));
    assert!(is_stdlib_class("TestCase", Language::Python));
    assert!(!is_stdlib_class("MyCustomClass", Language::Python));
}

#[test]
fn test_is_stdlib_class_typescript() {
    assert!(is_stdlib_class("Error", Language::TypeScript));
    assert!(is_stdlib_class("HTMLElement", Language::TypeScript));
    assert!(is_stdlib_class("Promise", Language::TypeScript));
    assert!(!is_stdlib_class("MyComponent", Language::TypeScript));
}

#[test]
fn test_is_stdlib_class_go() {
    assert!(is_stdlib_class("error", Language::Go));
    assert!(is_stdlib_class("Reader", Language::Go));
    assert!(is_stdlib_class("Writer", Language::Go));
    assert!(!is_stdlib_class("MyService", Language::Go));
}

#[test]
fn test_is_stdlib_class_rust() {
    assert!(is_stdlib_class("Clone", Language::Rust));
    assert!(is_stdlib_class("Debug", Language::Rust));
    assert!(is_stdlib_class("Iterator", Language::Rust));
    assert!(!is_stdlib_class("MyTrait", Language::Rust));
}

#[test]
fn test_resolve_base_project() {
    let graph = create_test_graph();

    let origin = resolve_base("Dog", &graph, Language::Python);
    assert_eq!(origin, BaseOrigin::Project);
}

#[test]
fn test_resolve_base_stdlib() {
    let graph = InheritanceGraph::new();

    let origin = resolve_base("Exception", &graph, Language::Python);
    assert_eq!(origin, BaseOrigin::Stdlib);
}

#[test]
fn test_resolve_base_unresolved() {
    let graph = InheritanceGraph::new();

    let origin = resolve_base("FlaskView", &graph, Language::Python);
    assert_eq!(origin, BaseOrigin::External);
}

// =============================================================================
// Filter Tests
// =============================================================================

#[test]
fn test_filter_by_class_exact_match() {
    let graph = create_test_graph();

    let filtered = filter_by_class(&graph, "Dog", None).unwrap();

    // Should include Dog, Animal (ancestor), and Cat (sibling)
    assert!(filtered.nodes.contains_key("Dog"));
    assert!(filtered.nodes.contains_key("Animal"));
}

#[test]
fn test_filter_by_class_with_depth() {
    let graph = create_test_graph();

    let filtered = filter_by_class(&graph, "Dog", Some(1)).unwrap();

    // Depth 1: Dog and Animal
    assert!(filtered.nodes.contains_key("Dog"));
    assert!(filtered.nodes.contains_key("Animal"));
}

#[test]
fn test_filter_by_class_not_found() {
    let graph = create_test_graph();

    let result = filter_by_class(&graph, "NotExists", None);

    assert!(result.is_err());
    let err = result.unwrap_err();
    let _err_string = err.to_string();
}

#[test]
fn test_fuzzy_suggestions() {
    let graph = create_test_graph();

    let suggestions = get_fuzzy_suggestions("Anmal", &graph); // Typo

    assert!(!suggestions.is_empty());
    assert!(suggestions.contains(&"Animal".to_string()));
}

// =============================================================================
// Format Tests
// =============================================================================

#[test]
fn test_escape_dot_string() {
    assert_eq!(escape_dot_string("Hello"), "Hello");
    assert_eq!(escape_dot_string("Hello\"World"), "Hello\\\"World");
    assert_eq!(escape_dot_string("Line1\nLine2"), "Line1\\nLine2");
    assert_eq!(escape_dot_string("A<B>C"), "A\\<B\\>C");
    assert_eq!(escape_dot_string("A{B}C"), "A\\{B\\}C");
}

#[test]
fn test_format_dot_basic() {
    use tldr_core::types::InheritanceReport;

    let mut report = InheritanceReport::new(PathBuf::from("/test/project"));
    report.count = 2;
    report.languages = vec![Language::Python];
    report.scan_time_ms = 42;

    report.nodes.push(InheritanceNode::new(
        "Animal".to_string(),
        PathBuf::from("animals.py"),
        1,
        Language::Python,
    ));
    report.nodes.push(InheritanceNode::new(
        "Dog".to_string(),
        PathBuf::from("animals.py"),
        10,
        Language::Python,
    ));

    let dot = format_dot(&report);

    assert!(dot.starts_with("digraph inheritance"));
    assert!(dot.contains("rankdir=BT"));
    assert!(dot.contains("\"Animal\""));
    assert!(dot.contains("\"Dog\""));
}

#[test]
fn test_format_text_basic() {
    use tldr_core::types::InheritanceReport;

    let mut report = InheritanceReport::new(PathBuf::from("/test/project"));
    report.count = 2;
    report.languages = vec![Language::Python];
    report.scan_time_ms = 42;

    report.nodes.push(InheritanceNode::new(
        "Animal".to_string(),
        PathBuf::from("animals.py"),
        1,
        Language::Python,
    ));
    report.nodes.push(InheritanceNode::new(
        "Dog".to_string(),
        PathBuf::from("animals.py"),
        10,
        Language::Python,
    ));

    report.roots = vec!["Animal".to_string()];
    report.leaves = vec!["Dog".to_string()];

    let text = format_text(&report);

    assert!(text.contains("Inheritance Graph"));
    assert!(text.contains("Classes found: 2"));
    assert!(text.contains("Animal"));
    assert!(text.contains("Dog"));
}

// =============================================================================
// Integration Tests
// =============================================================================

#[test]
fn test_full_inheritance_analysis_python() {
    let temp_dir = TempDir::new().unwrap();

    create_test_file(
        &temp_dir,
        "models.py",
        r#"
from abc import ABC, abstractmethod

class Animal(ABC):
    @abstractmethod
    def speak(self):
        pass

class Dog(Animal):
    def speak(self):
        return "woof"

class Cat(Animal):
    def speak(self):
        return "meow"
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Python), &options);

    assert!(result.is_ok());
    let report = result.unwrap();

    // Should find all classes
    assert!(report.nodes.iter().any(|n| n.name == "Animal"));
    assert!(report.nodes.iter().any(|n| n.name == "Dog"));
    assert!(report.nodes.iter().any(|n| n.name == "Cat"));

    // Animal should be abstract
    let animal = report.nodes.iter().find(|n| n.name == "Animal").unwrap();
    assert!(animal.is_abstract == Some(true) || animal.bases.contains(&"ABC".to_string()));
}

#[test]
fn test_full_inheritance_analysis_with_filter() {
    let temp_dir = TempDir::new().unwrap();

    create_test_file(
        &temp_dir,
        "models.py",
        r#"
class A:
    pass

class B(A):
    pass

class C(B):
    pass

class D(C):
    pass
"#,
    );

    let options = InheritanceOptions {
        class_filter: Some("C".to_string()),
        depth: Some(1),
        ..Default::default()
    };

    let result = extract_inheritance(temp_dir.path(), Some(Language::Python), &options);

    assert!(result.is_ok());
    let report = result.unwrap();

    // why: the old test bound `_report` and asserted nothing, so a regression
    // in `filter_by_class` (e.g. depth ignored, or the wrong class filtered)
    // would never fail this test. With depth 1 around C, the filtered graph
    // must contain C's immediate neighbors (B, D) and must not contain A,
    // which is two hops away.
    let names: Vec<&str> = report.nodes.iter().map(|n| n.name.as_str()).collect();
    assert!(
        names.contains(&"C"),
        "filtered graph must contain C: {names:?}"
    );
    assert!(
        names.contains(&"B"),
        "depth 1 must include parent B: {names:?}"
    );
    assert!(
        names.contains(&"D"),
        "depth 1 must include child D: {names:?}"
    );
    assert!(
        !names.contains(&"A"),
        "depth 1 must exclude A (two hops from C): {names:?}"
    );
}

#[test]
fn test_full_inheritance_analysis_no_patterns() {
    let temp_dir = TempDir::new().unwrap();

    create_test_file(
        &temp_dir,
        "models.py",
        r#"
class Base:
    pass

class Child(Base):
    pass
"#,
    );

    let options = InheritanceOptions {
        no_patterns: true,
        ..Default::default()
    };

    let result = extract_inheritance(temp_dir.path(), Some(Language::Python), &options);

    assert!(result.is_ok());
    let report = result.unwrap();

    // Should not have diamond patterns detected
    assert!(report.diamonds.is_empty());
}

// =============================================================================
// Bug Documentation Tests
// =============================================================================

/// Test to document behavior: extract_inheritance with non-existent path
#[test]
fn test_extract_inheritance_nonexistent_path() {
    let options = InheritanceOptions::default();
    let result = extract_inheritance(PathBuf::from("/nonexistent/path").as_path(), None, &options);

    // why: `result.is_ok() || result.is_err()` is a tautology that can never
    // fail (every Result is one or the other), so it verified nothing.
    // WalkDir silently drops the unreadable root (filter_map(|e| e.ok())),
    // so collect_source_files returns an empty file list and extract_inheritance
    // short-circuits to Ok(empty report) — assert that real, reachable behavior.
    let report = result.expect("nonexistent path should yield an empty report, not an error");
    assert_eq!(report.count, 0);
}

/// Test to document behavior: extract_inheritance with binary file
#[test]
fn test_extract_inheritance_binary_file() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("binary.bin");

    // Write binary data
    std::fs::write(&test_file, vec![0u8, 1, 2, 255, 254]).unwrap();

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), None, &options);

    // Should not panic
    assert!(result.is_ok());
}

/// Test to document behavior: filter_by_class with invalid depth
#[test]
fn test_filter_by_class_zero_depth() {
    let graph = create_test_graph();

    let result = filter_by_class(&graph, "Dog", Some(0));

    // Should handle gracefully
    assert!(result.is_ok());
    let filtered = result.unwrap();

    // With depth 0, should only include the class itself
    assert!(filtered.nodes.contains_key("Dog"));
}

/// Test to document behavior: empty graph operations
#[test]
fn test_detect_diamonds_empty_graph() {
    let graph = InheritanceGraph::new();

    let diamonds = detect_diamonds(&graph);

    assert!(diamonds.is_empty());
}

/// Test to document behavior: detect_mixins with empty graph
#[test]
fn test_detect_mixins_empty_graph() {
    let mut graph = InheritanceGraph::new();

    detect_mixins(&mut graph);

    // Should not panic
    assert!(graph.nodes.is_empty());
}

/// Test to document behavior: InheritanceNode with special characters in name
#[test]
fn test_inheritance_node_special_characters() {
    let node = InheritanceNode::new(
        "Class<With>Special{Chars}".to_string(),
        PathBuf::from("test.py"),
        1,
        Language::Python,
    );

    assert_eq!(node.name, "Class<With>Special{Chars}");

    // Test DOT escaping
    let escaped = escape_dot_string(&node.name);
    assert!(escaped.contains("\\<"));
    assert!(escaped.contains("\\>"));
    assert!(escaped.contains("\\{"));
    assert!(escaped.contains("\\}"));
}

// =============================================================================
// Scala Class Extraction Tests
// =============================================================================

#[test]
fn test_extract_inheritance_scala_simple_class() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.scala",
        r#"
class Animal {
  def speak(): String = "..."
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Scala), &options);

    assert!(result.is_ok());
    let report = result.unwrap();
    assert!(
        report.count >= 1,
        "Scala should find at least 1 class, found {}",
        report.count
    );
    assert!(
        report.nodes.iter().any(|n| n.name == "Animal"),
        "Should find Animal class, found: {:?}",
        report.nodes.iter().map(|n| &n.name).collect::<Vec<_>>()
    );
}

#[test]
fn test_extract_inheritance_scala_class_extends() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.scala",
        r#"
class Animal(val name: String)

class Dog(name: String) extends Animal(name) {
  def bark(): String = "Woof"
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Scala), &options);

    assert!(result.is_ok());
    let report = result.unwrap();
    assert!(
        report.count >= 2,
        "Scala should find at least 2 classes, found {}",
        report.count
    );

    let dog = report
        .nodes
        .iter()
        .find(|n| n.name == "Dog")
        .expect("Should find Dog class");
    assert!(
        dog.bases.contains(&"Animal".to_string()),
        "Dog should extend Animal, bases: {:?}",
        dog.bases
    );
}

#[test]
fn test_extract_inheritance_scala_trait() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.scala",
        r#"
trait Serializable {
  def serialize(): String
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Scala), &options);

    assert!(result.is_ok());
    let report = result.unwrap();
    assert!(
        report.count >= 1,
        "Scala should find trait, found {}",
        report.count
    );
    assert!(
        report.nodes.iter().any(|n| n.name == "Serializable"),
        "Should find Serializable trait"
    );
}

#[test]
fn test_extract_inheritance_scala_object_extends() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.scala",
        r#"
trait Compress {
  def headers: Seq[String]
}

object Gzip extends Compress {
  def headers = Seq("gzip")
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Scala), &options);

    assert!(result.is_ok());
    let report = result.unwrap();

    let gzip = report
        .nodes
        .iter()
        .find(|n| n.name == "Gzip")
        .expect("Should find Gzip object");
    assert!(
        gzip.bases.contains(&"Compress".to_string()),
        "Gzip should extend Compress, bases: {:?}",
        gzip.bases
    );
}

#[test]
fn test_extract_inheritance_scala_trait_extends_trait() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.scala",
        r#"
trait Base {
  def id: String
}

trait Extended extends Base {
  def name: String
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Scala), &options);

    assert!(result.is_ok());
    let report = result.unwrap();

    let extended = report
        .nodes
        .iter()
        .find(|n| n.name == "Extended")
        .expect("Should find Extended trait");
    assert!(
        extended.bases.contains(&"Base".to_string()),
        "Extended should extend Base, bases: {:?}",
        extended.bases
    );
}

#[test]
fn test_extract_inheritance_scala_class_with_trait_mixin() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.scala",
        r#"
class Animal(val name: String)

trait Serializable {
  def serialize(): String
}

class Dog(name: String) extends Animal(name) with Serializable {
  def serialize() = s"Dog($name)"
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Scala), &options);

    assert!(result.is_ok());
    let report = result.unwrap();

    let dog = report
        .nodes
        .iter()
        .find(|n| n.name == "Dog")
        .expect("Should find Dog class");
    assert!(
        dog.bases.contains(&"Animal".to_string()),
        "Dog should extend Animal, bases: {:?}",
        dog.bases
    );
    assert!(
        dog.bases.contains(&"Serializable".to_string()),
        "Dog should mix in Serializable, bases: {:?}",
        dog.bases
    );
}

#[test]
fn test_extract_inheritance_scala_case_class() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.scala",
        r#"
case class Request(url: String, method: String)
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Scala), &options);

    assert!(result.is_ok());
    let report = result.unwrap();
    assert!(
        report.count >= 1,
        "Scala should find case class, found {}",
        report.count
    );
    assert!(
        report.nodes.iter().any(|n| n.name == "Request"),
        "Should find Request case class"
    );
}

// =============================================================================
// Swift Class Extraction Tests
// =============================================================================

#[test]
fn test_extract_inheritance_swift_simple_class() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.swift",
        r#"
class Animal {
    func speak() -> String {
        return "..."
    }
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Swift), &options);

    assert!(result.is_ok());
    let report = result.unwrap();
    assert!(
        report.count >= 1,
        "Swift should find at least 1 class, found {}",
        report.count
    );
    assert!(
        report.nodes.iter().any(|n| n.name == "Animal"),
        "Should find Animal class, found: {:?}",
        report.nodes.iter().map(|n| &n.name).collect::<Vec<_>>()
    );
}

#[test]
fn test_extract_inheritance_swift_class_inherits() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.swift",
        r#"
class Animal {
    func speak() -> String { return "..." }
}

class Dog: Animal {
    override func speak() -> String { return "Woof" }
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Swift), &options);

    assert!(result.is_ok());
    let report = result.unwrap();
    assert!(
        report.count >= 2,
        "Swift should find at least 2 classes, found {}",
        report.count
    );

    let dog = report
        .nodes
        .iter()
        .find(|n| n.name == "Dog")
        .expect("Should find Dog class");
    assert!(
        dog.bases.contains(&"Animal".to_string()),
        "Dog should inherit from Animal, bases: {:?}",
        dog.bases
    );
}

#[test]
fn test_extract_inheritance_swift_protocol() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.swift",
        r#"
protocol Serializable {
    func serialize() -> String
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Swift), &options);

    assert!(result.is_ok());
    let report = result.unwrap();
    assert!(
        report.count >= 1,
        "Swift should find protocol, found {}",
        report.count
    );
    assert!(
        report.nodes.iter().any(|n| n.name == "Serializable"),
        "Should find Serializable protocol"
    );
}

#[test]
fn test_extract_inheritance_swift_class_with_protocol() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.swift",
        r#"
protocol ParameterEncoder {
    func encode() -> String
}

class JSONParameterEncoder: ParameterEncoder {
    func encode() -> String { return "{}" }
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Swift), &options);

    assert!(result.is_ok());
    let report = result.unwrap();

    let encoder = report
        .nodes
        .iter()
        .find(|n| n.name == "JSONParameterEncoder")
        .expect("Should find JSONParameterEncoder class");
    assert!(
        encoder.bases.contains(&"ParameterEncoder".to_string()),
        "JSONParameterEncoder should conform to ParameterEncoder, bases: {:?}",
        encoder.bases
    );
}

#[test]
fn test_extract_inheritance_swift_class_inherits_and_conforms() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.swift",
        r#"
class Request {
    var url: String = ""
}

protocol Sendable {}

class DownloadRequest: Request, Sendable {
    var destination: String = ""
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Swift), &options);

    assert!(result.is_ok());
    let report = result.unwrap();

    let download = report
        .nodes
        .iter()
        .find(|n| n.name == "DownloadRequest")
        .expect("Should find DownloadRequest class");
    assert!(
        download.bases.contains(&"Request".to_string()),
        "DownloadRequest should inherit from Request, bases: {:?}",
        download.bases
    );
    assert!(
        download.bases.contains(&"Sendable".to_string()),
        "DownloadRequest should conform to Sendable, bases: {:?}",
        download.bases
    );
}

#[test]
fn test_extract_inheritance_swift_protocol_inherits_protocol() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.swift",
        r#"
protocol Base {
    func id() -> String
}

protocol Extended: Base {
    func name() -> String
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Swift), &options);

    assert!(result.is_ok());
    let report = result.unwrap();

    let extended = report
        .nodes
        .iter()
        .find(|n| n.name == "Extended")
        .expect("Should find Extended protocol");
    assert!(
        extended.bases.contains(&"Base".to_string()),
        "Extended should inherit from Base, bases: {:?}",
        extended.bases
    );
}

#[test]
fn test_extract_inheritance_swift_struct_with_protocol() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.swift",
        r#"
protocol Encodable {}

struct Options: Encodable {
    var rawValue: Int = 0
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Swift), &options);

    assert!(result.is_ok());
    let report = result.unwrap();

    let opts = report
        .nodes
        .iter()
        .find(|n| n.name == "Options")
        .expect("Should find Options struct");
    assert!(
        opts.bases.contains(&"Encodable".to_string()),
        "Options should conform to Encodable, bases: {:?}",
        opts.bases
    );
}

// =============================================================================
// Kotlin Inheritance Integration Tests (kotlin module wire-up)
// =============================================================================

#[test]
fn test_extract_inheritance_kotlin_simple_class() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.kt",
        r#"
class Animal {
    fun speak() = "..."
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Kotlin), &options);

    assert!(result.is_ok());
    let report = result.unwrap();
    assert!(
        report.count >= 1,
        "Kotlin should find at least 1 class, found {}",
        report.count
    );
    assert!(
        report.nodes.iter().any(|n| n.name == "Animal"),
        "Should find Animal class"
    );
}

#[test]
fn test_extract_inheritance_kotlin_class_extends() {
    let temp_dir = TempDir::new().unwrap();
    create_test_file(
        &temp_dir,
        "test.kt",
        r#"
open class Animal(val name: String)

class Dog(name: String) : Animal(name) {
    fun bark() = "Woof"
}
"#,
    );

    let options = InheritanceOptions::default();
    let result = extract_inheritance(temp_dir.path(), Some(Language::Kotlin), &options);

    assert!(result.is_ok());
    let report = result.unwrap();
    assert!(
        report.count >= 2,
        "Kotlin should find at least 2 classes, found {}",
        report.count
    );

    let dog = report
        .nodes
        .iter()
        .find(|n| n.name == "Dog")
        .expect("Should find Dog class");
    assert!(
        dog.bases.contains(&"Animal".to_string()),
        "Dog should extend Animal, bases: {:?}",
        dog.bases
    );
}

/// Test to document behavior: InheritanceOptions validation edge cases
#[test]
fn test_inheritance_options_validation_edge_cases() {
    // Empty class filter with depth 0
    let options = InheritanceOptions {
        class_filter: None,
        depth: Some(0),
        ..Default::default()
    };

    let result = options.validate();
    assert!(result.is_err()); // Should require --class
}

// =============================================================================
// inheritance-and-dead-cleanup-v1 — M5 + M4 regression guards
// =============================================================================

/// M5 regression: edges from a directory scan must be deduplicated at the
/// (child, parent, parent_file) tuple level. Pre-fix, TS extractors emitted
/// the same heritage clause 3-4 times producing 6606 edges across 1562
/// nodes on the ts-dom-gen corpus.
#[test]
fn test_inheritance_edges_deduplicated() {
    use tempfile::TempDir;

    let dir = TempDir::new().unwrap();
    // Two TS files in which the same class extends the same parent.
    // Even if multiple files re-declare `class Child extends Base`, we
    // expect distinct (child, parent, parent_file) tuples — one edge per
    // distinct child-class definition. The bug duplicated within a single
    // file as well, which we simulate by listing the same parent twice
    // via a graph-level injection (tested below).
    let f1 = dir.path().join("a.ts");
    std::fs::write(
        &f1,
        "class Base {}\nclass Child extends Base {}\n",
    )
    .unwrap();

    let report = extract_inheritance(
        dir.path(),
        Some(Language::TypeScript),
        &InheritanceOptions::default(),
    )
    .unwrap();

    // Count edges with this exact (child, parent) — must be exactly 1.
    let child_to_base = report
        .edges
        .iter()
        .filter(|e| e.child == "Child" && e.parent == "Base")
        .count();
    assert_eq!(
        child_to_base, 1,
        "Child->Base edge should not be duplicated, got {} edges total: {:?}",
        child_to_base,
        report.edges,
    );

    // Stronger invariant: every (child, parent, parent_file) tuple is unique.
    let mut seen = std::collections::HashSet::new();
    for edge in &report.edges {
        let key = (edge.child.clone(), edge.parent.clone(), edge.parent_file.clone());
        assert!(
            seen.insert(key.clone()),
            "Duplicate edge tuple detected: {:?}",
            key,
        );
    }
}

/// M5 regression at the graph level: if an extractor calls add_edge multiple
/// times with the same (child, parent), build_edges must collapse to one
/// emitted edge.
#[test]
fn test_inheritance_edges_deduplicated_graph_level() {
    use tldr_core::inheritance::extract_inheritance;
    use tempfile::TempDir;

    // Construct a fixture where a single class extends a single parent.
    // We can't easily inject duplicate add_edge calls through the public
    // API, but we can validate the post-build_edges invariant on a real
    // scan: NO duplicate (child, parent, parent_file) tuples.
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("hier.ts"),
        r#"
class A {}
class B extends A {}
class C extends B {}
class D extends C {}
"#,
    )
    .unwrap();

    let report = extract_inheritance(
        dir.path(),
        Some(Language::TypeScript),
        &InheritanceOptions::default(),
    )
    .unwrap();

    let mut counts: std::collections::HashMap<(String, String), usize> =
        std::collections::HashMap::new();
    for edge in &report.edges {
        *counts.entry((edge.child.clone(), edge.parent.clone())).or_default() += 1;
    }
    for ((c, p), n) in &counts {
        assert_eq!(*n, 1, "edge {} -> {} appears {} times (expected 1)", c, p, n);
    }
}

/// M4 regression: a real diamond requires two DISTINCT immediate parents
/// converging on the same ancestor. A linear chain (C -> B -> A -> Object)
/// must NOT be reported as a diamond. Pre-fix, duplicate edges from M5
/// caused parents.len() >= 2 for what was effectively a single-parent
/// child, producing 1486 false-positive "diamonds" on ts-dom-gen.
#[test]
fn test_inheritance_diamond_real_pattern() {
    let mut graph = InheritanceGraph::new();

    // Real diamond: D inherits from BOTH B and A; B inherits from A; A
    // inherits from Object. Two distinct paths from D converge at A.
    let object = InheritanceNode::new("Object", PathBuf::from("test.ts"), 1, Language::TypeScript);
    let mut a = InheritanceNode::new("A", PathBuf::from("test.ts"), 2, Language::TypeScript);
    a.bases = vec!["Object".to_string()];
    let mut b = InheritanceNode::new("B", PathBuf::from("test.ts"), 3, Language::TypeScript);
    b.bases = vec!["A".to_string()];
    let mut c = InheritanceNode::new("C", PathBuf::from("test.ts"), 4, Language::TypeScript);
    c.bases = vec!["A".to_string(), "B".to_string()];

    graph.add_node(object);
    graph.add_node(a);
    graph.add_node(b);
    graph.add_node(c);
    graph.add_edge("A", "Object");
    graph.add_edge("B", "A");
    graph.add_edge("C", "A");
    graph.add_edge("C", "B");

    let diamonds = detect_diamonds(&graph);
    // The detector should report at least one diamond on C with
    // 2+ distinct paths (one direct C->A, one through B).
    let real_for_c: Vec<&_> = diamonds.iter().filter(|d| d.class_name == "C").collect();
    assert!(
        !real_for_c.is_empty(),
        "Expected at least one diamond on C; got: {:?}",
        diamonds,
    );
    for d in &real_for_c {
        assert!(
            d.paths.len() >= 2,
            "Diamond on C must have 2+ distinct paths; got {:?}",
            d.paths,
        );
        // All paths should be distinct.
        let mut sorted = d.paths.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            d.paths.len(),
            "Diamond paths must be distinct; got {:?}",
            d.paths,
        );
    }
}

/// M4 regression: linear chain must not be flagged as a diamond, even if
/// duplicate parent entries are accidentally injected (mirrors the
/// pre-M5-fix data shape that produced the 1486 false positives).
#[test]
fn test_inheritance_no_false_diamond_from_duplicate_parents() {
    let mut graph = InheritanceGraph::new();

    // Linear chain: CSSTransition -> Animation -> EventTarget
    let event_target =
        InheritanceNode::new("EventTarget", PathBuf::from("d.ts"), 1, Language::TypeScript);
    let mut animation =
        InheritanceNode::new("Animation", PathBuf::from("d.ts"), 2, Language::TypeScript);
    animation.bases = vec!["EventTarget".to_string()];
    let mut transition =
        InheritanceNode::new("CSSTransition", PathBuf::from("d.ts"), 3, Language::TypeScript);
    transition.bases = vec!["Animation".to_string()];

    graph.add_node(event_target);
    graph.add_node(animation);
    graph.add_node(transition);

    // Inject duplicates as the pre-M5 bug would have produced.
    graph.add_edge("Animation", "EventTarget");
    graph.add_edge("Animation", "EventTarget");
    graph.add_edge("Animation", "EventTarget");
    graph.add_edge("CSSTransition", "Animation");
    graph.add_edge("CSSTransition", "Animation");
    graph.add_edge("CSSTransition", "Animation");

    let diamonds = detect_diamonds(&graph);
    assert!(
        diamonds.is_empty(),
        "Linear chain (with duplicated edges) must NOT produce diamonds; got {:?}",
        diamonds,
    );
}
