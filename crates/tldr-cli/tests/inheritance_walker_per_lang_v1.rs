//! inheritance-walker-per-lang-v1 (M-039)
//!
//! Per-language inheritance walker improvements:
//! - **rust**: `impl Trait for Type` emits `kind: "implements"` (not extends);
//!   self-loop `impl std::error::Error for Error` is qualified to avoid edge
//!   to self.
//! - **ruby**: `include`, `extend`, `prepend` are emitted as mixin bases on
//!   the enclosing class, with `kind: "implements"`.
//! - **kotlin**: `sealed` modifier on class/interface is captured (mixin flag
//!   distinguishes sealed from regular); abstract flag emitted explicitly
//!   instead of being silently null when the modifier is absent.
//! - **swift**: `extension Type: Protocol` is now extracted as a
//!   protocol-conformance edge. Inheritance specifier kind distinguishes
//!   first base (class superclass: extends) from subsequent (protocol
//!   conformances: implements).
//! - **elixir**: `defprotocol`, `defimpl` (with `for: Type`), `use ModName`,
//!   and `@behaviour ModName` produce inheritance/conformance edges.
//! - **lua**: `setmetatable(child, { __index = parent })` idiom is detected
//!   as an inheritance edge (extends).
//!
//! Schema parity: `bases:[]` is always an array (never null) — verified by
//! the existing serde definition of `InheritanceNode.bases: Vec<String>`.

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

fn run_tldr(args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    let output = cmd.args(args).output().expect("tldr binary missing");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

fn parse_json(stdout: &str) -> Value {
    serde_json::from_str(stdout).unwrap_or_else(|e| {
        panic!("Failed to parse JSON: {}\nstdout:\n{}", e, stdout);
    })
}

/// Rust: `impl Display for MyType` must emit edge kind=implements, not
/// extends. The orphan-rule self-impl `impl std::error::Error for Error`
/// must not produce an Error->Error self-loop edge.
#[test]
fn test_rust_impl_trait_for_type_is_implements_no_self_loop() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("lib.rs"),
        r#"
pub struct Error {
    kind: String,
}

pub struct MyType;

pub trait Display {
    fn fmt(&self) -> String;
}

impl Display for MyType {
    fn fmt(&self) -> String {
        "x".to_string()
    }
}

// Orphan-rule self-impl — must NOT produce Error->Error edge.
impl std::error::Error for Error {}
"#,
    )
    .unwrap();

    let (code, stdout, stderr) = run_tldr(&[
        "inheritance",
        "--lang",
        "rust",
        "--format",
        "json",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "inheritance failed: {}", stderr);

    let v = parse_json(&stdout);
    let edges = v["edges"].as_array().expect("edges array");

    // MyType -> Display must be kind=implements (not extends)
    let mytype_display = edges
        .iter()
        .find(|e| e["child"] == "MyType" && e["parent"] == "Display")
        .unwrap_or_else(|| panic!("missing MyType->Display edge in {:?}", edges));
    assert_eq!(
        mytype_display["kind"], "implements",
        "impl Trait for Type must be implements, not extends"
    );

    // No self-loop Error -> Error. Qualified scoped path "std::error::Error"
    // should be preserved to avoid name collision with local `Error`.
    let self_loop = edges
        .iter()
        .find(|e| e["child"] == "Error" && e["parent"] == "Error");
    assert!(
        self_loop.is_none(),
        "Error->Error self-loop must be eliminated (qualified trait path), found {:?}",
        self_loop
    );
}

/// Ruby: `include Mod` / `extend Mod` / `prepend Mod` emit mixin edges.
#[test]
fn test_ruby_include_extend_prepend_mixin_edges() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("mixin.rb"),
        r#"
module Comparable
end

module Enumerable
end

module Loggable
end

class MyCollection
  include Comparable
  extend Enumerable
  prepend Loggable
end
"#,
    )
    .unwrap();

    let (code, stdout, stderr) = run_tldr(&[
        "inheritance",
        "--lang",
        "ruby",
        "--format",
        "json",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "inheritance failed: {}", stderr);

    let v = parse_json(&stdout);
    let edges = v["edges"].as_array().expect("edges array");

    // m114-adapter-tail-v1 (v0.4.2 M-114) / CL-11R: each mixin keyword maps
    // to a DISTINCT inheritance kind, preserving Ruby's method-resolution-order
    // semantics — `include` -> "includes", `extend` -> "extended",
    // `prepend` -> "prepends". They must NOT be collapsed to "implements".
    for (parent, expected_kind) in &[
        ("Comparable", "includes"),
        ("Enumerable", "extended"),
        ("Loggable", "prepends"),
    ] {
        let mixin = edges
            .iter()
            .find(|e| e["child"] == "MyCollection" && e["parent"] == *parent)
            .unwrap_or_else(|| {
                panic!(
                    "missing MyCollection->{} mixin edge in {:?}",
                    parent, edges
                )
            });
        assert_eq!(
            mixin["kind"], *expected_kind,
            "ruby mixin {} must be kind={} (distinct MRO semantics)",
            parent, expected_kind
        );
    }
}

/// Kotlin: sealed class/interface is distinguished from regular via the
/// `mixin` flag (treated as a sealed marker on the node). Abstract flag
/// stays unset (None) when modifier is absent — but regular non-abstract
/// classes should not appear with `abstract:null` when sealed/data/value/
/// open is present. For sealed specifically, mixin=Some(true) is the
/// stable distinguishing marker.
#[test]
fn test_kotlin_sealed_class_distinguished() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("Sealed.kt"),
        r#"
sealed class Result {
    class Success(val value: Int) : Result()
    class Failure(val error: String) : Result()
}

sealed interface State {
}

class Plain {
}
"#,
    )
    .unwrap();

    let (code, stdout, stderr) = run_tldr(&[
        "inheritance",
        "--lang",
        "kotlin",
        "--format",
        "json",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "inheritance failed: {}", stderr);

    let v = parse_json(&stdout);
    let nodes = v["nodes"].as_array().expect("nodes array");

    let result = nodes
        .iter()
        .find(|n| n["name"] == "Result")
        .expect("missing Result node");
    assert_eq!(
        result["mixin"], true,
        "sealed class Result must be marked mixin=true (sealed marker), got {:?}",
        result
    );

    let state = nodes
        .iter()
        .find(|n| n["name"] == "State")
        .expect("missing State node");
    assert_eq!(
        state["mixin"], true,
        "sealed interface State must be marked mixin=true (sealed marker), got {:?}",
        state
    );

    let plain = nodes
        .iter()
        .find(|n| n["name"] == "Plain")
        .expect("missing Plain node");
    // Plain class: must not be flagged as sealed.
    assert!(
        plain["mixin"].is_null() || plain["mixin"] == false,
        "plain class must not be flagged as sealed/mixin, got {:?}",
        plain
    );
}

/// Swift: `extension Type: Protocol` must yield a conformance edge from
/// `Type` to `Protocol` (the type may be defined elsewhere, including in
/// the same file). Multiple protocols in the same extension produce one
/// edge per protocol. Edges should be kind=implements.
#[test]
fn test_swift_extension_protocol_conformance() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("ext.swift"),
        r#"
struct Point {
    var x: Int
    var y: Int
}

protocol Drawable {
    func draw()
}

protocol Comparable {
    func compare(other: Self) -> Int
}

extension Point: Drawable, Comparable {
    func draw() {}
    func compare(other: Point) -> Int { return 0 }
}
"#,
    )
    .unwrap();

    let (code, stdout, stderr) = run_tldr(&[
        "inheritance",
        "--lang",
        "swift",
        "--format",
        "json",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "inheritance failed: {}", stderr);

    let v = parse_json(&stdout);
    let edges = v["edges"].as_array().expect("edges array");

    for protocol in &["Drawable", "Comparable"] {
        let conformance = edges
            .iter()
            .find(|e| e["child"] == "Point" && e["parent"] == *protocol)
            .unwrap_or_else(|| {
                panic!(
                    "missing Point->{} conformance edge in {:?}",
                    protocol, edges
                )
            });
        assert_eq!(
            conformance["kind"], "implements",
            "swift extension protocol conformance must be implements, not extends"
        );
    }
}

/// Elixir: `defprotocol`, `defimpl ... for: Type`, `use Mod`, `@behaviour
/// Mod` produce inheritance/conformance edges. No elixir inheritance
/// walker exists pre-fix, so this test asserts at least these four edges
/// appear post-fix.
#[test]
fn test_elixir_defprotocol_defimpl_use_behaviour() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("proto.ex"),
        r#"
defprotocol MyProto do
  def encode(data)
end

defmodule MyType do
  defstruct [:value]
end

defimpl MyProto, for: MyType do
  def encode(data), do: data.value
end

defmodule MyBehaviour do
  @callback handle() :: :ok
end

defmodule MyServer do
  use GenServer
  @behaviour MyBehaviour

  def init(_), do: {:ok, nil}
end
"#,
    )
    .unwrap();

    let (code, stdout, stderr) = run_tldr(&[
        "inheritance",
        "--lang",
        "elixir",
        "--format",
        "json",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "inheritance failed: {}", stderr);

    let v = parse_json(&stdout);
    let edges = v["edges"].as_array().expect("edges array");

    // defimpl: MyType -> MyProto
    let defimpl_edge = edges
        .iter()
        .find(|e| e["child"] == "MyType" && e["parent"] == "MyProto");
    assert!(
        defimpl_edge.is_some(),
        "missing defimpl MyType->MyProto edge in {:?}",
        edges
    );
    assert_eq!(
        defimpl_edge.unwrap()["kind"],
        "implements",
        "defimpl must be implements"
    );

    // use: MyServer -> GenServer
    let use_edge = edges
        .iter()
        .find(|e| e["child"] == "MyServer" && e["parent"] == "GenServer");
    assert!(
        use_edge.is_some(),
        "missing use MyServer->GenServer edge in {:?}",
        edges
    );

    // @behaviour: MyServer -> MyBehaviour
    let behaviour_edge = edges
        .iter()
        .find(|e| e["child"] == "MyServer" && e["parent"] == "MyBehaviour");
    assert!(
        behaviour_edge.is_some(),
        "missing @behaviour MyServer->MyBehaviour edge in {:?}",
        edges
    );
    assert_eq!(
        behaviour_edge.unwrap()["kind"],
        "implements",
        "@behaviour must be implements"
    );
}

/// Lua: `setmetatable(child, { __index = parent })` idiom is recognized as
/// an inheritance edge.
#[test]
fn test_lua_setmetatable_inheritance() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("oop.lua"),
        r#"
Animal = {}
Animal.__index = Animal

function Animal:new()
  local self = setmetatable({}, Animal)
  return self
end

Dog = {}
Dog.__index = Dog
setmetatable(Dog, { __index = Animal })

function Dog:new()
  local self = setmetatable({}, Dog)
  return self
end
"#,
    )
    .unwrap();

    let (code, stdout, stderr) = run_tldr(&[
        "inheritance",
        "--lang",
        "lua",
        "--format",
        "json",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "inheritance failed: {}", stderr);

    let v = parse_json(&stdout);
    let edges = v["edges"].as_array().expect("edges array");

    let dog_animal = edges
        .iter()
        .find(|e| e["child"] == "Dog" && e["parent"] == "Animal");
    assert!(
        dog_animal.is_some(),
        "missing Dog->Animal setmetatable __index inheritance edge in {:?}",
        edges
    );
}

/// Schema parity: every `InheritanceNode.bases` is an array (never null).
#[test]
fn test_bases_always_array_never_null() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("plain.rs"),
        r#"
pub struct StandAlone;
pub trait NoSuper {}
"#,
    )
    .unwrap();

    let (code, stdout, _stderr) = run_tldr(&[
        "inheritance",
        "--lang",
        "rust",
        "--format",
        "json",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    let v = parse_json(&stdout);
    for node in v["nodes"].as_array().expect("nodes") {
        assert!(
            node["bases"].is_array(),
            "bases must always be an array (never null), got {:?} for {:?}",
            node["bases"],
            node["name"]
        );
    }
}
