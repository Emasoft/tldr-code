//! pack-patterns-lib-v1 (v0.5.0 PACK-PATTERNS)
//!
//! Library-level corpus tests for the AST-driven design-pattern +
//! visibility-aware-naming work, exercising `PatternMiner::mine_patterns`
//! directly (the exact pipeline the `tldr patterns` CLI command runs).
//!
//! These complement the CLI integration test
//! `crates/tldr-cli/tests/pack_patterns_v1.rs` and let the pattern miner
//! be validated against the real corpora without the CLI binary.
//!
//! Real-repo gated per no-synthetic-fixtures-v1: each test returns early
//! (skip) when its `/tmp/repos/<repo>` corpus is absent.

/// True when `dir` exists AND contains at least one non-`.git` regular
/// file (or is itself a regular file). CI/dev environments sometimes
/// leave the corpus directories present as empty skeletons (a `git`
/// clone with no working tree); `Path::exists()` is then `true` but every
/// analysis returns 0 files. These real-repo tests must skip cleanly in
/// that case rather than assert against empty output.
#[allow(dead_code)]
fn corpus_ready<P: AsRef<std::path::Path>>(p: P) -> bool {
    fn walk(p: &std::path::Path, depth: usize) -> bool {
        if depth > 8 {
            return false;
        }
        let Ok(rd) = std::fs::read_dir(p) else {
            return false;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some(".git") {
                continue;
            }
            match entry.file_type() {
                Ok(ft) if ft.is_file() => return true,
                Ok(ft) if ft.is_dir() => {
                    if walk(&path, depth + 1) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }
    let root = p.as_ref();
    if root.is_file() {
        return true;
    }
    root.exists() && walk(root, 0)
}


use std::path::Path;

use tldr_core::patterns::{PatternConfig, PatternMiner};

const SOLIDITY_CORPUS: &str = "/tmp/repos/solidity-openzeppelin";
const GO_CORPUS: &str = "/tmp/repos/go-httprouter";
const PHP_CORPUS: &str = "/tmp/repos/php-symfony-console";
const OCAML_CORPUS: &str = "/tmp/repos/ocaml-dune";

fn mine(path: &str) -> tldr_core::types::PatternReport {
    // Raise max_files so the whole corpus is scanned (default is 1000;
    // OpenZeppelin alone has ~400 source files but we want headroom).
    let config = PatternConfig {
        max_files: 100_000,
        ..PatternConfig::default()
    };
    let miner = PatternMiner::new(config);
    miner
        .mine_patterns(Path::new(path), None)
        .expect("mine_patterns must succeed on the corpus")
}

/// Run the exact `tldr patterns` pipeline over an in-memory single-file
/// fixture written to a temp dir. Used by the R7 cluster[9] char-tests
/// that pin precise accuracy behaviour the real corpora confirmed but
/// which a minimal AST input exercises deterministically.
fn mine_source(file_name: &str, source: &str) -> tldr_core::types::PatternReport {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join(file_name);
    std::fs::write(&path, source).unwrap();
    let config = PatternConfig {
        max_files: 100_000,
        ..PatternConfig::default()
    };
    let miner = PatternMiner::new(config);
    miner
        .mine_patterns(dir.path(), None)
        .expect("mine_patterns must succeed on the fixture")
}

// ============================================================================
// R7 cluster[9] #216/#217: Solidity Factory must require construction of a
// USER-DEFINED type (`new ProxyAdmin(...)`), never `new string/bytes/T[]`
// dynamic-memory allocation. Pure libraries (Base64/Strings/MerkleProof)
// were flagged Factory solely because they call `new string(n)`.
// ============================================================================
#[test]
fn solidity_factory_excludes_new_primitive_and_array_alloc() {
    // A pure library that only allocates dynamic memory via `new string` /
    // `new bytes` / `new T[]` — NOT a factory.
    let lib = r#"
library Strings {
    function buffer(uint256 length) internal pure returns (string memory) {
        string memory s = new string(length);
        bytes memory b = new bytes(2 * length + 2);
        uint256[] memory arr = new uint256[](length);
        return s;
    }
}
"#;
    let report = mine_source("Strings.sol", lib);
    let factories: Vec<&str> = report
        .design_patterns
        .iter()
        .filter(|d| d.pattern == "Factory")
        .map(|d| d.subject.as_str())
        .collect();
    assert!(
        factories.is_empty(),
        "library allocating only new string/bytes/array must NOT be a Factory; got {:?}",
        factories
    );
}

#[test]
fn solidity_factory_detects_new_user_defined_contract() {
    // A real factory: constructs a user-defined contract via `new C(...)`.
    let factory = r#"
contract ProxyAdmin {}
contract Deployer {
    function deploy(address owner) public returns (address) {
        return address(new ProxyAdmin());
    }
}
"#;
    let report = mine_source("Deployer.sol", factory);
    let factory_subjects: Vec<&str> = report
        .design_patterns
        .iter()
        .filter(|d| d.pattern == "Factory")
        .map(|d| d.subject.as_str())
        .collect();
    assert!(
        factory_subjects.contains(&"Deployer"),
        "contract constructing a user-defined type via `new` must be a Factory; got {:?}",
        factory_subjects
    );
}

// ============================================================================
// R7 cluster[9] #226: Scala `import x._` wildcard must register a
// star_imports signal. Pre-fix scala.rs only pushed the whole import text
// into absolute_imports and never inspected the trailing `._`.
// ============================================================================
#[test]
fn scala_wildcard_import_registers_star_imports() {
    let src = r#"
import zio._
import scala.collection.mutable.{Map, Set}
object Foo {
  def bar(x: Int): Int = x + 1
}
"#;
    let report = mine_source("Foo.scala", src);
    let ip = report
        .import_patterns
        .expect("scala fixture must produce an import_patterns block");
    assert_ne!(
        ip.star_imports,
        tldr_core::types::StarImportUsage::None,
        "Scala `import zio._` wildcard must populate star_imports; got {:?}",
        ip.star_imports
    );
}

#[test]
fn scala_selective_brace_import_is_not_star() {
    // `import x.{a, b}` is a SELECTIVE import, not a wildcard — it must NOT
    // count as a star import.
    let src = r#"
import scala.collection.mutable.{Map, Set}
object Bar {
  def baz(x: Int): Int = x
}
"#;
    let report = mine_source("Bar.scala", src);
    let ip = report
        .import_patterns
        .expect("scala fixture must produce an import_patterns block");
    assert_eq!(
        ip.star_imports,
        tldr_core::types::StarImportUsage::None,
        "Scala selective brace-import `.{{a, b}}` must NOT count as star; got {:?}",
        ip.star_imports
    );
}

// ============================================================================
// R7 cluster[9] #cl9 (design-fork): Scala GoF / idiomatic design-pattern
// detection. Pre-fix `ScalaSemantics` never called `push_pattern`, so
// `design_patterns` was always `null` for Scala. The file-level detector
// reuses the already-parsed sealed/case modifiers, `extends_clause` parents,
// and companion `apply` (AST-only). See
// decisions/r7-cl9-scala-gof-detection-gap.md.
// ============================================================================

/// Helper: design patterns matching `pattern` with `subject` in a report.
fn scala_pattern_subjects<'a>(
    report: &'a tldr_core::types::PatternReport,
    pattern: &str,
) -> Vec<&'a str> {
    report
        .design_patterns
        .iter()
        .filter(|d| d.pattern == pattern && d.language == "scala")
        .map(|d| d.subject.as_str())
        .collect()
}

#[test]
fn scala_sealed_trait_with_case_classes_is_adt() {
    let src = r#"
sealed trait Shape
case class Circle(r: Int) extends Shape
case object Unit extends Shape
"#;
    let report = mine_source("Shape.scala", src);
    let adts = scala_pattern_subjects(&report, "ADT");
    assert_eq!(
        adts,
        vec!["Shape"],
        "sealed trait with case variants must surface exactly one ADT for Shape; got {:?}",
        adts
    );
    let adt = report
        .design_patterns
        .iter()
        .find(|d| d.pattern == "ADT" && d.subject == "Shape")
        .expect("ADT for Shape must exist");
    assert_eq!(adt.category, "structural");
    assert!(
        adt.evidence.contains("Circle") && adt.evidence.contains("Unit"),
        "ADT evidence must list the variants; got {:?}",
        adt.evidence
    );
}

#[test]
fn scala_sealed_variants_nested_in_companion_is_adt() {
    // Variants nested inside the companion object's body (R2 play-json #502).
    let src = r#"
sealed trait Shape
object Shape {
  case class A() extends Shape
  case object B extends Shape
}
"#;
    let report = mine_source("ShapeNested.scala", src);
    let adts = scala_pattern_subjects(&report, "ADT");
    assert!(
        adts.contains(&"Shape"),
        "ADT must still be detected when variants are nested in the companion object; got {:?}",
        adts
    );
}

#[test]
fn scala_companion_object_apply_constructs_is_factory() {
    let src = r#"
class Chunk
object Chunk {
  def apply[A](a: A): Chunk = new Chunk()
}
"#;
    let report = mine_source("Chunk.scala", src);
    let factories = scala_pattern_subjects(&report, "Factory");
    assert_eq!(
        factories,
        vec!["Chunk"],
        "companion object whose `apply` constructs the companion type must be a Factory; got {:?}",
        factories
    );
    let f = report
        .design_patterns
        .iter()
        .find(|d| d.pattern == "Factory" && d.subject == "Chunk")
        .unwrap();
    assert_eq!(f.category, "creational");
}

#[test]
fn scala_enum_definition_is_adt() {
    let src = r#"
enum Color {
  case Red, Green
}
"#;
    let report = mine_source("Color.scala", src);
    let adts = scala_pattern_subjects(&report, "ADT");
    assert!(
        adts.contains(&"Color"),
        "Scala 3 `enum` is an intrinsic ADT; got {:?}",
        adts
    );
}

#[test]
fn scala_plain_companion_object_is_singleton() {
    let src = r#"
class Foo
object Foo {
  val cfg = 1
}
"#;
    let report = mine_source("Foo.scala", src);
    let singletons = scala_pattern_subjects(&report, "Singleton");
    assert_eq!(
        singletons,
        vec!["Foo"],
        "companion object with no constructing apply must be a Singleton; got {:?}",
        singletons
    );
    let s = report
        .design_patterns
        .iter()
        .find(|d| d.pattern == "Singleton" && d.subject == "Foo")
        .unwrap();
    assert_eq!(s.category, "creational");
}

#[test]
fn scala_bare_sealed_trait_no_variants_is_not_adt() {
    // SC-W1079 / E145: a sealed trait with ZERO subclasses is not a sum type.
    let src = r#"
sealed trait Marker
"#;
    let report = mine_source("Marker.scala", src);
    let adts = scala_pattern_subjects(&report, "ADT");
    assert!(
        adts.is_empty(),
        "a bare sealed trait with no variants must NOT be an ADT; got {:?}",
        adts
    );
}

#[test]
fn scala_apply_returning_non_companion_is_not_factory() {
    // `apply` that transforms input (no `new`, return type != companion) must
    // NOT be a Factory — evidence over name (the php.rs lesson).
    let src = r#"
object U {
  def apply(s: String): Int = s.length
}
"#;
    let report = mine_source("U.scala", src);
    let factories = scala_pattern_subjects(&report, "Factory");
    assert!(
        factories.is_empty(),
        "an `apply` that constructs nothing must NOT be a Factory; got {:?}",
        factories
    );
}

#[test]
fn scala_factory_and_singleton_not_double_counted() {
    // A companion object that is a Factory must be Factory ONLY, never also
    // Singleton (disjoint branches).
    let src = r#"
class Chunk
object Chunk {
  def apply[A](a: A): Chunk = new Chunk()
}
"#;
    let report = mine_source("ChunkDup.scala", src);
    let factories = scala_pattern_subjects(&report, "Factory");
    let singletons = scala_pattern_subjects(&report, "Singleton");
    assert!(
        factories.contains(&"Chunk"),
        "factory companion must fire Factory; got {:?}",
        factories
    );
    assert!(
        !singletons.contains(&"Chunk"),
        "a Factory companion must NOT also be counted as a Singleton; got {:?}",
        singletons
    );
}

#[test]
fn scala_bare_package_object_is_not_singleton() {
    // A standalone object with no same-name type must NOT be flagged Singleton
    // (the Singleton precision guard that prevents the 966-object swamp).
    let src = r#"
object utils {
  val cfg = 1
}
"#;
    let report = mine_source("utils.scala", src);
    let singletons = scala_pattern_subjects(&report, "Singleton");
    assert!(
        singletons.is_empty(),
        "a non-companion package object must NOT be flagged Singleton; got {:?}",
        singletons
    );
}

// ============================================================================
// R7 cluster[9] #150/#158 (design-fork, Option A): PHP Factory must require
// EVIDENCE of construction (a `new` in the method body OR an abstract
// factory method OR a *Factory-named class with a constructing method) —
// never a bare name match. See
// decisions/r7-cl9-php-factory-name-only-heuristic.md.
// ============================================================================
#[test]
fn php_factory_requires_construction_not_just_name() {
    // Methods named like factories that do NOT construct anything must NOT
    // be flagged: newLine() -> void, buildLine() -> string, buildUri()
    // transforms its input.
    let src = r#"<?php
class OutputStyle {
    public function newLine(): void { echo "\n"; }
    public function buildLine(): string { return "x"; }
    public function buildUri(UriInterface $u): UriInterface { return $u->withPath("/"); }
}
"#;
    let report = mine_source("OutputStyle.php", src);
    let factories: Vec<&str> = report
        .design_patterns
        .iter()
        .filter(|d| d.pattern == "Factory")
        .map(|d| d.subject.as_str())
        .collect();
    assert!(
        factories.is_empty(),
        "PHP class with factory-NAMED but non-constructing methods must NOT \
         be a Factory; got {:?}",
        factories
    );
}

#[test]
fn php_factory_detects_constructs_new() {
    // A real factory: a method that constructs an object via `new`.
    let src = r#"<?php
class ClientBuilder {
    public function createClient(): Client { return new Client(); }
}
"#;
    let report = mine_source("ClientBuilder.php", src);
    let factories: Vec<&str> = report
        .design_patterns
        .iter()
        .filter(|d| d.pattern == "Factory")
        .map(|d| d.subject.as_str())
        .collect();
    assert!(
        factories.contains(&"ClientBuilder"),
        "PHP class whose method constructs via `new` must be a Factory; got {:?}",
        factories
    );
}

#[test]
fn php_factory_detects_abstract_factory_method() {
    // An abstract factory method IS a factory contract even with no `new`.
    let src = r#"<?php
abstract class ShapeFactory {
    abstract public function createShape(): Shape;
}
"#;
    let report = mine_source("ShapeFactory.php", src);
    let factories: Vec<&str> = report
        .design_patterns
        .iter()
        .filter(|d| d.pattern == "Factory")
        .map(|d| d.subject.as_str())
        .collect();
    assert!(
        factories.contains(&"ShapeFactory"),
        "PHP abstract factory method must be a Factory; got {:?}",
        factories
    );
}

// ============================================================================
// R7 cluster[9] CLOSEOUT (design-fork, see
// decisions/r7-cl9-php-factory-name-only-heuristic.md): the PHP Factory
// predicate is RETURN/YIELD-REACHABILITY, not the mere existence of a `new`
// in the body. A factory-NAMED method is a Factory only when a
// freshly-constructed object reaches a `return`/`yield`. This drops the three
// surviving false-positive shapes the existence test still mis-flagged —
// throw-guard construction (`createCompletionInput`, `createBodyStream`),
// field-mutator construction (`createResponse`), and unreturned temporaries —
// while preserving real factories.
// ============================================================================

/// Factory subjects detected for a single-file PHP fixture.
fn php_factories(file_name: &str, source: &str) -> Vec<String> {
    mine_source(file_name, source)
        .design_patterns
        .iter()
        .filter(|d| d.pattern == "Factory")
        .map(|d| d.subject.clone())
        .collect()
}

#[test]
fn php_factory_excludes_throw_guard_construction() {
    // Mirrors symfony-console `CompleteCommand::createCompletionInput`: the
    // ONLY `new` is `throw new \RuntimeException(...)` in a precondition
    // guard; the method `return`s a static-factory call result. The thrown
    // construction never reaches the return, so it must NOT be a Factory.
    let src = r#"<?php
class CompleteCommand {
    private function createCompletionInput(InputInterface $input): CompletionInput
    {
        if (!$input->getOption('current')) {
            throw new \RuntimeException('The "--current" option must be set.');
        }
        $completionInput = CompletionInput::fromTokens($input->getOption('input'));
        return $completionInput;
    }
}
"#;
    let factories = php_factories("CompleteCommand.php", src);
    assert!(
        factories.is_empty(),
        "a `create*` whose only `new` is a `throw new` guard (returns a \
         static-factory call) must NOT be a Factory; got {:?}",
        factories
    );
}

#[test]
fn php_factory_excludes_field_mutator_construction() {
    // Mirrors guzzle `EasyHandle::createResponse`: the `new` is the RHS of a
    // FIELD assignment (`$this->response = new Response(...)`), not a fresh
    // local. Returning the field (`return $this->response;`, a
    // member_access — NOT a `variable_name` local) does not make it a
    // factory. Class return type, so this isolates the field-mutator
    // exclusion from the void-return-type filter.
    let src = r#"<?php
class EasyHandle {
    public function createResponse(): Response
    {
        $this->response = new Response(200);
        return $this->response;
    }
}
"#;
    let factories = php_factories("EasyHandle.php", src);
    assert!(
        factories.is_empty(),
        "a `create*` whose `new` is stored in a FIELD and returned via \
         member-access (not a fresh local) must NOT be a Factory; got {:?}",
        factories
    );
}

#[test]
fn php_factory_excludes_unreturned_temporary() {
    // The only `new` builds a local TEMPORARY that is used as an
    // intermediate and never returned; the method returns a cached field.
    // Class return type, so the unreturned-temporary exclusion is tested
    // independently of the void-return-type filter.
    let src = r#"<?php
class Widget {
    public function buildThing(): Thing
    {
        $tmp = new Helper();
        $tmp->configure($this->options);
        return $this->cached;
    }
}
"#;
    let factories = php_factories("Widget.php", src);
    assert!(
        factories.is_empty(),
        "a `build*` whose only `new` is an unreturned temporary (returns a \
         cached field) must NOT be a Factory; got {:?}",
        factories
    );
}

#[test]
fn php_factory_excludes_void_return_type() {
    // Negative return-type filter: a `: void` method can never carry a
    // constructed object out, so even a `new` (here in a throw) must not
    // make it a Factory.
    let src = r#"<?php
class Renderer {
    public function createBlock(): void
    {
        if ($this->broken) {
            throw new \LogicException('cannot render');
        }
    }
}
"#;
    let factories = php_factories("Renderer.php", src);
    assert!(
        factories.is_empty(),
        "a `create*(): void` method must NOT be a Factory (negative \
         return-type filter); got {:?}",
        factories
    );
}

#[test]
fn php_factory_detects_return_of_constructed_local() {
    // Clause (b): a local is assigned `new` and then returned —
    // `$x = new CompletionInput(); ...; return $x;`. A real factory.
    let src = r#"<?php
class Builder {
    public function createInput(InputInterface $i): CompletionInput
    {
        $x = new CompletionInput($i);
        $x->bind();
        return $x;
    }
}
"#;
    let factories = php_factories("Builder.php", src);
    assert!(
        factories.contains(&"Builder".to_string()),
        "a `create*` that constructs a local via `new` and returns it must \
         be a Factory; got {:?}",
        factories
    );
}

#[test]
fn php_factory_detects_constructed_local_after_earlier_write() {
    // Clause (b) reaching-def rule: the LAST write to the returned local is
    // the `new`, even though an earlier (conditional) non-`new` write to the
    // same variable precedes it. Mirrors symfony-console
    // `CommandTester::createInput` (`$input = array_merge(..); … $input = new
    // ArrayInput($input); … return $input;`). Must REMAIN a Factory.
    let src = r#"<?php
class CommandTester {
    private function createInput(array $input): InputInterface
    {
        if (!isset($input['command'])) {
            $input = array_merge(['command' => 'list'], $input);
        }
        $input = new ArrayInput($input);
        $input->setStream($this->stream);
        return $input;
    }
}
"#;
    let factories = php_factories("CommandTester.php", src);
    assert!(
        factories.contains(&"CommandTester".to_string()),
        "a `create*` whose LAST write to the returned local is `new` (an \
         earlier non-`new` write notwithstanding) must be a Factory; got {:?}",
        factories
    );
}

#[test]
fn php_factory_excludes_local_reassigned_after_new() {
    // Conservative kill: the returned local is constructed by `new` but then
    // REASSIGNED to a non-`new` value afterward, so the reaching def at the
    // return is no longer the construction. Must NOT be a Factory.
    let src = r#"<?php
class Thing {
    public function createWidget(): Widget
    {
        $w = new Widget();
        $w = $this->registry->lookup($w);
        return $w;
    }
}
"#;
    let factories = php_factories("Thing.php", src);
    assert!(
        factories.is_empty(),
        "a `create*` whose constructed local is reassigned to a non-`new` \
         value before the return must NOT be a Factory; got {:?}",
        factories
    );
}

#[test]
fn php_factory_detects_return_new_with_chain() {
    // Clause (a) with receiver-chain peeling: mirrors
    // `SymfonyStyle::createTable` — `return (new Table($o))->setStyle($s);`.
    // The chain head is the inner `new`, so it IS a factory.
    let src = r#"<?php
class SymfonyStyle {
    public function createTable(): Table
    {
        return (new Table($this->output))->setStyle('default');
    }
}
"#;
    let factories = php_factories("SymfonyStyle.php", src);
    assert!(
        factories.contains(&"SymfonyStyle".to_string()),
        "a `create*` returning `(new X(..))->fluent(..)` must be a Factory \
         (chain-head is the construction); got {:?}",
        factories
    );
}

#[test]
fn php_factory_returns_arrow_new() {
    // A returned arrow whose body is a construction (`fn() => new X()`) is
    // return-equivalent and IS a factory; `fn() => throw new X()` is NOT.
    let src = r#"<?php
class ServiceRegistry {
    public function makeFactory()
    {
        return fn() => new Service($this->config);
    }
}
class ThrowerRegistry {
    public function makeThrower()
    {
        return fn() => throw new \LogicException('nope');
    }
}
"#;
    let factories = php_factories("Registry.php", src);
    assert!(
        factories.contains(&"ServiceRegistry".to_string()),
        "a `make*` returning `fn() => new X()` must be a Factory; got {:?}",
        factories
    );
    assert!(
        !factories.contains(&"ThrowerRegistry".to_string()),
        "a `make*` returning `fn() => throw new X()` must NOT be a Factory; \
         got {:?}",
        factories
    );
}

#[test]
fn php_factory_ignores_new_in_nested_closure() {
    // Boundary guard: the only `new` lives in a NESTED closure's `return`
    // (`array_map(function () { return new Item(); }, ...)`); it belongs to
    // that closure, not the outer method, which returns a cached field. The
    // nested-function pruning keeps this from re-broadening into an FP.
    let src = r#"<?php
class Mapper {
    public function buildCollection(): Collection
    {
        $items = array_map(function () { return new Item(); }, $this->raw);
        return $this->cached;
    }
}
"#;
    let factories = php_factories("Mapper.php", src);
    assert!(
        factories.is_empty(),
        "a `build*` whose only `new` is inside a nested closure's return \
         must NOT be a Factory (scope boundary); got {:?}",
        factories
    );
}

// ============================================================================
// Solidity: Ownable + Proxy design patterns detected from the AST.
// ============================================================================
#[test]
fn solidity_design_patterns_ownable_and_proxy() {
    if !corpus_ready(SOLIDITY_CORPUS) {
        eprintln!("[skip] solidity corpus {} absent", SOLIDITY_CORPUS);
        return;
    }
    let report = mine(SOLIDITY_CORPUS);
    assert!(
        !report.design_patterns.is_empty(),
        "design_patterns must be non-empty on the OpenZeppelin corpus"
    );

    let names: Vec<&str> = report
        .design_patterns
        .iter()
        .map(|d| d.pattern.as_str())
        .collect();

    assert!(
        names.contains(&"Ownable"),
        "expected Ownable detected; got {:?}",
        names
    );
    assert!(
        names.contains(&"Proxy"),
        "expected Proxy detected; got {:?}",
        names
    );

    // All Solidity hits must carry AST-grounded file + line.
    for dp in &report.design_patterns {
        if dp.language == "solidity" {
            assert!(!dp.file.is_empty(), "solidity pattern missing file: {:?}", dp);
            assert!(dp.line >= 1, "solidity pattern missing line: {:?}", dp);
            assert!(
                !dp.subject.is_empty(),
                "solidity pattern missing subject: {:?}",
                dp
            );
        }
    }

    // Solidity must now be a supported pattern language (non-zero count).
    let solidity_count = report
        .metadata
        .language_distribution
        .patterns_by_language
        .get("solidity")
        .copied()
        .unwrap_or(0);
    assert!(
        solidity_count >= 1,
        "solidity pattern count must be >= 1; got {}",
        solidity_count
    );
}

// ============================================================================
// Solidity: the full detector set must all fire somewhere in OZ.
// ============================================================================
#[test]
fn solidity_detects_full_pattern_set() {
    if !corpus_ready(SOLIDITY_CORPUS) {
        eprintln!("[skip] solidity corpus {} absent", SOLIDITY_CORPUS);
        return;
    }
    let report = mine(SOLIDITY_CORPUS);
    let names: std::collections::HashSet<&str> = report
        .design_patterns
        .iter()
        .filter(|d| d.language == "solidity")
        .map(|d| d.pattern.as_str())
        .collect();

    for expected in ["Ownable", "Pausable", "ReentrancyGuard", "Proxy"] {
        assert!(
            names.contains(expected),
            "expected Solidity pattern `{}` somewhere in OpenZeppelin; detected: {:?}",
            expected,
            names
        );
    }
}

// ============================================================================
// Go: visibility-aware naming — no false violations on unexported funcs.
// ============================================================================
#[test]
fn go_unexported_funcs_not_violations() {
    if !corpus_ready(GO_CORPUS) {
        eprintln!("[skip] go corpus {} absent", GO_CORPUS);
        return;
    }
    let report = mine(GO_CORPUS);
    let naming = report.naming.expect("Go corpus must produce a naming block");

    let unexported_false_positives: Vec<&str> = naming
        .violations
        .iter()
        .map(|v| v.name.as_str())
        .filter(|name| {
            name.chars()
                .next()
                .map(|c| c.is_ascii_lowercase())
                .unwrap_or(false)
        })
        .collect();

    assert!(
        unexported_false_positives.is_empty(),
        "unexported (lowercase-first) Go funcs must not be flagged; got {:?}",
        unexported_false_positives
    );

    for known in ["getParams", "addRoute", "longestCommonPrefix", "findWildcard"] {
        assert!(
            !naming.violations.iter().any(|v| v.name == known),
            "correctly-cased unexported Go func `{}` must not be flagged",
            known
        );
    }
    for known in ["ParamsFromContext", "MatchedRoutePath", "New"] {
        assert!(
            !naming.violations.iter().any(|v| v.name == known),
            "correctly-cased exported Go func `{}` must not be flagged",
            known
        );
    }
}

// ============================================================================
// PHP: enriched profile is wired and a supported pattern language.
// ============================================================================
#[test]
fn php_is_supported_and_profile_runs() {
    if !corpus_ready(PHP_CORPUS) {
        eprintln!("[skip] php corpus {} absent", PHP_CORPUS);
        return;
    }
    let report = mine(PHP_CORPUS);
    // PHP must be in files_by_language and (being supported) get a count.
    let files = report
        .metadata
        .language_distribution
        .files_by_language
        .get("php")
        .copied()
        .unwrap_or(0);
    assert!(files >= 1, "expected php files scanned; got {}", files);

    // Any PHP design pattern detected must carry AST-grounded evidence.
    for dp in report.design_patterns.iter().filter(|d| d.language == "php") {
        assert!(!dp.file.is_empty(), "php pattern missing file: {:?}", dp);
        assert!(dp.line >= 1, "php pattern missing line: {:?}", dp);
        assert!(
            ["Singleton", "Factory", "Observer"].contains(&dp.pattern.as_str()),
            "unexpected php pattern name: {:?}",
            dp
        );
    }
}

// ============================================================================
// OCaml: module/functor idioms are detected on a real corpus.
// ============================================================================
#[test]
fn ocaml_module_idioms_detected() {
    if !corpus_ready(OCAML_CORPUS) {
        eprintln!("[skip] ocaml corpus {} absent", OCAML_CORPUS);
        return;
    }
    let report = mine(OCAML_CORPUS);

    let ocaml_patterns: Vec<&str> = report
        .design_patterns
        .iter()
        .filter(|d| d.language == "ocaml")
        .map(|d| d.pattern.as_str())
        .collect();

    // dune is a large OCaml codebase; it must contain at least one module
    // signature OR functor. (We don't pin an exact count — only that the
    // module-idiom detector fires on real OCaml module code.)
    assert!(
        ocaml_patterns
            .iter()
            .any(|p| matches!(*p, "Functor" | "ModuleSignature" | "FunctorApplication")),
        "expected at least one OCaml module idiom (Functor/ModuleSignature/\
         FunctorApplication) on the dune corpus; got {:?}",
        ocaml_patterns
    );

    for dp in report.design_patterns.iter().filter(|d| d.language == "ocaml") {
        assert!(!dp.file.is_empty(), "ocaml pattern missing file: {:?}", dp);
        assert!(dp.line >= 1, "ocaml pattern missing line: {:?}", dp);
    }
}
