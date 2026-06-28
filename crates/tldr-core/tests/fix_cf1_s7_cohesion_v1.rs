//! fix-CF1-S7 (v0.5.0 RC CF-wave): cohesion mega-pass generalization test.
//!
//! Symptom class: `tldr cohesion` field-set + self-call + class accounting.
//! This is the anti-treadmill gate — it asserts correctness for EVERY language
//! in the slice's symptom class (rust, go, java, swift, cpp, kotlin) and the
//! empty-applicable `None` aggregation. A single-language pass is NOT enough.
//!
//! Each sub-assertion FAILS on the pre-fix source and PASSES after:
//!   - Bug 1 (rust):   `impl<T> Foo<T>` methods re-associate with `Foo`.
//!   - Bug 2 (go):     field accesses are RECEIVER-scoped (`z.value` for a local
//!                     `z` is not a field).
//!   - Bug 3 (java):   bare (this-less) field references are credited.
//!   - Bug 4 (swift):  extension-distributed bare field reads are credited.
//!   - Bug 5 (cpp):    a namespace-qualified free function (`detail::f`) is NOT a
//!                     phantom class.
//!   - Bug 6 (kt/...): intra-class self-method calls add LCOM4 call edges.
//!   - Bug 7:          when no class is applicable, `summary.avg_lcom4 == None`.
//!
//! AST-driven only (tree-sitter node kinds + fields) — no regex, no hardcoded
//! names/paths.

use std::collections::HashSet;
use std::fs;

use tempfile::TempDir;
use tldr_core::quality::cohesion::{analyze_cohesion, CohesionReport, CohesionVerdict};
use tldr_core::types::Language;

/// Write `files` into a fresh temp dir and run the production cohesion path.
fn report(files: &[(&str, &str)], lang: Language) -> (TempDir, CohesionReport) {
    let dir = TempDir::new().unwrap();
    for (name, src) in files {
        fs::write(dir.path().join(name), src).unwrap();
    }
    let report = analyze_cohesion(dir.path(), Some(lang), 2).unwrap();
    (dir, report)
}

/// Accessed-field set for a class (union over its components).
fn accessed_fields(report: &CohesionReport, name: &str) -> HashSet<String> {
    let class = report
        .classes
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("class {name} not in cohesion report"));
    class
        .components
        .iter()
        .flat_map(|c| c.fields.iter().cloned())
        .collect()
}

// ---------------------------------------------------------------------------
// Bug 1 — Rust: a generic-impl struct must be credited.
// ---------------------------------------------------------------------------
#[test]
fn cf1_s7_rust_generic_impl_methods_associated() {
    let src = "\
struct Foo<T> {
    items: Vec<T>,
    count: usize,
}

impl<T> Foo<T> {
    fn add(&mut self, x: T) { self.items.push(x); self.count += 1; }
    fn total(&self) -> usize { self.count }
}
";
    let (_d, rep) = report(&[("foo.rs", src)], Language::Rust);
    let foo = rep
        .classes
        .iter()
        .find(|c| c.name == "Foo")
        .expect("generic `impl<T> Foo<T>` must re-associate with struct `Foo`");
    assert_eq!(foo.method_count, 2, "both impl methods counted: {foo:?}");
    assert_eq!(
        foo.field_count, 2,
        "self.items + self.count are two fields, got {}",
        foo.field_count
    );
    assert_eq!(
        foo.lcom4, 1,
        "add/total share `count` -> lcom4 == 1, got {}",
        foo.lcom4
    );
}

// ---------------------------------------------------------------------------
// Bug 2 (go field scoping) + Bug 6 (go self-calls).
// ---------------------------------------------------------------------------
#[test]
fn cf1_s7_go_receiver_scoped_fields_and_self_calls() {
    let src = "\
package main

type Server struct {
\tname string
}

func (s *Server) Start() {
\tz := lookup()
\t_ = z.value
\ts.audit()
\ts.name = \"x\"
}

func (s *Server) Stop() { s.name = \"y\" }

func (s *Server) audit() {}
";
    let (_d, rep) = report(&[("server.go", src)], Language::Go);
    let fields = accessed_fields(&rep, "Server");
    assert!(
        !fields.contains("value"),
        "Bug 2: `z.value` (non-receiver local `z`) must NOT be a field, got {fields:?}"
    );
    assert!(
        fields.contains("name"),
        "real receiver field `s.name` lost, got {fields:?}"
    );
    let server = rep.classes.iter().find(|c| c.name == "Server").unwrap();
    assert_eq!(
        server.field_count, 1,
        "only `name` is a field (no z.value inflation), got {}",
        server.field_count
    );
    assert_eq!(
        server.lcom4, 1,
        "Bug 6: Start-Stop share `name` and Start calls audit -> lcom4 == 1, got {}",
        server.lcom4
    );
}

// ---------------------------------------------------------------------------
// Bug 3 (java bare fields) + Bug 6 (java self-calls).
// ---------------------------------------------------------------------------
#[test]
fn cf1_s7_java_bare_fields_and_self_calls() {
    let src = "\
public class Account {
    private int balance;

    void deposit(int amount) { audit(); balance = balance + amount; }

    void withdraw(int amount) { balance = balance - amount; }

    void audit() {}
}
";
    let (_d, rep) = report(&[("Account.java", src)], Language::Java);
    let fields = accessed_fields(&rep, "Account");
    assert!(
        fields.contains("balance"),
        "Bug 3: bare (this-less) `balance` must be credited, got {fields:?}"
    );
    assert!(
        !fields.contains("audit"),
        "self-call `audit()` is not a field, got {fields:?}"
    );
    let acc = rep.classes.iter().find(|c| c.name == "Account").unwrap();
    assert_eq!(acc.field_count, 1, "only `balance`, got {}", acc.field_count);
    assert_eq!(
        acc.lcom4, 1,
        "deposit/withdraw share `balance` + deposit calls audit -> lcom4 == 1, got {}",
        acc.lcom4
    );
}

// ---------------------------------------------------------------------------
// Bug 4 (swift extension-distributed bare fields) + Bug 6 (swift self-calls).
// ---------------------------------------------------------------------------
#[test]
fn cf1_s7_swift_extension_bare_fields_and_self_calls() {
    let src = "\
struct Bag {
  var items: Int
}

extension Bag {
  func add() { audit(); items = items + 1 }
  func size() -> Int { return items }
  func audit() {}
}
";
    let (_d, rep) = report(&[("bag.swift", src)], Language::Swift);
    let fields = accessed_fields(&rep, "Bag");
    assert!(
        fields.contains("items"),
        "Bug 4: bare struct field `items` read in an extension method must be \
         credited, got {fields:?}"
    );
    assert!(
        !fields.contains("audit"),
        "self-call `audit()` is not a field, got {fields:?}"
    );
    let bag = rep.classes.iter().find(|c| c.name == "Bag").unwrap();
    assert_eq!(bag.field_count, 1, "only `items`, got {}", bag.field_count);
    assert_eq!(
        bag.lcom4, 1,
        "add/size share `items` + add calls audit -> lcom4 == 1, got {}",
        bag.lcom4
    );

    // Residual corpus assertion: the real OrderedDictionary struct must now have
    // a non-empty field set and the correct name (not 'None'), and its many
    // extension methods must connect (lcom4 << method_count).
    let corpus = "/Users/cosimo/.tldr-audit/corpora/swift-collections/Sources/\
OrderedCollections/OrderedDictionary/OrderedDictionary.swift";
    if std::path::Path::new(corpus).exists() {
        let rep = analyze_cohesion(std::path::Path::new(corpus), Some(Language::Swift), 2)
            .expect("analyze OrderedDictionary.swift");
        let od = rep
            .classes
            .iter()
            .find(|c| c.name == "OrderedDictionary")
            .expect("OrderedDictionary struct must resolve by name (not 'None')");
        assert!(
            od.field_count > 0,
            "OrderedDictionary stored properties (_keys/_values) must be credited, \
             got field_count={}",
            od.field_count
        );
        assert!(
            od.lcom4 < od.method_count,
            "extension methods sharing _keys/_values must connect (lcom4 {} < methods {})",
            od.lcom4,
            od.method_count
        );
    }
}

// ---------------------------------------------------------------------------
// Bug 5 — C++: a namespace-qualified free function is not a phantom class.
// ---------------------------------------------------------------------------
#[test]
fn cf1_s7_cpp_namespace_not_phantom_class() {
    let header = "\
namespace detail {
  int helper(int x);
}

class Widget {
public:
  void show();
  int get();
private:
  int count_;
};
";
    let source = "\
#include \"lib.h\"

int detail::helper(int x) { return x + 1; }

void Widget::show() { count_ = count_ + 1; }

int Widget::get() { return count_; }
";
    let (_d, rep) = report(
        &[("lib.h", header), ("lib.cpp", source)],
        Language::Cpp,
    );
    let names: HashSet<&str> = rep.classes.iter().map(|c| c.name.as_str()).collect();
    assert!(
        !names.contains("detail"),
        "Bug 5: the `detail` NAMESPACE must not be emitted as a phantom class \
         (from `detail::helper`), got {names:?}"
    );
    assert!(
        names.contains("Widget"),
        "the real out-of-line `Widget` class must still be synthesized, got {names:?}"
    );
}

// ---------------------------------------------------------------------------
// Bug 6 — Kotlin: intra-class self-method calls add LCOM4 call edges.
// ---------------------------------------------------------------------------
#[test]
fn cf1_s7_kotlin_self_calls_connect_components() {
    let src = "\
class Worker {
    private var count: Int = 0
    fun run() { audit(); count = count + 1 }
    fun stop() { count = 0 }
    fun audit() {}
}
";
    let (_d, rep) = report(&[("worker.kt", src)], Language::Kotlin);
    let worker = rep
        .classes
        .iter()
        .find(|c| c.name == "Worker")
        .expect("Worker class analyzed");
    assert_eq!(
        worker.lcom4, 1,
        "Bug 6: run/stop share `count` and run calls audit -> lcom4 == 1 \
         (audit must not stay an isolated component), got {} comps {:?}",
        worker.lcom4, worker.components
    );
}

// ---------------------------------------------------------------------------
// Bug 7 — empty-applicable aggregation returns None (not the 0.0 sentinel) for
// EVERY language in the slice's symptom class.
// ---------------------------------------------------------------------------
#[test]
fn cf1_s7_empty_applicable_avg_is_none_all_langs() {
    // Each marker type DECLARES no fields and its methods access none / call
    // none -> every class is NotApplicable -> no applicable LCOM4 -> avg None.
    let cases: &[(&str, &str, Language)] = &[
        (
            "m.rs",
            "struct M;\nimpl M {\n    fn a(&self) {}\n    fn b(&self) {}\n}\n",
            Language::Rust,
        ),
        (
            "m.go",
            "package main\ntype M struct{}\nfunc (m M) a() {}\nfunc (m M) b() {}\n",
            Language::Go,
        ),
        (
            "M.java",
            "public class M {\n    void a() {}\n    void b() {}\n}\n",
            Language::Java,
        ),
        (
            "m.swift",
            "struct M {\n    func a() {}\n    func b() {}\n}\n",
            Language::Swift,
        ),
        (
            "m.cpp",
            "class M {\npublic:\n    void a() {}\n    void b() {}\n};\n",
            Language::Cpp,
        ),
        (
            "M.kt",
            "class M {\n    fun a() {}\n    fun b() {}\n}\n",
            Language::Kotlin,
        ),
    ];
    for (name, src, lang) in cases {
        let (_d, rep) = report(&[(name, src)], *lang);
        // Every analyzed class is NotApplicable for these markers.
        for c in &rep.classes {
            assert_eq!(
                c.verdict,
                CohesionVerdict::NotApplicable,
                "{lang:?}: fieldless marker `{}` should be NotApplicable, got {:?}",
                c.name,
                c.verdict
            );
        }
        assert!(
            rep.summary.avg_lcom4.is_none(),
            "Bug 7 ({lang:?}): no applicable class -> summary.avg_lcom4 must be \
             None (not 0.0), got {:?}",
            rep.summary.avg_lcom4
        );
    }
}
