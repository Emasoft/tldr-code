//! fix-CFr-RW5 (v0.5.0 RC CF-resid): Go cohesion — a receiver *method call*
//! (incl. a chained `recv.children[i].method(..)`) must NOT be counted as a
//! receiver *field*.
//!
//! RESIDUAL of fix-CF1-S7 (Wave-1 S7), which threaded the per-method Go
//! receiver name and restricted field accesses to `<recv>.field` (gin
//! field_count 37 -> 13). A field-less method that ONLY calls a receiver method
//! (`n.findCaseInsensitivePathRec(..)` and nothing else) produced an EMPTY AST
//! field walk — which then fell through to the legacy regex fallback
//! (`extract_go_receiver_accesses`, `n\.(\w+)`) that cannot tell a method CALL
//! from a field READ and re-captured the METHOD name as a phantom field
//! (go-httprouter `node`: field_count 8 vs the true 7).
//!
//! Anti-treadmill gate — every sub-assertion FAILS on the pre-fix source and
//! PASSES after, and the test ALSO re-asserts that the original S7
//! receiver-scoping still holds and that a non-Go/Rust language is unaffected:
//!   - NEW (go):   a pure receiver-method-call method credits NO phantom field;
//!                 a chained `recv.children[i].method(..)` credits `children`
//!                 (the real field) but NOT the trailing method name.
//!   - S7  (go):   a local/foreign-receiver `z.value` is still NOT a field, and
//!                 genuine `recv.field` reads are still credited (no regression).
//!   - OTHER (py): a class with genuine `self.field` reads is unaffected by the
//!                 Go|Rust empty-AST fallback exclusion.
//!
//! AST-driven only (tree-sitter node kinds + fields) — no regex, no hardcoded
//! names/paths in the analyzer.

use std::collections::HashSet;
use std::fs;

use tempfile::TempDir;
use tldr_core::quality::cohesion::{analyze_cohesion, CohesionReport};
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
// NEW (RW5) + S7 regression, distilled from go-httprouter `tree.go`'s `node`.
// ---------------------------------------------------------------------------
#[test]
fn cfr_rw5_go_receiver_method_call_not_field() {
    // `findCaseInsensitivePath` is field-LESS: it only CALLS a receiver method
    // (multi-line). `findCaseInsensitivePathRec` reads real fields and makes a
    // CHAINED receiver-method call `n.children[i].findCaseInsensitivePathRec(..)`
    // (selector operand is an `index_expression`). The trailing method name must
    // never be a field; `children` (the real field in the chain) must be.
    let src = "\
package router

type Handle int

type node struct {
\tpath     string
\tchildren []*node
\thandle   Handle
\tindices  string
}

func (n *node) findCaseInsensitivePath(path string) []byte {
\tciPath := n.findCaseInsensitivePathRec(
\t\tpath,
\t)
\treturn ciPath
}

func (n *node) findCaseInsensitivePathRec(path string) []byte {
\tz := lookup()
\t_ = z.value
\tif n.path == path {
\t\treturn n.handle.bytes()
\t}
\t_ = n.indices
\treturn n.children[0].findCaseInsensitivePathRec(path)
}

func lookup() *node { return nil }
";
    let (_d, rep) = report(&[("tree.go", src)], Language::Go);
    let fields = accessed_fields(&rep, "node");

    // NEW: the receiver-method name is NOT a field (pre-fix: phantom from the
    // field-less method's empty-AST regex fallback).
    assert!(
        !fields.contains("findCaseInsensitivePathRec"),
        "RW5: a receiver method CALL must not be counted as a field, got {fields:?}"
    );
    // S7 regression: a local/foreign-receiver `z.value` is still not a field.
    assert!(
        !fields.contains("value"),
        "S7: local `z.value` (non-receiver) must NOT be a field, got {fields:?}"
    );
    // No regression: every genuine `n.field` read (including the `children`
    // operand of the chained call) is still credited.
    for f in ["path", "children", "handle", "indices"] {
        assert!(
            fields.contains(f),
            "real receiver field `n.{f}` lost, got {fields:?}"
        );
    }

    let node = rep.classes.iter().find(|c| c.name == "node").unwrap();
    assert_eq!(
        node.method_count, 2,
        "both receiver methods counted, got {}",
        node.method_count
    );
    assert_eq!(
        node.field_count, 4,
        "exactly the 4 real fields {{path, children, handle, indices}} — no \
         phantom method-name field, got {}",
        node.field_count
    );
}

// ---------------------------------------------------------------------------
// S7 regression in isolation — receiver-scoped real fields still credited.
// ---------------------------------------------------------------------------
#[test]
fn cfr_rw5_go_real_receiver_fields_preserved() {
    let src = "\
package main

type Server struct {
\thost string
\tport int
}

func (s *Server) Dial() {
\tx := s.host
\ty := s.port
\t_ = x
\t_ = y
}

func (s *Server) Close() { s.audit() }

func (s *Server) audit() {}
";
    let (_d, rep) = report(&[("server.go", src)], Language::Go);
    let fields = accessed_fields(&rep, "Server");
    assert!(
        fields.contains("host") && fields.contains("port"),
        "genuine receiver fields must survive, got {fields:?}"
    );
    assert!(
        !fields.contains("audit"),
        "the receiver method call `s.audit()` must not be a field, got {fields:?}"
    );
    let server = rep.classes.iter().find(|c| c.name == "Server").unwrap();
    assert_eq!(
        server.field_count, 2,
        "only host + port are fields, got {}",
        server.field_count
    );
}

// ---------------------------------------------------------------------------
// OTHER language unaffected — Python `self.field` accounting is untouched by
// the Go|Rust empty-AST fallback exclusion.
// ---------------------------------------------------------------------------
#[test]
fn cfr_rw5_python_cohesion_unaffected() {
    let src = "\
class Account:
    def deposit(self, amount):
        self.balance = self.balance + amount

    def rate(self):
        return self.apr
";
    let (_d, rep) = report(&[("account.py", src)], Language::Python);
    let fields = accessed_fields(&rep, "Account");
    assert!(
        fields.contains("balance") && fields.contains("apr"),
        "Python self.field reads must still be credited, got {fields:?}"
    );
    let account = rep.classes.iter().find(|c| c.name == "Account").unwrap();
    assert_eq!(
        account.field_count, 2,
        "Python field accounting unaffected (balance + apr), got {}",
        account.field_count
    );
}
