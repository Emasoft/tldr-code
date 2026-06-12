//! fix-cl-6-v1 (v0.5.0 CL-6): cohesion extractor split-decl & missing lang arms
//!
//! Regression coverage for iter-3b gaps:
//!   - IT3-java-04: `this.field` dropped when it is the object-receiver of a
//!     `method_invocation` (`this.field.doSomething()`).
//!   - IT3-elixir-02: no `Language::Elixir` arm in cohesion -> `classes:0` for
//!     every Elixir module (`defmodule` with `def`/`defp` methods, `@attr`
//!     module attributes as the LCOM4 "fields").
//!   - IT3-cpp-03: out-of-line method definitions (`void Foo::method() {}`)
//!     in a split `.h`/`.cpp` idiom were never aggregated, so a `.cpp` with no
//!     in-body `class_specifier` yielded `classes:0`.
//!
//! AST-driven only (tree-sitter node kinds + fields).

use std::fs;
use tldr_core::quality::cohesion::analyze_cohesion;
use tldr_core::types::Language;

use tempfile::TempDir;

fn write(dir: &TempDir, name: &str, src: &str) {
    fs::write(dir.path().join(name), src).unwrap();
}

// ---------------------------------------------------------------------------
// IT3-java-04: `this.field.method()` must count `field`.
// ---------------------------------------------------------------------------
#[test]
fn cl6_java_this_field_as_method_receiver_is_counted() {
    let dir = TempDir::new().unwrap();
    write(
        &dir,
        "Foo.java",
        r#"
class Foo {
    private Bar field;
    private int count;

    void a() {
        this.field.doSomething();
        this.count = this.count + 1;
    }

    void b() {
        this.field.reset();
    }
}
"#,
    );

    let report = analyze_cohesion(dir.path(), Some(Language::Java), 2).unwrap();
    let foo = report
        .classes
        .iter()
        .find(|c| c.name == "Foo")
        .expect("Foo class should be analyzed");

    // Both `a` and `b` access `this.field`; `a` also accesses `count`.
    // So `field` is shared between a and b -> single connected component.
    assert_eq!(
        foo.lcom4, 1,
        "Foo should be cohesive (lcom4=1) because `field` is shared via \
         `this.field.method()`; got {} with components {:?}",
        foo.lcom4, foo.components
    );

    // `field` must appear among the recognised fields.
    let all_fields: std::collections::HashSet<&String> = foo
        .components
        .iter()
        .flat_map(|c| c.fields.iter())
        .collect();
    assert!(
        all_fields.iter().any(|f| f.as_str() == "field"),
        "`field` should be recognised as a field access, got {:?}",
        all_fields
    );
}

// ---------------------------------------------------------------------------
// IT3-elixir-02: Elixir module cohesion (defmodule + def/defp, @attr fields).
// ---------------------------------------------------------------------------
#[test]
fn cl6_elixir_module_cohesion_extracted() {
    let dir = TempDir::new().unwrap();
    write(
        &dir,
        "account.ex",
        r#"
defmodule Account do
  @currency :usd
  @max_balance 1000

  def deposit(amount) do
    new = @max_balance + amount
    {@currency, new}
  end

  defp validate(amount) do
    amount < @max_balance
  end

  def withdraw(amount) do
    if validate(amount), do: {@currency, amount}
  end
end
"#,
    );

    let report = analyze_cohesion(dir.path(), Some(Language::Elixir), 2).unwrap();

    let account = report
        .classes
        .iter()
        .find(|c| c.name == "Account")
        .expect("Account module should be analyzed as a class");

    // Three methods: deposit, validate, withdraw.
    assert_eq!(
        account.method_count, 3,
        "Account should expose 3 methods, got {}",
        account.method_count
    );

    // Module attributes @currency / @max_balance are the LCOM4 fields.
    assert!(
        account.field_count >= 1,
        "Account should track at least 1 module attribute field, got {}",
        account.field_count
    );
}

// ---------------------------------------------------------------------------
// IT3-cpp-03: out-of-line `Foo::method()` definitions in a `.cpp` aggregate
// into a synthesized `Foo` class.
// ---------------------------------------------------------------------------
#[test]
fn cl6_cpp_split_decl_out_of_line_methods_aggregated() {
    let dir = TempDir::new().unwrap();
    write(
        &dir,
        "widget.cpp",
        r#"
#include "widget.h"

int Widget::area() {
    return this->width * this->height;
}

void Widget::resize(int w, int h) {
    this->width = w;
    this->height = h;
}

void Widget::reset() {
    this->width = 0;
    this->height = 0;
}
"#,
    );

    let report = analyze_cohesion(dir.path(), Some(Language::Cpp), 2).unwrap();

    let widget = report
        .classes
        .iter()
        .find(|c| c.name == "Widget")
        .expect("Widget class should be synthesized from out-of-line defs");

    assert_eq!(
        widget.method_count, 3,
        "Widget should aggregate 3 out-of-line methods, got {}",
        widget.method_count
    );

    // All three methods touch width/height -> fully cohesive.
    assert_eq!(
        widget.lcom4, 1,
        "Widget should be cohesive (lcom4=1) since all methods share \
         width/height; got {} with {:?}",
        widget.lcom4, widget.components
    );
}
