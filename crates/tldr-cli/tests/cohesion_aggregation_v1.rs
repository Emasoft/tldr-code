//! cohesion-cross-file-aggregation-v1 (v0.4.2 M-030)
//!
//! Phase-22 audit cluster CLUSTER-M-030:
//!     "Cohesion `field_count:0` on partial-class / cross-file types"
//!
//! Pre-fix observed defects:
//!   - swift extension-only files report `classes:0`
//!     (e.g. `extension String { func reverseChars() {…} }`)
//!     because cohesion fell through `Language::Swift => _ => vec![]`.
//!   - swift class + extension(s) in the same file emit no aggregation:
//!     methods declared in `extension Shape {}` invisible to the
//!     `Shape` class entry.
//!   - csharp `partial class Customer` split across files emits two
//!     `Customer` ClassCohesion entries with split fields.
//!   - kotlin classes report `classes:0` (extractor entirely missing).
//!   - lua `local Point = {}` + `function Point:m()` setmetatable
//!     idiom emits `classes:0` (no extractor).
//!
//! Post-fix invariants:
//!   - swift extension-only file → 1+ classes, methods extracted.
//!   - swift class-with-extensions file → one merged entry with the
//!     union of method names + cohesion computed across all of them.
//!   - csharp directory walk → partial-class names occur ONCE with
//!     the union of fields across files.
//!   - kotlin class → emitted with methods.
//!   - lua setmetatable `Point` → emitted as a class with field count.
//!
//! Java & TypeScript already worked at the file level in the v0.4.1
//! baseline; their guards here lock the working behaviour against
//! regression while the aggregation paths land for the other langs.
//!
//! Synthetic-fixture allowance: per `claim-verification` and
//! `no-synthetic-fixtures-v1`, these tests stage real source snippets
//! into a `tempdir` and assert on the cohesion analyser's outputs;
//! they do NOT depend on any external `/tmp/repos/<repo>` corpus.

use std::path::{Path, PathBuf};

use tldr_core::quality::cohesion::analyze_cohesion;
use tldr_core::types::Language;

/// Create a temporary file at <dir>/<name> with <contents>.
fn write_file(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, contents).expect("failed to write fixture file");
    p
}

// ===========================================================================
// Swift: class + extensions in same file
// ===========================================================================

const SWIFT_SHAPE: &str = r#"
class Shape {
    var width: Double
    var height: Double
    init(width: Double, height: Double) {
        self.width = width
        self.height = height
    }
}

extension Shape {
    func area() -> Double {
        return self.width * self.height
    }
    func perimeter() -> Double {
        return 2 * (self.width + self.height)
    }
}

extension Shape {
    func describe() -> String {
        return "\(self.width) x \(self.height)"
    }
}
"#;

#[test]
fn swift_class_with_extensions_aggregates_into_single_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_file(dir.path(), "Shape.swift", SWIFT_SHAPE);

    let report = analyze_cohesion(&path, Some(Language::Swift), 2)
        .expect("analyze_cohesion swift Shape.swift");

    // Pre-fix: report.classes is empty.
    // Post-fix: one (merged) entry named `Shape`.
    let shape_entries: Vec<_> = report
        .classes
        .iter()
        .filter(|c| c.name == "Shape")
        .collect();
    assert_eq!(
        shape_entries.len(),
        1,
        "expected exactly one merged `Shape` entry across class+extensions, got {:?}",
        report
            .classes
            .iter()
            .map(|c| (&c.name, c.method_count, c.field_count))
            .collect::<Vec<_>>()
    );
    let shape = shape_entries[0];

    // Three extension methods (`area`, `perimeter`, `describe`) must be
    // aggregated. `init` is a constructor and is intentionally excluded
    // from the cohesion analysis (consistent with the existing TS/
    // Java/CSharp constructor-exclusion policy).
    assert!(
        shape.method_count >= 3,
        "expected >=3 methods from union of class+extensions, got method_count={}",
        shape.method_count
    );

    // `width` and `height` are accessed by area/perimeter/describe via
    // `self.width` / `self.height`.
    assert!(
        shape.field_count >= 2,
        "expected >=2 fields (width,height) accessed across methods, got field_count={}",
        shape.field_count
    );
}

// ===========================================================================
// Swift: extension-only file (Phase-21 regression)
// ===========================================================================

const SWIFT_EXT_ONLY: &str = r#"
import Foundation

extension String {
    func reverseChars() -> String {
        return String(self.reversed())
    }
    func myCount() -> Int {
        return self.count
    }
}

extension Array {
    func myFirst() -> Element? {
        return self.first
    }
}
"#;

#[test]
fn swift_extension_only_file_emits_classes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_file(dir.path(), "ExtOnly.swift", SWIFT_EXT_ONLY);

    let report = analyze_cohesion(&path, Some(Language::Swift), 2)
        .expect("analyze_cohesion swift ExtOnly.swift");

    // Pre-fix: classes_analyzed == 0 (the Phase-21 regression).
    // Post-fix: 2 entries — one for `String`, one for `Array`.
    let names: Vec<&str> = report.classes.iter().map(|c| c.name.as_str()).collect();
    assert!(
        names.contains(&"String"),
        "expected `String` class from extension, got {:?}",
        names
    );
    assert!(
        names.contains(&"Array"),
        "expected `Array` class from extension, got {:?}",
        names
    );

    // The `String` entry must surface its 2 methods.
    let string_entry = report
        .classes
        .iter()
        .find(|c| c.name == "String")
        .expect("String entry");
    assert!(
        string_entry.method_count >= 2,
        "expected >=2 methods on String extension, got {}",
        string_entry.method_count
    );
}

// ===========================================================================
// CSharp: partial class spread across two files
// ===========================================================================

const CSHARP_PARTIAL_1: &str = r#"
namespace MyApp {
    public partial class Customer {
        private string firstName;
        private string lastName;
        public string GetName() {
            return this.firstName + " " + this.lastName;
        }
    }
}
"#;

const CSHARP_PARTIAL_2: &str = r#"
namespace MyApp {
    public partial class Customer {
        private int age;
        private string email;
        public bool IsAdult() {
            return this.age >= 18;
        }
        public string GetContact() {
            return this.email;
        }
    }
}
"#;

#[test]
fn csharp_partial_class_unions_fields_across_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_file(dir.path(), "Partial1.cs", CSHARP_PARTIAL_1);
    write_file(dir.path(), "Partial2.cs", CSHARP_PARTIAL_2);

    let report = analyze_cohesion(dir.path(), Some(Language::CSharp), 2)
        .expect("analyze_cohesion csharp partial");

    // Pre-fix: two separate `Customer` entries with split methods.
    // Post-fix: exactly ONE `Customer` entry with the union.
    let customer_entries: Vec<_> = report
        .classes
        .iter()
        .filter(|c| c.name == "Customer")
        .collect();
    assert_eq!(
        customer_entries.len(),
        1,
        "expected exactly one merged `Customer` partial-class entry, got {} entries: {:?}",
        customer_entries.len(),
        customer_entries
            .iter()
            .map(|c| (c.file.display().to_string(), c.method_count, c.field_count))
            .collect::<Vec<_>>()
    );
    let customer = customer_entries[0];

    // Union: GetName + IsAdult + GetContact = 3 methods.
    assert!(
        customer.method_count >= 3,
        "expected union of 3 methods across files, got {}",
        customer.method_count
    );
    // Fields actually accessed via `this.X`:
    // GetName uses firstName, lastName;
    // IsAdult uses age; GetContact uses email
    // -> >= 4 unique fields seen.
    assert!(
        customer.field_count >= 4,
        "expected >=4 unioned fields across partial-class files, got {}",
        customer.field_count
    );
}

// ===========================================================================
// Kotlin: regular class (extractor was entirely missing)
// ===========================================================================

const KOTLIN_PERSON: &str = r#"
class Person(name: String, age: Int) {
    private var personName: String = name
    private var personAge: Int = age

    fun greet(): String = "Hello, ${this.personName}"
    fun birthday() { this.personAge = this.personAge + 1 }
    fun describe(): String = "${this.personName} is ${this.personAge}"
}
"#;

#[test]
fn kotlin_class_emits_with_methods() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_file(dir.path(), "Person.kt", KOTLIN_PERSON);

    let report = analyze_cohesion(&path, Some(Language::Kotlin), 2)
        .expect("analyze_cohesion kotlin Person.kt");

    // Pre-fix: report.classes is empty (no kotlin extractor).
    // Post-fix: one `Person` entry with 3 methods.
    let person = report
        .classes
        .iter()
        .find(|c| c.name == "Person")
        .unwrap_or_else(|| {
            panic!(
                "expected `Person` entry, got {:?}",
                report
                    .classes
                    .iter()
                    .map(|c| (&c.name, c.method_count, c.field_count))
                    .collect::<Vec<_>>()
            )
        });
    assert!(
        person.method_count >= 3,
        "expected >=3 methods on Kotlin Person, got {}",
        person.method_count
    );
}

// ===========================================================================
// Lua: setmetatable prototype idiom
// ===========================================================================

const LUA_POINT: &str = r#"
local Point = {}
Point.__index = Point

function Point.new(x, y)
    local self = setmetatable({}, Point)
    self.x = x
    self.y = y
    return self
end

function Point:distance(other)
    return math.sqrt((self.x - other.x)^2 + (self.y - other.y)^2)
end

function Point:translate(dx, dy)
    self.x = self.x + dx
    self.y = self.y + dy
end

return Point
"#;

#[test]
fn lua_setmetatable_prototype_emits_class() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_file(dir.path(), "Point.lua", LUA_POINT);

    let report = analyze_cohesion(&path, Some(Language::Lua), 2)
        .expect("analyze_cohesion lua Point.lua");

    // Pre-fix: 0 classes (no lua extractor).
    // Post-fix: one `Point` entry. setmetatable-style classes are the
    // dominant idiom for prototype OO in lua, so we emit one ClassInfo
    // per `local X = {}` table whose name is referenced by a
    // `function X.m()` / `function X:m()` definition.
    let point = report
        .classes
        .iter()
        .find(|c| c.name == "Point")
        .unwrap_or_else(|| {
            panic!(
                "expected `Point` setmetatable class, got {:?}",
                report
                    .classes
                    .iter()
                    .map(|c| (&c.name, c.method_count))
                    .collect::<Vec<_>>()
            )
        });

    // `Point.new` + `Point:distance` + `Point:translate` -> 3 methods.
    assert!(
        point.method_count >= 2,
        "expected >=2 methods on Point setmetatable proto, got {}",
        point.method_count
    );
}

// ===========================================================================
// Java: non-regression guard (already worked at v0.4.1 baseline)
// ===========================================================================

const JAVA_SERVICE: &str = r#"
package com.example;

public class Service {
    private String name;
    private int count;
    private boolean active;

    public String getName() {
        return this.name;
    }

    public void setName(String n) {
        this.name = n;
    }

    public int getCount() {
        return this.count;
    }

    public void incrementCount() {
        this.count++;
    }

    public boolean isActive() {
        return this.active;
    }
}
"#;

#[test]
fn java_simple_class_fields_visible_regression_guard() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_file(dir.path(), "Service.java", JAVA_SERVICE);

    let report = analyze_cohesion(&path, Some(Language::Java), 2)
        .expect("analyze_cohesion java Service.java");

    let service = report
        .classes
        .iter()
        .find(|c| c.name == "Service")
        .expect("Service entry");
    assert!(
        service.field_count >= 3,
        "expected >=3 fields (name,count,active), got {}",
        service.field_count
    );
}

// ===========================================================================
// TypeScript: non-regression guard
// ===========================================================================

const TS_CALC: &str = r#"
export class Calculator {
    private value: number = 0;
    private history: number[] = [];

    add(x: number): number {
        this.value += x;
        this.history.push(x);
        return this.value;
    }

    getHistory(): number[] {
        return this.history;
    }

    reset(): void {
        this.value = 0;
        this.history = [];
    }
}
"#;

#[test]
fn typescript_class_fields_visible_regression_guard() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_file(dir.path(), "Calc.ts", TS_CALC);

    let report = analyze_cohesion(&path, Some(Language::TypeScript), 2)
        .expect("analyze_cohesion ts Calc.ts");

    let calc = report
        .classes
        .iter()
        .find(|c| c.name == "Calculator")
        .expect("Calculator entry");
    assert!(
        calc.field_count >= 2,
        "expected >=2 fields (value,history), got {}",
        calc.field_count
    );
}

// ===========================================================================
// fix-cl-7-repair3-v1 (v0.5.0 DESIGN-TAIL): C++ cross-file / namespace
// behaviour of the SHARED partial-class aggregator, asserted end-to-end
// through the production `analyze_cohesion` entry point (the same function the
// `tldr cohesion` CLI command calls). Each test FAILS if the repair3 wiring
// (declared-field bare-member scan reaching members nested under macro-misparse
// `labeled_statement` wrappers; namespace-qualified partial key; empty-ns
// parse-recovery compatibility merge) is reverted.
// ===========================================================================

/// Macro-prefixed class declaration in a `.h` (the dominant library idiom,
/// e.g. tinyxml2's `class TINYXML2_LIB XMLElement`). tree-sitter-cpp misparses
/// the `class MACRO Name` form into a `function_definition`/`declaration`
/// whose body is a `compound_statement` in which access specifiers nest the
/// members under `labeled_statement` wrappers.
const CPP_HDR_MACRO: &str = r#"
namespace lib {
class LIBAPI Widget
{
public:
    int Area() const { return _w * _h; }
    void Resize(int w, int h);
    void Move(int dx, int dy);
private:
    int _w;
    int _h;
};
}
"#;

/// The out-of-line `.cpp` definitions for the same class, inside the SAME
/// namespace. These carry the real field accesses for the declared-only `.h`
/// signatures.
const CPP_SRC_MACRO: &str = r#"
namespace lib {
void Widget::Resize(int w, int h) { _w = w; _h = h; }
void Widget::Move(int dx, int dy) { _w = _w + dx; _h = _h + dy; }
}
"#;

#[test]
fn cpp_macro_prefixed_header_and_source_merge_into_one_entry() {
    // ROOT-CAUSE GUARD (tinyxml2 double-count): the `.h` macro-prefixed
    // declaration and the `.cpp` out-of-line definitions must collapse to a
    // SINGLE `Widget` entry. Pre-repair3 the `.h` macro class extracted zero
    // members (its `compound_statement` body nests members under a
    // `labeled_statement`), so it was dropped and only the `.cpp` entry showed
    // (field_count 0); when forced to emit it double-counted. This pins the
    // merged, deduplicated result.
    let dir = tempfile::tempdir().expect("tempdir");
    write_file(dir.path(), "widget.h", CPP_HDR_MACRO);
    write_file(dir.path(), "widget.cpp", CPP_SRC_MACRO);

    let report = analyze_cohesion(dir.path(), Some(Language::Cpp), 2)
        .expect("analyze_cohesion cpp macro .h/.cpp");

    let widgets: Vec<_> = report
        .classes
        .iter()
        .filter(|c| c.name == "Widget")
        .collect();
    assert_eq!(
        widgets.len(),
        1,
        "macro-prefixed .h declaration + .cpp out-of-line defs must merge into \
         ONE Widget entry (no double-count); got {} entries: {:?}",
        widgets.len(),
        widgets
            .iter()
            .map(|c| (c.file.display().to_string(), c.line, c.method_count, c.field_count))
            .collect::<Vec<_>>()
    );
    let w = widgets[0];

    // Area, Resize, Move = 3 distinct methods, deduplicated across the
    // declared-only `.h` signatures and their `.cpp` definitions.
    assert_eq!(
        w.method_count, 3,
        "merged Widget must expose exactly Area+Resize+Move (deduped), got {} \
         components {:?}",
        w.method_count, w.components
    );

    // `_w` and `_h` are touched bare (no `this->`) by Area (in the `.h` inline
    // body, resolved via the declared-field scan that now reaches members under
    // the `labeled_statement`) and by Resize/Move (in the `.cpp`). With the
    // shared field set every method connects -> a single cohesive component.
    let fields: std::collections::HashSet<String> = w
        .components
        .iter()
        .flat_map(|c| c.fields.iter().cloned())
        .collect();
    assert!(
        fields.contains("_w") && fields.contains("_h"),
        "bare member accesses _w/_h must resolve across the merged class, got {:?}",
        fields
    );
    assert_eq!(
        w.lcom4, 1,
        "merged Widget should be one cohesive component once _w/_h are shared, \
         got lcom4={} components={:?}",
        w.lcom4, w.components
    );
}

/// Two same-named C++ classes in DIFFERENT namespaces. Each is a clean in-body
/// `class_specifier` (no macro), so each carries its real namespace.
const CPP_TWO_NS_ISOLATION: &str = r#"
namespace alpha {
class Gadget {
    int x;
public:
    int getX() { return x; }
    void setX(int v) { x = v; }
};
}
namespace beta {
class Gadget {
    double y;
public:
    double getY() { return y; }
    void setY(double v) { y = v; }
};
}
"#;

#[test]
fn cpp_same_name_different_namespace_stay_separate() {
    // NAMESPACE-ISOLATION GUARD: alpha::Gadget and beta::Gadget share a bare
    // name but live in distinct namespaces. The shared partial aggregator's
    // namespace-qualified key MUST keep them as TWO entries (a bare-name key
    // would mis-merge them). Both carry non-empty distinct namespaces, so the
    // empty-ns compatibility merge does NOT apply.
    let dir = tempfile::tempdir().expect("tempdir");
    write_file(dir.path(), "gadgets.cpp", CPP_TWO_NS_ISOLATION);

    let report = analyze_cohesion(dir.path(), Some(Language::Cpp), 2)
        .expect("analyze_cohesion cpp two-namespace");

    let gadgets: Vec<_> = report
        .classes
        .iter()
        .filter(|c| c.name == "Gadget")
        .collect();
    assert_eq!(
        gadgets.len(),
        2,
        "alpha::Gadget and beta::Gadget must remain TWO distinct entries; got {} \
         entries: {:?}",
        gadgets.len(),
        gadgets
            .iter()
            .map(|c| (c.line, c.method_count, c.field_count))
            .collect::<Vec<_>>()
    );
}

/// A derived class whose method touches a BASE-class field bare. The own-class
/// declared-field scan cannot see the base's fields (they live in a different
/// declaration / translation unit), so the bare base-field reference is the
/// documented v1 under-count boundary.
const CPP_DERIVED_BARE_BASE: &str = r#"
class Base {
protected:
    int shared;
};
class Derived : public Base {
    int own;
public:
    // touches the OWN field bare -> credited
    void useOwn() { own = own + 1; }
    // touches an INHERITED (base) field bare -> documented under-count boundary
    void useBase() { shared = shared + 1; }
};
"#;

#[test]
fn cpp_inherited_bare_field_under_count_boundary() {
    // BOUNDARY GUARD (pinned, not hidden): `own` is an own-class field and is
    // credited; `shared` is inherited and is NOT credited by the own-class
    // declared-field scan. This documents the v1 inherited-field under-count
    // boundary so it stays VISIBLE and stable rather than silently masked.
    let dir = tempfile::tempdir().expect("tempdir");
    write_file(dir.path(), "derived.cpp", CPP_DERIVED_BARE_BASE);

    let report = analyze_cohesion(dir.path(), Some(Language::Cpp), 2)
        .expect("analyze_cohesion cpp derived bare-base");

    let derived = report
        .classes
        .iter()
        .find(|c| c.name == "Derived")
        .expect("Derived entry");
    let fields: std::collections::HashSet<String> = derived
        .components
        .iter()
        .flat_map(|c| c.fields.iter().cloned())
        .collect();

    // Own-class bare field IS credited (the A1 declared-field scan).
    assert!(
        fields.contains("own"),
        "own-class bare field `own` must be credited, got {:?}",
        fields
    );
    // Inherited bare field is the documented under-count boundary: NOT credited.
    assert!(
        !fields.contains("shared"),
        "inherited base-class field `shared` is the documented v1 under-count \
         boundary and must NOT be credited, got {:?}",
        fields
    );
    // useOwn touches `own`; useBase touches only the (uncounted) base field, so
    // it has no own-class field signal -> the two methods do NOT connect. This
    // pins the boundary's downstream effect (an LCOM4 split) explicitly.
    assert_eq!(
        derived.lcom4, 2,
        "with the inherited field uncounted, useOwn/useBase form 2 components, \
         got lcom4={} components={:?}",
        derived.lcom4, derived.components
    );
}

// ===========================================================================
// C#: cross-namespace partial collision. The existing
// `csharp_partial_class_unions_fields_across_files` uses `namespace MyApp` in
// BOTH files, so it never exercises the collision. These two tests pin BOTH
// directions of the namespace-qualified key through the production path:
//   - DIFFERENT namespaces -> stay SEPARATE,
//   - SAME namespace        -> still UNION.
// ===========================================================================

const CS_DIFF_NS_A: &str = r#"
namespace Alpha {
    public partial class Account {
        private int balance;
        public int GetBalance() { return this.balance; }
    }
}
"#;

const CS_DIFF_NS_B: &str = r#"
namespace Beta {
    public partial class Account {
        private string owner;
        public string GetOwner() { return this.owner; }
    }
}
"#;

#[test]
fn csharp_partial_class_different_namespaces_stay_separate() {
    // Alpha.Account and Beta.Account are unrelated classes that happen to share
    // a bare name. The namespace-qualified partial key MUST keep them as TWO
    // entries. Both namespaces are non-empty and distinct, so the empty-ns
    // compatibility merge does not apply.
    let dir = tempfile::tempdir().expect("tempdir");
    write_file(dir.path(), "Alpha.cs", CS_DIFF_NS_A);
    write_file(dir.path(), "Beta.cs", CS_DIFF_NS_B);

    let report = analyze_cohesion(dir.path(), Some(Language::CSharp), 2)
        .expect("analyze_cohesion csharp cross-namespace partial");

    let accounts: Vec<_> = report
        .classes
        .iter()
        .filter(|c| c.name == "Account")
        .collect();
    assert_eq!(
        accounts.len(),
        2,
        "Alpha.Account and Beta.Account must stay SEPARATE (cross-namespace \
         collision); got {} entries: {:?}",
        accounts.len(),
        accounts
            .iter()
            .map(|c| (c.file.display().to_string(), c.method_count, c.field_count))
            .collect::<Vec<_>>()
    );
}

const CS_SAME_NS_A: &str = r#"
namespace Gamma {
    public partial class Ledger {
        private int debit;
        public int GetDebit() { return this.debit; }
    }
}
"#;

const CS_SAME_NS_B: &str = r#"
namespace Gamma {
    public partial class Ledger {
        private int credit;
        public int GetCredit() { return this.credit; }
    }
}
"#;

#[test]
fn csharp_partial_class_same_namespace_unions() {
    // Two `Gamma.Ledger` partial fragments must still MERGE into one entry with
    // the union of their methods/fields (same namespace-qualified key).
    let dir = tempfile::tempdir().expect("tempdir");
    write_file(dir.path(), "Ledger1.cs", CS_SAME_NS_A);
    write_file(dir.path(), "Ledger2.cs", CS_SAME_NS_B);

    let report = analyze_cohesion(dir.path(), Some(Language::CSharp), 2)
        .expect("analyze_cohesion csharp same-namespace partial");

    let ledgers: Vec<_> = report
        .classes
        .iter()
        .filter(|c| c.name == "Ledger")
        .collect();
    assert_eq!(
        ledgers.len(),
        1,
        "two Gamma.Ledger partial fragments must MERGE into one entry; got {} \
         entries: {:?}",
        ledgers.len(),
        ledgers
            .iter()
            .map(|c| (c.file.display().to_string(), c.method_count, c.field_count))
            .collect::<Vec<_>>()
    );
    let ledger = ledgers[0];
    assert!(
        ledger.method_count >= 2,
        "merged Gamma.Ledger must expose GetDebit+GetCredit, got {}",
        ledger.method_count
    );
    assert!(
        ledger.field_count >= 2,
        "merged Gamma.Ledger must union debit+credit fields, got {}",
        ledger.field_count
    );
}

// ===========================================================================
// fix-FixA-bare-field-v1 (v0.5.0 AUDIT-FIX): BARE member references must be
// credited as field accesses for the languages whose idiom omits an explicit
// `this`/`self` receiver (C#, Scala, Kotlin, Ruby `attr_*`) and the
// pre-existing TypeScript bug where `public_field_definition` was miscounted
// as a method must be fixed. The mechanism mirrors the C++ A1 precedent:
// collect each class's DECLARED field/property set from the AST, then credit a
// bare identifier inside a method iff it matches a declared field AND is not
// shadowed by a local/parameter. The existing `this`/`self`-qualified
// detection must keep working. All assertions go through the production
// `analyze_cohesion` entry point (the same function `tldr cohesion` calls).
//
// Pre-fix LIVE defects (target/release/tldr cohesion):
//   C#    t.cs  -> field_count=0 lcom4=3 (bare `balance`/`Owner` missed)
//   Scala t.scala -> field_count=0 lcom4=3
//   Kotlin t.kt -> field_count=0 lcom4=3
//   TS    t.ts -> method_count=6 (3 field defs miscounted) lcom4=5
//   Ruby  t.rb -> `show` (attr_accessor `owner` bare ref) is a 0-field island
// ===========================================================================

/// C# class with BARE field reads (`balance`), a property assigned bare
/// (`Owner = o`), a field used as a call receiver (`history.Add(amount)` — the
/// receiver `history` is a field and must be credited; the `.Add` member must
/// NOT), and a shadowing local in `Shadowed`.
const CS_BARE_FIELDS: &str = r#"
public class Account {
    private int balance;
    public string Owner { get; set; }
    private List<int> history;
    public void Deposit(int amount) {
        balance = balance + amount;
        history.Add(amount);
    }
    public int GetBalance() {
        return balance;
    }
    public void Rename(string o) {
        Owner = o;
    }
    public int Shadowed() {
        int balance = 7;
        return balance;
    }
}
"#;

#[test]
fn csharp_bare_field_and_property_access_credited() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_file(dir.path(), "Account.cs", CS_BARE_FIELDS);

    let report = analyze_cohesion(&path, Some(Language::CSharp), 2)
        .expect("analyze_cohesion csharp bare fields");

    let acct = report
        .classes
        .iter()
        .find(|c| c.name == "Account")
        .expect("Account entry");

    let fields: std::collections::HashSet<String> = acct
        .components
        .iter()
        .flat_map(|c| c.fields.iter().cloned())
        .collect();

    // ROOT-CAUSE GUARD: bare `balance`, bare property `Owner`, and the field
    // used as a call receiver `history` are all credited.
    assert!(
        fields.contains("balance"),
        "bare field `balance` must be credited, got {:?}",
        fields
    );
    assert!(
        fields.contains("Owner"),
        "bare property `Owner` must be credited, got {:?}",
        fields
    );
    assert!(
        fields.contains("history"),
        "field used as call receiver `history` must be credited, got {:?}",
        fields
    );
    // SHADOW GUARD: in `Shadowed` the local `int balance = 7;` shadows the field;
    // that method must NOT connect via `balance`. `Shadowed` therefore forms its
    // own component (it shares no field with anyone).
    assert!(
        acct.field_count >= 3,
        "expected >=3 distinct fields (balance,Owner,history), got {}",
        acct.field_count
    );
    // Components: {Deposit,GetBalance} share `balance`; {Rename} owns `Owner`;
    // {Shadowed} is isolated (local shadow). -> LCOM4 = 3.
    assert_eq!(
        acct.lcom4, 3,
        "expected LCOM4=3 ({{Deposit,GetBalance}},{{Rename}},{{Shadowed}}), got {} \
         components={:?}",
        acct.lcom4, acct.components
    );
}

/// Scala class: bare `var`/`val` field reads plus a constructor-parameter field.
const SCALA_BARE_FIELDS: &str = r#"
class Account(initial: Int) {
  private var balance: Int = initial
  val owner: String = "x"
  def deposit(amount: Int): Unit = {
    balance = balance + amount
  }
  def getBalance(): Int = balance
  def show(): String = owner
}
"#;

#[test]
fn scala_bare_field_access_credited() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_file(dir.path(), "Account.scala", SCALA_BARE_FIELDS);

    let report = analyze_cohesion(&path, Some(Language::Scala), 2)
        .expect("analyze_cohesion scala bare fields");

    let acct = report
        .classes
        .iter()
        .find(|c| c.name == "Account")
        .expect("Account entry");

    let fields: std::collections::HashSet<String> = acct
        .components
        .iter()
        .flat_map(|c| c.fields.iter().cloned())
        .collect();

    assert!(
        fields.contains("balance"),
        "bare Scala field `balance` must be credited, got {:?}",
        fields
    );
    assert!(
        fields.contains("owner"),
        "bare Scala field `owner` must be credited, got {:?}",
        fields
    );
    assert!(
        acct.field_count >= 2,
        "expected >=2 fields (balance,owner), got {}",
        acct.field_count
    );
    // deposit+getBalance share `balance`; show owns `owner` -> LCOM4=2.
    assert_eq!(
        acct.lcom4, 2,
        "expected LCOM4=2 ({{deposit,getBalance}},{{show}}), got {} comps={:?}",
        acct.lcom4, acct.components
    );
}

/// Kotlin class: bare `var`/`val` property reads plus a constructor parameter.
const KOTLIN_BARE_FIELDS: &str = r#"
class Account(initial: Int) {
    private var balance: Int = initial
    val owner: String = "x"
    fun deposit(amount: Int) {
        balance = balance + amount
    }
    fun getBalance(): Int {
        return balance
    }
    fun show(): String = owner
}
"#;

#[test]
fn kotlin_bare_field_access_credited() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_file(dir.path(), "Account.kt", KOTLIN_BARE_FIELDS);

    let report = analyze_cohesion(&path, Some(Language::Kotlin), 2)
        .expect("analyze_cohesion kotlin bare fields");

    let acct = report
        .classes
        .iter()
        .find(|c| c.name == "Account")
        .expect("Account entry");

    let fields: std::collections::HashSet<String> = acct
        .components
        .iter()
        .flat_map(|c| c.fields.iter().cloned())
        .collect();

    assert!(
        fields.contains("balance"),
        "bare Kotlin property `balance` must be credited, got {:?}",
        fields
    );
    assert!(
        fields.contains("owner"),
        "bare Kotlin property `owner` must be credited, got {:?}",
        fields
    );
    assert!(
        acct.field_count >= 2,
        "expected >=2 fields (balance,owner), got {}",
        acct.field_count
    );
    assert_eq!(
        acct.lcom4, 2,
        "expected LCOM4=2 ({{deposit,getBalance}},{{show}}), got {} comps={:?}",
        acct.lcom4, acct.components
    );
}

/// TypeScript class: `this.`-qualified fields work today, but the three
/// `public_field_definition` declarations (balance/owner/history) were
/// MISCOUNTED as methods. This pins the corrected method_count and the absence
/// of bogus single-field components.
const TS_BARE_FIELDS: &str = r#"
class Account {
  private balance: number = 0;
  public owner: string = "x";
  history: number[] = [];
  deposit(amount: number): void {
    this.balance = this.balance + amount;
    this.history.push(amount);
  }
  getBalance(): number {
    return this.balance;
  }
  show(): string {
    return this.owner;
  }
}
"#;

#[test]
fn typescript_field_definitions_not_counted_as_methods() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_file(dir.path(), "Account.ts", TS_BARE_FIELDS);

    let report = analyze_cohesion(&path, Some(Language::TypeScript), 2)
        .expect("analyze_cohesion ts field defs");

    let acct = report
        .classes
        .iter()
        .find(|c| c.name == "Account")
        .expect("Account entry");

    // ROOT-CAUSE GUARD: exactly 3 real methods (deposit, getBalance, show).
    // Pre-fix this was 6 (the three field defs were pushed into the method list).
    assert_eq!(
        acct.method_count, 3,
        "public_field_definition must NOT be counted as a method; expected 3 \
         methods (deposit,getBalance,show), got {} comps={:?}",
        acct.method_count, acct.components
    );
    // No bogus single-field component whose sole "method" is a field name.
    for comp in &acct.components {
        for m in &comp.methods {
            assert!(
                m == "deposit" || m == "getBalance" || m == "show",
                "component method `{}` is not a real method (likely a leaked \
                 public_field_definition), comps={:?}",
                m, acct.components
            );
        }
    }
    // deposit+getBalance share balance (and deposit also uses history); show owns
    // owner -> two real responsibilities -> LCOM4=2.
    assert_eq!(
        acct.lcom4, 2,
        "expected LCOM4=2 ({{deposit,getBalance}},{{show}}), got {} comps={:?}",
        acct.lcom4, acct.components
    );
}

/// Ruby class mixing `@ivar` access (works today) with `attr_accessor`/
/// `attr_reader` pseudo-fields referenced BARE (`owner`).
const RUBY_BARE_ATTR: &str = r#"
class Account
  attr_accessor :owner
  attr_reader :balance
  def initialize(b)
    @balance = b
    @history = []
  end
  def deposit(amount)
    @balance = @balance + amount
    @history << amount
  end
  def get_balance
    @balance
  end
  def set_owner(o)
    self.owner = o
  end
  def show
    owner
  end
end
"#;

#[test]
fn ruby_attr_accessor_bare_reference_credited() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_file(dir.path(), "Account.rb", RUBY_BARE_ATTR);

    let report = analyze_cohesion(&path, Some(Language::Ruby), 2)
        .expect("analyze_cohesion ruby attr bare ref");

    let acct = report
        .classes
        .iter()
        .find(|c| c.name == "Account")
        .expect("Account entry");

    let fields: std::collections::HashSet<String> = acct
        .components
        .iter()
        .flat_map(|c| c.fields.iter().cloned())
        .collect();

    // @ivar fields still credited.
    assert!(
        fields.contains("balance"),
        "@balance must still be credited, got {:?}",
        fields
    );
    assert!(
        fields.contains("history"),
        "@history must still be credited, got {:?}",
        fields
    );
    // ROOT-CAUSE GUARD: the attr_accessor pseudo-field `owner`, referenced bare
    // in `show` and via `self.owner =` in `set_owner`, must be credited so
    // `show` is no longer a 0-field island.
    assert!(
        fields.contains("owner"),
        "attr_accessor `owner` referenced bare must be credited, got {:?}",
        fields
    );
    // `show` shares `owner` with `set_owner`, so it is no longer isolated. The
    // class collapses to a single cohesive component:
    //   {initialize,deposit,get_balance} (share @balance/@history) +
    //   {set_owner,show} (share owner) — these two groups are connected only if a
    //   field is shared; they are NOT, so LCOM4=2. The KEY guard is that `show`
    //   is no longer its OWN island: it joins `set_owner`.
    let show_comp = acct
        .components
        .iter()
        .find(|c| c.methods.iter().any(|m| m == "show"))
        .expect("component containing show");
    assert!(
        show_comp.methods.iter().any(|m| m == "set_owner"),
        "`show` must join `set_owner` via the bare `owner` field (no longer a \
         0-field island), got component {:?}",
        show_comp
    );
}
