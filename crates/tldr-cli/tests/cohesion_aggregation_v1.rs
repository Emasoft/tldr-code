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
