//! fix-cl-7-v1 (v0.5.0 DESIGN-TAIL ARCHITECTURE / T5-cpp-cohesion):
//! C++ cohesion bare-member-access + namespace-qualified partial merge.
//!
//! CHARACTERIZATION-FIRST golden tests. This file is committed BEFORE the
//! implementation (commit #1). It documents:
//!
//!   1. REGRESSION NET (must stay GREEN through the refactor):
//!      - C# same-namespace partial classes still merge into ONE entry
//!        (`csharp_same_namespace_partial_still_merges`).
//!      - C++ `this->member` access path still recognised
//!        (`cpp_this_arrow_member_still_counted`).
//!      - C++ inherited-field method under-count BOUNDARY: an own-class field
//!        scan does NOT credit a base-class field (documented v1 boundary;
//!        stays stable pre- AND post-fix)
//!        (`cpp_inherited_field_is_not_counted_boundary`).
//!      - C++ `a::Widget` / `b::Widget` (same name, different namespace) stay
//!        SEPARATE: pre-fix because in-body classes are non-partial; post-fix
//!        because the shared partial aggregator uses a namespace-qualified key
//!        (`cpp_two_namespace_same_name_golden`).
//!
//!   2. GOLDEN SNAPSHOTS of behaviour the implementation commit intentionally
//!      CHANGES (each marked `GOLDEN-FLIP`). They are GREEN on the pre-fix code
//!      (asserting the CURRENT/buggy behaviour) and the implementation commit
//!      REPLACES the asserted value with the corrected one in the same diff:
//!      - GOLDEN-FLIP A: C++ bare-member access inside an inline method is
//!        currently NOT counted (lcom4 == 2, field_count == 0) -> fix counts it
//!        (lcom4 == 1, fields include the members).
//!      - GOLDEN-FLIP C: C# `A.Widget` and `B.Widget` partial classes (same
//!        bare name, different namespace) currently MIS-MERGE into one entry
//!        -> fix keeps them separate (two entries).
//!
//! AST-driven only (tree-sitter node kinds + fields); no source-text heuristics.

use std::fs;
use tldr_core::quality::cohesion::analyze_cohesion;
use tldr_core::types::Language;

use tempfile::TempDir;

fn write(dir: &TempDir, name: &str, src: &str) {
    fs::write(dir.path().join(name), src).unwrap();
}

fn count_named<'a>(
    report: &'a tldr_core::quality::cohesion::CohesionReport,
    name: &str,
) -> Vec<&'a tldr_core::quality::cohesion::ClassCohesion> {
    report.classes.iter().filter(|c| c.name == name).collect()
}

fn fields_of(class: &tldr_core::quality::cohesion::ClassCohesion) -> std::collections::HashSet<String> {
    class
        .components
        .iter()
        .flat_map(|c| c.fields.iter().cloned())
        .collect()
}

// ===========================================================================
// REGRESSION NET 1 — C# same-namespace partial classes merge (already correct).
// The shared partial aggregator key change (bare name -> qualified key) MUST
// keep this merging because both declarations share namespace `App`.
// ===========================================================================
const CS_SAME_NS_1: &str = r#"
namespace App {
    public partial class Widget {
        private int a;
        public void Foo() { this.a = 1; }
    }
}
"#;

const CS_SAME_NS_2: &str = r#"
namespace App {
    public partial class Widget {
        private int b;
        public void Bar() { this.b = 2; }
    }
}
"#;

#[test]
fn csharp_same_namespace_partial_still_merges() {
    let dir = TempDir::new().unwrap();
    write(&dir, "W1.cs", CS_SAME_NS_1);
    write(&dir, "W2.cs", CS_SAME_NS_2);

    let report = analyze_cohesion(dir.path(), Some(Language::CSharp), 2).unwrap();
    let widgets = count_named(&report, "Widget");
    assert_eq!(
        widgets.len(),
        1,
        "C# partial classes in the SAME namespace must merge into one entry; got {:?}",
        widgets
            .iter()
            .map(|c| (c.file.display().to_string(), c.method_count))
            .collect::<Vec<_>>()
    );
    assert!(
        widgets[0].method_count >= 2,
        "merged Widget should expose Foo+Bar, got {}",
        widgets[0].method_count
    );
}

// ===========================================================================
// REGRESSION NET 2 — C++ `this->member` access path stays recognised.
// (cl6 covered this; we re-pin it here against the A1 set-membership refactor.)
// ===========================================================================
const CPP_THIS_ARROW: &str = r#"
class Box {
    int w;
    int h;
public:
    int area() { return this->w * this->h; }
    void grow() { this->w = this->w + 1; this->h = this->h + 1; }
};
"#;

#[test]
fn cpp_this_arrow_member_still_counted() {
    let dir = TempDir::new().unwrap();
    write(&dir, "box.cpp", CPP_THIS_ARROW);

    let report = analyze_cohesion(dir.path(), Some(Language::Cpp), 2).unwrap();
    let boxes = count_named(&report, "Box");
    assert_eq!(boxes.len(), 1, "exactly one Box entry, got {}", boxes.len());
    let b = boxes[0];
    let fields = fields_of(b);
    assert!(
        fields.contains("w") && fields.contains("h"),
        "this->w / this->h must be recognised as fields, got {:?}",
        fields
    );
    // area+grow both touch w,h -> single component.
    assert_eq!(
        b.lcom4, 1,
        "Box should be cohesive via shared this->w/this->h, got {} comps {:?}",
        b.lcom4, b.components
    );
}

// ===========================================================================
// REGRESSION NET 3 — Inherited-field under-count BOUNDARY (own-class only).
// A method that ONLY touches a base-class field (not declared in this class)
// contributes no own-class field. This is the documented v1 boundary; it holds
// BEFORE and AFTER the fix.
// ===========================================================================
const CPP_INHERITED: &str = r#"
class Derived : public Base {
    int own;
public:
    // touches own-class field only
    void useOwn() { own = 5; int x = own; }
    // touches an inherited (base-class) field only -> NOT credited in v1
    void useBase() { baseField = 9; int y = baseField; }
};
"#;

#[test]
fn cpp_inherited_field_is_not_counted_boundary() {
    let dir = TempDir::new().unwrap();
    write(&dir, "derived.cpp", CPP_INHERITED);

    let report = analyze_cohesion(dir.path(), Some(Language::Cpp), 2).unwrap();
    let ds = count_named(&report, "Derived");
    assert_eq!(ds.len(), 1, "exactly one Derived entry, got {}", ds.len());
    let d = ds[0];
    let fields = fields_of(d);
    // `own` is an own-class field; after the fix it is counted. `baseField`
    // is inherited and is the documented under-count boundary: never counted.
    assert!(
        !fields.contains("baseField"),
        "inherited base-class field must NOT be counted (v1 boundary), got {:?}",
        fields
    );
}

// ===========================================================================
// GOLDEN-FLIP A — C++ bare-member access inside an inline method.
// Pre-fix: bare `width`/`height` (no this->) are NOT recognised, so the two
// methods share no field and the class splits (lcom4 == 2, field_count == 0).
// Post-fix: bare members resolve to declared fields -> single cohesive
// component (lcom4 == 1, fields include width/height).
// ===========================================================================
const CPP_BARE_MEMBER: &str = r#"
class Rect {
    int width;
    int height;
public:
    int area() { return width * height; }
    void scale(int f) { width = width * f; height = height * f; }
};
"#;

#[test]
fn cpp_bare_member_access_golden() {
    let dir = TempDir::new().unwrap();
    write(&dir, "rect.cpp", CPP_BARE_MEMBER);

    let report = analyze_cohesion(dir.path(), Some(Language::Cpp), 2).unwrap();
    let rects = count_named(&report, "Rect");
    assert_eq!(rects.len(), 1, "exactly one Rect entry, got {}", rects.len());
    let r = rects[0];
    let fields = fields_of(r);

    // GOLDEN-FLIP A — FLIPPED by the implementation commit. Bare member
    // accesses (`width`, `height` with no `this->`) now resolve to the
    // class's declared fields, so area+scale share both fields and the class
    // is a single cohesive component.
    // (Pre-fix this asserted field_count == 0 / lcom4 == 2; see commit #1.)
    assert!(
        fields.contains("width") && fields.contains("height"),
        "bare member width/height must be recognised as fields, got {:?}",
        fields
    );
    assert_eq!(
        r.lcom4, 1,
        "Rect should be cohesive once bare members resolve, got {} comps {:?}",
        r.lcom4, r.components
    );
}

// ===========================================================================
// REGRESSION NET 4 — C++ `a::Widget` vs `b::Widget` (same name, two namespaces)
// must remain SEPARATE. Pre-fix they are already separate because C++ in-body
// classes are non-partial (each occurrence emitted independently). The B1'
// change marks C++ in-body classes `is_partial` and routes them through the
// SHARED partial aggregator; the namespace-qualified key MUST keep them
// separate (a bare-name key would regress this to a mis-merge). Stays GREEN
// (== 2) before AND after the fix.
// ===========================================================================
const CPP_TWO_NS: &str = r#"
namespace a {
class Widget {
    int x;
public:
    int gx() { return x; }
    void sx(int v) { x = v; }
};
}
namespace b {
class Widget {
    double y;
public:
    double gy() { return y; }
    void sy(double v) { y = v; }
};
}
"#;

#[test]
fn cpp_two_namespace_same_name_golden() {
    let dir = TempDir::new().unwrap();
    write(&dir, "two.cpp", CPP_TWO_NS);

    let report = analyze_cohesion(dir.path(), Some(Language::Cpp), 2).unwrap();
    let widgets = count_named(&report, "Widget");

    // REGRESSION NET (== 2 before and after the fix): two distinct namespaced
    // classes must be reported SEPARATELY. The B1' qualified key must not
    // collapse them once C++ in-body classes start flowing through the shared
    // partial aggregator.
    assert_eq!(
        widgets.len(),
        2,
        "a::Widget and b::Widget must be separate entries; got {} entries {:?}",
        widgets.len(),
        widgets
            .iter()
            .map(|c| (c.line, c.method_count, c.field_count))
            .collect::<Vec<_>>()
    );
}

// ===========================================================================
// GOLDEN-FLIP C — C# `A.Widget` vs `B.Widget` partial classes.
// Pre-fix: shared bare-name aggregator MIS-MERGES across namespaces.
// Post-fix: namespace-qualified key keeps them separate -> two entries.
// ===========================================================================
const CS_NS_A: &str = r#"
namespace A {
    public partial class Widget {
        private int x;
        public void Foo() { this.x = 1; }
    }
}
"#;

const CS_NS_B: &str = r#"
namespace B {
    public partial class Widget {
        private int y;
        public void Bar() { this.y = 2; }
    }
}
"#;

#[test]
fn csharp_two_namespace_partial_collision_golden() {
    let dir = TempDir::new().unwrap();
    write(&dir, "A.cs", CS_NS_A);
    write(&dir, "B.cs", CS_NS_B);

    let report = analyze_cohesion(dir.path(), Some(Language::CSharp), 2).unwrap();
    let widgets = count_named(&report, "Widget");

    // GOLDEN-FLIP C — FLIPPED by the implementation commit. The shared partial
    // aggregator now keys on the namespace-qualified `(namespace_path, name)`,
    // so A.Widget and B.Widget are kept SEPARATE.
    // (Pre-fix this asserted == 1, a mis-merge; see commit #1.)
    assert_eq!(
        widgets.len(),
        2,
        "A.Widget and B.Widget partial classes must be separate; got {} {:?}",
        widgets.len(),
        widgets
            .iter()
            .map(|c| (c.file.display().to_string(), c.method_count))
            .collect::<Vec<_>>()
    );
}
