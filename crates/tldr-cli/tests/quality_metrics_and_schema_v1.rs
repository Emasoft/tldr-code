//! quality-metrics-and-schema-v1 — regression tests for the P13.AGG13
//! (round C) milestone.
//!
//! All tests use real repos under `/tmp/repos/<repo>` and gate on
//! existence so they're skipped silently when the corpus isn't checked
//! out (per the no-synthetic-fixtures-v1 strategy).
//!
//! Bugs covered (8 total — 6 implemented, 2 already-fixed and only
//! pinned with regression tests):
//!
//! - **AGG13-6** (MED, judgment): Java `tldr coupling` returned
//!   `total_calls: 0` when the receiver of every `obj.method()` was a
//!   function parameter typed as a class defined in the OTHER module
//!   (`OwnerController.findPaginatedForOwnersLastName(Owner owner)`
//!   then calling `owner.getId()`). Fix: extend the coupling extractor
//!   to record `(param_name, type_name)` per function and a second
//!   call list `(receiver, method)` for object-typed languages
//!   (Java/C#/PHP/Scala). `find_cross_calls` now resolves
//!   parameter-typed receivers against the callee's `defined_names`.
//!
//! - **AGG13-8** (MED): Java `tldr dice` reported corrupt
//!   `tokens2_count: 4` (expected ~452) on first invocation against a
//!   fresh process. **Already-fixed** by an earlier P13 milestone (the
//!   tokenizer cache no longer races); a regression pin verifies the
//!   tokens2 count stays within the expected range across consecutive
//!   invocations.
//!
//! - **AGG13-9** (MED): OCaml `tldr halstead` returned `difficulty =
//!   1000.0` (sentinel cap) for every function whose body had ZERO
//!   distinct operands (`n2 == 0`). That made trivial 1-line lets
//!   like `let node_id { id; _ } = id` appear as the most "difficult"
//!   functions. Fix: when `n2 == 0`, fall back to `n1 / 2` (the
//!   operator-only difficulty component) instead of the 1000.0
//!   sentinel.
//!
//! - **AGG13-11** (MED): OCaml `tldr diff foo.ml foo.mli` reported
//!   `identical: true` (or near-identical with very few changes)
//!   because the diff extractor only knew about `value_definition`
//!   (the `let name ... = body` form) and ignored
//!   `value_specification` (the `val name : type` form found in
//!   .mli interface files). Fix: extend `extract_nodes_recursive`
//!   to extract `value_specification` nodes as functions so .mli
//!   declarations pair against .ml `let` bindings.
//!
//! - **AGG13-14** (LOW): `tldr references <sym> <path>` returned
//!   `definitions: []` even when the AST verifier classified one or
//!   more matches as `kind == "definition"` and listed them under
//!   `references[]`. Affected csharp, ocaml, java (and any language
//!   whose `find_definitions` Python/TS/JS/Go/Rust dispatch returned
//!   `Ok(None)`). Fix: in `find_references`, after building the
//!   reference list, promote every `kind == Definition` reference
//!   into the top-level `definitions[]` array (deduped by file+line)
//!   while keeping the original `references[]` entry intact.
//!
//! - **AGG13-15** (LOW): Java `tldr reaching-defs` flagged imported
//!   class names (`PageRequest`, `Sort`) and method names (`of`,
//!   `findByLastNameStartingWith`) as `uninitialized` variables with
//!   `severity: definite`. Fix: collect `import_declaration` simple
//!   names into the DFG builder; in `is_use_context` reject Java/C#
//!   identifiers that are (a) the `name` field of a
//!   `method_invocation`/`invocation_expression` (those are method
//!   names, not variables) or (b) the `object` field of a method
//!   invocation / field access matching an imported simple name.
//!
//! - **AGG13-17** (LOW): C `tldr smells` returned `summary: null` for
//!   `/tmp/repos/c-sds`. **Already-fixed** by a prior milestone (the
//!   summary now reports `total_smells`, `by_type`,
//!   `avg_smells_per_file`); a regression pin verifies the summary
//!   stays populated across C/cpp/Java/PHP/JS.
//!
//! - **AGG13-18** (LOW, deferral_elevated): PHP `tldr patterns`
//!   flagged `__construct`, `__invoke`, `__toString` as snake_case
//!   naming violations. Fix: in `find_violations`, allow-list any
//!   identifier matching the strict PHP magic-method dunder shape
//!   (starts with `__` followed by an ASCII letter). Plain leading
//!   underscores (`_helper`) are NOT allow-listed.

use assert_cmd::Command;
use serde_json::Value;
use std::path::Path;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Skip helper: returns true and prints a notice when `path` doesn't
/// exist. Tests gate on real-repo presence per no-synthetic-fixtures-v1.
fn skip_if_missing(path: &str) -> bool {
    if !Path::new(path).exists() {
        eprintln!("[skip] {} not present", path);
        return true;
    }
    false
}

fn run_json(args: &[&str]) -> Value {
    let out = tldr_cmd().args(args).output().expect("spawn tldr");
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "parse JSON for `tldr {}`: {}\nstdout: {}\nstderr: {}",
            args.join(" "),
            e,
            stdout,
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

// =============================================================================
// AGG13-6: Java coupling resolves parameter-typed object method calls
// =============================================================================

/// `tldr coupling OwnerController.java Owner.java` MUST detect at
/// least one cross-module call because `OwnerController` calls
/// `owner.getId()`, `owner.getLastName()`, `owner.setId()` on
/// parameters typed as `Owner` (a class defined in `Owner.java`).
/// Pre-fix the result was `total_calls: 0, coupling_score: 0.0,
/// verdict: low`.
#[test]
fn agg13_6_java_coupling_finds_param_typed_calls() {
    let owner_ctrl = "/tmp/repos/spring-petclinic/src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java";
    let owner = "/tmp/repos/spring-petclinic/src/main/java/org/springframework/samples/petclinic/owner/Owner.java";
    if skip_if_missing(owner_ctrl) || skip_if_missing(owner) {
        return;
    }
    let report = run_json(&["coupling", owner_ctrl, owner, "--format", "json"]);
    let total = report["total_calls"].as_u64().unwrap_or(0);
    assert!(
        total >= 3,
        "expected >= 3 cross-module calls (owner.getId/getLastName/setId), got {}\nreport: {report}",
        total
    );
    // Check the recorded callees include at least one Owner method.
    let calls = report["a_to_b"]["calls"]
        .as_array()
        .expect("a_to_b.calls array");
    let owner_methods: Vec<&str> = calls
        .iter()
        .filter_map(|c| c["callee"].as_str())
        .filter(|s| s.starts_with("Owner."))
        .collect();
    assert!(
        !owner_methods.is_empty(),
        "expected at least one `Owner.<method>` callee, got: {:?}",
        calls
    );
}

// =============================================================================
// AGG13-8: Java dice tokens2_count is sane (regression pin —
// already-fixed)
// =============================================================================

/// `tldr dice OwnerController.java VisitController.java` must report
/// `tokens2_count` consistent with the file size on the FIRST call.
/// Pre-fix the first-invocation tokens2 was 4 (corrupt) instead of
/// the expected ~452. Already-fixed; this test pins the fix and runs
/// the dice 3 times to catch any reintroduced cache race.
#[test]
fn agg13_8_java_dice_tokens2_consistent_across_calls() {
    let a = "/tmp/repos/spring-petclinic/src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java";
    let b = "/tmp/repos/spring-petclinic/src/main/java/org/springframework/samples/petclinic/owner/VisitController.java";
    if skip_if_missing(a) || skip_if_missing(b) {
        return;
    }
    let mut tokens2_seen = Vec::new();
    for _ in 0..3 {
        let report = run_json(&["dice", a, b, "--format", "json"]);
        let t2 = report["tokens2_count"].as_u64().unwrap_or(0);
        // VisitController.java is ~104 LOC; expect tokens2 at least
        // in the low hundreds. A value < 50 indicates the
        // pre-fix tokens2=4 corruption.
        assert!(
            t2 >= 100,
            "tokens2_count={} suggests cache-race corruption; report: {report}",
            t2
        );
        tokens2_seen.push(t2);
    }
    // All three runs should agree (no order-dependent output).
    let first = tokens2_seen[0];
    for t in &tokens2_seen {
        assert_eq!(
            *t, first,
            "tokens2_count varied across runs ({:?}); cache-race regression",
            tokens2_seen
        );
    }
}

// =============================================================================
// AGG13-9: OCaml halstead drops the difficulty=1000.0 sentinel
// =============================================================================

/// `tldr halstead opamStd.ml` must NOT report `difficulty == 1000.0`
/// for any function. Pre-fix 99 of 195 functions hit the sentinel
/// because n2=0 (no distinct operands) hard-coded difficulty to
/// 1000. Post-fix the n2=0 fallback is `n1/2`, so the sentinel
/// disappears and 99+ functions still get a meaningful (low)
/// difficulty value.
#[test]
fn agg13_9_ocaml_halstead_no_difficulty_sentinel() {
    let path = "/tmp/repos/ocaml-dune/vendor/opam/src/core/opamStd.ml";
    if skip_if_missing(path) {
        return;
    }
    let report = run_json(&["halstead", path, "--format", "json"]);
    let funcs = report["functions"].as_array().expect("functions array");
    assert!(
        funcs.len() >= 50,
        "expected >= 50 functions in opamStd.ml, got {}",
        funcs.len()
    );

    let sentinel_count = funcs
        .iter()
        .filter(|f| {
            f["metrics"]["difficulty"]
                .as_f64()
                .map(|d| (d - 1000.0).abs() < f64::EPSILON)
                .unwrap_or(false)
        })
        .count();
    assert_eq!(
        sentinel_count, 0,
        "expected 0 functions hitting the difficulty=1000.0 sentinel, got {}",
        sentinel_count
    );

    // n2=0 functions should now report a low, meaningful difficulty
    // (the "operator-only" component n1/2). At least one such
    // function MUST exist in opamStd.ml (record-pattern lets are
    // common in the file).
    let n2_zero: Vec<&Value> = funcs
        .iter()
        .filter(|f| f["metrics"]["n2"].as_u64() == Some(0))
        .collect();
    assert!(
        !n2_zero.is_empty(),
        "expected at least one n2=0 function in opamStd.ml; the file uses record-pattern lets"
    );
    for f in &n2_zero {
        let diff = f["metrics"]["difficulty"].as_f64().unwrap_or(-1.0);
        assert!(
            (0.0..50.0).contains(&diff),
            "n2=0 function {:?} has difficulty {} outside the expected (0, 50) range",
            f.get("name"),
            diff
        );
    }
}

// =============================================================================
// AGG13-11: OCaml diff between .ml and .mli reports real changes
// =============================================================================

/// `tldr diff opamFile.ml opamFile.mli` must NOT report
/// `identical: true`. Pre-fix the diff extractor only handled
/// `value_definition` (.ml `let` bindings) and ignored
/// `value_specification` (.mli `val` declarations), so the .mli
/// side extracted ZERO function nodes and the diff collapsed to
/// "identical".
#[test]
fn agg13_11_ocaml_diff_ml_vs_mli_reports_changes() {
    let ml = "/tmp/repos/ocaml-dune/vendor/opam/src/format/opamFile.ml";
    let mli = "/tmp/repos/ocaml-dune/vendor/opam/src/format/opamFile.mli";
    if skip_if_missing(ml) || skip_if_missing(mli) {
        return;
    }
    let report = run_json(&["diff", ml, mli, "--format", "json"]);
    assert_eq!(report["identical"], false);
    let changes = report["changes"].as_array().expect("changes array");
    // opamFile.ml is ~4061 LOC, opamFile.mli is ~1162 LOC. Pre-fix
    // we got 4 changes (only top-level let bindings). Post-fix the
    // diff sees the .mli `val` declarations as functions too, which
    // produces many more pair/move/delete edits. Demand at least 10
    // — a numeric threshold that comfortably exceeds the pre-fix
    // value while remaining stable across small grammar updates.
    assert!(
        changes.len() >= 10,
        "expected >= 10 changes between opamFile.ml and opamFile.mli, got {}",
        changes.len()
    );
}

// =============================================================================
// AGG13-14: references definitions[] is populated for csharp/ocaml/java
// =============================================================================

/// `tldr references findOwner spring-petclinic` must populate
/// `definitions[]` (not just leave it empty while the definition
/// hides under `references[]`). Pre-fix Java/C#/OCaml had
/// `definitions: []` because `find_definitions` only implemented
/// per-language detection for python/ts/js/go/rust.
#[test]
fn agg13_14_references_definitions_populated_java() {
    let root = "/tmp/repos/spring-petclinic/src/main/java";
    if skip_if_missing(root) {
        return;
    }
    let report = run_json(&["references", "findOwner", root, "--format", "json"]);
    let defs = report["definitions"].as_array().expect("definitions array");
    assert!(
        !defs.is_empty(),
        "expected >= 1 definition for findOwner, got 0\nreport: {report}"
    );
    // Schema invariant: every definition recorded under
    // references[] (kind=definition) appears in definitions[] too.
    let ref_def_locs: Vec<(String, u64)> = report["references"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .filter(|r| r["kind"].as_str() == Some("definition"))
        .filter_map(|r| {
            let f = r["file"].as_str()?.to_string();
            let l = r["line"].as_u64()?;
            Some((f, l))
        })
        .collect();
    for (f, l) in &ref_def_locs {
        let promoted = defs
            .iter()
            .any(|d| d["file"].as_str() == Some(f.as_str()) && d["line"].as_u64() == Some(*l));
        assert!(
            promoted,
            "definition at {}:{} present in references[] but missing from definitions[]",
            f, l
        );
    }
}

/// Same schema invariant on OCaml (`find_definitions` returns Ok(None)
/// for OCaml; the promotion path supplies the definitions).
#[test]
fn agg13_14_references_definitions_populated_ocaml() {
    let path = "/tmp/repos/ocaml-dune/vendor/opam/src/core/opamStd.ml";
    if skip_if_missing(path) {
        return;
    }
    let report = run_json(&["references", "fatal", path, "--format", "json"]);
    let defs = report["definitions"].as_array().expect("definitions array");
    let refs = report["references"].as_array().expect("references array");
    let ref_defs: Vec<&Value> = refs
        .iter()
        .filter(|r| r["kind"].as_str() == Some("definition"))
        .collect();
    if !ref_defs.is_empty() {
        assert!(
            !defs.is_empty(),
            "ocaml: references[] contains kind=definition entries but definitions[] is empty"
        );
    }
}

/// Same schema invariant on C# (also has `find_definitions` ->
/// Ok(None)).
#[test]
fn agg13_14_references_definitions_populated_csharp() {
    let root = "/tmp/repos/csharp-newtonsoft-bson/Src/Newtonsoft.Json.Bson";
    if skip_if_missing(root) {
        return;
    }
    let report = run_json(&["references", "ReadAsync", root, "--format", "json"]);
    let defs = report["definitions"].as_array().expect("definitions array");
    let refs = report["references"].as_array().expect("references array");
    let ref_defs: Vec<&Value> = refs
        .iter()
        .filter(|r| r["kind"].as_str() == Some("definition"))
        .collect();
    if !ref_defs.is_empty() {
        assert!(
            !defs.is_empty(),
            "csharp: references[] has kind=definition but definitions[] is empty"
        );
    }
}

// =============================================================================
// AGG13-15: Java reaching-defs no longer flags imported types / method names
// =============================================================================

/// `tldr reaching-defs OwnerController.java findPaginatedForOwnersLastName`
/// must NOT flag `PageRequest`, `Sort`, `of`, or
/// `findByLastNameStartingWith` as uninitialized. Pre-fix all four
/// were emitted with `severity: definite` even though they are
/// imported class names + the `name` field of a method invocation.
#[test]
fn agg13_15_java_reaching_defs_no_import_or_method_fps() {
    let path = "/tmp/repos/spring-petclinic/src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java";
    if skip_if_missing(path) {
        return;
    }
    let report = run_json(&[
        "reaching-defs",
        path,
        "findPaginatedForOwnersLastName",
        "--format",
        "json",
    ]);
    let uninit = report["uninitialized"]
        .as_array()
        .expect("uninitialized array");
    let fps: Vec<&str> = uninit
        .iter()
        .filter_map(|u| u["var"].as_str())
        .filter(|n| {
            matches!(
                *n,
                "PageRequest" | "Sort" | "of" | "findByLastNameStartingWith"
            )
        })
        .collect();
    assert!(
        fps.is_empty(),
        "expected zero false-positive uninitialized flags for imports / method names, got {:?}",
        fps
    );
}

// =============================================================================
// AGG13-17: smells summary populated across languages (regression pin —
// already-fixed)
// =============================================================================

/// `tldr smells <c-repo>` must emit a non-null `summary` object with
/// at least `total_smells` and `by_type` populated. Pre-fix C
/// returned `summary: null`. Already-fixed; this regression pin
/// also verifies cpp/java/php/js to catch any future reintroduction.
#[test]
fn agg13_17_smells_summary_populated_multi_lang() {
    let repos = [
        "/tmp/repos/c-sds",
        "/tmp/repos/cpp-tinyxml2",
        "/tmp/repos/spring-petclinic/src",
        "/tmp/repos/php-symfony-string",
        "/tmp/repos/express",
    ];
    let mut tested = 0;
    for repo in &repos {
        if !Path::new(repo).exists() {
            eprintln!("[skip] {} not present", repo);
            continue;
        }
        let report = run_json(&["smells", repo, "--format", "json"]);
        let summary = &report["summary"];
        assert!(
            !summary.is_null(),
            "{}: summary is null (AGG13-17 regression)",
            repo
        );
        assert!(
            summary.get("total_smells").is_some(),
            "{}: summary missing total_smells field",
            repo
        );
        assert!(
            summary.get("by_type").is_some(),
            "{}: summary missing by_type field",
            repo
        );
        tested += 1;
    }
    assert!(
        tested >= 1,
        "no repos available for AGG13-17 multi-language summary check"
    );
}

// =============================================================================
// AGG13-18: PHP magic methods are not flagged as snake_case violations
// =============================================================================

/// `tldr patterns php-symfony-string` must NOT flag any function
/// whose name starts with `__` followed by an ASCII letter
/// (PHP magic methods: `__construct`, `__invoke`, `__toString`,
/// etc.). Pre-fix the audit reported 5 such false positives.
#[test]
fn agg13_18_php_patterns_allows_magic_methods() {
    let path = "/tmp/repos/php-symfony-string";
    if skip_if_missing(path) {
        return;
    }
    let report = run_json(&["patterns", path, "--format", "json"]);
    // Post-fix `naming.violations` may be omitted entirely when there
    // are no violations (default-skipped Vec serializer). Pre-fix the
    // array was always present and contained 5 dunder false positives.
    // Either shape is acceptable as long as zero dunders are flagged.
    let empty_arr = Vec::<Value>::new();
    let violations = report["naming"]["violations"]
        .as_array()
        .unwrap_or(&empty_arr);
    let dunder_violations: Vec<&str> = violations
        .iter()
        .filter_map(|v| v["name"].as_str())
        .filter(|n| {
            // PHP magic-method shape: starts with `__` + ASCII letter.
            let bytes = n.as_bytes();
            bytes.len() > 2
                && bytes[0] == b'_'
                && bytes[1] == b'_'
                && bytes[2].is_ascii_alphabetic()
        })
        .collect();
    assert!(
        dunder_violations.is_empty(),
        "expected zero dunder violations, got {:?}",
        dunder_violations
    );
    // Sanity check: the patterns scan still ran (naming object
    // present with at least the `functions` field). Pre-fix this was
    // always populated; we keep it as a presence check.
    assert!(
        report["naming"]["functions"].is_string(),
        "expected naming.functions to be a string, got: {}",
        report["naming"]
    );
}
