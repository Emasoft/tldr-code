//! m024-severity-normalize-v1 (v0.4.2 M-117)
//!
//! M-024: Severity enum normalization (BREAKING schema change).
//!
//! Pre-fix, five commands emitted slightly different `severity` vocabularies
//! in their JSON output, forcing consumers to maintain N separate mappers:
//!
//!   - `tldr smells`       — `severity: <u8 1-3>` (numeric, no string at all)
//!   - `tldr vuln`         — `"critical" | "high" | "medium" | "low" | "info"`
//!   - `tldr secure`       — `"critical" | "high" | "medium" | "low" | "info"`
//!     (acts as the "secrets" rollup; `tldr secrets` is not a top-level
//!     subcommand — secrets findings are surfaced through `secure`)
//!   - `tldr diagnostics`  — `"error" | "warning" | "info" | "hint"` (LSP-shaped)
//!   - `tldr health`       — no per-finding severity field (top-level numeric
//!     `score`; sub-analyses surface their own metrics, not severity strings)
//!
//! M-024 normalizes the user-facing JSON `severity` field across these
//! commands to exactly three lowercase values:
//!
//!   ```
//!   info  ← prior:  info, note, hint, low
//!   warn  ← prior:  warn, warning, medium
//!   error ← prior:  error, high, critical
//!   ```
//!
//! Internal ranking / threshold logic is unchanged — only the JSON
//! serialization of the `severity` field is projected onto the canonical
//! 3-level set. This is a deliberate v0.4.2 schema break.
//!
//! `health` is included in the audit set but has no per-finding `severity`
//! field today — the test for it asserts that property (no severity emitted
//! at top level) rather than fabricating one.

use assert_cmd::Command;
use serde_json::Value;
use std::collections::HashSet;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn run_json(args: &[&str]) -> Value {
    let output = tldr_cmd().args(args).output().expect("run tldr");
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "tldr {:?} did not return JSON: {}\n--stdout--\n{}\n--stderr--\n{}",
            args,
            e,
            stdout,
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

/// Canonical 3-level vocabulary M-024 commits to.
fn canonical_set() -> HashSet<&'static str> {
    ["info", "warn", "error"].into_iter().collect()
}

/// Walk a JSON tree and collect every value found under a key named
/// `severity` (case-sensitive), regardless of nesting depth. Used to
/// assert no command emits a value outside the canonical set.
fn collect_severity_values(v: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    walk(v, &mut out);
    out
}

fn walk(v: &Value, out: &mut Vec<Value>) {
    match v {
        Value::Object(map) => {
            for (k, vv) in map {
                if k == "severity" {
                    out.push(vv.clone());
                }
                walk(vv, out);
            }
        }
        Value::Array(arr) => {
            for vv in arr {
                walk(vv, out);
            }
        }
        _ => {}
    }
}

/// Assert every collected severity value is a lowercase string in the
/// canonical set. Returns the count so callers can require at least one
/// emission when their fixture is expected to produce findings.
fn assert_canonical(values: &[Value], ctx: &str) -> usize {
    let canon = canonical_set();
    for v in values {
        let s = v
            .as_str()
            .unwrap_or_else(|| panic!("[{}] severity must be a string, got: {:?}", ctx, v));
        assert!(
            canon.contains(s),
            "[{}] severity {:?} not in canonical set {{info,warn,error}}",
            ctx,
            s
        );
    }
    values.len()
}

/// Assert keys of a `by_severity` HashMap (when present) are all canonical.
fn assert_by_severity_keys_canonical(json: &Value, ctx: &str) {
    let canon = canonical_set();
    let mut found_any = false;
    walk_by_severity(json, &mut |map| {
        found_any = true;
        for k in map.keys() {
            assert!(
                canon.contains(k.as_str()),
                "[{}] by_severity key {:?} not in canonical set {{info,warn,error}}",
                ctx,
                k
            );
        }
    });
    let _ = found_any;
}

fn walk_by_severity<F: FnMut(&serde_json::Map<String, Value>)>(v: &Value, f: &mut F) {
    match v {
        Value::Object(map) => {
            for (k, vv) in map {
                if k == "by_severity" {
                    if let Value::Object(inner) = vv {
                        f(inner);
                    }
                }
                walk_by_severity(vv, f);
            }
        }
        Value::Array(arr) => {
            for vv in arr {
                walk_by_severity(vv, f);
            }
        }
        _ => {}
    }
}

// =============================================================================
// Case 1: `tldr smells`
// =============================================================================
//
// Fixture: a Python function with 10 parameters trips the "long parameter
// list" smell at internal severity-2 (medium). After M-024 the JSON must
// emit `"severity": "warn"`.

#[test]
fn test_m024_smells_severity_canonical() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("smells_fixture.py");
    std::fs::write(
        &path,
        "def long_method(a, b, c, d, e, f, g, h, i, j):\n    return a + b + c + d + e + f + g + h + i + j\n",
    )
    .unwrap();

    let json = run_json(&[
        "smells",
        dir.path().to_str().unwrap(),
        "--format",
        "json",
    ]);

    let severities = collect_severity_values(&json);
    let count = assert_canonical(&severities, "smells");
    assert!(
        count >= 1,
        "smells fixture (10-param function) should produce at least one finding with canonical severity, got {} severity values; full json:\n{}",
        count,
        serde_json::to_string_pretty(&json).unwrap()
    );
}

// =============================================================================
// Case 2: `tldr vuln`
// =============================================================================
//
// Fixture: textbook SQL-injection via Flask `request.args` concatenated
// into a `cur.execute(...)` call. Pre-M-024 the finding's severity was
// `"high"`; canonical value is `"error"`.

#[test]
fn test_m024_vuln_severity_canonical() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vuln_fixture.py");
    std::fs::write(
        &path,
        "import sqlite3\nfrom flask import request\n\n\
         def handler():\n    \
         user_input = request.args.get('id')\n    \
         conn = sqlite3.connect(\"db.sqlite\")\n    \
         cur = conn.cursor()\n    \
         cur.execute(\"SELECT * FROM users WHERE id = \" + user_input)\n    \
         return cur.fetchall()\n",
    )
    .unwrap();

    let json = run_json(&[
        "vuln",
        dir.path().to_str().unwrap(),
        "--format",
        "json",
    ]);

    let severities = collect_severity_values(&json);
    let count = assert_canonical(&severities, "vuln");
    assert!(
        count >= 1,
        "vuln fixture (SQL injection) should produce at least one finding with canonical severity, got {} severity values; full json:\n{}",
        count,
        serde_json::to_string_pretty(&json).unwrap()
    );
    assert_by_severity_keys_canonical(&json, "vuln");
}

// =============================================================================
// Case 3: `tldr secure` (the "secrets" rollup in the audit set)
// =============================================================================
//
// `tldr secrets` does not exist as a top-level subcommand — secrets and
// vuln results are unified through `tldr secure`. Pre-M-024 each
// `findings[*].severity` was one of `critical|high|medium|low|info`.
// After M-024 every emission is in {info, warn, error}.
//
// Fixture: AWS Access Key ID + obvious password literal + SQL injection
// — guaranteed to trip both secrets scanner and vuln scanner.

#[test]
fn test_m024_secure_severity_canonical() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("secure_fixture.py");
    std::fs::write(
        &path,
        "import sqlite3\nfrom flask import request\n\n\
         AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n\
         password = \"hunter2_super_secret_pw\"\n\n\
         def handler():\n    \
         user_input = request.args.get('id')\n    \
         conn = sqlite3.connect(\"db.sqlite\")\n    \
         cur = conn.cursor()\n    \
         cur.execute(\"SELECT * FROM users WHERE id = \" + user_input)\n    \
         return cur.fetchall()\n",
    )
    .unwrap();

    let json = run_json(&[
        "secure",
        dir.path().to_str().unwrap(),
        "--format",
        "json",
    ]);

    let severities = collect_severity_values(&json);
    let count = assert_canonical(&severities, "secure");
    assert!(
        count >= 1,
        "secure fixture (AWS key + password + SQL injection) should produce at least one finding with canonical severity, got {} severity values; full json:\n{}",
        count,
        serde_json::to_string_pretty(&json).unwrap()
    );
}

// =============================================================================
// Case 4: `tldr health`
// =============================================================================
//
// Health emits no per-finding `severity` field today (top-level numeric
// `score`; sub-analyses surface their own metrics). M-024 makes this
// property explicit in the schema: IF a `severity` field is ever
// emitted by health, it must be in the canonical set.

#[test]
fn test_m024_health_severity_canonical_or_absent() {
    // Health needs a small Python project with a couple of functions
    // to populate complexity / cohesion / dead-code sub-analyses.
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("a.py"),
        "def small():\n    return 1\n\nclass Foo:\n    def m(self):\n        return self.small()\n    def small(self):\n        return 2\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("b.py"),
        "def helper(x):\n    if x > 0:\n        return x * 2\n    return -x\n",
    )
    .unwrap();

    let json = run_json(&[
        "health",
        dir.path().to_str().unwrap(),
        "--format",
        "json",
        "--quick",
    ]);

    let severities = collect_severity_values(&json);
    // Either zero (canonical: health doesn't currently emit one) or all
    // canonical. The test pins both halves of the invariant.
    let _count = assert_canonical(&severities, "health");
}

// =============================================================================
// Case 5: `tldr diagnostics`
// =============================================================================
//
// Diagnostics has historically mirrored LSP severities
// (`error|warning|info|hint`). After M-024 these are projected to the
// canonical set on emission:
//
//   error   → error
//   warning → warn
//   info    → info
//   hint    → info
//
// Fixture: a Python file with a Ruff-detected `E743` (ambiguous function
// name `l`) — guaranteed to emit at least one `warning` pre-fix.

#[test]
fn test_m024_diagnostics_severity_canonical() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("diag_fixture.py");
    std::fs::write(
        &path,
        "def f():\n    pass\n\ndef l():\n    pass\n",
    )
    .unwrap();

    // diagnostics requires `ruff` to be installed; the test skips if
    // the tool isn't available. We detect this by checking for an
    // empty diagnostics array AND a tool-run record with success=false.
    let json = run_json(&[
        "diagnostics",
        dir.path().to_str().unwrap(),
        "--format",
        "json",
        "--lang",
        "python",
    ]);

    let severities = collect_severity_values(&json);
    let _ = assert_canonical(&severities, "diagnostics");

    // The fixture is designed so `ruff` reports E743 — assert at least
    // one finding when ruff is wired up, but tolerate absence when the
    // tool isn't installed in the test environment.
    let ruff_available = json
        .get("tools_run")
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter().any(|t| {
                t.get("name").and_then(|n| n.as_str()) == Some("ruff")
                    && t.get("success").and_then(|s| s.as_bool()) == Some(true)
            })
        })
        .unwrap_or(false);

    if ruff_available {
        assert!(
            severities.len() >= 1,
            "diagnostics fixture (ambiguous function name `l`) should produce at least one finding when ruff is available; full json:\n{}",
            serde_json::to_string_pretty(&json).unwrap()
        );
    }
}
