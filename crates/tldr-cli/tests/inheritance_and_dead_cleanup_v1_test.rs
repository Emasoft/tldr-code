//! inheritance-and-dead-cleanup-v1 — CLI guards
//!
//! M6: `tldr dead` must skip TypeScript declaration files (`.d.ts`).
//! These contain ambient `interface` / `type` / `declare` statements only —
//! no executable code — so flagging them as `possibly_dead` is always a
//! false positive. Mirrors the M-Y3 oversize-skip pattern.
//!
//! Pre-fix repro:
//!   ts-dom-gen → 299 `.d.ts` symbols flagged as possibly_dead.
//! Post-fix invariant:
//!   no `.d.ts` file appears anywhere in `dead_functions[]` or
//!   `possibly_dead[]` of a `tldr dead --format json` report.

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

#[test]
fn test_dead_skips_dts_files() {
    let dir = TempDir::new().unwrap();

    // foo.ts: a public exported function that is never called.
    // (It would normally appear as `possibly_dead` for an exported,
    // uncalled, public function.)
    fs::write(
        dir.path().join("foo.ts"),
        r#"
export function someUncalledFn(): number {
    return 42;
}
"#,
    )
    .unwrap();

    // foo.d.ts: declarations only — pre-fix these symbols showed up as
    // possibly_dead even though `.d.ts` has no executable code.
    fs::write(
        dir.path().join("foo.d.ts"),
        r#"
export interface IFoo {
    bar(x: number): string;
}
export declare function ambientHelper(): void;
export type Alias = number;
"#,
    )
    .unwrap();

    let path = dir.path().to_string_lossy().to_string();
    let (code, stdout, stderr) = run_tldr(&[
        "dead",
        &path,
        "--lang",
        "typescript",
        "--format",
        "json",
        "-q",
    ]);

    assert_eq!(code, 0, "tldr dead failed (stderr: {})", stderr);

    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("dead output is not JSON: {}\nstdout was:\n{}", e, stdout));

    // No `.d.ts` should appear in dead_functions or possibly_dead.
    let mut dts_findings = Vec::new();
    for key in &["dead_functions", "possibly_dead"] {
        if let Some(arr) = v.get(*key).and_then(|x| x.as_array()) {
            for item in arr {
                let file = item.get("file").and_then(|f| f.as_str()).unwrap_or("");
                if file.ends_with(".d.ts") {
                    dts_findings.push(format!("{}::{}", key, item));
                }
            }
        }
    }

    assert!(
        dts_findings.is_empty(),
        "tldr dead must NOT include .d.ts files in possibly_dead / dead_functions, got:\n{}",
        dts_findings.join("\n"),
    );
}
