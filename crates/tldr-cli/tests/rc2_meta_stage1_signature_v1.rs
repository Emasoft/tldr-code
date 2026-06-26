//! rc2-meta-stage1-signature-v1: cross-command signature agreement.
//!
//! RC2-META Stage 1 (shared header-span signature resolver). Before this
//! stage each command sliced the WHOLE declaration node and mangled the
//! signature of `class Qux { m(): void {} }`'s method `m` differently:
//!
//! ```text
//! structure : "m(): void {} }"   (whole-node first line — inline body leaks)
//! interface : "(): : void"       (params field + return-type field whose text
//!                                 already carries `: `, and the name dropped)
//! extract   : (structured params/return_type — already correct)
//! ```
//!
//! After Stage 1 the SAME un-mangled signature `m(): void` is rendered from the
//! header span across all three commands. This suite is the cross-command
//! anti-regression guard for that invariant.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

/// The canonical Stage-1 fixture (mirrors `/tmp/rc2_ts.ts`).
const FIXTURE: &str = "export interface Foo {\n  a: number;\n  b(): void;\n}\nexport type Bar = { x: string; };\nexport class Qux { m(): void {} }\n";

const EXPECTED_M_SIG: &str = "m(): void";

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn run_json(args: &[&str]) -> Value {
    let mut cmd = tldr_cmd();
    cmd.env("TLDR_NO_DAEMON", "1");
    cmd.args(args);
    let out = cmd.assert().success().get_output().stdout.clone();
    serde_json::from_slice(&out)
        .unwrap_or_else(|e| panic!("output not JSON for {:?}: {}", args, e))
}

fn write_fixture() -> (TempDir, String) {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("rc2_ts.ts");
    fs::write(&path, FIXTURE).unwrap();
    let p = path.to_str().unwrap().to_string();
    (temp, p)
}

/// `structure` renders `Qux.m` from the header span — the inline body block
/// `{}` must NOT leak into the signature.
#[test]
fn structure_qux_m_signature_is_unmangled() {
    let (_t, path) = write_fixture();
    let v = run_json(&["structure", &path, "--format", "json"]);

    let f0 = &v["files"][0];
    let mi = f0["method_infos"]
        .as_array()
        .expect("method_infos array");
    let m = mi
        .iter()
        .find(|e| e["name"].as_str() == Some("m"))
        .expect("method_infos must contain `m`");
    assert_eq!(
        m["signature"].as_str(),
        Some(EXPECTED_M_SIG),
        "structure method_infos[m].signature must be un-mangled; got {:?}",
        m["signature"]
    );

    // The `definitions[]` view (which method_infos derives from) must agree.
    let defs = f0["definitions"].as_array().expect("definitions array");
    let dm = defs
        .iter()
        .find(|e| e["name"].as_str() == Some("m") && e["kind"].as_str() == Some("method"))
        .expect("definitions must contain method `m`");
    assert_eq!(
        dm["signature"].as_str(),
        Some(EXPECTED_M_SIG),
        "structure definitions[m].signature must be un-mangled; got {:?}",
        dm["signature"]
    );
}

/// `interface` renders `Qux.m` from the same header span — no `(): : void`
/// double-colon mangling, and the method name is included.
#[test]
fn interface_qux_m_signature_is_unmangled() {
    let (_t, path) = write_fixture();
    let v = run_json(&["interface", &path, "--format", "json"]);

    let classes = v["classes"].as_array().expect("classes array");
    let qux = classes
        .iter()
        .find(|c| c["name"].as_str() == Some("Qux"))
        .expect("interface must report class Qux");
    let methods = qux["methods"].as_array().expect("Qux.methods array");
    let m = methods
        .iter()
        .find(|e| e["name"].as_str() == Some("m"))
        .expect("Qux must expose method m");
    assert_eq!(
        m["signature"].as_str(),
        Some(EXPECTED_M_SIG),
        "interface Qux.m signature must be un-mangled; got {:?}",
        m["signature"]
    );
}

/// `extract` carries the structured `name`/`params`/`return_type` for `Qux.m`;
/// reconstructed they yield the SAME `m(): void` signature.
#[test]
fn extract_qux_m_reconstructs_same_signature() {
    let (_t, path) = write_fixture();
    let v = run_json(&["extract", &path, "--format", "json"]);

    let classes = v["classes"].as_array().expect("classes array");
    let qux = classes
        .iter()
        .find(|c| c["name"].as_str() == Some("Qux"))
        .expect("extract must report class Qux");
    let methods = qux["methods"].as_array().expect("Qux.methods array");
    let m = methods
        .iter()
        .find(|e| e["name"].as_str() == Some("m"))
        .expect("Qux must expose method m");

    let name = m["name"].as_str().unwrap_or("");
    let params: Vec<String> = m["params"]
        .as_array()
        .map(|a| a.iter().filter_map(|p| p.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let ret = m["return_type"].as_str().unwrap_or("");

    let reconstructed = format!("{}({}): {}", name, params.join(", "), ret);
    assert_eq!(
        reconstructed, EXPECTED_M_SIG,
        "extract structured fields for Qux.m must reconstruct to `{}`; got `{}`",
        EXPECTED_M_SIG, reconstructed
    );
}

/// The headline cross-command invariant: all THREE commands agree on the
/// un-mangled `Qux.m` signature.
#[test]
fn all_three_commands_agree_on_qux_m_signature() {
    let (_t, path) = write_fixture();

    // structure
    let s = run_json(&["structure", &path, "--format", "json"]);
    let s_sig = s["files"][0]["method_infos"]
        .as_array()
        .and_then(|a| a.iter().find(|e| e["name"].as_str() == Some("m")))
        .and_then(|m| m["signature"].as_str())
        .map(str::to_string)
        .expect("structure m signature");

    // interface
    let i = run_json(&["interface", &path, "--format", "json"]);
    let i_sig = i["classes"]
        .as_array()
        .and_then(|cs| cs.iter().find(|c| c["name"].as_str() == Some("Qux")))
        .and_then(|c| c["methods"].as_array())
        .and_then(|ms| ms.iter().find(|e| e["name"].as_str() == Some("m")))
        .and_then(|m| m["signature"].as_str())
        .map(str::to_string)
        .expect("interface m signature");

    // extract (reconstructed)
    let e = run_json(&["extract", &path, "--format", "json"]);
    let em = e["classes"]
        .as_array()
        .and_then(|cs| cs.iter().find(|c| c["name"].as_str() == Some("Qux")))
        .and_then(|c| c["methods"].as_array())
        .and_then(|ms| ms.iter().find(|x| x["name"].as_str() == Some("m")))
        .cloned()
        .expect("extract m entry");
    let e_params: Vec<String> = em["params"]
        .as_array()
        .map(|a| a.iter().filter_map(|p| p.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let e_sig = format!(
        "{}({}): {}",
        em["name"].as_str().unwrap_or(""),
        e_params.join(", "),
        em["return_type"].as_str().unwrap_or("")
    );

    assert_eq!(s_sig, EXPECTED_M_SIG, "structure");
    assert_eq!(i_sig, EXPECTED_M_SIG, "interface");
    assert_eq!(e_sig, EXPECTED_M_SIG, "extract (reconstructed)");
    assert_eq!(s_sig, i_sig, "structure vs interface must agree");
    assert_eq!(s_sig, e_sig, "structure vs extract must agree");
}
