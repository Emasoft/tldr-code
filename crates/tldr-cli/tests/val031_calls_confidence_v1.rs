use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

fn run_calls_json(dir: &TempDir) -> Value {
    run_calls_json_lang(dir, "python")
}

fn run_calls_json_lang(dir: &TempDir, lang: &str) -> Value {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .env("TLDR_NO_DAEMON", "1")
        .args([
            "calls",
            dir.path().to_str().expect("utf-8 temp path"),
            "--lang",
            lang,
            "--format",
            "json",
        ])
        .output()
        .expect("run tldr calls");

    assert!(
        output.status.success(),
        "tldr calls failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "calls output was not valid JSON: {e}\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn write_basic_import_fixture(dir: &TempDir) {
    std::fs::write(
        dir.path().join("helper.py"),
        "def process(value):\n    return value + 1\n",
    )
    .expect("write helper");
    std::fs::write(
        dir.path().join("main.py"),
        "from helper import process\n\n\
def main():\n    return process(41)\n",
    )
    .expect("write main");
}

#[test]
fn calls_json_schema_is_calls_v2() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_basic_import_fixture(&dir);

    let value = run_calls_json(&dir);

    assert_eq!(value["schema"], "calls.v2");
}

#[test]
fn resolved_edge_has_confidence_provenance_and_staleness() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_basic_import_fixture(&dir);

    let value = run_calls_json(&dir);
    let edges = value["edges"].as_array().expect("edges array");
    let edge = edges
        .iter()
        .find(|edge| edge["src_func"] == "main" && edge["dst_func"] == "process")
        .unwrap_or_else(|| panic!("main->process edge missing: {edges:#?}"));

    assert_eq!(edge["confidence"], "T1");
    assert!(edge["provenance"]["rung"].as_str().is_some());
    assert!(edge["provenance"]["mechanism"].as_str().is_some());

    let hash = edge["staleness"]["src_hash"]
        .as_str()
        .expect("src_hash string");
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));

    let generated_at = edge["staleness"]["generated_at"]
        .as_str()
        .expect("generated_at string");
    assert!(generated_at.len() >= 10);
    assert_eq!(generated_at.as_bytes()[4], b'-');
    assert_eq!(generated_at.as_bytes()[7], b'-');
}

#[test]
fn capitalized_receiver_guess_is_t2_with_rung_id() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("app.ts"),
        "class User {\n\
  save() { return 1; }\n\
}\n\
function main(user) {\n\
  return user.save();\n\
}\n",
    )
    .expect("write app");

    let value = run_calls_json_lang(&dir, "typescript");
    let edges = value["edges"].as_array().expect("edges array");
    let edge = edges
        .iter()
        .find(|edge| edge["src_func"] == "main" && edge["dst_func"] == "User.save")
        .unwrap_or_else(|| panic!("main->User.save edge missing: {edges:#?}"));

    assert_eq!(edge["confidence"], "T2");
    assert_eq!(edge["provenance"]["rung"], "capitalized_receiver_guess");
}

#[test]
fn unresolved_dynamic_import_appears_top_level_with_reason() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("plugin.py"),
        "import importlib\n\n\
def load_plugin(name):\n    return importlib.import_module(name)\n",
    )
    .expect("write plugin");

    let value = run_calls_json(&dir);
    let unresolved = value["unresolved"].as_array().expect("unresolved array");
    let entry = unresolved
        .iter()
        .find(|entry| entry["caller_func"] == "load_plugin" && entry["target"] == "import_module")
        .unwrap_or_else(|| panic!("dynamic import unresolved entry missing: {unresolved:#?}"));

    assert_eq!(entry["caller_file"], "plugin.py");
    assert_eq!(entry["line"], 4);
    assert_eq!(
        entry["reason"],
        "Dynamic import pattern cannot be resolved statically"
    );
}
