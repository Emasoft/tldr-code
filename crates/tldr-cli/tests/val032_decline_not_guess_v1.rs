use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

fn run_tldr(args: &[&str]) -> Value {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .env("TLDR_NO_DAEMON", "1")
        .args(args)
        .output()
        .expect("run tldr");

    assert!(
        output.status.success(),
        "tldr {:?} failed\nstdout:\n{}\nstderr:\n{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "output was not valid JSON: {e}\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn write_typescript_weak_receiver_fixture(dir: &TempDir) {
    std::fs::write(
        dir.path().join("app.ts"),
        "class User {\n\
  save() { return 1; }\n\
}\n\
\n\
function caller(user) {\n\
  return user.save();\n\
}\n\
\n\
function _unused() {\n\
  return 0;\n\
}\n",
    )
    .expect("write app");
}

fn write_typescript_typed_receiver_fixture(dir: &TempDir) {
    std::fs::write(
        dir.path().join("app.ts"),
        "class User {\n\
  save() { return 1; }\n\
}\n\
\n\
function caller() {\n\
  const user: User = new User();\n\
  return user.save();\n\
}\n",
    )
    .expect("write app");
}

#[test]
fn impact_separates_t2_callers_by_default_and_merges_with_approximate() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_typescript_weak_receiver_fixture(&dir);
    let root = dir.path().to_str().expect("utf-8 temp path");

    let value = run_tldr(&[
        "impact",
        "save",
        root,
        "--lang",
        "typescript",
        "--format",
        "json",
    ]);
    assert_eq!(value["schema"], "impact.v2");

    let targets = value["targets"].as_object().expect("targets object");
    let tree = targets
        .values()
        .find(|target| target["function"] == "User.save")
        .unwrap_or_else(|| panic!("User.save target missing: {targets:#?}"));

    assert_eq!(tree["caller_count"], 0);
    assert!(tree["callers"]
        .as_array()
        .expect("callers array")
        .is_empty());
    let approximate = tree["approximate_callers"]
        .as_array()
        .expect("approximate_callers array");
    assert!(
        approximate
            .iter()
            .any(|caller| caller["function"] == "caller"
                && caller["confidence"] == "T2"
                && caller["rung"] == "capitalized_receiver_guess"),
        "weak caller missing: {approximate:#?}"
    );

    let approximate_value = run_tldr(&[
        "impact",
        "save",
        root,
        "--lang",
        "typescript",
        "--format",
        "json",
        "--approximate",
    ]);
    let targets = approximate_value["targets"]
        .as_object()
        .expect("targets object");
    let tree = targets
        .values()
        .find(|target| target["function"] == "User.save")
        .unwrap_or_else(|| panic!("User.save target missing: {targets:#?}"));
    assert_eq!(tree["caller_count"], 1);
    assert!(
        tree["callers"]
            .as_array()
            .expect("callers array")
            .iter()
            .any(|caller| caller["function"] == "caller"),
        "approximate caller was not merged into callers: {tree:#?}"
    );
}

#[test]
fn impact_separates_rebinned_receiver_type_callers() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_typescript_typed_receiver_fixture(&dir);
    let root = dir.path().to_str().expect("utf-8 temp path");

    let value = run_tldr(&[
        "impact",
        "save",
        root,
        "--lang",
        "typescript",
        "--format",
        "json",
    ]);
    assert_eq!(value["schema"], "impact.v2");

    let targets = value["targets"].as_object().expect("targets object");
    let tree = targets
        .values()
        .find(|target| target["function"] == "User.save")
        .unwrap_or_else(|| panic!("User.save target missing: {targets:#?}"));

    assert_eq!(tree["caller_count"], 0);
    assert!(tree["callers"]
        .as_array()
        .expect("callers array")
        .is_empty());
    let approximate = tree["approximate_callers"]
        .as_array()
        .expect("approximate_callers array");
    assert!(
        approximate
            .iter()
            .any(|caller| caller["function"] == "caller"
                && caller["confidence"] == "T2"
                && caller["rung"] == "receiver_type"),
        "rebinned caller missing: {approximate:#?}"
    );

    let approximate_value = run_tldr(&[
        "impact",
        "save",
        root,
        "--lang",
        "typescript",
        "--format",
        "json",
        "--approximate",
    ]);
    let targets = approximate_value["targets"]
        .as_object()
        .expect("targets object");
    let tree = targets
        .values()
        .find(|target| target["function"] == "User.save")
        .unwrap_or_else(|| panic!("User.save target missing: {targets:#?}"));
    assert_eq!(tree["caller_count"], 1);
    assert!(
        tree["callers"]
            .as_array()
            .expect("callers array")
            .iter()
            .any(|caller| caller["function"] == "caller"),
        "approximate receiver_type caller was not merged into callers: {tree:#?}"
    );
    assert!(
        tree["approximate_callers"]
            .as_array()
            .expect("approximate_callers array")
            .iter()
            .any(|caller| caller["function"] == "caller"
                && caller["confidence"] == "T2"
                && caller["rung"] == "receiver_type"),
        "approximate evidence lost receiver_type rung: {tree:#?}"
    );
}

#[test]
fn definition_declines_t2_only_guess_unless_approximate_is_requested() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_typescript_weak_receiver_fixture(&dir);
    let file = dir.path().join("app.ts");
    let file_arg = file.to_str().expect("utf-8 temp path");
    let root = dir.path().to_str().expect("utf-8 temp path");

    let value = run_tldr(&[
        "definition",
        file_arg,
        "6",
        "14",
        "--project",
        root,
        "--lang",
        "typescript",
        "--format",
        "json",
    ]);
    assert_eq!(value["schema"], "definition.v2");
    assert!(value.get("definition").is_none() || value["definition"].is_null());
    assert_eq!(value["declined"][0]["reason"], "t2_only_definition_guess");
    assert_eq!(
        value["approximate_definitions"][0]["rung"],
        "capitalized_receiver_guess"
    );

    let approximate_value = run_tldr(&[
        "definition",
        file_arg,
        "6",
        "14",
        "--project",
        root,
        "--lang",
        "typescript",
        "--format",
        "json",
        "--approximate",
    ]);
    assert_eq!(approximate_value["schema"], "definition.v2");
    assert_eq!(approximate_value["definition"]["line"], 2);
}

#[test]
fn dead_uses_t2_edges_as_weak_liveness_evidence() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_typescript_weak_receiver_fixture(&dir);
    let root = dir.path().to_str().expect("utf-8 temp path");

    let value = run_tldr(&["dead", root, "--lang", "typescript", "--format", "json"]);
    assert_eq!(value["schema"], "dead.v2");

    let dead_functions = value["dead_functions"]
        .as_array()
        .expect("dead_functions array");
    assert!(
        dead_functions.iter().any(|func| func["name"] == "_unused"),
        "_unused should remain definitely dead: {dead_functions:#?}"
    );
    assert!(
        !dead_functions
            .iter()
            .any(|func| func["name"] == "User.save"),
        "weakly reached method should not be definitely dead: {dead_functions:#?}"
    );

    let possibly_dead = value["possibly_dead"]
        .as_array()
        .expect("possibly_dead array");
    let save = possibly_dead
        .iter()
        .find(|func| func["name"] == "User.save")
        .unwrap_or_else(|| panic!("User.save missing from possibly_dead: {possibly_dead:#?}"));
    let evidence = save["dead_evidence"]
        .as_array()
        .expect("dead_evidence array");
    assert!(
        evidence
            .iter()
            .any(|item| item.as_str().unwrap_or("").contains("t2-edge-only")),
        "missing t2 evidence: {evidence:#?}"
    );

    let approximate_value = run_tldr(&[
        "dead",
        root,
        "--lang",
        "typescript",
        "--format",
        "json",
        "--approximate",
    ]);
    let approximate_dead = approximate_value["dead_functions"]
        .as_array()
        .expect("dead_functions array");
    assert!(
        approximate_dead
            .iter()
            .any(|func| func["name"] == "User.save"),
        "--approximate should promote weak evidence into dead_functions: {approximate_dead:#?}"
    );
}
