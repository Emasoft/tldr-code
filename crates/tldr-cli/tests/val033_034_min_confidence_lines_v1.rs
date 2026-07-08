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

fn write_confidence_fixture(dir: &TempDir) {
    std::fs::write(
        dir.path().join("app.ts"),
        "class User {\n\
  save() {\n\
    return deep();\n\
  }\n\
}\n\
\n\
function direct() {\n\
  return 1;\n\
}\n\
\n\
function deep() {\n\
  return 2;\n\
}\n\
\n\
function entry(user) {\n\
  direct();\n\
  return user.save();\n\
}\n",
    )
    .expect("write app");
}

fn edge<'a>(value: &'a Value, src: &str, dst: &str) -> &'a Value {
    let edges = value["edges"].as_array().expect("edges array");
    edges
        .iter()
        .find(|edge| edge["src_func"] == src && edge["dst_func"] == dst)
        .unwrap_or_else(|| panic!("{src}->{dst} edge missing: {edges:#?}"))
}

#[test]
fn calls_min_confidence_t1_filters_t2_and_emits_endpoint_lines() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_confidence_fixture(&dir);
    let root = dir.path().to_str().expect("utf-8 temp path");

    let default_value = run_tldr(&["calls", root, "--lang", "typescript", "--format", "json"]);
    let weak = edge(&default_value, "entry", "User.save");
    assert_eq!(weak["confidence"], "T2");

    let strong_only = run_tldr(&[
        "calls",
        root,
        "--lang",
        "typescript",
        "--format",
        "json",
        "--min-confidence",
        "T1",
    ]);
    let strong = edge(&strong_only, "entry", "direct");
    assert_eq!(strong["confidence"], "T1");
    assert_eq!(strong["src_line"], 15);
    assert_eq!(strong["call_line"], 16);
    assert_eq!(strong["dst_line"], 7);
    assert!(strong_only["edges"]
        .as_array()
        .expect("edges array")
        .iter()
        .all(|edge| edge["confidence"] == "T1"));
    assert!(strong_only["edges"]
        .as_array()
        .expect("edges array")
        .iter()
        .all(|edge| !(edge["src_func"] == "entry" && edge["dst_func"] == "User.save")));
}

#[test]
fn context_min_confidence_t1_does_not_traverse_t2_neighborhood() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_confidence_fixture(&dir);
    let root = dir.path().to_str().expect("utf-8 temp path");

    let default_value = run_tldr(&[
        "context",
        "entry",
        root,
        "--lang",
        "typescript",
        "--depth",
        "2",
        "--format",
        "json",
    ]);
    let default_functions = default_value["functions"]
        .as_array()
        .expect("functions array");
    assert!(
        default_functions.iter().any(|func| func["name"] == "deep"),
        "default T2 context should traverse through User.save to deep: {default_functions:#?}"
    );

    let strong_only = run_tldr(&[
        "context",
        "entry",
        root,
        "--lang",
        "typescript",
        "--depth",
        "2",
        "--format",
        "json",
        "--min-confidence",
        "T1",
    ]);
    let functions = strong_only["functions"]
        .as_array()
        .expect("functions array");
    assert!(functions.iter().any(|func| func["name"] == "entry"));
    assert!(functions.iter().any(|func| func["name"] == "direct"));
    assert!(
        functions
            .iter()
            .all(|func| func["name"] != "User.save" && func["name"] != "save"),
        "T1 context traversed through a T2 receiver edge: {functions:#?}"
    );
    assert!(
        functions.iter().all(|func| func["name"] != "deep"),
        "T1 context reached a callee behind the T2 receiver edge: {functions:#?}"
    );

    let entry = functions
        .iter()
        .find(|func| func["name"] == "entry")
        .expect("entry context item");
    let call_edges = entry["call_edges"].as_array().expect("call_edges array");
    let direct_edge = call_edges
        .iter()
        .find(|edge| edge["dst_func"] == "direct")
        .unwrap_or_else(|| panic!("entry->direct call edge missing: {call_edges:#?}"));
    assert_eq!(direct_edge["confidence"], "T1");
    assert_eq!(direct_edge["call_line"], 16);
    assert_eq!(direct_edge["dst_line"], 7);
    assert_eq!(direct_edge["provenance"]["rung"], "local_function");
}
