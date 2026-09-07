//! TRDD-O66FM8TN: the daemon `dead` handler must ANNOUNCE files it could not
//! read, not drop them silently.
//!
//! Why this test exists, and why it is shaped this way.
//!
//! A file the builder cannot read is left out of the call graph entirely
//! (`callgraph/builder_v2.rs:154` pushes a warning and `continue`s). Its call
//! sites vanish with it, so a function whose ONLY caller lived in the dropped
//! file is reported `possibly_dead` when it is not. The answer is wrong and
//! nothing in the payload says so — that is the whole defect.
//!
//! Before this file, no test in `crates/tldr-daemon/` asserted on the `dead`
//! handler's output at all, so a regression that zeroed `files_skipped` would
//! have gone unnoticed by a green suite.
//!
//! (An earlier draft of this comment said "no test asserted on ANY handler's
//! output content". That is false — `handler_path_traversal_audit_test.rs`
//! inspects handler responses with `json_contains_substring`. The narrower
//! claim above is the true one.)
//!
//! Two cases, not one. `skipped_file_is_announced` alone would still pass if
//! `files_skipped` were hardcoded to 1, so `clean_project_reports_zero_skipped`
//! is the control that makes the assertion discriminate. A test whose claim a
//! constant could satisfy measures nothing.
//!
//! Assertions run against the SERIALIZED JSON rather than the Rust struct,
//! because the wire field name is what a consumer actually reads and
//! `DeadCodeReport` has a hand-rolled `Serialize` impl
//! (`tldr-core/src/types.rs:2508`) that a `#[serde(rename)]` on the struct
//! could not override. Asserting on the struct field would pass while the
//! wire name silently changed.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::{extract::State, Json};
use serde_json::Value;
use tempfile::TempDir;

use tldr_daemon::handlers::callgraph::{dead, DeadRequest};
use tldr_daemon::server::compute_socket_path;
use tldr_daemon::state::DaemonState;

fn make_state(project_root: PathBuf) -> Arc<DaemonState> {
    let socket = compute_socket_path(&project_root, "1.0");
    Arc::new(DaemonState::new(project_root, socket))
}

/// A readable Python file with a real call edge, so the graph is non-empty and
/// the analysis has something to answer about.
fn write_readable_source(dir: &Path) {
    std::fs::write(
        dir.join("good.py"),
        "def callee():\n    return 1\n\n\ndef caller():\n    return callee()\n",
    )
    .expect("write good.py");
}

/// A file the builder CANNOT read: UTF-16 LE, BOM first.
///
/// why UTF-16-with-BOM specifically: `fs::wide_encoding_marker`
/// (tldr-core/src/fs/mod.rs:57) keys on the `FF FE` prefix, so
/// `read_to_string_tolerant` returns `WideEncoded` and `builder_v2.rs:119`
/// turns that into `FileParseResult.error`, which is the single condition that
/// reaches the warning push. A merely malformed source would NOT do it — a
/// syntax error still yields a tree with ERROR nodes and no `error`, so the
/// file keeps contributing what it parsed (see the comment at builder_v2.rs:145).
fn write_unreadable_source(dir: &Path) -> PathBuf {
    let path = dir.join("unreadable.py");
    let mut bytes = vec![0xFF, 0xFE];
    for unit in "def orphan():\n    return 2\n".encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    std::fs::write(&path, &bytes).expect("write unreadable.py");
    path
}

async fn run_dead(project: &Path) -> Value {
    let state = make_state(project.to_path_buf());
    let response = dead(
        State(state),
        Json(DeadRequest {
            language: "python".to_string(),
            entry_points: None,
        }),
    )
    .await;

    // why not `.expect(..)`: `HandlerError` does not implement `Debug`, so
    // `Result::expect` will not compile against it. Match instead of adding a
    // derive to production code purely to satisfy a test.
    let response = match response {
        Ok(response) => response,
        Err(_) => panic!("dead handler returned an error for a valid request"),
    };

    serde_json::to_value(&response.0).expect("response serializes")
}

#[tokio::test]
async fn skipped_file_is_announced_in_the_dead_report() {
    let project = TempDir::new().expect("project tempdir");
    write_readable_source(project.path());
    let unreadable = write_unreadable_source(project.path());

    let body = run_dead(project.path()).await;
    let report = &body["result"];

    assert_eq!(
        report["files_skipped"], 1,
        "a file the builder could not read must be counted in files_skipped; \
         got payload: {body}"
    );

    let warnings = report["warnings"]
        .as_array()
        .expect("warnings must serialize as an array");
    assert_eq!(
        warnings.len(),
        1,
        "exactly one warning per skipped file; got: {warnings:?}"
    );

    let name = unreadable
        .file_name()
        .and_then(|n| n.to_str())
        .expect("fixture filename");
    let text = warnings[0].as_str().expect("warning is a string");
    assert!(
        text.contains(name),
        "the warning must NAME the dropped file, otherwise the count is \
         unactionable — a user cannot find what was skipped. got: {text}"
    );
}

#[tokio::test]
async fn clean_project_reports_zero_skipped() {
    // The control. Without it, `files_skipped == 1` above is satisfied by a
    // hardcoded constant and proves nothing about the wiring.
    let project = TempDir::new().expect("project tempdir");
    write_readable_source(project.path());

    let body = run_dead(project.path()).await;
    let report = &body["result"];

    assert_eq!(
        report["files_skipped"], 0,
        "a project with no unreadable file must report zero; got payload: {body}"
    );
    assert_eq!(
        report["warnings"]
            .as_array()
            .expect("warnings must serialize as an array")
            .len(),
        0,
        "no skipped files means no warnings"
    );
}
