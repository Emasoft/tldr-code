//! TRDD-O66FM8TN — `tldr dead`, `tldr calls` and `tldr smells` must NAME every
//! source file they drop from the scan.
//!
//! Absence from the result is exactly what the buggy behaviour produced too
//! (the file was silently excluded), so every assertion here is on the
//! warning that names the file — never merely on the file being missing.
//!
//! The dead-code case is the one that matters most: dead-code detection is
//! whole-program, so a function whose only caller sits in a dropped file is
//! reported as dead. The user gets a false positive in the one report whose
//! purpose is saying what is safe to delete — with exit 0 and, pre-fix, no
//! warning at all.

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

/// The fixture directory checked in for TRDD-BKALIK1B: 3 readable Python
/// files and 5 wide-encoded ones (`.gitattributes` keeps them from rotting).
fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../design/reproducers/TRDD-BKALIK1B")
        .canonicalize()
        .expect("TRDD-BKALIK1B reproducer directory is missing")
}

const SKIPPED: [&str; 5] = ["bad.py", "u16be.py", "u32be.py", "u32le.py", "nobom.py"];
const ANALYSED: [&str; 3] = ["control.py", "good.py", "late_nul.py"];

/// Run the built binary with daemon routing defeated, so a daemon left running
/// for one of these paths cannot serve a cached (pre-fix) payload that would
/// make these tests vacuous.
///
/// The CLI finds a daemon by probing `std::env::temp_dir()/tldr-<md5(path)>.sock`
/// (`commands/daemon/ipc.rs::compute_socket_path`) — it does NOT consult the
/// daemon registry, so `TLDR_DAEMON_REGISTRY_DIR` would isolate nothing.
/// `temp_dir()` honours `TMPDIR` on Unix; pointing it at an empty directory
/// makes the probe miss. On Unix the socket is the ONLY probe
/// (`IpcStream::connect` → `connect_unix`; the TCP path is `cfg(windows)`), so
/// this is airtight here and merely best-effort on Windows.
fn tldr(scratch_tmp: &TempDir) -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    cmd.env("TMPDIR", scratch_tmp.path());
    cmd
}

fn json_of(cmd: &mut Command) -> serde_json::Value {
    let out = cmd.output().expect("failed to run tldr");
    assert!(
        out.status.success(),
        "tldr exited {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON ({e}):\n{}",
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

fn warnings_of(json: &serde_json::Value) -> Vec<String> {
    json["warnings"]
        .as_array()
        .unwrap_or_else(|| panic!("no `warnings` array in {json}"))
        .iter()
        .map(|w| w.as_str().unwrap_or_default().to_string())
        .collect()
}

fn assert_names_exactly_the_skipped_files(command: &str, json: &serde_json::Value) {
    let warnings = warnings_of(json);
    for file in SKIPPED {
        assert!(
            warnings.iter().any(|w| w.contains(file)),
            "`tldr {command}` dropped {file} with no warning naming it. Warnings: {warnings:?}"
        );
    }
    for file in ANALYSED {
        assert!(
            !warnings.iter().any(|w| w.contains(file)),
            "`tldr {command}` reported readable {file} as skipped. Warnings: {warnings:?}"
        );
    }
    assert_eq!(
        json["files_skipped"].as_u64(),
        Some(SKIPPED.len() as u64),
        "`tldr {command}` files_skipped must equal the number of warnings; got {json}"
    );
}

#[test]
fn dead_json_names_every_skipped_file() {
    let scratch_tmp = TempDir::new().unwrap();
    let json = json_of(tldr(&scratch_tmp).args(["dead", fixtures().to_str().unwrap(), "-f", "json"]));
    assert_names_exactly_the_skipped_files("dead", &json);
    // The readable files still contribute their definitions.
    assert!(
        json["functions_analyzed"].as_u64().unwrap_or(0) >= 4,
        "the readable fixtures define at least 4 functions; got {json}"
    );
}

#[test]
fn dead_text_prints_every_skipped_file() {
    let scratch_tmp = TempDir::new().unwrap();
    // `-f text` is explicit: the default format is JSON when stdout is not a
    // terminal, which is exactly the situation under a test harness.
    let out = tldr(&scratch_tmp)
        .args(["dead", fixtures().to_str().unwrap(), "-f", "text"])
        .output()
        .expect("failed to run tldr");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("Files skipped: 5"),
        "text output must announce the skipped files up front:\n{text}"
    );
    for file in SKIPPED {
        // One `Skipped <path>` line whose path ends with this fixture; a bare
        // `contains(file)` would also match the file name echoed anywhere else.
        assert!(
            text.lines().any(|l| {
                let l = l.trim();
                l.starts_with("Skipped ")
                    && l.split(':').next().unwrap_or_default().ends_with(file)
            }),
            "text output must carry a `Skipped …/{file}: …` line:\n{text}"
        );
    }
}

#[test]
fn calls_json_names_every_skipped_file() {
    let scratch_tmp = TempDir::new().unwrap();
    let json = json_of(tldr(&scratch_tmp).args(["calls", fixtures().to_str().unwrap(), "-f", "json"]));
    assert_names_exactly_the_skipped_files("calls", &json);
    // Pre-fix an unreadable file was kept in the graph as an EMPTY file, so
    // `nodes` is where the analysed-as-empty shape would still leak through:
    // a readable file has nodes, a dropped one must have none.
    let nodes: Vec<String> = json["nodes"]
        .as_array()
        .expect("nodes array")
        .iter()
        .map(|n| n.as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        nodes.iter().any(|n| n.starts_with("good.py:")),
        "good.py is readable and must contribute nodes: {nodes:?}"
    );
    for file in SKIPPED {
        assert!(
            !nodes.iter().any(|n| n.starts_with(&format!("{file}:"))),
            "{file} was dropped and must contribute no nodes: {nodes:?}"
        );
    }
}

#[test]
fn smells_json_names_every_skipped_file() {
    let scratch_tmp = TempDir::new().unwrap();
    let json = json_of(tldr(&scratch_tmp).args([
        "smells",
        fixtures().to_str().unwrap(),
        "-f",
        "json",
        "-q",
    ]));
    let warnings = warnings_of(&json);
    for file in SKIPPED {
        assert!(
            warnings.iter().any(|w| w.contains(file)),
            "`tldr smells` dropped {file} with no warning naming it. Warnings: {warnings:?}"
        );
    }
    for file in ANALYSED {
        assert!(
            !warnings.iter().any(|w| w.contains(file)),
            "`tldr smells` reported readable {file} as skipped. Warnings: {warnings:?}"
        );
    }
    assert_eq!(
        json["files_scanned"].as_u64(),
        Some(ANALYSED.len() as u64),
        "files_scanned must count only the analysed files; got {json}"
    );
}

/// The exact scenario measured on the card: a caller file the scan cannot
/// read makes a genuinely-called function look uncalled. Any static analyser
/// can only count references within what it read, so the false positive is
/// inherent — what is NOT acceptable is producing it with no warning that a
/// file was dropped. Writes the UTF-16 caller itself so nothing can rot.
#[test]
fn dead_over_a_project_with_an_unreadable_caller_warns_about_the_caller() {
    let scratch_tmp = TempDir::new().unwrap();
    let project = TempDir::new().unwrap();
    std::fs::write(
        project.path().join("lib.py"),
        "def used_only_from_utf16():\n    return 1\n\ndef genuinely_dead():\n    return 2\n",
    )
    .unwrap();
    let caller = "from lib import used_only_from_utf16\n\ndef caller():\n    return used_only_from_utf16()\n";
    let mut utf16 = vec![0xFF, 0xFE];
    for unit in caller.encode_utf16() {
        utf16.extend_from_slice(&unit.to_le_bytes());
    }
    std::fs::write(project.path().join("caller.py"), utf16).unwrap();

    let json = json_of(tldr(&scratch_tmp).args([
        "dead",
        project.path().to_str().unwrap(),
        "-l",
        "python",
        "-f",
        "json",
    ]));
    let warnings = warnings_of(&json);
    assert!(
        warnings.iter().any(|w| w.contains("caller.py")),
        "caller.py was dropped and the report says nothing about it — the user cannot tell \
         `used_only_from_utf16` is a false positive. Report: {json}"
    );
    assert_eq!(json["files_skipped"].as_u64(), Some(1), "{json}");
    assert!(
        !warnings.iter().any(|w| w.contains("lib.py")),
        "lib.py is readable and must not be reported as skipped: {warnings:?}"
    );
}
