//! Regression tests for TRDD-BKALIK1B — a wide-encoded source file must be SKIPPED WITH A
//! WARNING, never reported as successfully analysed with zero symbols.
//!
//! The bug these guard against was not a crash. `String::from_utf8_lossy` never fails: on
//! UTF-16 bytes it substitutes U+FFFD and returns a string that parses cleanly to zero
//! symbols, so the file was listed in the output with no definitions, no warning, and a zero
//! exit code — indistinguishable from a genuinely empty file.
//!
//! Every test here asserts the FIXTURE'S ENCODING before it asserts behaviour. That ordering is
//! the point: these fixtures are deliberately not valid UTF-8, and a checkout or a well-meaning
//! "fix the line endings" pass could rewrite them into UTF-8. A behaviour-only test would then
//! keep passing while testing nothing at all, because the file it reads is no longer a
//! reproducer. `.gitattributes` marks the directory `-text -diff` to prevent that; these
//! assertions are the backstop that notices if it ever happens anyway.

use std::path::PathBuf;
use tldr_core::ast::extractor::get_code_structure;
use tldr_core::types::Language;

fn fixtures() -> PathBuf {
    // tests run with CARGO_MANIFEST_DIR = crates/tldr-core
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../design/reproducers/TRDD-BKALIK1B")
        .canonicalize()
        .expect("TRDD-BKALIK1B reproducer directory is missing")
}

/// The UTF-16-with-BOM fixture really is UTF-16 with a BOM, and is not valid UTF-8.
#[test]
fn bom_fixture_is_still_utf16_on_disk() {
    let bytes = std::fs::read(fixtures().join("bad.py")).expect("bad.py missing");
    assert_eq!(
        &bytes[..2],
        &[0xFF, 0xFE],
        "bad.py lost its UTF-16 LE BOM — the fixture has rotted and every test using it is \
         now vacuous"
    );
    assert!(
        String::from_utf8(bytes).is_err(),
        "bad.py decodes as valid UTF-8, so it no longer reproduces anything"
    );
}

/// The BOM-less fixture really is BOM-less UTF-16 — and, crucially, IS valid UTF-8.
///
/// That last assertion is the whole reason this fixture exists separately from `bad.py`. A
/// UTF-16 encoding of ASCII text is valid UTF-8 (every byte is an ASCII character or NUL, and
/// NUL is a legal 1-byte sequence), so a `str::from_utf8` check accepts it and cannot be the
/// guard. If this assertion ever fails, the fixture stopped being the hard case.
#[test]
fn bomless_fixture_is_utf16_without_a_bom_and_passes_utf8_validation() {
    let bytes = std::fs::read(fixtures().join("nobom.py")).expect("nobom.py missing");
    assert_ne!(&bytes[..2], &[0xFF, 0xFE], "nobom.py must not carry a BOM");
    assert_ne!(&bytes[..2], &[0xFE, 0xFF], "nobom.py must not carry a BOM");
    assert!(
        bytes.contains(&0x00),
        "nobom.py has no NUL byte — it is no longer wide-encoded"
    );
    assert!(
        String::from_utf8(bytes).is_ok(),
        "nobom.py is no longer valid UTF-8, so it no longer demonstrates why a UTF-8 validity \
         check is an inadequate guard"
    );
}

/// Both wide-encoded files are skipped with a warning; the UTF-8 siblings are analysed.
#[test]
fn wide_encoded_files_are_skipped_with_a_warning_not_analysed_as_empty() {
    let structure = get_code_structure(&fixtures(), Language::Python, 0, None)
        .expect("structure extraction over the reproducer directory failed");

    let analysed: Vec<&str> = structure
        .files
        .iter()
        .map(|f| f.path.to_str().unwrap_or_default())
        .collect();

    for skipped in ["bad.py", "nobom.py"] {
        assert!(
            !analysed.iter().any(|p| p.ends_with(skipped)),
            "{skipped} was reported as analysed. That is the bug: a wide-encoded file parses to \
             zero symbols and is indistinguishable from an empty file. Analysed: {analysed:?}"
        );
        assert!(
            structure.warnings.iter().any(|w| w.contains(skipped)),
            "{skipped} was skipped but no warning names it, so the omission is silent. \
             Warnings: {:?}",
            structure.warnings
        );
    }

    // Deliberately NOT `assert_eq!(files_skipped, 2)`. That couples this test to the directory's
    // contents: adding a fifth fixture — a latin-1 file for the still-open identifier-mangling
    // defect, which this card calls for — would break it, and the failure message would blame
    // the wide-encoded fixtures while the real cause is an unrelated new file. The per-file
    // assertions above already cover everything a count would, and they name the file that
    // actually failed.
    assert!(
        structure.files_skipped >= 2,
        "both wide-encoded fixtures should count as skipped; got {} with warnings {:?}",
        structure.files_skipped,
        structure.warnings
    );

    // The UTF-8 siblings must still be analysed — a guard that skips everything would pass
    // every assertion above while destroying the tool.
    for (name, expected) in [("good.py", 2usize), ("control.py", 2usize)] {
        let file = structure
            .files
            .iter()
            .find(|f| f.path.to_str().unwrap_or_default().ends_with(name))
            .unwrap_or_else(|| panic!("{name} was not analysed; analysed: {analysed:?}"));
        assert_eq!(
            file.definitions.len(),
            expected,
            "{name} should still yield {expected} definitions"
        );
    }
}

/// Every BOM branch of `wide_encoding_marker` is exercised, each with its own marker.
///
/// These three shipped with no coverage at all: only the UTF-16 **LE** BOM had a fixture. Big-endian
/// is the branch easiest to get backwards, and `FF FE 00 00` (UTF-32 LE) is a live trap — it starts
/// with the UTF-16 LE BOM bytes, so a naive ordering reports it as "UTF-16 LE BOM". The marker must
/// test the UTF-32 BOMs FIRST, and this test fails if anyone reorders them.
#[test]
fn every_bom_variant_is_skipped_with_its_own_marker() {
    let structure = get_code_structure(&fixtures(), Language::Python, 0, None)
        .expect("structure extraction over the reproducer directory failed");

    for (file, expected) in [
        ("u16be.py", "UTF-16 BE BOM"),
        ("u32be.py", "UTF-32 BOM"),
        ("u32le.py", "UTF-32 BOM"),
    ] {
        let warning = structure
            .warnings
            .iter()
            .find(|w| w.contains(file))
            .unwrap_or_else(|| {
                panic!("{file} produced no warning; warnings were {:?}", structure.warnings)
            });
        assert!(
            warning.contains(expected),
            "{file} should be reported as {expected:?}, got {warning:?}"
        );
    }
}

/// A NUL PAST `NUL_SCAN_PREFIX` must be ANALYSED, not skipped.
///
/// This pins the deliberate bound on the NUL scan, which is otherwise invisible to every other
/// test here — they all use files whose NUL is at byte 1. The bound exists so a legitimate source
/// file that embeds a raw NUL far in (generated C tables, protobuf output, binary-protocol
/// fixtures written as `.py`/`.js`/`.rs`) is not skipped along with the wide-encoded ones, which
/// would trade one silent-loss bug for another.
///
/// Without this test, shrinking the prefix "for speed" or replacing the bounded slice with a
/// whole-file scan breaks that design decision while every other test still passes.
#[test]
fn a_nul_past_the_scan_prefix_is_analysed_not_skipped() {
    let bytes = std::fs::read(fixtures().join("late_nul.py")).expect("late_nul.py missing");
    let first_nul = bytes
        .iter()
        .position(|b| *b == 0)
        .expect("late_nul.py has no NUL — the fixture no longer tests the boundary");
    // Imported, NOT hardcoded to 1024. If the constant is ever RAISED above this fixture's NUL
    // offset, the file legitimately becomes skippable — and a hardcoded bound would let this
    // precondition pass while the behaviour assertion below failed, pointing at the wrong cause.
    assert!(
        first_nul > tldr_core::fs::NUL_SCAN_PREFIX,
        "late_nul.py's first NUL is at {first_nul}, inside the {}-byte scan prefix; the fixture \
         must place it BEYOND the prefix or it tests nothing",
        tldr_core::fs::NUL_SCAN_PREFIX
    );

    let structure = get_code_structure(&fixtures(), Language::Python, 0, None)
        .expect("structure extraction over the reproducer directory failed");
    let analysed: Vec<&str> = structure
        .files
        .iter()
        .map(|f| f.path.to_str().unwrap_or_default())
        .collect();
    assert!(
        analysed.iter().any(|p| p.ends_with("late_nul.py")),
        "late_nul.py was skipped, but its NUL is past the scan prefix so it must be analysed. \
         Analysed: {analysed:?}"
    );
}

/// `control.py` and `bad.py` hold the same source text and differ only in encoding.
///
/// This is what makes the fixture set an experiment rather than an anecdote: it removes every
/// explanation for the difference in behaviour except the encoding.
#[test]
fn the_utf8_control_and_the_utf16_file_hold_identical_source_text() {
    let control = std::fs::read_to_string(fixtures().join("control.py")).expect("control.py");
    let bad = std::fs::read(fixtures().join("bad.py")).expect("bad.py");
    let decoded: String = bad[2..]
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect::<Vec<u16>>()
        .iter()
        .filter_map(|c| char::from_u32(*c as u32))
        .collect();
    assert_eq!(
        control, decoded,
        "control.py and bad.py have drifted apart; they must differ ONLY in encoding"
    );
}

// ---------------------------------------------------------------------------
// TRDD-O66FM8TN — a file the scan drops must be ANNOUNCED, not silently absent.
//
// Absence from the output is exactly what the buggy behaviour produced too, so
// these assert the WARNING that names the file, not merely that the file is
// missing from the results.
// ---------------------------------------------------------------------------

const SKIPPED: [&str; 5] = ["bad.py", "u16be.py", "u32be.py", "u32le.py", "nobom.py"];
const ANALYSED: [&str; 3] = ["control.py", "good.py", "late_nul.py"];

#[test]
fn smells_names_every_file_it_dropped() {
    let report = tldr_core::detect_smells(
        &fixtures(),
        tldr_core::ThresholdPreset::Default,
        None,
        false,
    )
    .expect("smell detection over the reproducer directory failed");

    for file in SKIPPED {
        assert!(
            report.warnings.iter().any(|w| w.contains(file)),
            "{file} was dropped from the smells scan with no warning naming it. Warnings: {:?}",
            report.warnings
        );
    }
    for file in ANALYSED {
        assert!(
            !report.warnings.iter().any(|w| w.contains(file)),
            "{file} is readable and must not be reported as skipped. Warnings: {:?}",
            report.warnings
        );
    }
    assert_eq!(
        report.files_scanned,
        ANALYSED.len(),
        "files_scanned must count only the files actually analysed; warnings {:?}",
        report.warnings
    );
}

#[test]
fn calls_names_every_file_it_dropped_and_keeps_it_out_of_the_graph() {
    use tldr_core::callgraph::{build_project_call_graph_v2, BuildConfig};

    let ir = build_project_call_graph_v2(
        &fixtures(),
        BuildConfig {
            language: "python".to_string(),
            ..Default::default()
        },
    )
    .expect("call-graph build over the reproducer directory failed");

    let in_graph: Vec<String> = ir.files.keys().map(|p| p.display().to_string()).collect();

    for file in SKIPPED {
        assert!(
            ir.warnings.iter().any(|w| w.contains(file)),
            "{file} was dropped from the call graph with no warning naming it. Warnings: {:?}",
            ir.warnings
        );
        // Pre-fix, an unreadable file was pushed as an EMPTY FileIR — present
        // with zero functions, indistinguishable from an empty source file.
        assert!(
            !in_graph.iter().any(|p| p.ends_with(file)),
            "{file} is still listed as a graph file; it must be skipped, not analysed-as-empty. \
             Files: {in_graph:?}"
        );
    }
    for file in ANALYSED {
        assert!(
            in_graph.iter().any(|p| p.ends_with(file)),
            "{file} is readable and must be in the graph. Files: {in_graph:?}"
        );
        assert!(
            !ir.warnings.iter().any(|w| w.contains(file)),
            "{file} must not be reported as skipped. Warnings: {:?}",
            ir.warnings
        );
    }
}
