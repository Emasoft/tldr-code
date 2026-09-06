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
