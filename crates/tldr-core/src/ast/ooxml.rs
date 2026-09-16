//! OOXML container extraction (2026-xx): `.docx` / `.xlsx` / `.pptx`
//! structure via in-memory unzip + the existing XML element walker.
//!
//! # The container is NOT a language (no new `Language` variant)
//!
//! There is deliberately NO new `Language` variant for OOXML. `Language`
//! classifies tree-sitter parse targets: `from_extension` maps extensions
//! onto grammars, `scan_extensions` drives directory walks, and `Log` — the
//! only grammar-less member — is an exception carved out for a NATIVE
//! scanner. An OOXML container is not a parse target at all: it is a ZIP
//! package (OPC) whose XML PARTS (`word/document.xml`, `xl/worksheets/*.xml`,
//! `ppt/slides/slide*.xml`) are ordinary XML documents, and XML already has a
//! grammar (`tree-sitter-xml`) and an element walker
//! (`ast::elements::walk_xml`). Adding `Language::Docx`/`Xlsx`/`Pptx`
//! variants would poison every `Language` consumer — grammar lookup,
//! `from_directory` majority voting, `scan_extensions`, daemon `--lang`
//! params — with values that have no grammar and no extension semantics.
//! So: container recognition goes through the PATH predicate
//! [`is_ooxml_path`] (checked before language resolution in
//! `get_code_structure`'s early return, mirroring the jsonl/Log precedents),
//! the parts parse as `Language::Xml`, and the reported
//! `CodeStructure.language` is `None` — the honest answer, because a
//! document container is not "written in" a language (a `.json` file IS a
//! JSON document; a `.docx` is a PACKAGE). `Language::from_path("x.docx")`
//! returns `None` today (`.docx`/`.xlsx`/`.pptx` are absent from
//! `from_extension`) and that is left unchanged — the early return keys off
//! the path predicate, never off the language.
//!
//! # Main-part selection (v1)
//!
//! | Container | Parts analyzed | Order |
//! |-----------|----------------|-------|
//! | `.docx`   | `word/document.xml` ONLY — headers, footers, footnotes, endnotes and comments are documented future work | fixed (the one part) |
//! | `.xlsx`   | `xl/worksheets/*.xml` | lexicographic by part name. v1 does not read `workbook.xml`, which holds the REAL sheet order; name order is the only deterministic proxy (and sheet names sort `sheet1, sheet10, sheet2` — that is the documented v1 behaviour, unlike pptx below) |
//! | `.pptx`   | `ppt/slides/slideN.xml` (N = 1, 2, …) | NATURAL numeric order by N — slide2 before slide10 — because the slide number IS the presentation order; a lexicographic sort would put slide10 second |
//!
//! Everything else in the package (`[Content_Types].xml`, `_rels/*`,
//! `docProps/*`, shared strings, styles, theme, media) is metadata or shared
//! content, not document structure, and never emits.
//!
//! # Byte spans are PART-RELATIVE — documented loudly
//!
//! `byte_start`/`byte_end` on every emitted `DefinitionInfo` are offsets into
//! the DECOMPRESSED part bytes, NOT into the `.docx`/`.xlsx`/`.pptx` file on
//! disk. There is no stable way to map a tree-sitter byte range inside a
//! deflate stream back to container-file offsets (the container's physical
//! layout is per-writer and carries no content meaning), so the spans answer
//! "where is this element inside its XML part":
//! `part_text[byte_start..byte_end]` is the element's exact source text.
//! `definition_line` is likewise the line WITHIN the part (1-indexed). To
//! keep cross-part duplicates distinguishable (two worksheets both have a
//! `sheetData`), `signature` carries the zip part path instead of the
//! element's first source line.
//!
//! # Size policy
//!
//! - The CONTAINER file goes through the central `fs::oversize::check_size`
//!   gate FIRST — the same policy every plain source file passes through in
//!   `parse_file_with_lang`. An oversize container surfaces as a recoverable
//!   `TldrError::FileTooLarge`, which the extractor's early return converts
//!   into the standard structured skip (`files_skipped` + warning), exactly
//!   like the single-file path; it is never a hard abort.
//! - Each PART's DECOMPRESSED size is capped at
//!   `fs::oversize::MAX_FILE_SIZE_BYTES` — the same `u32::MAX` ceiling that
//!   bounds every tree-sitter parse, so a part under the cap can never be
//!   rejected by the parser pool for size. A part over the cap is skipped
//!   with a warning string; the container's other parts still emit. One
//!   bloated part never aborts the whole file.
//!
//! # Errors (structured, never a panic)
//!
//! Not-a-zip bytes, an unreadable ZIP central directory, and a valid zip
//! that is missing its main part(s) (e.g. a `.docx` without
//! `word/document.xml`, or a package with no worksheets/slides) all surface
//! as `TldrError::ParseError` / `TldrError::FileTooLarge` — the same
//! structured error style as the rest of the parse layer.
//!
//! # Determinism
//!
//! Parts are processed in the fixed order above; within a part, elements
//! emit in source order (the walker is a pre-order DFS). No HashMap/HashSet
//! iteration participates in output ordering.

use std::io::Read;
use std::path::Path;

use crate::error::TldrError;
use crate::types::{DefinitionInfo, Language};
use crate::TldrResult;

use super::elements::extract_elements;
use super::parser::PARSER_POOL;

/// Which OOXML family a path's extension names. Deliberately NOT a
/// `Language` variant — see the module docs for the container-is-not-a-
/// language decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OoxmlKind {
    /// Word processing (`.docx`).
    Docx,
    /// Spreadsheets (`.xlsx`).
    Xlsx,
    /// Presentations (`.pptx`).
    Pptx,
}

/// The one docx main part v1 analyzes. Headers/footers/footnotes are
/// documented future work (see the module docs' selection table).
const DOCX_MAIN_PART: &str = "word/document.xml";

const XLSX_PARTS_DIR: &str = "xl/worksheets/";
const PPTX_PARTS_DIR: &str = "ppt/slides/";

/// Recognize which OOXML family `path`'s extension names (case-insensitive).
fn container_kind(path: &Path) -> Option<OoxmlKind> {
    let ext = path.extension().and_then(|e| e.to_str())?;
    match ext.to_ascii_lowercase().as_str() {
        "docx" => Some(OoxmlKind::Docx),
        "xlsx" => Some(OoxmlKind::Xlsx),
        "pptx" => Some(OoxmlKind::Pptx),
        _ => None,
    }
}

/// Check whether `path` names an OOXML container (`.docx` / `.xlsx` /
/// `.pptx`, case-insensitive).
///
/// This — NOT `Language::from_path`, which returns `None` for these
/// extensions and must keep doing so — is the predicate the structure
/// extractor's early return keys on.
#[must_use]
pub fn is_ooxml_path(path: &Path) -> bool {
    container_kind(path).is_some()
}

/// Slide number of a `ppt/slides/slideN.xml` part name (`slide12.xml` →
/// `12`). Non-numeric or differently-shaped names return `None` and are
/// excluded from analysis.
fn slide_number(name: &str) -> Option<u32> {
    let stem = name.strip_prefix(PPTX_PARTS_DIR)?.strip_prefix("slide")?;
    let num = stem.strip_suffix(".xml")?;
    if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    num.parse().ok()
}

/// Select and order the parts of `kind` worth analyzing out of the archive's
/// file names.
///
/// Pure function over names so the selection and ordering contracts (the
/// natural-sort rule for slides in particular) are unit-testable without
/// building containers. Zip part names always use `/` separators per the
/// ZIP spec, so prefix matching needs no path normalization.
fn main_parts(kind: OoxmlKind, names: &[String]) -> Vec<String> {
    match kind {
        OoxmlKind::Docx => names
            .iter()
            .filter(|n| n.as_str() == DOCX_MAIN_PART)
            .cloned()
            .collect(),
        OoxmlKind::Xlsx => {
            // `xl/worksheets/*.xml` with a non-empty stem, lexicographic
            // (see the selection table for why this is NOT natural order).
            let mut parts: Vec<String> = names
                .iter()
                .filter(|n| {
                    n.starts_with(XLSX_PARTS_DIR)
                        && n.ends_with(".xml")
                        && n.len() > XLSX_PARTS_DIR.len() + ".xml".len()
                })
                .cloned()
                .collect();
            parts.sort();
            parts
        }
        OoxmlKind::Pptx => {
            // `ppt/slides/slideN.xml`, natural order by N (slide2 < slide10).
            // The (number, name) key makes the order total even for the
            // pathological slide07/slide7 collision (lexicographic
            // tiebreak); non-matching names never emit.
            let mut parts: Vec<String> = names
                .iter()
                .filter(|n| slide_number(n).is_some())
                .cloned()
                .collect();
            parts.sort_by_cached_key(|n| (slide_number(n), n.clone()));
            parts
        }
    }
}

/// Extract element-level structure from an OOXML container.
///
/// Returns `(definitions, warnings)`: the container's element definitions —
/// parts processed in the fixed main-part order, elements in source order
/// per part, `signature` = the zip part path, byte spans PART-RELATIVE
/// (module docs) — plus one warning string per part skipped over the
/// decompressed-size cap.
pub fn extract_ooxml(path: &Path) -> TldrResult<(Vec<DefinitionInfo>, Vec<String>)> {
    extract_ooxml_with_cap(path, None)
}

/// [`extract_ooxml`] with an injectable cap override — the
/// `fs::oversize::check_size_with_override` hook (the daemon warm-pass
/// precedent). `None` applies the central policy unchanged; production
/// callers go through [`extract_ooxml`]. The override exists ONLY so the
/// per-part and per-container skip decisions are exercisable with tiny
/// fixtures; injected and default caps route through the same decision code
/// and cannot diverge.
fn extract_ooxml_with_cap(
    path: &Path,
    override_cap: Option<u64>,
) -> TldrResult<(Vec<DefinitionInfo>, Vec<String>)> {
    // 1. Container size policy FIRST, before the file is even opened — the
    //    same central gate `parse_file_with_lang` applies to plain source
    //    files. Oversize is a recoverable FileTooLarge the extractor turns
    //    into a structured skip; `Unknown` (unstatable) falls through to the
    //    open, whose I/O error is the honest one.
    if let crate::fs::oversize::SizeCheck::Oversize {
        size_bytes,
        max_bytes,
        ..
    } = crate::fs::oversize::check_size_with_override(path, override_cap)
    {
        return Err(TldrError::FileTooLarge {
            path: path.to_path_buf(),
            size_mb: (size_bytes as usize).div_ceil(1024 * 1024),
            max_mb: (max_bytes as usize).div_ceil(1024 * 1024),
        });
    }

    // Defensive: the extractor's early return already gated on the path
    // predicate; a direct caller with a non-container path gets the
    // structured UnsupportedLanguage, not a zip error.
    let kind = container_kind(path).ok_or_else(|| {
        TldrError::UnsupportedLanguage(format!(
            "not an OOXML container (expected .docx/.xlsx/.pptx): {}",
            path.display()
        ))
    })?;

    // 2. Open + read the ZIP central directory. The archive is read-only;
    //    parts are decompressed into RAM one at a time and dropped after
    //    their elements are extracted.
    let file = std::fs::File::open(path).map_err(TldrError::IoError)?;
    let mut archive =
        zip::ZipArchive::new(std::io::BufReader::new(file)).map_err(|e| TldrError::ParseError {
            file: path.to_path_buf(),
            line: None,
            message: format!("not a valid OOXML container (unreadable ZIP archive): {e}"),
        })?;

    let names: Vec<String> = archive.file_names().map(str::to_string).collect();
    let parts = main_parts(kind, &names);

    // 3. Missing main part(s) → structured error. The file IS a zip but is
    //    not the container its extension claims (or is a stub package).
    if parts.is_empty() {
        let detail = match kind {
            OoxmlKind::Docx => format!("'{DOCX_MAIN_PART}' not found in the archive"),
            OoxmlKind::Xlsx => {
                format!("no '{XLSX_PARTS_DIR}*.xml' worksheet parts found in the archive")
            }
            OoxmlKind::Pptx => {
                format!("no '{PPTX_PARTS_DIR}slideN.xml' slide parts found in the archive")
            }
        };
        return Err(TldrError::ParseError {
            file: path.to_path_buf(),
            line: None,
            message: format!("missing OOXML main part(s): {detail}"),
        });
    }

    // 4. Per-part cap on the DECOMPRESSED size (module docs): skip the part
    //    with a warning, never abort the whole container.
    let cap = override_cap.unwrap_or(crate::fs::oversize::MAX_FILE_SIZE_BYTES);

    let mut definitions: Vec<DefinitionInfo> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    for part in parts {
        // Scope the part file borrow: `by_name` holds &mut archive.
        let bytes = {
            let mut part_file = archive.by_name(&part).map_err(|e| TldrError::ParseError {
                file: path.to_path_buf(),
                line: None,
                message: format!("listed OOXML part '{part}' failed to open: {e}"),
            })?;
            let mut buf = Vec::with_capacity(part_file.size() as usize);
            part_file
                .read_to_end(&mut buf)
                .map_err(TldrError::IoError)?;
            buf
        };

        if bytes.len() as u64 > cap {
            warnings.push(format!(
                "Skipped OOXML part {part} in {}: decompressed size {} bytes exceeds {}-byte cap",
                path.display(),
                bytes.len(),
                cap
            ));
            continue;
        }

        // XML parts are UTF-8 per the OPC spec; lossy decoding keeps one
        // mis-encoded part from aborting the container (same tolerance the
        // source-file path applies to mixed encodings).
        let text = String::from_utf8_lossy(&bytes).into_owned();

        // The XML parts ARE tree-sitter files: parse with the existing XML
        // grammar through the shared pool, then run the shared element
        // walker (Language::Xml dispatches to `elements::walk_xml`).
        let tree = PARSER_POOL.parse(&text, Language::Xml)?;
        for mut def in extract_elements(Language::Xml, &tree, &text) {
            // Post-process for the container context:
            // - byte_start/byte_end stay PART-RELATIVE (module docs — the
            //   walker already emitted part-relative offsets, nothing to
            //   shift);
            // - definition_line is the line WITHIN the part;
            // - signature = the zip part path, so cross-part duplicates
            //   stay distinguishable.
            def.definition_line = Some(def.line_start);
            def.signature = part.clone();
            definitions.push(def);
        }
    }

    Ok((definitions, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    // -------------------------------------------------------------------------
    // Path predicate
    // -------------------------------------------------------------------------

    #[test]
    fn is_ooxml_path_matches_case_insensitively() {
        assert!(is_ooxml_path(Path::new("report.docx")));
        assert!(is_ooxml_path(Path::new("REPORT.DOCX")));
        assert!(is_ooxml_path(Path::new("book.Xlsx")));
        assert!(is_ooxml_path(Path::new("/a/b/deck.pptx")));
        assert!(is_ooxml_path(Path::new("deck.PPTX")));
    }

    #[test]
    fn is_ooxml_path_rejects_legacy_and_other_extensions() {
        // The legacy single-letter formats are NOT containers we unzip.
        assert!(!is_ooxml_path(Path::new("report.doc")));
        assert!(!is_ooxml_path(Path::new("book.xls")));
        assert!(!is_ooxml_path(Path::new("deck.ppt")));
        // Plain zip / xml are not OOXML containers.
        assert!(!is_ooxml_path(Path::new("archive.zip")));
        assert!(!is_ooxml_path(Path::new("config.xml")));
        // Near misses.
        assert!(!is_ooxml_path(Path::new("report.docxx")));
        assert!(!is_ooxml_path(Path::new("docx")));
        assert!(!is_ooxml_path(Path::new("noext")));
    }

    // -------------------------------------------------------------------------
    // Main-part selection + ordering
    // -------------------------------------------------------------------------

    #[test]
    fn main_parts_docx_selects_document_xml_only() {
        let got = main_parts(
            OoxmlKind::Docx,
            &names(&[
                "[Content_Types].xml",
                "_rels/.rels",
                "word/document.xml",
                // Future work (headers/footers) must stay excluded in v1:
                "word/header1.xml",
                "word/footer1.xml",
                "docProps/core.xml",
            ]),
        );
        assert_eq!(got, vec!["word/document.xml"]);
    }

    #[test]
    fn main_parts_xlsx_selects_worksheets_sorted_by_name() {
        // Deliberately lexicographic (v1 does not read workbook.xml's real
        // order): sheet10 sorts between sheet1 and sheet2. This pins the
        // documented asymmetry against the pptx natural sort.
        let got = main_parts(
            OoxmlKind::Xlsx,
            &names(&[
                "[Content_Types].xml",
                "xl/workbook.xml",
                "xl/worksheets/sheet2.xml",
                "xl/worksheets/sheet10.xml",
                "xl/worksheets/sheet1.xml",
                "xl/sharedStrings.xml",
                // Not worksheets — excluded:
                "xl/worksheets/_rels/sheet1.xml.rels",
            ]),
        );
        assert_eq!(
            got,
            vec![
                "xl/worksheets/sheet1.xml",
                "xl/worksheets/sheet10.xml",
                "xl/worksheets/sheet2.xml",
            ]
        );
    }

    #[test]
    fn main_parts_pptx_sorts_slides_numerically() {
        // The pinned natural-sort contract: slide2 before slide10 (a
        // lexicographic sort would put slide10 second).
        let got = main_parts(
            OoxmlKind::Pptx,
            &names(&[
                "[Content_Types].xml",
                "ppt/slides/slide10.xml",
                "ppt/slides/slide2.xml",
                "ppt/slides/slide1.xml",
                "ppt/slides/slide3.xml",
                "ppt/slideLayouts/slideLayout1.xml",
            ]),
        );
        assert_eq!(
            got,
            vec![
                "ppt/slides/slide1.xml",
                "ppt/slides/slide2.xml",
                "ppt/slides/slide3.xml",
                "ppt/slides/slide10.xml",
            ]
        );
    }

    #[test]
    fn main_parts_pptx_ignores_non_numeric_slide_names() {
        let got = main_parts(
            OoxmlKind::Pptx,
            &names(&[
                "ppt/slides/slide1.xml",
                "ppt/slides/slideBackup.xml",
                "ppt/slides/slide.xml",
                "ppt/slides/slide1a.xml",
            ]),
        );
        assert_eq!(got, vec!["ppt/slides/slide1.xml"]);
    }

    #[test]
    fn main_parts_empty_when_container_has_no_main_parts() {
        let got = main_parts(
            OoxmlKind::Docx,
            &names(&["[Content_Types].xml", "_rels/.rels"]),
        );
        assert!(got.is_empty());
    }

    // -------------------------------------------------------------------------
    // Container extraction (real in-memory fixtures)
    // -------------------------------------------------------------------------

    /// Build a minimal OPC-ish package on disk: deflate-compressed parts,
    /// exactly the compression docx/xlsx/pptx use.
    fn write_zip(path: &Path, parts: &[(&str, &str)]) {
        let file = std::fs::File::create(path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, content) in parts {
            writer.start_file(*name, options).unwrap();
            writer.write_all(content.as_bytes()).unwrap();
        }
        writer.finish().unwrap();
    }

    #[test]
    fn extract_maps_elements_with_part_relative_spans() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.docx");
        let document = "<?xml version=\"1.0\"?>\n<w:doc><w:p id=\"p1\"><w:t>hi</w:t></w:p></w:doc>";
        write_zip(&path, &[("word/document.xml", document)]);

        let (defs, warnings) = extract_ooxml_with_cap(&path, None).unwrap();
        assert!(warnings.is_empty());

        let doc_start = document.find("<w:doc").unwrap();
        let doc_line = document[..doc_start].matches('\n').count() + 1;

        // Root element first, then the nested ones, all source-order.
        assert_eq!(defs.len(), 3);
        assert_eq!(defs[0].name, "w:doc");
        assert_eq!(defs[0].kind, "element");
        assert_eq!(defs[0].signature, "word/document.xml");
        assert_eq!(defs[0].line_start, doc_line as u32);
        assert_eq!(defs[0].definition_line, Some(doc_line as u32));
        // PART-relative byte span: slicing the DECOMPRESSED part text at the
        // span yields the element text starting at its `<`.
        assert_eq!(defs[0].byte_start, Some(doc_start as u64));
        let span = &document[doc_start..document.len()];
        assert_eq!(
            &document[defs[0].byte_start.unwrap() as usize..defs[0].byte_end.unwrap() as usize],
            span
        );
        // `tag#id` naming flows through the shared walker (unprefixed `id`).
        assert_eq!(defs[1].name, "w:p#p1");
        assert_eq!(defs[2].name, "w:t");
    }

    #[test]
    fn extract_errors_on_not_a_zip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broken.docx");
        std::fs::write(&path, b"this is definitely not a zip archive").unwrap();

        let err = extract_ooxml(&path).unwrap_err();
        match &err {
            TldrError::ParseError {
                file,
                line,
                message,
            } => {
                assert_eq!(file, &path);
                assert!(line.is_none());
                assert!(message.contains("not a valid OOXML container"), "{message}");
            }
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn extract_errors_on_zip_missing_main_part() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stub.docx");
        write_zip(&path, &[("[Content_Types].xml", "<Types/>")]);

        let err = extract_ooxml(&path).unwrap_err();
        match &err {
            TldrError::ParseError { message, .. } => {
                assert!(message.contains("missing OOXML main part"), "{message}");
                assert!(message.contains("word/document.xml"), "{message}");
            }
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn extract_skips_oversize_parts_with_warning_and_keeps_the_rest() {
        // The production cap is u32::MAX — untestable with real bytes — so
        // this exercises the SAME decision code through the injectable cap
        // (the check_size_with_override precedent). The override replaces
        // the cap at BOTH levels (container + part), exactly like
        // `max_size_for_with_override` replaces the per-path policy
        // entirely, so the cap is derived from the container's on-disk
        // size: the container itself fits (size == cap is not "exceeds"),
        // sheet1's decompressed size stays under it, and sheet2's lands
        // over it. One bloated part never aborts the container.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("book.xlsx");
        let small =
            "<worksheet><sheetData><row r=\"1\"><c><v>1</v></c></row></sheetData></worksheet>";
        let big = format!(
            "<worksheet><sheetData>{}</sheetData></worksheet>",
            "<row r=\"1\"><c><v>x</v></c></row>".repeat(50)
        );
        write_zip(
            &path,
            &[
                ("xl/worksheets/sheet1.xml", small),
                ("xl/worksheets/sheet2.xml", &big),
            ],
        );
        let cap = std::fs::metadata(&path).unwrap().len();
        assert!(
            (small.len() as u64) < cap,
            "fixture assumption: the small part's decompressed size must stay under the container-sized cap"
        );
        assert!(
            (big.len() as u64) > cap,
            "fixture assumption: the big part's decompressed size must exceed the container-sized cap"
        );

        let (defs, warnings) = extract_ooxml_with_cap(&path, Some(cap)).unwrap();

        // sheet2 skipped, sheet1 fully walked.
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].contains("xl/worksheets/sheet2.xml"),
            "{}",
            warnings[0]
        );
        assert!(warnings[0].contains("exceeds"), "{}", warnings[0]);
        assert!(!defs.is_empty());
        assert!(defs
            .iter()
            .all(|d| d.signature == "xl/worksheets/sheet1.xml"));
    }

    #[test]
    fn extract_rejects_container_over_injected_cap_as_file_too_large() {
        // Container-level policy: the file on disk is tiny, the injected cap
        // is smaller — the same FileTooLarge the central policy produces at
        // u32::MAX, which the extractor converts into a structured skip.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.docx");
        write_zip(&path, &[("word/document.xml", "<w:doc/>")]);

        let err = extract_ooxml_with_cap(&path, Some(4)).unwrap_err();
        match &err {
            TldrError::FileTooLarge { path: p, .. } => assert_eq!(p, &path.to_path_buf()),
            other => panic!("expected FileTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn extract_rejects_non_container_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notes.txt");
        std::fs::write(&path, "hello").unwrap();
        let err = extract_ooxml(&path).unwrap_err();
        assert!(matches!(err, TldrError::UnsupportedLanguage(_)));
    }
}
