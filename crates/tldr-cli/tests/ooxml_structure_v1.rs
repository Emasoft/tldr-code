//! ooxml-structure-v1 (2026-xx) — end-to-end tests for OOXML container
//! structure extraction (`tldr structure <file>.docx|.xlsx|.pptx`).
//!
//! The fixtures are genuine minimal OOXML packages built IN-TEST with `zip`'s
//! `ZipWriter` (deflate — the only compression method docx/xlsx/pptx use).
//! The `zip` dev-dependency here is a TEST-ONLY fixture writer; the runtime
//! unpacking lives in tldr-core (`ast::ooxml`) and never links into the CLI
//! through this crate.
//!
//! Pinned contracts:
//!
//! 1. **docx** → only `word/document.xml` is analyzed (v1: headers/footers
//!    are future work); elements surface as `kind: "element"` definitions in
//!    source order through the shared XML element walker.
//! 2. **`#id` naming**: an element with an `id` attribute is named `tag#id`.
//!    (OOXML mostly uses namespaced `w:id` attributes, which the shared
//!    walker — matching the literal attribute name `id` — does not treat as
//!    ids, so the fixture uses a bare `id` to exercise the naming rule.)
//! 3. **signature = the zip part path**, which disambiguates cross-part
//!    duplicates; `[Content_Types].xml`/`_rels/.rels` metadata never emits.
//! 4. **xlsx**: the two worksheets are analyzed in part-NAME order (v1 does
//!    not read workbook.xml's real sheet order — documented proxy).
//! 5. **pptx**: 10 slides pin the NATURAL slide order — slide1 before
//!    slide10 — which a lexicographic sort would get wrong.
//! 6. **Byte spans are PART-RELATIVE**: slicing the decompressed part text
//!    at `byte_start..byte_end` yields the element's text starting with its
//!    `<` (container-relative offsets are not stable — see `ast::ooxml`).
//! 7. **`language` is `null`**: the container is a package, not a document
//!    written in a language (and `Language::from_path` returns `None` for
//!    these extensions — the early return keys off the path predicate).
//! 8. **Corrupt container** (not-a-zip bytes): clean structured error, the
//!    documented exit code (ParseError → 10), no panic.
//! 9. **Container over the central size cap**: structured skip
//!    (`files_skipped` + warning, exit 0) via a sparse fixture — the same
//!    behaviour the single-file path has for oversize source files.

use assert_cmd::Command;
use std::io::Write as _;
use std::path::Path;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Deflate-compressed package writer — the OPC compression docx/xlsx/pptx
/// use, written through zip's ZipWriter so the fixtures are genuine
/// containers, not mocks.
fn write_zip(path: &Path, parts: &[(&str, &str)]) {
    let file = std::fs::File::create(path).expect("create container file");
    let mut writer = zip::ZipWriter::new(file);
    let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, content) in parts {
        writer.start_file(*name, options).expect("start part");
        writer.write_all(content.as_bytes()).expect("write part");
    }
    writer.finish().expect("finish container");
}

/// Minimal-but-real OPC package scaffolding shared by the three fixtures.
fn content_types(overrides: &[&str]) -> String {
    let mut s = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
"#,
    );
    for o in overrides {
        s.push_str("  ");
        s.push_str(o);
        s.push('\n');
    }
    s.push_str("</Types>");
    s
}

fn root_rels(target: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="{target}"/>
</Relationships>"#
    )
}

const DOCX_DOCUMENT: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>Hello</w:t></w:r></w:p>
    <w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>World</w:t></w:r></w:p>
    <w:bookmarkStart id="_GoBack"/>
    <w:tbl>
      <w:tr><w:tc><w:p><w:r><w:t>cell</w:t></w:r></w:p></w:tc></w:tr>
    </w:tbl>
  </w:body>
</w:document>"#;

/// The exact pre-order element sequence of [`DOCX_DOCUMENT`] under the shared
/// XML walker (verified by construction; the test asserts it end-to-end).
const DOCX_EXPECTED_NAMES: [&str; 17] = [
    "w:document",
    "w:body",
    "w:p",
    "w:r",
    "w:t",
    "w:p",
    "w:pPr",
    "w:pStyle",
    "w:r",
    "w:t",
    // Self-closing element with a bare `id` attribute → `tag#id` naming.
    "w:bookmarkStart#_GoBack",
    "w:tbl",
    "w:tr",
    "w:tc",
    "w:p",
    "w:r",
    "w:t",
];

fn worksheet(rows: &[(&str, &str)]) -> String {
    let mut s = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
"#,
    );
    for (row, value) in rows {
        s.push_str(&format!(
            "    <row r=\"{row}\"><c t=\"inlineStr\"><is><t>{value}</t></is></c></row>\n"
        ));
    }
    s.push_str("  </sheetData>\n</worksheet>");
    s
}

fn slide(n: u32) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld>
    <p:spTree>
      <p:sp><p:txt><p:t>Slide {n}</p:t></p:txt></p:sp>
    </p:spTree>
  </p:cSld>
</p:sld>"#
    )
}

fn run_structure_json(path: &Path) -> (std::process::Output, serde_json::Value) {
    let output = tldr_cmd()
        .args(["structure", path.to_str().unwrap(), "-f", "json"])
        .output()
        .expect("run tldr structure");
    let json: serde_json::Value = if output.status.success() {
        serde_json::from_slice(&output.stdout).expect("structure JSON on stdout")
    } else {
        serde_json::Value::Null
    };
    (output, json)
}

/// (1)(2)(3)(6)(7) docx: document.xml elements, #id naming, part-path
/// signatures, part-relative byte spans, language null.
#[test]
fn docx_structure_walks_document_xml_elements() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("report.docx");
    write_zip(
        &path,
        &[
            (
                "[Content_Types].xml",
                &content_types(&[
                    r#"<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>"#,
                ]),
            ),
            ("_rels/.rels", &root_rels("word/document.xml")),
            // A header MUST NOT be analyzed in v1 — its elements would
            // otherwise interleave into the definitions.
            (
                "word/header1.xml",
                r#"<?xml version="1.0"?><w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:r><w:t>HEADER</w:t></w:r></w:p></w:hdr>"#,
            ),
            ("word/document.xml", DOCX_DOCUMENT),
        ],
    );

    let (output, json) = run_structure_json(&path);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // (7) The container is not a language: `language` serializes null (and
    // is present — this is an explicit null, not an absent field).
    assert!(json.get("language").is_some(), "language field present");
    assert!(json["language"].is_null(), "language must be null: {json}");
    // Clean run: `files_skipped` omitted entirely, one file entry.
    assert!(json.get("files_skipped").is_none(), "{json}");
    assert_eq!(json["files"].as_array().unwrap().len(), 1);

    let defs = json["files"][0]["definitions"].as_array().expect("defs");

    // (1) source-order elements, (2) #id naming, (3) part-path signatures.
    let names: Vec<&str> = defs
        .iter()
        .map(|d| d["name"].as_str().expect("name"))
        .collect();
    assert_eq!(names, DOCX_EXPECTED_NAMES, "element sequence");
    for d in defs {
        assert_eq!(d["kind"], "element");
        assert_eq!(d["signature"], "word/document.xml", "signature = part path");
    }

    // (6) Byte spans are PART-RELATIVE: slice-back against the same text we
    // wrote into the part (zip stores the exact bytes, and the part is
    // UTF-8, so String offsets == byte offsets).
    for d in defs {
        let start = d["byte_start"].as_u64().expect("byte_start") as usize;
        let end = d["byte_end"].as_u64().expect("byte_end") as usize;
        let slice = &DOCX_DOCUMENT[start..end];
        assert!(
            slice.starts_with('<'),
            "span must open at the element's '<': {slice:?}"
        );
    }
    // The root element's span covers the whole <w:document>…</w:document>.
    let root_start = DOCX_DOCUMENT.find("<w:document").unwrap();
    assert_eq!(defs[0]["byte_start"].as_u64(), Some(root_start as u64));
    // definition_line is the line WITHIN the part (prolog is line 1).
    assert_eq!(defs[0]["definition_line"].as_u64(), Some(2));
    assert_eq!(defs[0]["line_start"].as_u64(), Some(2));

    // (3) header1.xml never contributed a definition.
    assert!(
        defs.iter().all(|d| d["signature"] == "word/document.xml"),
        "v1 analyzes document.xml only"
    );
}

/// (3)(4) xlsx: both worksheets analyzed in part-name order; metadata parts
/// never emit.
#[test]
fn xlsx_structure_walks_worksheets_in_name_order() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("book.xlsx");
    write_zip(
        &path,
        &[
            ("[Content_Types].xml", &content_types(&[])),
            ("_rels/.rels", &root_rels("xl/workbook.xml")),
            (
                "xl/workbook.xml",
                r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"/>"#,
            ),
            (
                "xl/worksheets/sheet1.xml",
                &worksheet(&[("1", "Name"), ("2", "Alice")]),
            ),
            (
                "xl/worksheets/sheet2.xml",
                &worksheet(&[("1", "Score"), ("2", "42")]),
            ),
        ],
    );

    let (output, json) = run_structure_json(&path);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(json["language"].is_null(), "{json}");

    let defs = json["files"][0]["definitions"].as_array().expect("defs");
    // Each worksheet walks worksheet > sheetData > (row > c > is > t) × 2.
    assert_eq!(defs.len(), 20, "10 elements per worksheet: {json}");
    assert_eq!(defs[0]["name"], "worksheet");

    // (4) Part-name order: ALL sheet1 definitions precede ALL sheet2
    // definitions (parts are processed one at a time, in sorted order).
    let signatures: Vec<&str> = defs
        .iter()
        .map(|d| d["signature"].as_str().expect("signature"))
        .collect();
    assert_eq!(&signatures[..10], &["xl/worksheets/sheet1.xml"; 10]);
    assert_eq!(&signatures[10..], &["xl/worksheets/sheet2.xml"; 10]);
}

/// (3)(5) pptx: 10 slides pin the NATURAL slide order (slide1 before
/// slide10 — lexicographic would put slide10 second).
#[test]
fn pptx_structure_walks_slides_in_natural_order() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("deck.pptx");
    // Slides are written to the archive in LEXICOGRAPHIC order (slide1,
    // slide10, slide2, … slide9) so the end-to-end result can only match the
    // expected output if extraction sorts by slide NUMBER — with a
    // lexicographic sort the reported order would agree with this archive
    // order instead and the assertion below would fail.
    let mut slide_numbers: Vec<u32> = (1..=10u32).collect();
    slide_numbers.sort_by_cached_key(|n| format!("ppt/slides/slide{n}.xml"));
    let mut parts: Vec<(String, String)> = vec![
        ("[Content_Types].xml".to_string(), content_types(&[])),
        ("_rels/.rels".to_string(), root_rels("ppt/presentation.xml")),
    ];
    for n in slide_numbers {
        parts.push((format!("ppt/slides/slide{n}.xml"), slide(n)));
    }
    let parts: Vec<(&str, &str)> = parts
        .iter()
        .map(|(name, body)| (name.as_str(), body.as_str()))
        .collect();
    write_zip(&path, &parts);

    let (output, json) = run_structure_json(&path);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(json["language"].is_null(), "{json}");

    let defs = json["files"][0]["definitions"].as_array().expect("defs");
    // p:sld > p:cSld > p:spTree > p:sp > p:txt > p:t = 6 elements per slide.
    assert_eq!(defs.len(), 60, "6 elements per slide × 10 slides: {json}");

    // (5) Unique part paths in first-appearance order = slide1…slide10
    // NUMERICALLY (the archive deliberately stores them lexicographically).
    let mut order: Vec<&str> = Vec::new();
    for d in defs {
        let sig = d["signature"].as_str().expect("signature");
        if order.last() != Some(&sig) {
            order.push(sig);
        }
    }
    let expected: Vec<String> = (1..=10u32)
        .map(|n| format!("ppt/slides/slide{n}.xml"))
        .collect();
    assert_eq!(order, expected, "natural slide order");

    // (3) Package metadata never emits as a definition part.
    assert!(
        defs.iter()
            .all(|d| d["signature"].as_str().unwrap().starts_with("ppt/slides/")),
        "only slide parts contribute definitions"
    );
}

/// (8) Not-a-zip bytes under a .docx name: clean structured error, the
/// documented ParseError exit code, no panic.
#[test]
fn corrupt_container_errors_cleanly() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("broken.docx");
    std::fs::write(&path, b"this is definitely not a zip archive").unwrap();

    let output = tldr_cmd()
        .args(["structure", path.to_str().unwrap(), "-f", "json"])
        .output()
        .expect("run tldr structure on a non-zip docx");

    assert!(!output.status.success(), "must fail, not emit empty JSON");
    assert_eq!(
        output.status.code(),
        Some(10),
        "ParseError exit code (error.rs exit-code table)"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("panicked"), "no panic allowed: {stderr}");
    assert!(
        stderr.contains("not a valid OOXML container"),
        "structured message expected: {stderr}"
    );
    assert!(stderr.contains("broken.docx"), "names the file: {stderr}");
    assert!(
        output.stdout.is_empty(),
        "no partial JSON on the error path"
    );
}

/// (9) Container over the central size cap → structured skip (exit 0,
/// `files_skipped` = 1, warning, empty `files`). Sparse fixture: `set_len`
/// extends the logical size past `MAX_FILE_SIZE_BYTES` without writing the
/// bytes (the same trick `fs::oversize`'s own tests use); the size policy
/// only stats the file, and extraction never opens it.
#[test]
fn container_over_central_cap_is_a_structured_skip() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("huge.docx");
    let f = std::fs::File::create(&path).unwrap();
    f.set_len(u32::MAX as u64 + 1).unwrap();
    drop(f);

    let (output, json) = run_structure_json(&path);
    assert!(
        output.status.success(),
        "oversize container is a structured skip, not an error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(json["files_skipped"], 1, "{json}");
    assert_eq!(json["files"].as_array().unwrap().len(), 0);
    let warnings = json["warnings"].as_array().expect("warnings");
    assert_eq!(warnings.len(), 1, "{json}");
    let warning = warnings[0].as_str().unwrap();
    assert!(warning.contains("exceeds"), "{warning}");
    assert!(warning.contains("huge.docx"), "{warning}");
    // The container is not an auto-generated/minified artefact, so the
    // shared formatter reports the plain source-file cap category.
    assert!(warning.contains("source files"), "{warning}");
}
