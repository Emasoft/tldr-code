//! XML-family 100 MiB **navigation** e2e — depth-filtered node-tree views at
//! scale (xml-navigation-v1, the navigation companion to
//! `large_file_accuracy_v1`, which already pins XML/HTML byte-accuracy at
//! 100 MiB).
//!
//! USER REQUIREMENT: tldr must be able to navigate 100 MB XML files and show
//! the XML node tree at different nesting levels — same for every XML-based
//! format (xhtml, svg, docx, xlsx, pptx, …). This suite proves that contract
//! end to end: a ≥ 100 MiB fixture per format is extracted ONCE through the
//! real public entry point (`tldr_core::get_code_structure`), then the
//! XML-1 navigation helper `filter_structure_max_depth` (the machinery behind
//! `structure --max-depth N`) is applied to that ONE extraction at several
//! levels, with every assertion computable from the fixture grammar.
//!
//! # What every test pins
//!
//! 1. **Full extraction** — timed, `files_skipped == 0`, `warnings` empty,
//!    the right reported language (or `None` for OOXML containers), and the
//!    EXACT total element count implied by the fixture grammar.
//! 2. **Per-level element counts** — the `depth` histogram over all element
//!    rows must equal the grammar's expected table EXACTLY (every level
//!    listed, no extras), and the LEVEL-BY-LEVEL SUM must equal the full
//!    count.
//! 3. **Depth-filtered views through the real helper** —
//!    `filter_structure_max_depth` on a clone of the ONE extraction at
//!    several `--max-depth` levels: the kept count must equal the cumulative
//!    histogram up to that level, and the filter must be ~FREE (it is
//!    post-walk: no re-parse — the filtered query is asserted to take < 10 %
//!    of the extraction time).
//! 4. **Depth probes byte-exact at scale** — first/mid/last unit probes at
//!    shallow and deepest levels: `depth` == the level, `line_start` == the
//!    grammar-computed line, and `source[byte_start..byte_end]` reproduces
//!    the element's exact bytes (reconstructed from the same primitives the
//!    generator used — per-unit `id`s make any span offset fail loudly).
//!
//! # Fixture shapes (DEEP + WIDE — depth semantics provable at scale)
//!
//! Every fixture repeats [`UNITS`] = 2,000 unit subtrees of ~50 KB so each
//! format has thousands of elements at every probed level (single-line
//! payloads keep element `signature`s small; every unit is a fixed number of
//! lines, which makes the probe line numbers exact):
//!
//! | Format   | Unit grammar                                                              | Lines/unit | Elements/unit | Expected depth histogram (per level)                                  | Total    |
//! |----------|---------------------------------------------------------------------------|-----------|---------------|-----------------------------------------------------------------------|----------|
//! | xml      | `<n0…>` chain, 12 levels, payload text line per level, no root wrapper     | 36        | 12            | depths 0..=11 → 2,000 each                                            | 24,000   |
//! | xhtml    | html/head/title/body wrapper + the same 12-level chain of `<div>`          | 36        | 12            | 0→1 (html), 1→2 (head,body), 2→1+2,000 (title,div0), 3..=13→2,000      | 24,004   |
//! | svg      | `<svg>` root + 12 nested `<g>` per unit, one `<path/>` leaf per g          | 48        | 24            | 0→1 (svg), 1→2,000 (g0), 2..=12→4,000 (path,g), 13→2,000 (path)        | 48,001   |
//! | docx     | `word/document.xml` ~108 MB decompressed; per unit 8 nested `w:tbl` levels | 104       | 48            | 0→1, 1→1, 2..=4→2,000, 5..=25→4,000, 26..=28→2,000                     | 96,002   |
//!
//! The docx depth table falls out of the nested-table grammar: `w:document`
//! is depth 0, `w:body` 1, and level `k` of a unit contributes
//! `w:tbl@3k+2, w:tr@3k+3, w:tc@3k+4, w:p@3k+5, w:r@3k+6, w:t@3k+7` — so
//! depths 2..=4 carry one element per unit, 5..=25 carry two (each level's
//! `p/r/t` overlaps the next level's `tbl/tr/tc`), and 26..=28 one again.
//!
//! # OOXML scoping (xlsx / pptx / the "etc." formats)
//!
//! The docx test proves the CONTAINER path at scale: one `word/document.xml`
//! part of ~108 MB decompressed (far under the per-part
//! `fs::oversize::MAX_FILE_SIZE_BYTES` cap, so no part-skip warning), parts
//! walked with the same XML element walker, `signature` carrying the zip
//! part path, and per-part depth restarting at 0. xlsx and pptx get LIGHT
//! checks (small parts, depth correctness only): per-part depth restart
//! (each worksheet's / slide's root is depth 0 again, signature-scoped) and
//! `--max-depth` filtering through the same container path. The mechanism is
//! shared — every OOXML family member rides unzip → per-part XML walk — so
//! no additional 100 MB fixture is needed for those two.
//!
//! # Opt-in
//!
//! Each test materialises a ≥ 100 MiB fixture and holds the source plus the
//! extraction structures in RAM, so the suite is `#[ignore]`-gated. Run it in
//! release, sequentially (one fixture's peak RAM at a time):
//!
//! ```bash
//! timeout 1800 cargo test -p tldr-core --test xml_navigation_v1 --release -- --ignored --test-threads=1
//! ```
//!
//! The default (`cargo test -p tldr-core --test xml_navigation_v1`) must
//! compile-and-skip: `5 ignored; 0 failed`. The mid-size TEXT-MODE snapshot
//! (the tree-indented `--max-depth 2` renderer output and its 200-cap line)
//! lives with the renderer, in
//! `tldr-cli/tests/structure_max_depth_v1.rs` (5 MB xml — big enough for the
//! cap to fire, small enough for a plain CLI run).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tldr_core::types::DefinitionInfo;
use tldr_core::{filter_structure_max_depth, get_code_structure, CodeStructure, Language};

/// Target fixture size: 100 MiB (the assembled source must reach it).
const TARGET_BYTES: usize = 100 * 1024 * 1024;

/// Repetitions of the per-format unit subtree (the fixture grammar's WIDTH).
const UNITS: usize = 2000;

/// Nesting levels per unit subtree (the fixture grammar's DEPTH).
const LEVELS: usize = 12;

/// Nested `w:tbl` levels per docx unit (docx DEPTH: max element depth 3·8+4).
const DOCX_LEVELS: usize = 8;

/// Extraction wall-clock budget for one ≥ 100 MiB fixture (release opt-in;
/// debug runs are slower but the suite is release-gated).
const EXTRACTION_BUDGET: Duration = Duration::from_secs(120);

/// A depth probe: one element located by name (+ occurrence for the
/// id-less tags), whose nesting depth, absolute line and byte span must all
/// match the fixture grammar at scale.
struct NavProbe {
    name: String,
    occurrence: usize,
    depth: u32,
    line_start: u32,
    /// Exact expected node bytes — `source[byte_start..byte_end]`.
    text: String,
}

/// One assembled fixture plus its in-memory source (written once, then every
/// span assertion slices THIS string — a span bug can never hide behind a
/// re-read).
struct BigFixture {
    path: std::path::PathBuf,
    /// Keeps the tempdir (and therefore `path`) alive until the test ends.
    _dir: tempfile::TempDir,
    source: String,
}

impl BigFixture {
    fn summary(&self) -> String {
        format!(
            "fixture {} ({} bytes, {} MiB)",
            self.path.display(),
            self.source.len(),
            self.source.len() / (1024 * 1024)
        )
    }
}

/// Assemble `prefix` + the fixed unit list + `trailer`, write it once, and
/// assert it reached the 100 MiB target.
fn assemble(
    dir: tempfile::TempDir,
    filename: &str,
    prefix: &str,
    units: &[String],
    trailer: &str,
) -> BigFixture {
    let mut source = String::with_capacity(TARGET_BYTES + TARGET_BYTES / 8);
    source.push_str(prefix);
    for unit in units {
        source.push_str(unit);
    }
    source.push_str(trailer);
    assert!(
        source.len() >= TARGET_BYTES,
        "fixture never reached the target: {} bytes — {filename}",
        source.len()
    );
    let path = dir.path().join(filename);
    std::fs::write(&path, source.as_bytes()).expect("write fixture");
    BigFixture {
        path,
        _dir: dir,
        source,
    }
}

/// The extraction plus everything the assertions need.
struct Extracted {
    structure: CodeStructure,
    /// Wall time of the ONE full extraction (the baseline the filtered views
    /// are compared against — they must not re-parse).
    elapsed: Duration,
}

/// Extract ONCE and pin the suite-level invariants: no skips, no warnings,
/// exactly one file, the expected reported language (None for containers),
/// a definition floor, the tree-sitter size-policy class, and the 120 s
/// extraction budget.
fn extract_and_pin(
    fx: &BigFixture,
    language: Language,
    reported: Option<Language>,
    min_defs: usize,
    tag: &str,
) -> Extracted {
    let started = Instant::now();
    let structure = get_code_structure(&fx.path, language, 0, None)
        .unwrap_or_else(|e| panic!("get_code_structure failed — {tag}: {e:?}"));
    let elapsed = started.elapsed();

    assert_eq!(
        structure.files_skipped,
        0,
        "no file may be skipped — {tag} — {}",
        fx.summary()
    );
    assert!(
        structure.warnings.is_empty(),
        "no warnings expected, got {:?} — {tag} — {}",
        structure.warnings,
        fx.summary()
    );
    assert_eq!(
        structure.language,
        reported,
        "wrong reported language — {tag} — {}",
        fx.summary()
    );
    assert_eq!(structure.files.len(), 1, "exactly one file — {tag}");
    let defs = &structure.files[0].definitions;
    assert!(
        defs.len() >= min_defs,
        "definitions {} < floor {min_defs} — {tag}",
        defs.len()
    );
    // Size policy: these files sit in the plain tree-sitter class (u32::MAX)
    // — a 100 MiB fixture under a smaller class would have been skipped above.
    assert_eq!(
        tldr_core::fs::oversize::max_size_for(&fx.path),
        tldr_core::fs::oversize::MAX_FILE_SIZE_BYTES,
        "wrong size-policy class — {tag} — {}",
        fx.summary()
    );
    assert!(
        elapsed < EXTRACTION_BUDGET,
        "extraction took {elapsed:?}, over the {EXTRACTION_BUDGET:?} budget — {tag}"
    );
    println!("{tag}: extracted {} definitions in {elapsed:?}", defs.len());

    Extracted { structure, elapsed }
}

/// Per-depth histogram over the extracted rows. Every row in these fixtures
/// is a markup element and MUST carry a depth — a `None` depth here is a
/// broken depth contract, not a histogram gap.
fn depth_histogram(defs: &[DefinitionInfo], tag: &str) -> HashMap<u32, usize> {
    let mut histogram: HashMap<u32, usize> = HashMap::new();
    for def in defs {
        assert_eq!(
            def.kind, "element",
            "every row in these fixtures is an element — {tag}"
        );
        let depth = def
            .depth
            .unwrap_or_else(|| panic!("element {:?} carries no depth — {tag}", def.name));
        *histogram.entry(depth).or_insert(0) += 1;
    }
    histogram
}

/// Assert the histogram equals the fixture grammar's expected table EXACTLY
/// (every level listed, no extras) and that the level-by-level sum equals the
/// full count.
fn assert_level_table(
    histogram: &HashMap<u32, usize>,
    expected: &[(u32, usize)],
    full_count: usize,
    tag: &str,
) {
    let mut expected_map: HashMap<u32, usize> = HashMap::new();
    let mut sum = 0usize;
    for (depth, count) in expected {
        expected_map.insert(*depth, *count);
        sum += count;
    }
    assert_eq!(
        histogram, &expected_map,
        "per-level element counts diverge from the fixture grammar — {tag}"
    );
    assert_eq!(
        sum, full_count,
        "the level-by-level sum must equal the full count — {tag}"
    );
}

/// Apply the REAL XML-1 filter helper to a clone of the ONE extraction and
/// pin the cumulative kept count + the post-walk timing contract (the filter
/// must be ~free: no re-parse).
fn assert_filtered_view(extracted: &Extracted, max_depth: u32, expected: usize, tag: &str) {
    let started = Instant::now();
    let mut view = extracted.structure.clone();
    filter_structure_max_depth(&mut view, max_depth);
    let elapsed = started.elapsed();
    let kept = view.files[0].definitions.len();
    println!(
        "{tag}: max-depth {max_depth} -> {kept} rows in {elapsed:?} ({:.1}% of extraction)",
        elapsed.as_secs_f64() / extracted.elapsed.as_secs_f64() * 100.0
    );
    assert_eq!(
        kept, expected,
        "filtered count at --max-depth {max_depth} — {tag}"
    );
    assert!(
        elapsed < extracted.elapsed / 10,
        "the depth filter is post-walk and must not re-parse: {elapsed:?} \
         vs extraction {:?} — {tag}",
        extracted.elapsed
    );
}

/// Locate the `probe.occurrence`-th definition named `probe.name` and pin
/// its depth, absolute line and byte span (sliced out of the in-memory
/// source / part text). On a miss, dump the first 10 definitions.
fn assert_probe(source: &str, defs: &[DefinitionInfo], probe: &NavProbe, tag: &str) {
    let mut seen = 0usize;
    let mut hit = None;
    for def in defs {
        if def.name == probe.name {
            if seen == probe.occurrence {
                hit = Some(def);
                break;
            }
            seen += 1;
        }
    }
    let def = hit.unwrap_or_else(|| {
        panic!(
            "probe {:?} (occurrence {}) not found — {} name matches, first 10 defs: {:#?} — {tag}",
            probe.name,
            probe.occurrence,
            seen,
            &defs[..defs.len().min(10)]
        )
    });
    assert_eq!(
        def.depth,
        Some(probe.depth),
        "probe {:?} sits at the wrong nesting level — {tag}",
        probe.name
    );
    assert_eq!(
        def.line_start, probe.line_start,
        "probe {:?} starts on the wrong line — {tag}",
        probe.name
    );
    let (bs, be) = match (def.byte_start, def.byte_end) {
        (Some(s), Some(e)) => (s as usize, e as usize),
        other => panic!(
            "probe {:?} must carry byte spans, got {other:?} — {tag}",
            probe.name
        ),
    };
    let slice = &source[bs..be];
    assert_eq!(
        slice, probe.text,
        "byte-span mismatch for probe {:?} (bytes {bs}..{be}) — {tag}",
        probe.name
    );
    assert!(
        slice.starts_with('<'),
        "probe span must open at the element's '<' — {tag}"
    );
}

/// Deflate-compressed package writer — the OPC compression docx/xlsx/pptx
/// use, written through zip's ZipWriter so the containers are genuine
/// packages, not mocks (the `zip` dependency is tldr-core's own runtime dep;
/// the ooxml-structure-v1 CLI suite uses the identical writer shape).
fn write_container(path: &std::path::Path, parts: &[(&str, &[u8])]) {
    use std::io::Write as _;
    let file = std::fs::File::create(path).expect("create container file");
    let mut writer = zip::ZipWriter::new(file);
    let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, bytes) in parts {
        writer.start_file(*name, options).expect("start part");
        writer.write_all(bytes).expect("write part");
    }
    writer.finish().expect("finish container");
}

// =============================================================================
// xml — 2,000 repetitions of a 12-level-deep chain (`<n0>` … `<n11>`), no
// root wrapper, so depths 0..=11 exist with 2,000 elements at every level.
// One `id`-carrying element per level makes every probe name globally unique
// (`n{d}#u{i}d{d}`); the payload is a single text line per level.
// =============================================================================

/// The xml/xhtml unit: `LEVELS` nested `tag` elements, each opening on its
/// own line, a payload line, then all the closing tags — 3·LEVELS lines.
fn chain_unit(tag: fn(usize) -> String, i: usize, payload: &str) -> String {
    let mut unit = String::new();
    for d in 0..LEVELS {
        unit.push_str(&format!("<{} id=\"u{i}d{d}\">\n{payload}\n", tag(d)));
    }
    for d in (0..LEVELS).rev() {
        unit.push_str(&format!("</{}>\n", tag(d)));
    }
    unit
}

/// The exact node bytes of chain level `d` of unit `i` (open tag → its close
/// tag, child subtree and the interleaved newlines included, trailing
/// newline excluded — the node range ends at the closing `>`).
fn chain_element_text(tag: fn(usize) -> String, i: usize, d: usize, payload: &str) -> String {
    let mut text = format!("<{} id=\"u{i}d{d}\">\n{payload}\n", tag(d));
    if d + 1 < LEVELS {
        text.push_str(&chain_element_text(tag, i, d + 1, payload));
        text.push('\n');
    }
    text.push_str(&format!("</{}>", tag(d)));
    text
}

fn xml_tag(d: usize) -> String {
    format!("n{d}")
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn xml_100mib_navigation_depth_filtered_views() {
    let tag = "xml";
    let payload = "m".repeat(4400);
    let units: Vec<String> = (0..UNITS)
        .map(|i| chain_unit(xml_tag, i, &payload))
        .collect();
    // Generator self-check: the unit IS level 0's node text plus one newline,
    // so the probe reconstruction can never drift from the generator.
    assert_eq!(
        units[0],
        format!("{}\n", chain_element_text(xml_tag, 0, 0, &payload)),
        "chain generator and probe reconstruction diverged"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let fx = assemble(dir, "large.xml", "", &units, "");
    let extracted = extract_and_pin(&fx, Language::Xml, Some(Language::Xml), UNITS * LEVELS, tag);
    let defs = &extracted.structure.files[0].definitions;
    assert_eq!(
        defs.len(),
        UNITS * LEVELS,
        "exact element count — {tag} — {}",
        fx.summary()
    );

    // Per-level counts + the level-sum invariant: 2,000 elements at EVERY
    // depth 0..=11.
    let histogram = depth_histogram(&defs, tag);
    let expected: Vec<(u32, usize)> = (0..LEVELS as u32).map(|d| (d, UNITS)).collect();
    assert_level_table(&histogram, &expected, defs.len(), tag);

    // Depth-filtered views through the real helper, off the ONE extraction
    // (cumulative up to each level: (L+1)·2,000).
    for (level, expected_kept) in [
        (0u32, UNITS),
        (1, 2 * UNITS),
        (3, 4 * UNITS),
        (6, 7 * UNITS),
    ] {
        assert_filtered_view(&extracted, level, expected_kept, tag);
    }

    // Depth probes byte-exact at scale: first/mid/last unit × shallow/deep.
    for (i, d) in [
        (0usize, 0usize),
        (0, LEVELS - 1),
        (UNITS / 2, 5),
        (UNITS - 1, 0),
        (UNITS - 1, LEVELS - 1),
    ] {
        // Level d of unit i opens on the unit's line + 2d (each ancestor level
        // contributes its open + payload line before descending).
        let line_start = (36 * i + 2 * d + 1) as u32;
        assert_probe(
            &fx.source,
            defs,
            &NavProbe {
                name: format!("n{d}#u{i}d{d}"),
                occurrence: 0,
                depth: d as u32,
                line_start,
                text: chain_element_text(xml_tag, i, d, &payload),
            },
            tag,
        );
    }
    println!(
        "{tag}: PASS {} — {} units, {} elements, file {} MiB",
        fx.path.display(),
        UNITS,
        defs.len(),
        fx.source.len() / (1024 * 1024)
    );
}

// =============================================================================
// xhtml — the html grammar (.xhtml → Language::Html, walk_html): the same
// 12-level chain of `<div>` under an html/head/title/body wrapper, so the
// wrapper occupies depths 0-2 and the chain's levels shift down by two.
// =============================================================================

fn xhtml_tag(_d: usize) -> String {
    "div".to_string()
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn xhtml_100mib_navigation_depth_filtered_views() {
    let tag = "xhtml";
    let payload = "m".repeat(4400);
    let units: Vec<String> = (0..UNITS)
        .map(|i| chain_unit(xhtml_tag, i, &payload))
        .collect();
    assert_eq!(
        units[0],
        format!("{}\n", chain_element_text(xhtml_tag, 0, 0, &payload)),
        "chain generator and probe reconstruction diverged"
    );

    // Wrapper: html(0) > head(1) > title(2); body(1) carries the units.
    let prefix = "\
<!DOCTYPE html>
<html xmlns=\"http://www.w3.org/1999/xhtml\">
<head>
<title>Navigation</title>
</head>
<body>
";
    let dir = tempfile::tempdir().expect("tempdir");
    let fx = assemble(dir, "large.xhtml", prefix, &units, "</body>\n</html>\n");
    let extracted = extract_and_pin(
        &fx,
        Language::Html,
        Some(Language::Html),
        UNITS * LEVELS,
        tag,
    );
    let defs = &extracted.structure.files[0].definitions;
    // 24,000 chain elements + html + head + title + body.
    assert_eq!(
        defs.len(),
        UNITS * LEVELS + 4,
        "exact element count — {tag} — {}",
        fx.summary()
    );

    // Wrapper rows + the shifted chain: depth 0 → html; 1 → head,body;
    // 2 → title + div0; 3..=13 → one div level per unit.
    let histogram = depth_histogram(&defs, tag);
    let mut expected: Vec<(u32, usize)> = vec![(0, 1), (1, 2), (2, 1 + UNITS)];
    for d in 3..=(LEVELS as u32 + 1) {
        expected.push((d, UNITS));
    }
    assert_level_table(&histogram, &expected, defs.len(), tag);

    // Cumulative kept counts: L0 → 1, L1 → 3, L3 → 3+2001+2000, L6 → +div2..4.
    for (level, expected_kept) in [
        (0u32, 1),
        (1, 3),
        (3, 3 + (1 + UNITS) + UNITS),
        (6, 3 + (1 + UNITS) + 4 * UNITS),
    ] {
        assert_filtered_view(&extracted, level, expected_kept, tag);
    }

    // Depth probes: div level d of unit i sits at depth d+2, on the unit's
    // line + 2d; the wrapper occupies the first 6 lines.
    for (i, d) in [
        (0usize, 0usize),
        (0, LEVELS - 1),
        (UNITS / 2, 5),
        (UNITS - 1, 0),
        (UNITS - 1, LEVELS - 1),
    ] {
        assert_probe(
            &fx.source,
            defs,
            &NavProbe {
                name: format!("div#u{i}d{d}"),
                occurrence: 0,
                depth: d as u32 + 2,
                line_start: (6 + 36 * i + 2 * d + 1) as u32,
                text: chain_element_text(xhtml_tag, i, d, &payload),
            },
            tag,
        );
    }
    println!(
        "{tag}: PASS {} — {} units, {} elements, file {} MiB",
        fx.path.display(),
        UNITS,
        defs.len(),
        fx.source.len() / (1024 * 1024)
    );
}

// =============================================================================
// svg — nested `<g>` groups (12 levels) with one `<path/>` leaf per group,
// under the `<svg>` root: groups at depths 1..=12, paths one level deeper
// (2..=13). SVG rides the XML grammar (`.svg` → Language::Xml).
// =============================================================================

const SVG_PATH: &str = "<path d=\"M0 0L9 9\"/>";

fn svg_unit(i: usize, payload: &str) -> String {
    let mut unit = String::new();
    for d in 0..LEVELS {
        unit.push_str(&format!("<g id=\"u{i}d{d}\">\n{payload}\n{SVG_PATH}\n"));
    }
    for _ in 0..LEVELS {
        unit.push_str("</g>\n");
    }
    unit
}

/// The exact node bytes of `g` level `d` of unit `i`.
fn svg_g_text(i: usize, d: usize, payload: &str) -> String {
    let mut text = format!("<g id=\"u{i}d{d}\">\n{payload}\n{SVG_PATH}\n");
    if d + 1 < LEVELS {
        text.push_str(&svg_g_text(i, d + 1, payload));
        text.push('\n');
    }
    text.push_str("</g>");
    text
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn svg_100mib_navigation_depth_filtered_views() {
    let tag = "svg";
    let payload = "m".repeat(4400);
    let units: Vec<String> = (0..UNITS).map(|i| svg_unit(i, &payload)).collect();
    assert_eq!(
        units[0],
        format!("{}\n", svg_g_text(0, 0, &payload)),
        "svg generator and probe reconstruction diverged"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let fx = assemble(
        dir,
        "large.svg",
        "<?xml version=\"1.0\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\">\n",
        &units,
        "</svg>\n",
    );
    let extracted = extract_and_pin(
        &fx,
        Language::Xml,
        Some(Language::Xml),
        UNITS * 2 * LEVELS,
        tag,
    );
    let defs = &extracted.structure.files[0].definitions;
    // 12 groups + 12 paths per unit, plus the svg root.
    assert_eq!(
        defs.len(),
        UNITS * 2 * LEVELS + 1,
        "exact element count — {tag} — {}",
        fx.summary()
    );

    // 0 → svg; 1 → g0; 2..=12 → path_{d-2} + g_{d-1}; 13 → path_11.
    let histogram = depth_histogram(&defs, tag);
    let mut expected: Vec<(u32, usize)> = vec![(0, 1), (1, UNITS)];
    for d in 2..=(LEVELS as u32) {
        expected.push((d, 2 * UNITS));
    }
    expected.push((LEVELS as u32 + 1, UNITS));
    assert_level_table(&histogram, &expected, defs.len(), tag);

    // Cumulative kept counts: L0 → 1, L1 → 1+2000, L3 → +2·4,000·2, L6 → +5·4,000.
    for (level, expected_kept) in [
        (0u32, 1),
        (1, 1 + UNITS),
        (3, 1 + UNITS + 2 * 2 * UNITS),
        (6, 1 + UNITS + 5 * 2 * UNITS),
    ] {
        assert_filtered_view(&extracted, level, expected_kept, tag);
    }

    // Groups carry per-unit ids → unique names; level d opens on the unit's
    // line + 3d (open + payload + path line per ancestor level); the svg root
    // and its prolog occupy the first 2 lines.
    for (i, d) in [
        (0usize, 0usize),
        (0, LEVELS - 1),
        (UNITS / 2, LEVELS - 1),
        (UNITS - 1, 0),
    ] {
        assert_probe(
            &fx.source,
            defs,
            &NavProbe {
                name: format!("g#u{i}d{d}"),
                occurrence: 0,
                depth: d as u32 + 1,
                line_start: (3 + 48 * i + 3 * d) as u32,
                text: svg_g_text(i, d, &payload),
            },
            tag,
        );
    }
    // Paths are id-less (name `path`) — probe them by occurrence: the path of
    // unit i, level d is the (12i + d)-th `path` row in source order. Its
    // depth is d+2 (one deeper than its owning group).
    for (i, d) in [(0usize, 0usize), (UNITS / 2, 0), (UNITS - 1, LEVELS - 1)] {
        assert_probe(
            &fx.source,
            defs,
            &NavProbe {
                name: "path".to_string(),
                occurrence: i * LEVELS + d,
                depth: d as u32 + 2,
                line_start: (3 + 48 * i + 3 * d + 2) as u32,
                text: SVG_PATH.to_string(),
            },
            tag,
        );
    }
    println!(
        "{tag}: PASS {} — {} units, {} elements, file {} MiB",
        fx.path.display(),
        UNITS,
        defs.len(),
        fx.source.len() / (1024 * 1024)
    );
}

// =============================================================================
// docx — a 100 MiB CONTAINER: `word/document.xml` of ~108 MB decompressed
// (8 nested `w:tbl > w:tr > w:tc > w:p` levels per unit — deep w:p/w:tbl
// nesting) plus 2 small extra parts that v1 must NOT analyze. Per-part depth
// restarts at 0 (signature-scoped), max-depth filtering works through the
// container path, and the ~108 MB part sits far under the decompressed-part
// cap (`fs::oversize::MAX_FILE_SIZE_BYTES`) — the no-skip policy pin.
// =============================================================================

/// Minimal-but-real OPC scaffolding (same shapes as the ooxml-structure-v1
/// CLI fixtures).
const DOCX_CONTENT_TYPES: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"#;

const DOCX_ROOT_RELS: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"#;

/// An extra part v1 must NOT analyze (headers/footers are documented future
/// work) — its elements would otherwise interleave into the definitions.
const DOCX_HEADER1: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:r><w:t>HEADER</w:t></w:r></w:p></w:hdr>"#;

/// A second extra part (package metadata) that must NOT emit either.
const DOCX_CORE_PROPS: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"/>"#;

/// The exact node bytes of the level-`k` nested table of unit `i`:
/// `w:tbl > w:tr > w:tc > (w:p > w:r > w:t) > [next level] `, 13 lines per
/// level (6 opens + payload + 3 closes + the child subtree + 3 closes).
fn docx_tbl_text(i: usize, k: usize, payload: &str) -> String {
    let mut text = format!(
        "<w:tbl id=\"u{i}L{k}\">\n<w:tr>\n<w:tc>\n<w:p>\n<w:r>\n<w:t>\n{payload}\n</w:t>\n</w:r>\n</w:p>\n"
    );
    if k + 1 < DOCX_LEVELS {
        text.push_str(&docx_tbl_text(i, k + 1, payload));
        text.push('\n');
    }
    text.push_str("</w:tc>\n</w:tr>\n</w:tbl>");
    text
}

fn docx_unit(i: usize, payload: &str) -> String {
    format!("{}\n", docx_tbl_text(i, 0, payload))
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn docx_100mib_container_navigation() {
    let tag = "docx";
    let payload = "m".repeat(6600);
    let mut part = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n");
    part.push_str(
        "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\n",
    );
    part.push_str("<w:body>\n");
    for i in 0..UNITS {
        part.push_str(&docx_unit(i, &payload));
    }
    part.push_str("</w:body>\n</w:document>\n");
    // Generator self-check (same guard as the xml-family tests).
    assert_eq!(
        docx_unit(0, &payload),
        format!("{}\n", docx_tbl_text(0, 0, &payload)),
        "docx generator and probe reconstruction diverged"
    );
    // The fixture grammar: ≥ 100 MiB of decompressed document.xml.
    assert!(
        part.len() >= TARGET_BYTES,
        "document.xml part never reached the target: {} bytes",
        part.len()
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let container_path = dir.path().join("large.docx");
    write_container(
        &container_path,
        &[
            ("[Content_Types].xml", DOCX_CONTENT_TYPES.as_bytes()),
            ("_rels/.rels", DOCX_ROOT_RELS.as_bytes()),
            ("word/header1.xml", DOCX_HEADER1.as_bytes()),
            ("docProps/core.xml", DOCX_CORE_PROPS.as_bytes()),
            ("word/document.xml", part.as_bytes()),
        ],
    );

    // Size policy through the container path: the CONTAINER file and the
    // DECOMPRESSED part both sit under the central cap — nothing may be
    // skipped for size (the warnings-empty pin below is the no-skip proof).
    let container_len = std::fs::metadata(&container_path)
        .expect("stat container")
        .len();
    assert!(
        container_len < tldr_core::fs::oversize::MAX_FILE_SIZE_BYTES,
        "container over the central cap would be a structured skip"
    );
    assert!(
        (part.len() as u64) < tldr_core::fs::oversize::MAX_FILE_SIZE_BYTES,
        "the ~108 MB decompressed part is far under the per-part cap — the policy pin"
    );

    let started = Instant::now();
    let structure = get_code_structure(&container_path, Language::Xml, 0, None)
        .unwrap_or_else(|e| panic!("get_code_structure failed — {tag}: {e:?}"));
    let elapsed = started.elapsed();
    println!("{tag}: extracted the container in {elapsed:?}");

    // Container report shape: a PACKAGE, not a document — `language` is None
    // (the container-is-not-a-language decision), one file entry, no skips,
    // no warnings (both extra parts silently contribute nothing; the big
    // part stays under the cap).
    assert_eq!(
        structure.language, None,
        "a container reports language null"
    );
    assert_eq!(structure.files_skipped, 0, "no container skipped — {tag}");
    assert!(
        structure.warnings.is_empty(),
        "no part-skip warnings expected, got {:?} — {tag}",
        structure.warnings
    );
    assert_eq!(structure.files.len(), 1, "exactly one file entry — {tag}");
    assert!(
        elapsed < EXTRACTION_BUDGET,
        "container extraction over budget"
    );

    let extracted = Extracted { structure, elapsed };
    let defs = &extracted.structure.files[0].definitions;
    // 48 elements per unit (6 per nested level × 8) + w:document + w:body.
    assert_eq!(
        defs.len(),
        UNITS * 6 * DOCX_LEVELS + 2,
        "exact element count — {tag}"
    );
    // v1 analyzes word/document.xml ONLY: every row is signature-scoped to
    // the one analyzed part (the 2 extra parts never emit).
    assert!(
        defs.iter()
            .all(|d| d.kind == "element" && d.signature == "word/document.xml"),
        "every definition must be a document.xml element — {tag}"
    );

    // Per-part depth restarts at 0 (signature-scoped): the part's first two
    // rows are the part root and its body.
    assert_eq!(defs[0].name, "w:document");
    assert_eq!(defs[0].depth, Some(0));
    assert_eq!(defs[1].name, "w:body");
    assert_eq!(defs[1].depth, Some(1));
    // Byte spans are PART-RELATIVE: the root spans from `<w:document` to the
    // final `>` — slicing the DECOMPRESSED part text at the span reproduces
    // the element (the container-file offsets are meaningless, per ast::ooxml).
    let root_start = part
        .find("<w:document")
        .expect("document root in part text");
    assert_eq!(defs[0].byte_start, Some(root_start as u64));
    assert_eq!(
        &part[root_start..part.len() - 1],
        &part[defs[0].byte_start.unwrap() as usize..defs[0].byte_end.unwrap() as usize],
        "the root element's part-relative span must cover the whole document"
    );

    // Depth table of the nested-table grammar: 0→w:document, 1→w:body,
    // 2..=4 → one element per unit, 5..=25 → two (p/r/t of level k overlaps
    // tbl/tr/tc of level k+1), 26..=28 → one (the innermost p/r/t).
    let histogram = depth_histogram(defs, tag);
    let mut expected: Vec<(u32, usize)> = vec![(0, 1), (1, 1)];
    for d in 2..=4u32 {
        expected.push((d, UNITS));
    }
    for d in 5..=(3 * DOCX_LEVELS as u32 + 1) {
        expected.push((d, 2 * UNITS));
    }
    for d in (3 * DOCX_LEVELS as u32 + 2)..=(3 * DOCX_LEVELS as u32 + 4) {
        expected.push((d, UNITS));
    }
    assert_level_table(&histogram, &expected, defs.len(), tag);

    // max-depth filtering through the CONTAINER path — the same post-walk
    // helper the CLI and daemon apply, here on the container's extraction.
    for (level, expected_kept) in [
        (0u32, 1),
        (1, 2),
        (5, 2 + 3 * UNITS + 2 * UNITS),
        (12, 2 + 3 * UNITS + 8 * 2 * UNITS),
    ] {
        assert_filtered_view(&extracted, level, expected_kept, tag);
    }

    // Depth probes byte-exact, PART-RELATIVE: `w:tbl#u{i}L{k}` at depth
    // 3k+2, opening on the unit's line + 10k (each level's 10 head lines —
    // tbl..`</w:p>` — precede its child subtree; the 3 closing lines of a
    // level come after that subtree).
    for (i, k) in [
        (0usize, 0usize),
        (UNITS / 2, 0),
        (UNITS / 2, DOCX_LEVELS - 1),
        (UNITS - 1, DOCX_LEVELS - 1),
    ] {
        assert_probe(
            &part,
            defs,
            &NavProbe {
                name: format!("w:tbl#u{i}L{k}"),
                occurrence: 0,
                depth: (3 * k + 2) as u32,
                line_start: (4 + 104 * i + 10 * k) as u32,
                text: docx_tbl_text(i, k, &payload),
            },
            tag,
        );
    }
    // The id-less `w:t` of unit 0, level 0: the part's first w:t row, at
    // depth 3·0+7 = 7, opening on the 5th line of unit 0.
    assert_probe(
        &part,
        defs,
        &NavProbe {
            name: "w:t".to_string(),
            occurrence: 0,
            depth: 7,
            line_start: 4 + 5,
            text: format!("<w:t>\n{payload}\n</w:t>"),
        },
        tag,
    );
    println!(
        "{tag}: PASS {} — {UNITS} units, {} elements, part {} MiB decompressed, container {} KB on disk",
        container_path.display(),
        defs.len(),
        part.len() / (1024 * 1024),
        container_len / 1024
    );
}

// =============================================================================
// xlsx / pptx — LIGHT container checks (small parts, depth correctness only;
// the 100 MiB requirement is proven for the shared container path by the
// docx test above): per-part depth RESTARTS at 0 (each worksheet's / slide's
// root elements are depth 0 again, scoped by the signature = part path), and
// max-depth filtering works through the container path. The "etc." formats
// ride the same unzip → per-part XML walk mechanism.
// =============================================================================

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

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn ooxml_xlsx_pptx_per_part_depth_restart() {
    // --- xlsx: two worksheets, each walked as its own XML document. ---
    let dir = tempfile::tempdir().expect("tempdir");
    let xlsx_path = dir.path().join("light.xlsx");
    write_container(
        &xlsx_path,
        &[
            (
                "[Content_Types].xml",
                r#"<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>"#.as_bytes(),
            ),
            ("_rels/.rels", DOCX_ROOT_RELS.as_bytes()),
            (
                "xl/worksheets/sheet1.xml",
                worksheet(&[("1", "Alpha"), ("2", "Beta")]).as_bytes(),
            ),
            (
                "xl/worksheets/sheet2.xml",
                worksheet(&[("1", "Gamma"), ("2", "Delta")]).as_bytes(),
            ),
        ],
    );
    let started = Instant::now();
    let structure =
        get_code_structure(&xlsx_path, Language::Xml, 0, None).expect("xlsx container extraction");
    println!("xlsx: extracted in {:?}", started.elapsed());
    assert_eq!(
        structure.language, None,
        "a container reports language null"
    );
    assert!(
        structure.warnings.is_empty(),
        "no warnings: {:?}",
        structure.warnings
    );

    let defs = &structure.files[0].definitions;
    // Per worksheet: worksheet > sheetData > (row > c > is > t) × 2 = 10.
    assert_eq!(defs.len(), 20, "10 elements per worksheet");

    // PER-PART DEPTH RESTART (signature-scoped): sheet2's worksheet root is
    // depth 0 again, exactly like sheet1's, distinguishable only by the part
    // path in `signature`.
    for (offset, part) in [
        (0usize, "xl/worksheets/sheet1.xml"),
        (10, "xl/worksheets/sheet2.xml"),
    ] {
        assert_eq!(defs[offset].name, "worksheet");
        assert_eq!(
            defs[offset].depth,
            Some(0),
            "each part's root restarts at 0"
        );
        assert_eq!(
            defs[offset].signature, part,
            "signature = the zip part path"
        );
    }
    // The within-part depth walk: worksheet(0) sheetData(1) then two
    // row(2) c(3) is(4) t(5) groups.
    for (offset, depth) in [
        (0usize, 0),
        (1, 1),
        (2, 2),
        (3, 3),
        (4, 4),
        (5, 5),
        (6, 2),
        (7, 3),
        (8, 4),
        (9, 5),
    ] {
        assert_eq!(
            defs[offset].depth,
            Some(depth),
            "xlsx depth walk at row {offset}"
        );
    }
    // max-depth through the container path: depth ≤ 1 keeps the two roots
    // and their sheetData rows — two depth-0 rows with DIFFERENT signatures.
    let mut view = structure.clone();
    filter_structure_max_depth(&mut view, 1);
    let kept = &view.files[0].definitions;
    assert_eq!(kept.len(), 4, "worksheet + sheetData per part");
    let roots: Vec<&str> = kept
        .iter()
        .filter(|d| d.depth == Some(0))
        .map(|d| d.signature.as_str())
        .collect();
    assert_eq!(
        roots,
        ["xl/worksheets/sheet1.xml", "xl/worksheets/sheet2.xml"],
        "both parts survive the filter with their own depth-0 roots"
    );

    // --- pptx: two slides, same per-part restart contract. ---
    let pptx_path = dir.path().join("light.pptx");
    write_container(
        &pptx_path,
        &[
            (
                "[Content_Types].xml",
                r#"<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>"#.as_bytes(),
            ),
            ("_rels/.rels", DOCX_ROOT_RELS.as_bytes()),
            ("ppt/slides/slide1.xml", slide(1).as_bytes()),
            ("ppt/slides/slide2.xml", slide(2).as_bytes()),
        ],
    );
    let started = Instant::now();
    let structure =
        get_code_structure(&pptx_path, Language::Xml, 0, None).expect("pptx container extraction");
    println!("pptx: extracted in {:?}", started.elapsed());
    assert_eq!(structure.language, None);
    assert!(
        structure.warnings.is_empty(),
        "no warnings: {:?}",
        structure.warnings
    );

    let defs = &structure.files[0].definitions;
    // p:sld > p:cSld > p:spTree > p:sp > p:txt > p:t = 6 per slide.
    assert_eq!(defs.len(), 12, "6 elements per slide");
    for (offset, part) in [
        (0usize, "ppt/slides/slide1.xml"),
        (6, "ppt/slides/slide2.xml"),
    ] {
        assert_eq!(defs[offset].name, "p:sld");
        assert_eq!(
            defs[offset].depth,
            Some(0),
            "each slide's root restarts at 0"
        );
        assert_eq!(defs[offset].signature, part);
    }
    // max-depth 2 keeps the slide root chain (p:sld, p:cSld, p:spTree) per part.
    let mut view = structure.clone();
    filter_structure_max_depth(&mut view, 2);
    let kept = &view.files[0].definitions;
    assert_eq!(kept.len(), 6, "3 root-chain elements per slide");
    assert!(
        kept.iter()
            .all(|d| d.depth == Some(0) || d.depth == Some(1) || d.depth == Some(2)),
        "only the slide root chain survives --max-depth 2"
    );
}
