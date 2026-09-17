//! Large-file byte-accuracy e2e — 100 MiB per language (13 formats + 18 code).
//!
//! Every test in this suite assembles a ≥ 100 MiB fixture from a small,
//! deterministic unit, extracts its structure through the REAL public entry
//! point (`tldr_core::get_code_structure`), and asserts that the extracted
//! definition bodies reproduce the generated source **byte for byte** — both
//! through the element byte spans (`DefinitionInfo.byte_start/byte_end`:
//! `source[byte_start..byte_end]` must BE the element) and through the
//! line-span path (`line_start/line_end` sliced over a `line_starts` table
//! minus one trailing `\n`). It also pins the suite-level invariants on every
//! language: `files_skipped == 0`, `warnings` empty, the size-policy cap for
//! the file's class (`u64::MAX` for the streamed `.log`/`.csv`/`.tsv` classes,
//! `u32::MAX` for tree-sitter formats and code languages), and a floor on the
//! definition count. Element kinds carry byte spans and are verified on the
//! byte path; code-language definitions are line-span only and are verified
//! on the line path.
//!
//! # Design
//!
//! - [`Probe`] — the EXACT expected extracted body of one definition, plus
//!   how to find it (`name` + `occurrence`, because formats repeat names like
//!   `id`/`items`/`@media`/`itemize` once per unit) and which span path to
//!   verify (byte-span for element kinds, line-span for the streamed/native
//!   and content-spanning shapes where the two spans legitimately differ —
//!   e.g. a TOML section's byte span ends with its trailing newline while the
//!   line span does not).
//! - [`assemble`] — repeats the unit builder until the file reaches the
//!   target size (asserting the final size lands within two unit sizes of
//!   it), collects probes for a spread of units (head, stride, last) so a
//!   failure names a byte-exact mid-file body, keeps the whole generated
//!   source IN MEMORY (the fixture is written once from it, never re-read),
//!   and computes each probe's absolute line number from the running line
//!   count.
//! - [`verify_fixture`] — one extraction per fixture (parsing 100 MiB once
//!   is the point of the suite; re-parsing per probe would be pointless),
//!   the suite-level asserts, and a precomputed `line_starts` table.
//! - [`assert_byte_exact`] — the per-probe byte-exact assertion.
//!
//! # Code tranche (18 languages)
//!
//! One test per code language — python, typescript, javascript, go, rust,
//! java, c, cpp, ruby, kotlin, swift, csharp, scala, php, lua, luau, elixir,
//! ocaml — driven by [`run_code_case`], which first runs a cheap 3-unit
//! sanity parse (the generator itself is validated — parseability, the
//! definition floor, and byte-exact probes — on a ~5 MB fixture BEFORE the
//! 100 MiB assembly spends a minute on it), then the full run. Three shapes
//! keep the code tranche tractable:
//!
//! - **~60 units of ~1.8 MB.** `build_intra_file_call_graph` (ast/extract.rs)
//!   walks the whole tree once per function to collect calls —
//!   O(functions × tree nodes). The format tranche's ~14k units would turn
//!   that into a multi-billion-step walk; ~60 units keep it at a few hundred
//!   thousand.
//! - **Bodies are one string token, no calls.** Every body block is a single
//!   string literal (triple-quoted / raw / template / heredoc / adjacent
//!   concatenation, whichever the language offers) containing no call
//!   expression: the syntax tree stays tiny AND the call graph has no edges
//!   to build.
//! - **Ceilings respected.** 62 content lines of ~29 KB per unit: max column
//!   ~29 KB and ~4k rows per file — both far under the 32-bit tree-sitter
//!   point ceilings and the int16 row counter that overflowed in
//!   tree-sitter-yaml (yaml-chunk-v1).
//!
//! Every 10th unit carries decorator / attribute / annotation / doc-comment
//! trivia ABOVE the declaration and the probe body STARTS at that trivia
//! line, mirroring symbol_fidelity_v1's attached-trivia region semantics at
//! 100 MiB scale; every test probes the head units, the [`CODE_KEEP_STRIDE`]
//! stride units and the last unit.
//!
//! # Opt-in
//!
//! Each test materialises a 100 MiB fixture and holds the source plus the
//! extraction structures in RAM (several GiB on the element-heavy formats),
//! so the suite is `#[ignore]`-gated. Run it in release, sequentially (one
//! fixture's peak RAM at a time):
//!
//! ```bash
//! timeout 3600 cargo test -p tldr-core --test large_file_accuracy_v1 --release -- --ignored --test-threads=1
//! ```
//!
//! The default (`cargo test -p tldr-core --test large_file_accuracy_v1`) must
//! compile-and-skip: `31 ignored; 0 failed`. All thirty-one run green.
//! (yaml-chunk-v1: the yaml test previously carried a defect pin —
//! tree-sitter-yaml's scanner overflows its int16 row counter at source row
//! 32768 — fixed by document-aligned chunk parsing in `ast::yaml_chunk`.)

use std::fmt::Write as _;
use std::time::Instant;

use tldr_core::{get_code_structure, CodeStructure, Language};

/// Target fixture size per format: 100 MiB.
const TARGET_BYTES: usize = 100 * 1024 * 1024;

/// Probes are collected for the first [`KEEP_HEAD`] units (every probe
/// flavour of a format appears within the first 12 units of its builder) …
const KEEP_HEAD: usize = 12;
/// … for every [`KEEP_STRIDE`]-th unit (so failures can surface mid-file) …
const KEEP_STRIDE: usize = 4096;
/// … and always for the LAST unit (EOF is where span edge cases live).
///
/// `line == UNANCHORED_LINE` marks a probe anchored to the fixture PREFIX
/// (e.g. the CSV/TSV header record) whose absolute line the unit builder
/// cannot know — the `line_start` cross-check is skipped for it.
const UNANCHORED_LINE: u32 = u32::MAX;

/// One expected extraction result: the definition named `name` (the
/// `occurrence`-th definition with that name, in source order) must have
/// `line_start == line` (unless unanchored) and a body equal to `body` on the
/// probed span path — `body` is the EXACT expected bytes (no trailing newline
/// for line-span extraction; exact node bytes for byte-span extraction).
#[derive(Debug, Clone)]
struct Probe {
    name: String,
    body: String,
    /// Absolute 1-indexed line the definition must start on (computed by
    /// `assemble` from the unit-relative line the builder supplies).
    line: u32,
    occurrence: usize,
    /// `true` → verify the byte span (`source[byte_start..byte_end]`);
    /// `false` → verify the line span (`line_start..line_end` sliced over the
    /// line-starts table, one trailing `\n` stripped).
    byte_span: bool,
}

impl Probe {
    /// Byte-span probe: `body` must equal the element's exact node bytes.
    fn byte(name: impl Into<String>, body: impl Into<String>, unit_line: u32) -> Probe {
        Probe {
            name: name.into(),
            body: body.into(),
            line: unit_line,
            occurrence: 0,
            byte_span: true,
        }
    }

    /// Line-span probe: `body` must equal the definition's lines minus one
    /// trailing `\n`.
    fn line_span(name: impl Into<String>, body: impl Into<String>, unit_line: u32) -> Probe {
        Probe {
            name: name.into(),
            body: body.into(),
            line: unit_line,
            occurrence: 0,
            byte_span: false,
        }
    }

    /// Select the `n`-th definition with this name (formats repeat generic
    /// names — `id`, `items`, `@media`, `itemize`, `info` — once per unit).
    fn at(mut self, occurrence: usize) -> Probe {
        self.occurrence = occurrence;
        self
    }
}

/// One assembled 100 MiB fixture plus its expected probes.
struct Fixture {
    path: std::path::PathBuf,
    /// Keeps the tempdir (and therefore `path`) alive until the test ends.
    _dir: tempfile::TempDir,
    /// The full generated source, kept in memory — the fixture is written
    /// once from it and every span assertion slices THIS string, so a span
    /// bug can never hide behind a re-read.
    source: String,
    probes: Vec<Probe>,
    /// Floor for `files[0].definitions.len()`.
    min_defs: usize,
    units: usize,
}

impl Fixture {
    /// One-line summary for assertion messages — failure output must show
    /// the file size.
    fn summary(&self) -> String {
        format!(
            "fixture {} ({} bytes, {} MiB, {} units, min_defs {})",
            self.path.display(),
            self.source.len(),
            self.source.len() / (1024 * 1024),
            self.units,
            self.min_defs
        )
    }
}

/// Assemble a fixture: `prefix`, then the unit builder's output repeated
/// until the file reaches `target_bytes`, then `trailer` — written once.
///
/// The builder returns `(unit_source, probe)` where `unit_source` ends with
/// `\n` and the probe's `line` is the definition's 0-based line WITHIN the
/// unit (or `UNANCHORED_LINE`); `assemble` rewrites it into the absolute
/// line from the running line count. Probes are kept for the head units, the
/// `keep_stride` units and the last unit. Panics unless the final size is ≥
/// target and ≤ target + 2 unit sizes (the last repeat may overshoot).
fn assemble(
    dir: tempfile::TempDir,
    filename: &str,
    prefix: &str,
    unit_builder: impl Fn(usize) -> (String, Probe),
    target_bytes: usize,
    trailer: &str,
    keep_stride: usize,
) -> Fixture {
    let mut source = String::with_capacity(target_bytes + target_bytes / 8);
    source.push_str(prefix);
    let mut lines: u32 = source.matches('\n').count() as u32;
    let mut probes = Vec::new();
    let mut last_probe: Option<Probe> = None;
    let mut max_unit_bytes = 0usize;
    let mut units = 0usize;

    loop {
        let (unit, mut probe) = unit_builder(units);
        assert!(unit.ends_with('\n'), "unit source must end with \\n");
        max_unit_bytes = max_unit_bytes.max(unit.len());
        if probe.line != UNANCHORED_LINE {
            probe.line += lines + 1;
        }
        if units < KEEP_HEAD || units % keep_stride == 0 {
            probes.push(probe);
        } else {
            // Keep only the most recent non-kept probe as the EOF candidate —
            // replaced (read) in place on every loop, so no dead assignment.
            match last_probe.as_mut() {
                Some(slot) => *slot = probe,
                None => last_probe = Some(probe),
            }
        }
        source.push_str(&unit);
        lines += unit.matches('\n').count() as u32;
        units += 1;
        if source.len() >= target_bytes {
            break;
        }
    }
    // Always keep the FINAL unit's probe — EOF is the interesting edge.
    if let Some(probe) = last_probe {
        probes.push(probe);
    }
    source.push_str(trailer);

    assert!(
        source.len() >= target_bytes,
        "fixture never reached the target: {} bytes — {}",
        source.len(),
        filename
    );
    assert!(
        source.len() <= target_bytes + 2 * max_unit_bytes,
        "fixture overshot the target by more than two units: {} bytes (largest unit = {} bytes)",
        source.len(),
        max_unit_bytes
    );

    let path = dir.path().join(filename);
    std::fs::write(&path, source.as_bytes()).expect("write fixture");
    Fixture {
        path,
        _dir: dir,
        source,
        probes,
        // Every unit contributes at least one definition in all 31 languages.
        min_defs: units,
        units,
    }
}

/// The extraction plus everything the per-probe assertions need.
struct Verified {
    structure: CodeStructure,
    /// Byte offset of each line start (`line_starts[L - 1]` = start of line
    /// L, 1-indexed); the trailing entry is the offset past the final `\n`.
    line_starts: Vec<u64>,
}

/// Extract ONCE and assert the suite-level invariants: no skips, no
/// warnings, the right language, the right size-policy class, the
/// definition-count floor.
fn verify_fixture(fx: &Fixture, language: Language) -> Verified {
    let started = Instant::now();
    let structure = get_code_structure(&fx.path, language, 0, None)
        .unwrap_or_else(|e| panic!("get_code_structure failed — {}: {e:?}", fx.summary()));
    println!(
        "{:>8}: extracted {} definitions from {} in {:?}",
        language_tag(language),
        structure.files[0].definitions.len(),
        fx.summary(),
        started.elapsed()
    );

    assert_eq!(
        structure.files_skipped,
        0,
        "no file may be skipped — {}",
        fx.summary()
    );
    assert!(
        structure.warnings.is_empty(),
        "no warnings expected, got {:?} — {}",
        structure.warnings,
        fx.summary()
    );
    assert_eq!(
        structure.language,
        Some(language),
        "wrong language reported — {}",
        fx.summary()
    );
    assert_eq!(
        structure.files.len(),
        1,
        "exactly one file — {}",
        fx.summary()
    );
    assert!(
        structure.files[0].definitions.len() >= fx.min_defs,
        "definitions {} < min_defs {} — {}",
        structure.files[0].definitions.len(),
        fx.min_defs,
        fx.summary()
    );

    // Size policy: the streamed classes (.log/.csv/.tsv) must be UNCAPPED —
    // a 100 MiB fixture under a capped class would have been skipped above —
    // and every other format sits under the tree-sitter u32::MAX ceiling.
    let expected_cap = if matches!(language, Language::Log | Language::Csv | Language::Tsv) {
        u64::MAX
    } else {
        u64::from(u32::MAX)
    };
    assert_eq!(
        tldr_core::fs::oversize::max_size_for(&fx.path),
        expected_cap,
        "wrong size-policy class for {} — {}",
        fx.path.display(),
        fx.summary()
    );

    let line_starts = build_line_starts(&fx.source);
    Verified {
        structure,
        line_starts,
    }
}

/// Byte offsets of every line start (plus the past-the-final-newline entry).
fn build_line_starts(source: &str) -> Vec<u64> {
    let mut starts = vec![0u64];
    for (i, b) in source.bytes().enumerate() {
        if b == b'\n' {
            starts.push((i + 1) as u64);
        }
    }
    starts
}

/// Slice one definition's line span: lines `start..=end`, one trailing `\n`
/// stripped (the same convention the extraction uses for `line_end`).
fn line_span_slice<'a>(
    source: &'a str,
    line_starts: &[u64],
    start: u32,
    end: u32,
) -> (usize, &'a str) {
    let slice_start = line_starts[(start - 1) as usize] as usize;
    let slice_end = line_starts
        .get(end as usize)
        .map_or(source.len(), |&o| o as usize);
    let raw = &source[slice_start..slice_end];
    let stripped = raw.strip_suffix('\n').unwrap_or(raw);
    (slice_start, stripped)
}

/// Find the `probe.occurrence`-th definition named `probe.name` and assert
/// its body byte-for-byte against the fixture source, on the probe's span
/// path. On a miss, dump the first 10 definitions.
fn assert_byte_exact(fx: &Fixture, verified: &Verified, probe: &Probe) {
    let defs = &verified.structure.files[0].definitions;
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
            "definition {:?} (occurrence {}) not found — {} name matches, first 10 defs: {:#?} — {}",
            probe.name,
            probe.occurrence,
            seen,
            &defs[..defs.len().min(10)],
            fx.summary()
        )
    });

    if probe.line != UNANCHORED_LINE {
        assert_eq!(
            def.line_start,
            probe.line,
            "definition {:?} starts on line {} but the fixture places it on line {} — {}",
            probe.name,
            def.line_start,
            probe.line,
            fx.summary()
        );
    }

    let source = &fx.source;
    if probe.byte_span {
        let (bs, be) = match (def.byte_start, def.byte_end) {
            (Some(s), Some(e)) => (s as usize, e as usize),
            other => panic!(
                "definition {:?} must carry byte spans, got {other:?} — {}",
                probe.name,
                fx.summary()
            ),
        };
        assert_eq!(
            &source[bs..be],
            probe.body,
            "byte-span body mismatch for {:?} (bytes {bs}..{be}) — {}",
            probe.name,
            fx.summary()
        );
    } else {
        let (slice_start, body) =
            line_span_slice(source, &verified.line_starts, def.line_start, def.line_end);
        assert_eq!(
            body,
            probe.body,
            "line-span body mismatch for {:?} (lines {}..{}) — {}",
            probe.name,
            def.line_start,
            def.line_end,
            fx.summary()
        );
        // The stripped slice must sit immediately before a newline (the one
        // that was stripped) — a mis-sliced span fails here even when the
        // bodies happen to agree.
        assert_eq!(
            source.as_bytes().get(slice_start + body.len()),
            Some(&b'\n'),
            "line span for {:?} must end at a newline — {}",
            probe.name,
            fx.summary()
        );
    }
}

/// Shared test driver: assemble at 100 MiB, verify, byte-check every probe.
fn run_case(
    language: Language,
    filename: &str,
    prefix: &str,
    trailer: &str,
    unit_builder: impl Fn(usize) -> (String, Probe),
    min_defs: impl Fn(usize) -> usize,
) {
    run_case_with_stride(
        language,
        filename,
        prefix,
        trailer,
        unit_builder,
        min_defs,
        KEEP_STRIDE,
    );
}

/// [`run_case`] with an explicit probe stride — the code tranche's ~60-unit
/// files need a tighter stride than the format tests' [`KEEP_STRIDE`] for
/// mid-file probes to exist at all.
fn run_case_with_stride(
    language: Language,
    filename: &str,
    prefix: &str,
    trailer: &str,
    unit_builder: impl Fn(usize) -> (String, Probe),
    min_defs: impl Fn(usize) -> usize,
    keep_stride: usize,
) {
    let started = Instant::now();
    let dir = tempfile::tempdir().expect("tempdir");
    let mut fx = assemble(
        dir,
        filename,
        prefix,
        unit_builder,
        TARGET_BYTES,
        trailer,
        keep_stride,
    );
    fx.min_defs = min_defs(fx.units);
    let verified = verify_fixture(&fx, language);
    for probe in &fx.probes {
        assert_byte_exact(&fx, &verified, probe);
    }
    println!(
        "{:>8}: PASS {} — {} units, {} defs, {} probes, file {} MiB, {:?}",
        language_tag(language),
        filename,
        fx.units,
        verified.structure.files[0].definitions.len(),
        fx.probes.len(),
        fx.source.len() / (1024 * 1024),
        started.elapsed()
    );
}

/// Short tag for the per-test timing lines.
fn language_tag(language: Language) -> &'static str {
    match language {
        Language::Json => "json",
        Language::Yaml => "yaml",
        Language::Toml => "toml",
        Language::Xml => "xml",
        Language::Html => "html",
        Language::Css => "css",
        Language::Bash => "bash",
        Language::Latex => "latex",
        Language::Markdown => "markdown",
        Language::Csv => "csv",
        Language::Tsv => "tsv",
        Language::Log => "log",
        Language::Text => "text",
        // Code tranche.
        Language::Python => "python",
        Language::TypeScript => "typescript",
        Language::JavaScript => "javascript",
        Language::Go => "go",
        Language::Rust => "rust",
        Language::Java => "java",
        Language::C => "c",
        Language::Cpp => "cpp",
        Language::Ruby => "ruby",
        Language::Kotlin => "kotlin",
        Language::Swift => "swift",
        Language::CSharp => "csharp",
        Language::Scala => "scala",
        Language::Php => "php",
        Language::Lua => "lua",
        Language::Luau => "luau",
        Language::Elixir => "elixir",
        Language::Ocaml => "ocaml",
        _ => "other",
    }
}

// =============================================================================
// json — one top-level object per unit inside an array (the leading comma
// keeps every unit a single source line), element path: `key` byte spans.
// =============================================================================

fn json_unit(i: usize) -> (String, Probe) {
    let lead = if i == 0 { "" } else { "," };
    let unit =
        format!("{lead}{{\"id\": \"unit-{i}\", \"nested\": {{\"a\": 1, \"b\": [1, 2, 3]}}}}\n");
    let probe = match i % 4 {
        0 => Probe::byte("id", format!("\"id\": \"unit-{i}\""), 0).at(i),
        1 => Probe::byte("nested", "\"nested\": {\"a\": 1, \"b\": [1, 2, 3]}", 0).at(i),
        2 => Probe::byte("a", "\"a\": 1", 0).at(i),
        _ => Probe::byte("b", "\"b\": [1, 2, 3]", 0).at(i),
    };
    (unit, probe)
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn json_100mib_byte_exact() {
    run_case(
        Language::Json,
        "large.json",
        "[\n",
        "]\n",
        json_unit,
        |units| units * 4,
    );
}

// =============================================================================
// yaml — `---`-delimited documents (one per unit). The document and the
// `items` key are probed on the LINE path: their byte span swallows the
// file's final newline at EOF, while the line span is EOF-stable. The
// single-line `id` key is probed on the byte path.
//
// yaml-chunk-v1 (was a defect pin): tree-sitter-yaml's external scanner
// tracks the source row in `int16_t` (scanner.c:136/147) and overflows at
// source row 32768 — a single whole-file parse of this fixture aborts into a
// root ERROR and extracts ZERO definitions. Fixed by document-aligned chunk
// parsing (`ast::yaml_chunk`): the engine splits at column-0 `---` markers,
// parses each segment independently under the row ceiling, and translates
// every span back into full-file coordinates — which is what this test now
// proves at 100 MiB scale (byte-exact `id` spans, line-exact documents and
// `items`, continuous `document-N` numbering, no warnings, nothing skipped).
// =============================================================================

fn yaml_unit(i: usize) -> (String, Probe) {
    let unit = format!("---\nid: unit-{i}\nitems:\n  - x\n  - y\n");
    let probe = match i % 3 {
        0 => Probe::line_span(
            format!("document-{}", i + 1),
            format!("---\nid: unit-{i}\nitems:\n  - x\n  - y"),
            0,
        ),
        1 => Probe::byte("id", format!("id: unit-{i}"), 1).at(i),
        _ => Probe::line_span("items", "items:\n  - x\n  - y", 2).at(i),
    };
    (unit, probe)
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn yaml_100mib_byte_exact() {
    run_case(Language::Yaml, "large.yaml", "", "", yaml_unit, |units| {
        units * 3
    });
}

// =============================================================================
// toml — one `[unit-N]` table per unit (self-delimiting). The section's byte
// span INCLUDES its trailing newline (the table block runs to the next
// header), so the section probe body ends with `\n` on the byte path.
// =============================================================================

fn toml_unit(i: usize) -> (String, Probe) {
    let unit = format!("[unit-{i}]\nkey = \"v\"\npath = \"./assets/unit-{i}.svg\"\n");
    let probe = match i % 3 {
        0 => Probe::byte(
            format!("unit-{i}"),
            format!("[unit-{i}]\nkey = \"v\"\npath = \"./assets/unit-{i}.svg\"\n"),
            0,
        ),
        1 => Probe::byte("key", "key = \"v\"", 1).at(i),
        _ => Probe::byte("path", format!("path = \"./assets/unit-{i}.svg\""), 2).at(i),
    };
    (unit, probe)
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn toml_100mib_byte_exact() {
    run_case(Language::Toml, "large.toml", "", "", toml_unit, |units| {
        units * 3
    });
}

// =============================================================================
// xml — `item` elements with ids under one root; `element` kind, byte path.
// =============================================================================

fn xml_unit(i: usize) -> (String, Probe) {
    let unit = format!("<item id=\"unit-{i}\"><sub>x</sub></item>\n");
    let probe = match i % 2 {
        0 => Probe::byte(
            format!("item#unit-{i}"),
            format!("<item id=\"unit-{i}\"><sub>x</sub></item>"),
            0,
        ),
        _ => Probe::byte("sub", "<sub>x</sub>", 0).at(i),
    };
    (unit, probe)
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn xml_100mib_byte_exact() {
    run_case(
        Language::Xml,
        "large.xml",
        "<root>\n",
        "</root>\n",
        xml_unit,
        |units| units * 2,
    );
}

// =============================================================================
// html — `section` elements with ids (fragment, no wrapper needed).
// =============================================================================

fn html_unit(i: usize) -> (String, Probe) {
    let unit = format!("<section id=\"unit-{i}\"><p>x</p></section>\n");
    let probe = match i % 2 {
        0 => Probe::byte(
            format!("section#unit-{i}"),
            format!("<section id=\"unit-{i}\"><p>x</p></section>"),
            0,
        ),
        _ => Probe::byte("p", "<p>x</p>", 0).at(i),
    };
    (unit, probe)
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn html_100mib_byte_exact() {
    run_case(Language::Html, "large.html", "", "", html_unit, |units| {
        units * 2
    });
}

// =============================================================================
// css — one rule per unit; every 10th unit adds an @media block whose inner
// rule is its own nested selector. All three kinds on the byte path; the
// generic `@media` name is disambiguated by occurrence.
// =============================================================================

const MEDIA_EVERY: usize = 10;

fn css_unit(i: usize) -> (String, Probe) {
    let mut unit = format!(".unit-{i} {{ color: red; background: url(img/unit-{i}.png); }}\n");
    if i % MEDIA_EVERY == 0 {
        unit.push_str(&format!(
            "@media (min-width: 1px) {{ .inner-{i} {{ color: blue }} }}\n"
        ));
    }
    let probe = if i % MEDIA_EVERY != 0 {
        Probe::byte(
            format!(".unit-{i}"),
            format!(".unit-{i} {{ color: red; background: url(img/unit-{i}.png); }}"),
            0,
        )
    } else if (i / MEDIA_EVERY) % 2 == 0 {
        Probe::byte(
            "@media",
            format!("@media (min-width: 1px) {{ .inner-{i} {{ color: blue }} }}"),
            1,
        )
        .at(i / MEDIA_EVERY)
    } else {
        Probe::byte(
            format!(".inner-{i}"),
            format!(".inner-{i} {{ color: blue }}"),
            1,
        )
    };
    (unit, probe)
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn css_100mib_byte_exact() {
    run_case(Language::Css, "large.css", "", "", css_unit, |units| units);
}

// =============================================================================
// bash — one function per unit (`function` kind through the element engine,
// byte path).
// =============================================================================

fn bash_unit(i: usize) -> (String, Probe) {
    let body = format!("unit-{i}() {{ echo \"{i}\"; }}");
    (
        format!("{body}\n"),
        Probe::byte(format!("unit-{i}"), body, 0),
    )
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn bash_100mib_byte_exact() {
    run_case(Language::Bash, "large.sh", "", "", bash_unit, |units| units);
}

// =============================================================================
// latex — the section node is CONTENT-SPANNING (it nests everything up to the
// next equal-level sectioning command), so its probe body is the whole unit
// less one trailing newline — verified on the LINE path, which is EOF-stable
// for the last section. The environment is probed on the byte path.
// =============================================================================

fn latex_unit(i: usize) -> (String, Probe) {
    let unit =
        format!("\\section{{Unit {i}}}\nbody text\n\\begin{{itemize}}\\item a\n\\end{{itemize}}\n");
    let probe = match i % 2 {
        0 => Probe::line_span(
            format!("Unit {i}"),
            format!(
                "\\section{{Unit {i}}}\nbody text\n\\begin{{itemize}}\\item a\n\\end{{itemize}}"
            ),
            0,
        ),
        _ => Probe::byte("itemize", "\\begin{itemize}\\item a\n\\end{itemize}", 2).at(i),
    };
    (unit, probe)
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn latex_100mib_byte_exact() {
    run_case(Language::Latex, "large.tex", "", "", latex_unit, |units| {
        units * 2
    });
}

// =============================================================================
// markdown — heading + fenced code block + pipe table per unit. All three
// kinds on the byte path; their node bytes END with the line/block newline,
// so the probe bodies carry the trailing `\n`. Generic names (`rust`,
// `A | B`) are disambiguated by occurrence.
// =============================================================================

fn markdown_unit(i: usize) -> (String, Probe) {
    let unit = format!(
        "## Unit {i}\n\nparagraph text\n\n```rust\nfn n() {{}}\n```\n\n| A | B |\n|---|---|\n| 1 | 2 |\n"
    );
    let probe = match i % 3 {
        0 => Probe::byte(format!("Unit {i}"), format!("## Unit {i}\n"), 0),
        1 => Probe::byte("rust", "```rust\nfn n() {}\n```\n", 4).at(i),
        _ => Probe::byte("A | B", "| A | B |\n|---|---|\n| 1 | 2 |\n", 8).at(i),
    };
    (unit, probe)
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn markdown_100mib_byte_exact() {
    run_case(
        Language::Markdown,
        "large.md",
        "",
        "",
        markdown_unit,
        |units| units * 3,
    );
}

// =============================================================================
// csv/tsv — ~2.3 MB records: a header prefix (its record + cells are the only
// `cell` definitions), an embedded-newline record first, then wide quoted
// records whose long field is packed with delimiters. Byte path throughout —
// the record span spans its embedded line break and excludes only the
// terminating newline. `UNANCHORED_LINE` marks the prefix-anchored probes.
// =============================================================================

/// Tokens packed into each record's long quoted field (~2.3 MB with seps).
const WIDE_TOKENS: usize = 200_000;

fn wide_record(i: usize, delim: char) -> String {
    let mut wide = String::with_capacity(WIDE_TOKENS * 12);
    for k in 0..WIDE_TOKENS {
        if k > 0 {
            wide.push(delim);
        }
        let _ = write!(wide, "w{i}c{k}");
    }
    format!("unit-{i}{delim}\"{wide}\"{delim}extra-{i}{delim}end\n")
}

/// The embedded-newline record: the record span must include the line break
/// INSIDE the quoted field (the quote opens AT field start, right after the
/// delimiter — a quote mid-field is content under the scanner's documented
/// leniency, which is why the delimiter matters here).
fn embed_record(delim: char) -> String {
    format!("unit-embed{delim}\"line one\nline two\"{delim}tail-embed{delim}end")
}

fn csv_unit(i: usize) -> (String, Probe) {
    if i == 0 {
        let body = embed_record(',');
        (format!("{body}\n"), Probe::byte("unit-embed", body, 0))
    } else if i == 1 {
        // Probe the PREFIX header record (record kind).
        (
            wide_record(i, ','),
            Probe::byte("id", "id,wide,extra,tail", UNANCHORED_LINE),
        )
    } else if i == 2 {
        // Probe a PREFIX header cell (cell kind — first record's fields only).
        (
            wide_record(i, ','),
            Probe::byte("wide", "wide", UNANCHORED_LINE),
        )
    } else {
        let record = wide_record(i, ',');
        let body = record.trim_end_matches('\n').to_string();
        (record, Probe::byte(format!("unit-{i}"), body, 0))
    }
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn csv_100mib_byte_exact() {
    run_case(
        Language::Csv,
        "large.csv",
        "id,wide,extra,tail\n",
        "",
        csv_unit,
        |units| units + 5,
    );
}

fn tsv_unit(i: usize) -> (String, Probe) {
    if i == 0 {
        let body = embed_record('\t');
        (format!("{body}\n"), Probe::byte("unit-embed", body, 0))
    } else if i == 1 {
        (
            wide_record(i, '\t'),
            Probe::byte("id", "id\twide\textra\ttail", UNANCHORED_LINE),
        )
    } else if i == 2 {
        (
            wide_record(i, '\t'),
            Probe::byte("wide", "wide", UNANCHORED_LINE),
        )
    } else {
        let record = wide_record(i, '\t');
        let body = record.trim_end_matches('\n').to_string();
        (record, Probe::byte(format!("unit-{i}"), body, 0))
    }
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn tsv_100mib_byte_exact() {
    run_case(
        Language::Tsv,
        "large.tsv",
        "id\twide\textra\ttail\n",
        "",
        tsv_unit,
        |units| units + 5,
    );
}

// =============================================================================
// log — native streamed scanner: one timestamp-led INFO entry per unit; every
// 20th unit carries a 3-line stack-trace continuation block that must attach
// to the entry (4-line body, byte span and line span agree). Both span paths
// are exercised; the size-policy assert in `verify_fixture` proves `.log` is
// uncapped (u64::MAX) at 100 MiB.
// =============================================================================

const LOG_CONT_EVERY: usize = 20;

fn log_unit(i: usize) -> (String, Probe) {
    let entry = format!("2026-09-14T08:00:00Z INFO unit-{i} service ok");
    if i % LOG_CONT_EVERY == 0 {
        let continuation = format!(
            "\tat com.example.Service.run(Service.java:{i})\nCaused by: wrapped unit-{i}\n\tat com.example.Service.check(Service.java:{i})"
        );
        let body = format!("{entry}\n{continuation}");
        let probe = Probe {
            byte_span: (i / LOG_CONT_EVERY) % 2 == 0,
            ..Probe::byte("info", body.clone(), 0).at(i)
        };
        (format!("{body}\n"), probe)
    } else {
        let probe = Probe {
            byte_span: i % 2 == 0,
            ..Probe::byte("info", entry.clone(), 0).at(i)
        };
        (format!("{entry}\n"), probe)
    }
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn log_100mib_byte_exact() {
    run_case(Language::Log, "large.log", "", "", log_unit, |units| units);
}

// =============================================================================
// text — native TOC scanner: numbered-outline headings (the `N.M` prefix is
// part of the name) alternating with prose that must emit nothing. Both span
// paths exercised (identical bodies — the heading span is one line).
// =============================================================================

fn text_unit(i: usize) -> (String, Probe) {
    let heading = format!("{i}.1 Heading unit-{i}");
    let prose = format!("prose paragraph unit-{i} with ordinary words.");
    let probe = Probe {
        byte_span: i % 2 == 0,
        ..Probe::byte(heading.clone(), heading.clone(), 0)
    };
    (format!("{heading}\n{prose}\n"), probe)
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn text_100mib_byte_exact() {
    run_case(Language::Text, "large.txt", "", "", text_unit, |units| {
        units
    });
}

// =============================================================================
// Code tranche — 18 languages × ~100 MiB, ~60 units of ~1.8 MB each (see the
// "# Code tranche" module docs for the three load-bearing shapes: low unit
// counts vs the call graph's O(functions × tree nodes) walk, single-string-
// token bodies with no call expressions, and the row/column ceilings).
//
// Fidelity at scale: every 10th unit carries decorator / attribute /
// annotation / doc-comment trivia ABOVE the declaration and the probe body
// STARTS at that trivia line (symbol_fidelity_v1 semantics at 100 MiB).
// Bodies deliberately avoid call expressions — string literals and plain
// identifiers only — so the intra-file call graph has no edges and the
// per-function whole-tree walk has nothing to do but terminate.
// =============================================================================

/// One content chunk (~77 bytes); repeated to build a body line.
const CODE_CHUNK: &str =
    "0123456789abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ unit payload ";
/// Repeats per content line → ~29 KB lines (comfortably below every scanner
/// column ceiling, including int16-class ones).
const CODE_CHUNK_REPEATS: usize = 380;
/// Content lines per unit body → ~1.8 MB units → ~60 units per 100 MiB file.
const CODE_BODY_LINES: usize = 62;
/// Fidelity trivia rides every 10th unit.
const CODE_TRIVIA_EVERY: usize = 10;
/// Probe stride for the code cases: a ~60-unit file needs a tighter stride
/// than the format tests' [`KEEP_STRIDE`] for mid-file probes to exist.
const CODE_KEEP_STRIDE: usize = 12;

/// The ~1.8 MB body block shared by every code-language unit: 62 identical
/// content lines. Identical across units ON PURPOSE — per-unit identity lives
/// in the declaration line, which each probe pins by absolute line number
/// before the body comparison runs.
fn code_body_block() -> String {
    let line = CODE_CHUNK.repeat(CODE_CHUNK_REPEATS);
    let mut s = String::with_capacity(CODE_BODY_LINES * (line.len() + 1));
    for _ in 0..CODE_BODY_LINES {
        s.push_str(&line);
        s.push('\n');
    }
    s
}

/// The line-span probe every code-language builder emits: the definition's
/// region (declaration + attached trivia above) is the WHOLE unit less one
/// trailing newline, starting on the unit's first line.
fn code_probe(name: impl Into<String>, unit: &str) -> Probe {
    Probe::line_span(name, unit.strip_suffix('\n').unwrap_or(unit).to_string(), 0)
}

/// One cheap sanity parse per code-language test: build THREE full-size units
/// with the real builder at indices 0, 5 and 10 — enough to cover every probe
/// flavour the builder emits (the fidelity cadence is every 10th unit) —
/// extract through the real entry point, and assert the suite invariants plus
/// byte exactness of every probe. A generator that does not parse, yields
/// fewer definitions than its floor, or disagrees with its own probes panics
/// HERE, on a ~5 MB fixture, instead of after a 100 MiB assembly.
fn sanity_parse_three_units(
    language: Language,
    filename: &str,
    prefix: &str,
    trailer: &str,
    unit_builder: &impl Fn(usize) -> (String, Probe),
    min_defs: &impl Fn(usize) -> usize,
) {
    let dir = tempfile::tempdir().expect("sanity tempdir");
    let mut source = String::new();
    source.push_str(prefix);
    let mut lines: u32 = source.matches('\n').count() as u32;
    let mut probes = Vec::new();
    for i in [0usize, 5, 10] {
        let (unit, mut probe) = unit_builder(i);
        assert!(unit.ends_with('\n'), "unit source must end with \\n");
        if probe.line != UNANCHORED_LINE {
            probe.line += lines + 1;
        }
        probes.push(probe);
        source.push_str(&unit);
        lines += unit.matches('\n').count() as u32;
    }
    source.push_str(trailer);
    std::fs::write(dir.path().join(filename), source.as_bytes()).expect("write sanity fixture");
    let fx = Fixture {
        path: dir.path().join(filename),
        _dir: dir,
        source,
        probes,
        min_defs: min_defs(3),
        units: 3,
    };
    let started = Instant::now();
    let verified = verify_fixture(&fx, language);
    for probe in &fx.probes {
        assert_byte_exact(&fx, &verified, probe);
    }
    println!(
        "{:>8}: sanity OK — 3 units, {} defs, {:?}",
        language_tag(language),
        verified.structure.files[0].definitions.len(),
        started.elapsed()
    );
}

/// Shared code-language test driver: the cheap sanity parse first, then the
/// full 100 MiB run with the code stride.
fn run_code_case(
    language: Language,
    filename: &str,
    prefix: &str,
    trailer: &str,
    unit_builder: impl Fn(usize) -> (String, Probe),
    min_defs: impl Fn(usize) -> usize,
) {
    sanity_parse_three_units(
        language,
        filename,
        prefix,
        trailer,
        &unit_builder,
        &min_defs,
    );
    run_case_with_stride(
        language,
        filename,
        prefix,
        trailer,
        unit_builder,
        min_defs,
        CODE_KEEP_STRIDE,
    );
}

// -----------------------------------------------------------------------------
// python — `def unit_N():` over a huge triple-quoted string. Every 10th def
// gets `@deco_N` above it; the probe body starts at the decorator line
// (tree-sitter-python climbs the `decorated_definition` wrapper).
// -----------------------------------------------------------------------------

fn python_unit(i: usize) -> (String, Probe) {
    let body = code_body_block();
    let head = if i % CODE_TRIVIA_EVERY == 0 {
        format!("@deco_{i}\n")
    } else {
        String::new()
    };
    let unit = format!("{head}def unit_{i}():\n    S = \"\"\"\n{body}\"\"\"\n    return S\n");
    (unit.clone(), code_probe(format!("unit_{i}"), &unit))
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn python_100mib_byte_exact() {
    run_code_case(Language::Python, "large.py", "", "", python_unit, |units| {
        units
    });
}

// -----------------------------------------------------------------------------
// rust — huge `pub fn` over a raw string; every 10th unit is a derived struct
// and every 20th (interleaved) fn carries `#[inline]`. Both attribute kinds
// are sibling `attribute_item`s that attach via the contiguous-sibling walk,
// so their probes include the attribute line.
// -----------------------------------------------------------------------------

fn rust_unit(i: usize) -> (String, Probe) {
    let body = code_body_block();
    let (head, decl) = if i % CODE_TRIVIA_EVERY == 0 {
        (
            String::from("#[derive(Clone)]\n"),
            format!("pub struct Unit{i} {{ a: u32 }}\n"),
        )
    } else if i % (2 * CODE_TRIVIA_EVERY) == CODE_TRIVIA_EVERY {
        (
            String::from("#[inline]\n"),
            format!("pub fn unit_{i}() {{\n    let s = r#\"\n{body}\"#;\n}}\n"),
        )
    } else {
        (
            String::new(),
            format!("pub fn unit_{i}() {{\n    let s = r#\"\n{body}\"#;\n}}\n"),
        )
    };
    let unit = format!("{head}{decl}");
    let name = if i % CODE_TRIVIA_EVERY == 0 {
        format!("Unit{i}")
    } else {
        format!("unit_{i}")
    };
    (unit.clone(), code_probe(name, &unit))
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn rust_100mib_byte_exact() {
    run_code_case(Language::Rust, "large.rs", "", "", rust_unit, |units| units);
}

// -----------------------------------------------------------------------------
// typescript — huge exported functions over a template literal; every 10th
// unit is a decorated exported class (`@dec` above `export` sits INSIDE the
// `export_statement` wrapper, so the probe starts at the decorator line).
// -----------------------------------------------------------------------------

fn typescript_unit(i: usize) -> (String, Probe) {
    let body = code_body_block();
    let (head, decl) = if i % CODE_TRIVIA_EVERY == 0 {
        (
            String::from("@dec\n"),
            format!("export class Unit{i} {{ a: number }}\n"),
        )
    } else {
        (
            String::new(),
            format!("export function unit_{i}() {{\n    let s = `\n{body}`;\n    return s;\n}}\n"),
        )
    };
    let unit = format!("{head}{decl}");
    let name = if i % CODE_TRIVIA_EVERY == 0 {
        format!("Unit{i}")
    } else {
        format!("unit_{i}")
    };
    (unit.clone(), code_probe(name, &unit))
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn typescript_100mib_byte_exact() {
    run_code_case(
        Language::TypeScript,
        "large.ts",
        "",
        "",
        typescript_unit,
        |units| units,
    );
}

// -----------------------------------------------------------------------------
// javascript — huge exported functions; every 10th carries a JSDoc block
// above (attached sibling comment — the probe includes it).
// -----------------------------------------------------------------------------

fn javascript_unit(i: usize) -> (String, Probe) {
    let body = code_body_block();
    let head = if i % CODE_TRIVIA_EVERY == 0 {
        format!("/** jsdoc for unit_{i} */\n")
    } else {
        String::new()
    };
    let unit = format!(
        "{head}export function unit_{i}() {{\n    let s = `\n{body}`;\n    return s;\n}}\n"
    );
    (unit.clone(), code_probe(format!("unit_{i}"), &unit))
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn javascript_100mib_byte_exact() {
    run_code_case(
        Language::JavaScript,
        "large.js",
        "",
        "",
        javascript_unit,
        |units| units,
    );
}

// -----------------------------------------------------------------------------
// java — one class of static methods; every 10th method carries a javadoc
// comment AND `@Override` above it (annotations live INSIDE the declaration
// node via `modifiers`, the javadoc is an attached sibling — the probe
// includes both lines). The body is a text block.
// -----------------------------------------------------------------------------

fn java_unit(i: usize) -> (String, Probe) {
    let body = code_body_block();
    let head = if i % CODE_TRIVIA_EVERY == 0 {
        format!("    /** doc for unit_{i} */\n    @Override\n")
    } else {
        String::new()
    };
    let unit = format!(
        "{head}    public static void unit_{i}() {{\n        String s = \"\"\"\n{body}        \"\"\";\n    }}\n"
    );
    (unit.clone(), code_probe(format!("unit_{i}"), &unit))
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn java_100mib_byte_exact() {
    run_code_case(
        Language::Java,
        "large.java",
        "public class Big {\n",
        "}\n",
        java_unit,
        |units| units + 1, // + the wrapping class
    );
}

// -----------------------------------------------------------------------------
// go — huge functions over a raw (backtick) string; every 10th carries a doc
// comment above (attached sibling — the probe includes it).
// -----------------------------------------------------------------------------

fn go_unit(i: usize) -> (String, Probe) {
    let body = code_body_block();
    let head = if i % CODE_TRIVIA_EVERY == 0 {
        format!("// doc for unit_{i}\n")
    } else {
        String::new()
    };
    let unit = format!("{head}func unit_{i}() {{\n\ts := `\n{body}`\n\t_ = s\n}}\n");
    (unit.clone(), code_probe(format!("unit_{i}"), &unit))
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn go_100mib_byte_exact() {
    run_code_case(Language::Go, "large.go", "", "", go_unit, |units| units);
}

// -----------------------------------------------------------------------------
// ruby — huge methods over a multi-line double-quoted string; every 10th
// carries a `#` comment above (the probe includes it).
// -----------------------------------------------------------------------------

fn ruby_unit(i: usize) -> (String, Probe) {
    let body = code_body_block();
    let head = if i % CODE_TRIVIA_EVERY == 0 {
        format!("# doc for unit_{i}\n")
    } else {
        String::new()
    };
    let unit = format!("{head}def unit_{i}\n  s = \"\n{body}\"\n  s\nend\n");
    (unit.clone(), code_probe(format!("unit_{i}"), &unit))
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn ruby_100mib_byte_exact() {
    run_code_case(Language::Ruby, "large.rb", "", "", ruby_unit, |units| units);
}

// -----------------------------------------------------------------------------
// lua / luau — huge functions over a `[[` long-bracket string; every 10th
// carries a `--` comment above (the probe includes it).
// -----------------------------------------------------------------------------

fn lua_unit(i: usize) -> (String, Probe) {
    let body = code_body_block();
    let head = if i % CODE_TRIVIA_EVERY == 0 {
        format!("-- doc for unit_{i}\n")
    } else {
        String::new()
    };
    let unit = format!("{head}function unit_{i}()\n\tlocal s = [[\n{body}]]\n\treturn s\nend\n");
    (unit.clone(), code_probe(format!("unit_{i}"), &unit))
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn lua_100mib_byte_exact() {
    run_code_case(Language::Lua, "large.lua", "", "", lua_unit, |units| units);
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn luau_100mib_byte_exact() {
    run_code_case(Language::Luau, "large.luau", "", "", lua_unit, |units| {
        units
    });
}

// -----------------------------------------------------------------------------
// kotlin — huge functions over a raw triple-quoted string; every 10th carries
// a KDoc block above (attached sibling comment — the probe includes it).
// -----------------------------------------------------------------------------

fn kotlin_unit(i: usize) -> (String, Probe) {
    let body = code_body_block();
    let head = if i % CODE_TRIVIA_EVERY == 0 {
        format!("/** doc for unit_{i} */\n")
    } else {
        String::new()
    };
    let unit = format!("{head}fun unit_{i}() {{\n    val s = \"\"\"\n{body}\"\"\"\n}}\n");
    (unit.clone(), code_probe(format!("unit_{i}"), &unit))
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn kotlin_100mib_byte_exact() {
    run_code_case(Language::Kotlin, "large.kt", "", "", kotlin_unit, |units| {
        units
    });
}

// -----------------------------------------------------------------------------
// swift — huge functions over a multi-line `"""` string; every 10th carries a
// `///` doc comment above (attached sibling — the probe includes it).
// -----------------------------------------------------------------------------

fn swift_unit(i: usize) -> (String, Probe) {
    let body = code_body_block();
    let head = if i % CODE_TRIVIA_EVERY == 0 {
        format!("/// doc for unit_{i}\n")
    } else {
        String::new()
    };
    let unit = format!("{head}func unit_{i}() {{\n    let s = \"\"\"\n{body}\"\"\"\n}}\n");
    (unit.clone(), code_probe(format!("unit_{i}"), &unit))
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn swift_100mib_byte_exact() {
    run_code_case(
        Language::Swift,
        "large.swift",
        "",
        "",
        swift_unit,
        |units| units,
    );
}

// -----------------------------------------------------------------------------
// c# — static methods inside one class (methods need a type scope), bodies in
// a verbatim `@"…"` string; every 10th carries a `///` doc comment above (the
// probe includes it).
// -----------------------------------------------------------------------------

fn csharp_unit(i: usize) -> (String, Probe) {
    let body = code_body_block();
    let head = if i % CODE_TRIVIA_EVERY == 0 {
        format!("    /// <doc>unit_{i}</doc>\n")
    } else {
        String::new()
    };
    let unit = format!(
        "{head}    public static void unit_{i}()\n    {{\n        var s = @\"\n{body}\";\n    }}\n"
    );
    (unit.clone(), code_probe(format!("unit_{i}"), &unit))
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn csharp_100mib_byte_exact() {
    run_code_case(
        Language::CSharp,
        "large.cs",
        "public class Big {\n",
        "}\n",
        csharp_unit,
        |units| units + 1, // + the wrapping class
    );
}

// -----------------------------------------------------------------------------
// scala — huge defs over a triple-quoted string; every 10th carries a scaladoc
// block above (attached sibling comment — the probe includes it).
// -----------------------------------------------------------------------------

fn scala_unit(i: usize) -> (String, Probe) {
    let body = code_body_block();
    let head = if i % CODE_TRIVIA_EVERY == 0 {
        format!("/** doc for unit_{i} */\n")
    } else {
        String::new()
    };
    let unit = format!("{head}def unit_{i}(): Unit = {{\n    val s = \"\"\"\n{body}\"\"\"\n}}\n");
    (unit.clone(), code_probe(format!("unit_{i}"), &unit))
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn scala_100mib_byte_exact() {
    run_code_case(
        Language::Scala,
        "large.scala",
        "",
        "",
        scala_unit,
        |units| units,
    );
}

// -----------------------------------------------------------------------------
// php — huge functions over a heredoc; every 10th carries a docblock above
// (attached sibling comment — the probe includes it).
// -----------------------------------------------------------------------------

fn php_unit(i: usize) -> (String, Probe) {
    let body = code_body_block();
    let head = if i % CODE_TRIVIA_EVERY == 0 {
        format!("/** doc for unit_{i} */\n")
    } else {
        String::new()
    };
    let unit = format!("{head}function unit_{i}()\n{{\n    $s = <<<EOT\n{body}EOT;\n}}\n");
    (unit.clone(), code_probe(format!("unit_{i}"), &unit))
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn php_100mib_byte_exact() {
    run_code_case(
        Language::Php,
        "large.php",
        "<?php\n",
        "",
        php_unit,
        |units| units,
    );
}

// -----------------------------------------------------------------------------
// c / cpp — huge functions whose body strings are chains of adjacent literals
// (C strings cannot span lines); cpp's every 10th function carries a `///`
// doc comment above (attached sibling — the probe includes it).
// -----------------------------------------------------------------------------

/// Turn the body block into a chain of adjacent string literals, one physical
/// line each — C string literals concatenate, so this is one initialiser.
fn c_string_chain(body: &str) -> String {
    body.lines().map(|l| format!("        \"{l}\"\n")).collect()
}

fn c_unit(i: usize) -> (String, Probe) {
    let body = code_body_block();
    let chain = c_string_chain(&body);
    let unit =
        format!("void unit_{i}(void)\n{{\n    const char *s =\n{chain}    ;\n    (void)s;\n}}\n");
    (unit.clone(), code_probe(format!("unit_{i}"), &unit))
}

fn cpp_unit(i: usize) -> (String, Probe) {
    let body = code_body_block();
    let chain = c_string_chain(&body);
    let head = if i % CODE_TRIVIA_EVERY == 0 {
        format!("/// doc for unit_{i}\n")
    } else {
        String::new()
    };
    let unit =
        format!("{head}void unit_{i}()\n{{\n    const char *s =\n{chain}    ;\n    (void)s;\n}}\n");
    (unit.clone(), code_probe(format!("unit_{i}"), &unit))
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn c_100mib_byte_exact() {
    run_code_case(Language::C, "large.c", "", "", c_unit, |units| units);
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn cpp_100mib_byte_exact() {
    run_code_case(Language::Cpp, "large.cpp", "", "", cpp_unit, |units| units);
}

// -----------------------------------------------------------------------------
// elixir — defs inside one module, bodies in `"""` heredocs; every 10th def
// carries `@doc "…"` above it (the attached-trivia special case in
// `sibling_is_attached_trivia` — the probe includes the @doc line).
// -----------------------------------------------------------------------------

fn elixir_unit(i: usize) -> (String, Probe) {
    let body = code_body_block();
    let head = if i % CODE_TRIVIA_EVERY == 0 {
        format!("  @doc \"doc for unit_{i}\"\n")
    } else {
        String::new()
    };
    let unit = format!("{head}  def unit_{i} do\n    s = \"\"\"\n{body}\"\"\"\n    s\n  end\n");
    (unit.clone(), code_probe(format!("unit_{i}"), &unit))
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn elixir_100mib_byte_exact() {
    run_code_case(
        Language::Elixir,
        "large.ex",
        "defmodule Big do\n",
        "end\n",
        elixir_unit,
        |units| units, // the wrapping defmodule is extra
    );
}

// -----------------------------------------------------------------------------
// ocaml — top-level `let unit_N = "…"` over a multi-line string; every 10th
// carries a `(* … *)` comment above (attached sibling — the probe includes
// it).
// -----------------------------------------------------------------------------

fn ocaml_unit(i: usize) -> (String, Probe) {
    let body = code_body_block();
    let head = if i % CODE_TRIVIA_EVERY == 0 {
        format!("(* doc for unit_{i} *)\n")
    } else {
        String::new()
    };
    let unit = format!("{head}let unit_{i} = \"\n{body}\"\n");
    (unit.clone(), code_probe(format!("unit_{i}"), &unit))
}

#[test]
#[ignore = "100 MiB release e2e — see the module docs for the opt-in command"]
fn ocaml_100mib_byte_exact() {
    run_code_case(Language::Ocaml, "large.ml", "", "", ocaml_unit, |units| {
        units
    });
}
