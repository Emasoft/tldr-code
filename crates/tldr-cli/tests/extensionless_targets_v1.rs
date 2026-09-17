//! extensionless-targets-v1 — extensionless text files are first-class tldr
//! targets, end to end.
//!
//! Pins the content sniffer's user-visible contract across the four surfaces
//! a single-file target flows through:
//!
//! 1. `tldr structure LICENSE` — an extensionless prose file resolves to
//!    language "text" via the sniffer (no shebang, no XML declaration →
//!    Text) and reports the TOC headings the `ast::toc` scanner finds.
//! 2. `tldr structure` / `tldr imports` on a Makefile — Text TOC heading
//!    (`# Variables` comment is an ATX heading) plus the path scanner's
//!    reference for `config/other.mk`.
//! 3. `tldr imports <root>/.bashrc` — a shebang-sniffed Bash target whose
//!    `source ./lib/env.sh` line is the import edge (language "bash").
//! 4. `tldr impact <root>/lib/env.sh` — the sniffed extensionless target
//!    takes the document-link path and its callers include the sniffed
//!    `.bashrc`: sniffed files JOIN the doc graph (the directory walk probes
//!    extensionless files, hidden files included).
//! 5. `tldr structure` / `tldr imports` on `data.bin` — NUL-carrying content
//!    is a clean structured error ("binary" wording, UnsupportedLanguage
//!    exit code 11), not a Python mislabel.
//! 6. `tldr structure <root>/sitemap` — `<?xml`-prefixed extensionless
//!    content resolves to Xml and reports element definitions.
//! 7. `tldr structure` / `tldr imports` on `notes.xyz` — unknown-ext-text-v1:
//!    a text file under an unknown extension resolves to Text (TOC scan),
//!    superseding the old unsupported verdict.
//! 8. `tldr structure` on `schema.sql` — the same unknown-ext rule applied to
//!    the motivating case: `.sql` is in no extension bucket, so the file
//!    resolves to Text in an isolated dir AND beside a `lib.rs` (the parent's
//!    dominant Rust must not mislabel it). Directory scans stay
//!    extension-list-driven and never pick the file up.
//!
//! Fixture (one tempdir): `package.json` (project marker for the impact
//! doc-root + a Json doc-language file with no references), `LICENSE`
//! (prose: an ALL-CAPS heading, a bare URL, a `./docs/x.md` path),
//! `Makefile` (ATX comment heading + `include config/other.mk`),
//! `.bashrc` (shebang + `source ./lib/env.sh`), `lib/env.sh` (prose, no
//! shebang), `sitemap` (`<?xml` + elements), `data.bin` (NUL bytes) and a
//! `.xyz` text file pinning the unknown-extension Text resolution. The
//! `.sql` probes build their own tempdirs (isolated / beside-`lib.rs`). No
//! daemon is started; every command takes the direct-compute path.

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn write(p: impl AsRef<Path>, body: &str) {
    let p = p.as_ref();
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).expect("mkdir -p");
    }
    fs::write(p, body).expect("write fixture");
}

/// All fixtures live in one tempdir; the `package.json` marker resolves the
/// impact doc-root to the tempdir root (same pattern as the doclinks config
/// fixture).
fn build_extensionless_project() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    // Project marker (and a Json doc-language file that emits no references).
    write(root.join("package.json"), "{\"name\": \"extless-probe\"}\n");

    // Prose with a URL and a project-relative path — sniffed Text.
    write(
        root.join("LICENSE"),
        concat!(
            "PROJECT LICENSE\n",
            "\n",
            "Copyright (c) 2026 Example Corp\n",
            "\n",
            "Full text at https://example.com/license.txt\n",
            "See also ./docs/x.md for usage notes.\n",
        ),
    );

    // Makefile: `# Variables` is an ATX heading for the TOC scanner;
    // `include config/other.mk` is a path-shaped token for the reference
    // scanner (contains `/` AND a dotted last segment — the scanner's rule).
    write(
        root.join("Makefile"),
        concat!(
            "# Variables\n",
            "CC = gcc\n",
            "\n",
            "build: main.o\n",
            "\tgcc -o app main.o\n",
            "\n",
            "include config/other.mk\n",
        ),
    );

    // Hidden extensionless shell file: shebang → Bash, `source` → doc edge.
    write(root.join(".bashrc"), "#!/bin/bash\nsource ./lib/env.sh\n");

    // Extensionless prose target, no shebang → Text.
    write(root.join("lib/env.sh"), "export TLDR_EDITOR=vim\n");

    // XML-declared extensionless content → Xml.
    write(
        root.join("sitemap"),
        "<?xml version=\"1.0\"?>\n<urlset>\n  <url><loc>https://example.com/</loc></url>\n</urlset>\n",
    );

    // Binary: NUL bytes in the first bytes of the file.
    write(
        root.join("data.bin"),
        "\u{0}\u{1}\u{2}\u{3}raw binary payload",
    );

    // The unknown-extension probe: text content under an extension the
    // extension map does not know — resolves to Text (unknown-ext-text-v1).
    write(root.join("notes.xyz"), "plain prose\n");

    dir
}

fn parse(stdout: &[u8]) -> Value {
    serde_json::from_slice(stdout).expect("valid JSON on stdout")
}

// =============================================================================
// structure: LICENSE resolves to Text with TOC headings
// =============================================================================

#[test]
fn structure_on_extensionless_license_reports_text_with_toc() {
    let dir = build_extensionless_project();
    let root = dir.path();

    let output = tldr_cmd()
        .arg("structure")
        .arg(root.join("LICENSE"))
        .assert()
        .success();
    let json = parse(&output.get_output().stdout);

    assert_eq!(
        json["language"], "text",
        "the sniffer must resolve LICENSE to Text, got {json}"
    );
    let defs = json["files"][0]["definitions"]
        .as_array()
        .expect("definitions array");
    assert!(
        defs.iter()
            .any(|d| d["kind"] == "heading" && d["name"] == "PROJECT LICENSE"),
        "ALL-CAPS heading must surface: {defs:?}"
    );
}

// =============================================================================
// structure + imports: Makefile (Text TOC heading + path reference)
// =============================================================================

#[test]
fn structure_on_makefile_reports_text_with_heading() {
    let dir = build_extensionless_project();
    let root = dir.path();

    let output = tldr_cmd()
        .arg("structure")
        .arg(root.join("Makefile"))
        .assert()
        .success();
    let json = parse(&output.get_output().stdout);

    assert_eq!(json["language"], "text", "got {json}");
    let defs = json["files"][0]["definitions"].as_array().unwrap();
    assert!(
        defs.iter()
            .any(|d| d["kind"] == "heading" && d["name"] == "Variables"),
        "`# Variables` comment must be an ATX heading: {defs:?}"
    );
}

#[test]
fn imports_on_makefile_finds_the_path_reference() {
    let dir = build_extensionless_project();
    let root = dir.path();

    let output = tldr_cmd()
        .arg("imports")
        .arg(root.join("Makefile"))
        .assert()
        .success();
    let json = parse(&output.get_output().stdout);

    assert_eq!(json["language"], "text", "got {json}");
    let imports = json["imports"].as_array().unwrap();
    assert!(
        imports
            .iter()
            .any(|i| i["module"] == "config/other.mk" && i["alias"] == "path"),
        "the path scanner must surface the included file: {imports:?}"
    );
}

// =============================================================================
// imports: .bashrc is shebang-sniffed Bash and shows the source edge
// =============================================================================

#[test]
fn imports_on_bashrc_reports_bash_with_source_edge() {
    let dir = build_extensionless_project();
    let root = dir.path();

    let output = tldr_cmd()
        .arg("imports")
        .arg(root.join(".bashrc"))
        .assert()
        .success();
    let json = parse(&output.get_output().stdout);

    assert_eq!(
        json["language"], "bash",
        "shebang sniffing must resolve .bashrc to Bash, got {json}"
    );
    let imports = json["imports"].as_array().unwrap();
    assert!(
        imports
            .iter()
            .any(|i| i["module"] == "./lib/env.sh" && i["alias"] == "source"),
        "the `source` edge must be an import: {imports:?}"
    );
}

// =============================================================================
// impact: the sniffed extensionless target joins the doc graph
// =============================================================================

#[test]
fn impact_on_extensionless_target_finds_sniffed_bashrc() {
    let dir = build_extensionless_project();
    let root = dir.path();

    // Single-argument invocation: the doc path occupies the FUNCTION slot.
    let output = tldr_cmd()
        .current_dir(root)
        .arg("impact")
        .arg(root.join("lib/env.sh"))
        .assert()
        .success();
    let json = parse(&output.get_output().stdout);

    assert_eq!(
        json["total_targets"], 1,
        "document impact is a single-target report: {json}"
    );
    let (key, tree) = json["targets"]
        .as_object()
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    assert!(key.ends_with("lib/env.sh:<doc>"), "key = {key}");
    assert_eq!(tree["note"], "discovered via document link");
    let callers = tree["callers"].as_array().unwrap();
    assert_eq!(
        callers.len(),
        1,
        "the sniffed .bashrc must be the only caller: {callers:?}"
    );
    assert!(
        callers[0]["file"].as_str().unwrap().ends_with(".bashrc"),
        "caller = {}",
        callers[0]["file"]
    );
}

// =============================================================================
// binary rejection: clean structured error, not a mislabel
// =============================================================================

#[test]
fn structure_on_binary_file_is_clean_structured_error() {
    let dir = build_extensionless_project();
    let root = dir.path();

    let output = tldr_cmd()
        .arg("structure")
        .arg(root.join("data.bin"))
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    let code = output.get_output().status.code().expect("exit code");

    assert!(
        stderr.to_lowercase().contains("binary"),
        "error must name the binary verdict: {stderr}"
    );
    assert_eq!(
        code, 11,
        "UnsupportedLanguage exit code for a binary target, got {code}: {stderr}"
    );
}

#[test]
fn imports_on_binary_file_is_clean_structured_error() {
    let dir = build_extensionless_project();
    let root = dir.path();

    let output = tldr_cmd()
        .arg("imports")
        .arg(root.join("data.bin"))
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    let code = output.get_output().status.code().expect("exit code");

    assert!(
        stderr.to_lowercase().contains("binary"),
        "error must name the binary verdict: {stderr}"
    );
    assert_eq!(code, 11, "got {code}: {stderr}");
}

// =============================================================================
// xml ladder: `<?xml` extensionless content reports xml elements
// =============================================================================

#[test]
fn structure_on_xml_content_extensionless_file_reports_xml_elements() {
    let dir = build_extensionless_project();
    let root = dir.path();

    let output = tldr_cmd()
        .arg("structure")
        .arg(root.join("sitemap"))
        .assert()
        .success();
    let json = parse(&output.get_output().stdout);

    assert_eq!(
        json["language"], "xml",
        "`<?xml` sniffing must resolve to Xml, got {json}"
    );
    let defs = json["files"][0]["definitions"].as_array().unwrap();
    assert!(
        defs.iter()
            .any(|d| d["kind"] == "element" && d["name"] == "urlset"),
        "xml elements must surface: {defs:?}"
    );
}

// =============================================================================
// the unknown-extension flip: an existing text file under an unknown
// extension resolves to Text (unknown-ext-text-v1)
// =============================================================================

#[test]
fn unknown_extension_text_resolves_to_text() {
    let dir = build_extensionless_project();
    let root = dir.path();

    let output = tldr_cmd()
        .arg("structure")
        .arg(root.join("notes.xyz"))
        .assert()
        .success();
    let json = parse(&output.get_output().stdout);

    assert_eq!(
        json["language"], "text",
        "an existing unknown-extension TEXT file is a text target: {json}"
    );
    // "plain prose" is not heading-shaped, so the TOC scan yields nothing —
    // the point is the RESOLUTION (previously a hard unsupported error).
    let defs = json["files"][0]["definitions"].as_array().unwrap();
    assert!(defs.is_empty(), "no heading-shaped lines: {defs:?}");

    // imports takes the same Text resolution and the Text path scanner.
    let output = tldr_cmd()
        .arg("imports")
        .arg(root.join("notes.xyz"))
        .assert()
        .success();
    let json = parse(&output.get_output().stdout);
    assert_eq!(json["language"], "text", "got {json}");
}

// =============================================================================
// unknown-ext-text-v1: `.sql` — the motivating case. `.sql` is in no
// extension bucket, so the OLD behavior resolved it Ok(None) and the
// structure command fell through to the PARENT DIRECTORY's dominant language
// (`schema.sql` beside a `lib.rs` reported "rust"). The new Text resolution
// must hold both in an isolated directory (nothing to mislabel from) and
// next to a code file (the parent must NOT win). Directory SCANS are
// unchanged: they key on the extension lists, which do not contain `.sql`.
// =============================================================================

const SQL_FIXTURE: &str = concat!(
    "-- users table\n",
    "CREATE TABLE users (\n",
    "    id INTEGER PRIMARY KEY,\n",
    "    name TEXT NOT NULL\n",
    ");\n",
);

#[test]
fn unknown_extension_sql_isolated_dir_is_text() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root.join("schema.sql"), SQL_FIXTURE);

    let output = tldr_cmd()
        .arg("structure")
        .arg(root.join("schema.sql"))
        .assert()
        .success();
    let json = parse(&output.get_output().stdout);

    assert_eq!(
        json["language"], "text",
        "an isolated .sql file is a text target, not a fallback: {json}"
    );
    // imports takes the same resolution.
    let output = tldr_cmd()
        .arg("imports")
        .arg(root.join("schema.sql"))
        .assert()
        .success();
    let json = parse(&output.get_output().stdout);
    assert_eq!(json["language"], "text", "got {json}");
}

#[test]
fn unknown_extension_sql_beside_lib_rs_is_text_not_parent_language() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root.join("lib.rs"), "pub fn run() {}\n");
    write(root.join("schema.sql"), SQL_FIXTURE);

    let output = tldr_cmd()
        .arg("structure")
        .arg(root.join("schema.sql"))
        .assert()
        .success();
    let json = parse(&output.get_output().stdout);

    assert_eq!(
        json["language"], "text",
        "the parent directory's dominant Rust must NOT mislabel schema.sql: {json}"
    );
}
