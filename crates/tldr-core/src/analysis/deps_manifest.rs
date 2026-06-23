//! Dependency-manifest parsing for `tldr deps`.
//!
//! `deps-manifest-external-v1` (v0.5.0 T1 AUDIT-FIX). `analyze_dependencies`
//! previously populated `external_dependencies` exclusively from per-file
//! import statements *and only* when the caller opted in with
//! `--include-external` (a flag that defaults to `false`). The practical
//! result was that a plain `tldr deps <dir>` reported
//! `external_dependencies = {}` / `total_external_deps = 0` for every
//! ecosystem, even though the project's manifest (`go.mod`, `Cargo.toml`,
//! `package.json`, `pom.xml` / `build.gradle`, `Gemfile` / `*.gemspec`,
//! `mix.exs`, `Package.swift`) declares the authoritative set of
//! third-party dependencies.
//!
//! This module reads each ecosystem's manifest and returns the declared
//! external package coordinates. The manifest is the canonical, cheap,
//! authoritative source — so [`analyze_dependencies`](super::analyze_dependencies)
//! merges it into `external_dependencies` **unconditionally** (it does not
//! gate on `include_external`, which only governs the *import-derived*
//! augmentation).
//!
//! # AST vs structured parse (constitution: AST-driven where avoidable)
//!
//! * **Ruby (`Gemfile`, `*.gemspec`), Elixir (`mix.exs`), Swift
//!   (`Package.swift`)** are themselves source files in languages that have
//!   a tree-sitter grammar, so they are parsed via
//!   [`crate::ast::parser::parse`] and walked over the real AST
//!   (`call` / `tuple` / `call_expression` nodes). No regex.
//! * **Go (`go.mod`) and Rust / npm (`Cargo.toml`, `package.json`)** have no
//!   tree-sitter grammar in this workspace (`go.mod` is its own DSL; there is
//!   no `toml` crate dependency, and adding one is out of scope for this
//!   change). They are parsed with a *structured, block-aware* line scanner
//!   that tracks the `require ( … )` / `[section]` / JSON-object frame and
//!   extracts the dependency key by its structural delimiter — not a content
//!   regex. `package.json` is parsed with `serde_json` (a real structured
//!   parser that IS available).
//!
//! Every parser is intentionally tolerant: a missing or malformed manifest
//! yields an empty result rather than aborting the dependency scan.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::types::Language;

/// A manifest-declared dependency set for a single manifest file.
///
/// `manifest` is the manifest path *relative to the analysis root* (used as
/// the `external_dependencies` map key so the report attributes the deps to
/// the file that declares them). `packages` is the sorted, de-duplicated set
/// of external package coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestDeps {
    /// Manifest path relative to the analysis root (e.g. `go.mod`).
    pub manifest: PathBuf,
    /// Declared external package names (sorted, de-duplicated).
    pub packages: Vec<String>,
}

/// Parse every dependency manifest under `root` for the given `language` and
/// return the declared external dependencies, one [`ManifestDeps`] per
/// manifest file found.
///
/// Returns an empty `Vec` when the ecosystem has no recognised manifest, the
/// manifest is absent, or it declares no external dependencies. Never errors:
/// manifest parsing is best-effort and must not abort the surrounding scan.
pub fn parse_manifest_dependencies(root: &Path, language: Language) -> Vec<ManifestDeps> {
    let mut out = Vec::new();
    match language {
        Language::Go => {
            if let Some(d) = parse_go_mod(root) {
                out.push(d);
            }
        }
        Language::Rust => {
            collect_cargo_tomls(root, &mut out);
        }
        Language::TypeScript | Language::JavaScript => {
            collect_package_jsons(root, &mut out);
        }
        Language::Java | Language::Kotlin | Language::Scala => {
            collect_jvm_manifests(root, &mut out);
        }
        Language::Ruby => {
            collect_ruby_manifests(root, &mut out);
        }
        Language::Elixir => {
            if let Some(d) = parse_mix_exs(root) {
                out.push(d);
            }
        }
        Language::Swift => {
            if let Some(d) = parse_package_swift(root) {
                out.push(d);
            }
        }
        _ => {}
    }
    // Drop empties and keep deterministic ordering by manifest path.
    out.retain(|m| !m.packages.is_empty());
    out.sort_by(|a, b| a.manifest.cmp(&b.manifest));
    out
}

/// Finalise a raw package set into a sorted, de-duplicated, non-empty list
/// attributed to `manifest_rel`.
fn finalize(manifest_rel: PathBuf, set: BTreeSet<String>) -> Option<ManifestDeps> {
    if set.is_empty() {
        return None;
    }
    Some(ManifestDeps {
        manifest: manifest_rel,
        packages: set.into_iter().collect(),
    })
}

// =============================================================================
// Go — go.mod (structured block parse; no grammar available)
// =============================================================================

/// Parse `go.mod` `require` directives.
///
/// go.mod is a line-structured DSL. Two shapes:
/// ```text
/// require github.com/foo/bar v1.2.3
/// require (
///     github.com/foo/bar v1.2.3
///     golang.org/x/net v0.1.0 // indirect
/// )
/// ```
/// We track the `require ( … )` block frame structurally and take the FIRST
/// whitespace-delimited token of each in-block line as the module path. The
/// single-line form `require <path> <version>` is handled directly. Lines
/// flagged `// indirect` are transitive (pulled in by a direct dep, not
/// declared by this module) and are skipped — `tldr deps` reports the
/// project's *declared* dependencies, mirroring `go mod`'s direct set.
fn parse_go_mod(root: &Path) -> Option<ManifestDeps> {
    let content = std::fs::read_to_string(root.join("go.mod")).ok()?;
    let mut set: BTreeSet<String> = BTreeSet::new();
    let mut in_require_block = false;

    for raw in content.lines() {
        // Strip a trailing line comment but remember whether it was
        // `// indirect` (a structural marker in go.mod, not free text).
        let is_indirect = raw.contains("// indirect");
        let line = match raw.find("//") {
            Some(i) => &raw[..i],
            None => raw,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if in_require_block {
            if line == ")" {
                in_require_block = false;
                continue;
            }
            if is_indirect {
                continue;
            }
            if let Some(module) = line.split_whitespace().next() {
                if looks_like_go_module(module) {
                    set.insert(module.to_string());
                }
            }
            continue;
        }

        if let Some(rest) = line.strip_prefix("require") {
            let rest = rest.trim_start();
            if rest == "(" || rest.is_empty() {
                // `require (` opens a block (the `(` may be the only token).
                in_require_block = true;
                continue;
            }
            if rest.starts_with('(') {
                in_require_block = true;
                // Anything after `(` on the same line is unusual; ignore.
                continue;
            }
            // Single-line: `require <path> <version>`.
            if is_indirect {
                continue;
            }
            if let Some(module) = rest.split_whitespace().next() {
                if looks_like_go_module(module) {
                    set.insert(module.to_string());
                }
            }
        }
    }

    finalize(PathBuf::from("go.mod"), set)
}

/// A go.mod module path is a slash-separated import path with a dotted host
/// (`github.com/...`, `golang.org/...`, `go.uber.org/...`). Reject obvious
/// non-module tokens so a stray line never becomes a "dependency".
fn looks_like_go_module(token: &str) -> bool {
    !token.is_empty()
        && token.contains('/')
        && token.split('/').next().map(|h| h.contains('.')).unwrap_or(false)
}

// =============================================================================
// Rust — Cargo.toml (structured TOML block parse; no toml crate available)
// =============================================================================

/// Walk the project tree collecting every `Cargo.toml` (workspace members
/// live in nested crate dirs, e.g. ripgrep's `crates/*/Cargo.toml`). The deps
/// declared by each crate are attributed to that crate's manifest.
fn collect_cargo_tomls(root: &Path, out: &mut Vec<ManifestDeps>) {
    for manifest in find_manifests(root, "Cargo.toml") {
        if let Some(d) = parse_cargo_toml(root, &manifest) {
            out.push(d);
        }
    }
}

/// Parse the dependency tables of a single `Cargo.toml`.
///
/// Tracks the active `[table]` header structurally and collects keys from
/// `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]` and their
/// `[target.'cfg(...)'.dependencies]` variants. For each table the dependency
/// NAME is the key left of the first top-level `=` (`serde = "1"` or
/// `serde = { version = "1" }`). A `package = "real-name"` rename inside an
/// inline table is NOT unwrapped — Cargo's *dependency identity* for the
/// declared name is the table key, which is what users query. Workspace
/// internal path-deps are kept too (they are still declared third-party-shaped
/// coordinates; the import-derived classifier separately handles intra-repo
/// resolution).
fn parse_cargo_toml(root: &Path, manifest: &Path) -> Option<ManifestDeps> {
    let content = std::fs::read_to_string(manifest).ok()?;
    let mut set: BTreeSet<String> = BTreeSet::new();
    let mut in_dep_table = false;

    for raw in content.lines() {
        let line = strip_toml_comment(raw).trim();
        if line.is_empty() {
            continue;
        }

        // Table header.
        if line.starts_with('[') && line.ends_with(']') {
            let header = line.trim_start_matches('[').trim_end_matches(']').trim();
            // A single-dependency detail table `[dependencies.serde]` (or
            // `[dev-dependencies.foo]`, `[target.'cfg(..)'.dependencies.bar]`)
            // declares ONE dep whose name is the last header segment. Record
            // it directly and leave `in_dep_table=false` so its inner
            // `version`/`path`/`features` keys are NOT misread as deps.
            if let Some(name) = cargo_detail_table_dep(header) {
                if is_valid_cargo_dep_name(&name) {
                    set.insert(name);
                }
                in_dep_table = false;
                continue;
            }
            in_dep_table = is_cargo_dep_table(header);
            continue;
        }

        if !in_dep_table {
            continue;
        }

        // A dependency line: `name = ...`. The name is the token before the
        // first `=`. Guard against array-of-table noise.
        if let Some(eq) = line.find('=') {
            let key = line[..eq].trim().trim_matches('"').trim();
            if is_valid_cargo_dep_name(key) {
                set.insert(key.to_string());
            }
        }
    }

    let rel = manifest.strip_prefix(root).unwrap_or(manifest).to_path_buf();
    finalize(rel, set)
}

/// Is this `[header]` a plain Cargo dependency *table* (whose body is a list
/// of `name = …` lines)?
///
/// Matches `dependencies`, `dev-dependencies`, `build-dependencies` and the
/// `target.'cfg(...)'.<kind>` forms. A per-dependency *detail* table like
/// `[dependencies.serde]` is NOT a plain dep table (it is handled by
/// [`cargo_detail_table_dep`]); this returns `false` for those.
fn is_cargo_dep_table(header: &str) -> bool {
    if cargo_detail_table_dep(header).is_some() {
        return false;
    }
    let tail = header.rsplit('.').next().unwrap_or(header);
    matches!(tail, "dependencies" | "dev-dependencies" | "build-dependencies")
}

/// If `header` is a single-dependency *detail* table
/// (`dependencies.serde`, `dev-dependencies.foo`,
/// `target.'cfg(..)'.dependencies.bar`), return the declared dependency name
/// (the segment AFTER the `dependencies` / `dev-dependencies` /
/// `build-dependencies` kind). Otherwise `None`.
fn cargo_detail_table_dep(header: &str) -> Option<String> {
    for kind in ["dependencies.", "dev-dependencies.", "build-dependencies."] {
        if let Some(idx) = header.find(kind) {
            let after = &header[idx + kind.len()..];
            // The dep name is the next single segment; reject if it contains
            // a further `.` (would be a nested key, not a dep name).
            let name = after.split('.').next().unwrap_or(after).trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// Validate a Cargo dependency key (left of `=`). Rejects empty, quoted-path
/// fragments, and anything containing whitespace/structural chars.
fn is_valid_cargo_dep_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains(char::is_whitespace)
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Strip a `#` line comment from a TOML line, respecting that `#` inside a
/// quoted string is literal. (Cargo.toml dep lines rarely embed `#`, but a
/// version like `"1.0 #:version"` appears in ripgrep, so be careful.)
fn strip_toml_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_str = false;
    let mut quote = b'"';
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if in_str {
            if c == quote {
                in_str = false;
            }
        } else if c == b'"' || c == b'\'' {
            in_str = true;
            quote = c;
        } else if c == b'#' {
            return &line[..i];
        }
        i += 1;
    }
    line
}

// =============================================================================
// JS/TS — package.json (serde_json structured parse)
// =============================================================================

/// Collect every `package.json` under `root` (monorepos nest many) and union
/// their declared dependency objects.
fn collect_package_jsons(root: &Path, out: &mut Vec<ManifestDeps>) {
    for manifest in find_manifests(root, "package.json") {
        if let Some(d) = parse_package_json(root, &manifest) {
            out.push(d);
        }
    }
}

/// Parse `dependencies` / `devDependencies` / `peerDependencies` /
/// `optionalDependencies` object keys from a `package.json`.
fn parse_package_json(root: &Path, manifest: &Path) -> Option<ManifestDeps> {
    let content = std::fs::read_to_string(manifest).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    let mut set: BTreeSet<String> = BTreeSet::new();

    for key in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        if let Some(obj) = json.get(key).and_then(|v| v.as_object()) {
            for dep_name in obj.keys() {
                if !dep_name.is_empty() {
                    set.insert(dep_name.clone());
                }
            }
        }
    }

    let rel = manifest.strip_prefix(root).unwrap_or(manifest).to_path_buf();
    finalize(rel, set)
}

// =============================================================================
// JVM — pom.xml (Maven) and build.gradle[.kts] (Gradle)
// =============================================================================

/// Collect Maven `pom.xml` and Gradle `build.gradle` / `build.gradle.kts`
/// manifests across a (possibly multi-module) JVM project.
fn collect_jvm_manifests(root: &Path, out: &mut Vec<ManifestDeps>) {
    for manifest in find_manifests(root, "pom.xml") {
        if let Some(d) = parse_pom_xml(root, &manifest) {
            out.push(d);
        }
    }
    for name in ["build.gradle", "build.gradle.kts"] {
        for manifest in find_manifests(root, name) {
            if let Some(d) = parse_build_gradle(root, &manifest) {
                out.push(d);
            }
        }
    }
}

/// Parse Maven `<dependency>` coordinates from a `pom.xml`.
///
/// Extracts `groupId:artifactId` for each `<dependency>` element. XML has no
/// tree-sitter grammar here, but the extraction is structural: we track the
/// `<dependency>` open/close frame and read the `<groupId>`/`<artifactId>`
/// element text inside it (element-boundary anchored, not free-text regex).
fn parse_pom_xml(root: &Path, manifest: &Path) -> Option<ManifestDeps> {
    let content = std::fs::read_to_string(manifest).ok()?;
    let mut set: BTreeSet<String> = BTreeSet::new();

    let mut in_dep = false;
    let mut group: Option<String> = None;
    let mut artifact: Option<String> = None;

    for raw in content.lines() {
        let line = raw.trim();
        if line.contains("<dependency>") {
            in_dep = true;
            group = None;
            artifact = None;
            continue;
        }
        if line.contains("</dependency>") {
            if let Some(a) = artifact.take() {
                let coord = match group.take() {
                    Some(g) => format!("{}:{}", g, a),
                    None => a,
                };
                set.insert(coord);
            }
            in_dep = false;
            continue;
        }
        if in_dep {
            if let Some(g) = xml_element_text(line, "groupId") {
                group = Some(g);
            }
            if let Some(a) = xml_element_text(line, "artifactId") {
                artifact = Some(a);
            }
        }
    }

    let rel = manifest.strip_prefix(root).unwrap_or(manifest).to_path_buf();
    finalize(rel, set)
}

/// Extract the inner text of `<tag>text</tag>` on a single line, or `None`.
fn xml_element_text(line: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = line.find(&open)? + open.len();
    let end = line[start..].find(&close)? + start;
    let text = line[start..end].trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

/// Parse Gradle `dependencies { … }` declarations from a `build.gradle` or
/// `build.gradle.kts`.
///
/// Gradle build scripts are Groovy / Kotlin DSL; there is no Groovy grammar
/// in this workspace. We track the `dependencies { … }` brace frame
/// structurally and, for each configuration line
/// (`implementation "g:a:v"`, `api libs.okhttp.client`, etc.), extract the
/// coordinate. Two coordinate shapes:
///   * string literal `"group:artifact:version"` -> `group:artifact`
///   * version-catalog accessor `libs.okhttp.client` -> `okhttp.client`
fn parse_build_gradle(root: &Path, manifest: &Path) -> Option<ManifestDeps> {
    let content = std::fs::read_to_string(manifest).ok()?;
    let mut set: BTreeSet<String> = BTreeSet::new();

    let mut depth: i32 = 0;
    let mut in_deps = false;
    let mut deps_brace_depth = 0;

    for raw in content.lines() {
        let line = strip_line_comment(raw, "//").trim().to_string();
        if line.is_empty() {
            continue;
        }

        // Detect the start of a `dependencies {` block before counting braces
        // so the opening brace on the same line is accounted for.
        if !in_deps && is_gradle_dependencies_header(&line) {
            in_deps = true;
            deps_brace_depth = depth;
        }

        if in_deps && depth >= deps_brace_depth {
            if let Some(coord) = gradle_coordinate(&line) {
                set.insert(coord);
            }
        }

        // Update brace depth AFTER processing the line.
        depth += line.matches('{').count() as i32;
        depth -= line.matches('}').count() as i32;
        if in_deps && depth <= deps_brace_depth {
            in_deps = false;
        }
    }

    let rel = manifest.strip_prefix(root).unwrap_or(manifest).to_path_buf();
    finalize(rel, set)
}

/// Does this line open a Gradle `dependencies {` block (not
/// `dependencyResolutionManagement` or a method call)?
fn is_gradle_dependencies_header(line: &str) -> bool {
    let l = line.trim_start();
    (l == "dependencies {" || l.starts_with("dependencies {") || l == "dependencies")
        && !l.starts_with("dependencyResolution")
}

/// Extract a dependency coordinate from a Gradle configuration line.
///
/// Recognised configurations: implementation/api/compileOnly/runtimeOnly/
/// testImplementation/etc. The coordinate is either a quoted
/// `"group:artifact:version"` (collapsed to `group:artifact`) or a
/// version-catalog accessor `libs.<group>.<name>` (collapsed to the
/// dotted accessor tail).
fn gradle_coordinate(line: &str) -> Option<String> {
    let l = line.trim();
    // Must begin with a known configuration keyword followed by whitespace.
    let config = [
        "implementation",
        "api",
        "compileOnly",
        "compileOnlyApi",
        "runtimeOnly",
        "testImplementation",
        "testCompileOnly",
        "testRuntimeOnly",
        "annotationProcessor",
        "kapt",
        "ksp",
    ]
    .iter()
    .find(|kw| {
        l.strip_prefix(**kw)
            .map(|rest| rest.starts_with(|c: char| c.is_whitespace() || c == '(' ))
            .unwrap_or(false)
    })?;
    let rest = l[config.len()..].trim_start_matches('(').trim();

    // String-literal coordinate.
    if let Some(coord) = first_quoted(rest) {
        // `group:artifact:version` -> `group:artifact`.
        let parts: Vec<&str> = coord.split(':').collect();
        if parts.len() >= 2 {
            return Some(format!("{}:{}", parts[0], parts[1]));
        }
        if !coord.is_empty() {
            return Some(coord);
        }
    }

    // Version-catalog accessor: `libs.okhttp.client` / `libs.kotlinx.coroutines`.
    let accessor = rest
        .split(|c: char| c.is_whitespace() || c == ')' || c == ',')
        .next()
        .unwrap_or("");
    if let Some(tail) = accessor.strip_prefix("libs.") {
        if !tail.is_empty()
            && tail
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_')
        {
            return Some(tail.to_string());
        }
    }

    None
}

/// Return the contents of the first single- or double-quoted string in `s`.
fn first_quoted(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'"' || c == b'\'' {
            let quote = c;
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != quote {
                j += 1;
            }
            if j <= bytes.len() {
                return Some(s[start..j.min(s.len())].to_string());
            }
        }
        i += 1;
    }
    None
}

// =============================================================================
// Ruby — Gemfile + *.gemspec (AST: tree-sitter-ruby)
// =============================================================================

/// Collect Ruby `Gemfile` and `*.gemspec` manifests and union the gems they
/// declare via `gem`, `add_dependency`, and `add_development_dependency`
/// calls.
fn collect_ruby_manifests(root: &Path, out: &mut Vec<ManifestDeps>) {
    let mut manifests: Vec<PathBuf> = Vec::new();
    let gemfile = root.join("Gemfile");
    if gemfile.is_file() {
        manifests.push(gemfile);
    }
    for m in find_manifests_by_ext(root, "gemspec") {
        manifests.push(m);
    }
    for manifest in manifests {
        if let Some(d) = parse_ruby_manifest(root, &manifest) {
            out.push(d);
        }
    }
}

/// Parse a Ruby manifest via the tree-sitter AST, collecting the first string
/// argument of `gem` / `add_dependency` / `add_development_dependency` /
/// `add_runtime_dependency` calls.
fn parse_ruby_manifest(root: &Path, manifest: &Path) -> Option<ManifestDeps> {
    let source = std::fs::read_to_string(manifest).ok()?;
    let tree = crate::ast::parser::parse(&source, Language::Ruby).ok()?;
    let mut set: BTreeSet<String> = BTreeSet::new();
    collect_ruby_gem_calls(tree.root_node(), source.as_bytes(), &mut set);
    let rel = manifest.strip_prefix(root).unwrap_or(manifest).to_path_buf();
    finalize(rel, set)
}

/// Recursively visit `call` nodes; when the method is a gem-declaring helper,
/// record the first string-literal argument.
fn collect_ruby_gem_calls(node: tree_sitter::Node, source: &[u8], set: &mut BTreeSet<String>) {
    if node.kind() == "call" {
        if let Some(method) = node.child_by_field_name("method") {
            let name = node_text(method, source);
            let is_gem_decl = matches!(
                name.as_str(),
                "gem" | "add_dependency" | "add_runtime_dependency" | "add_development_dependency"
            );
            if is_gem_decl {
                if let Some(args) = node.child_by_field_name("arguments") {
                    if let Some(gem) = first_string_arg(args, source) {
                        if !gem.is_empty() {
                            set.insert(gem);
                        }
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_ruby_gem_calls(child, source, set);
    }
}

/// Return the `string_content` of the first `string` child of an
/// `argument_list` node.
fn first_string_arg(args: tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        if child.kind() == "string" {
            return Some(string_node_content(child, source));
        }
    }
    None
}

/// Concatenate the `string_content` children of a `string` node (handles the
/// common single-segment case and tolerates the grammar's quote children).
fn string_node_content(string_node: tree_sitter::Node, source: &[u8]) -> String {
    let mut out = String::new();
    let mut cursor = string_node.walk();
    for child in string_node.children(&mut cursor) {
        if child.kind() == "string_content" {
            out.push_str(&node_text(child, source));
        }
    }
    if out.is_empty() {
        // Fallback: strip the outer quotes from the raw text.
        let raw = node_text(string_node, source);
        out = raw
            .trim_matches(|c| c == '"' || c == '\'')
            .to_string();
    }
    out
}

// =============================================================================
// Elixir — mix.exs (AST: tree-sitter-elixir)
// =============================================================================

/// Parse `mix.exs` `defp deps do [ {:dep, ...}, ... ] end`.
///
/// The dependency name is the leading `atom` of each dependency `tuple`
/// (`{:plug, "~> 1.14"}` -> `plug`). We locate the `deps` function by its
/// `call`(`defp`/`def`) whose first argument identifier is `deps`, then walk
/// its `do_block` for `tuple` nodes and read the leading atom.
fn parse_mix_exs(root: &Path) -> Option<ManifestDeps> {
    let source = std::fs::read_to_string(root.join("mix.exs")).ok()?;
    let tree = crate::ast::parser::parse(&source, Language::Elixir).ok()?;
    let mut set: BTreeSet<String> = BTreeSet::new();
    collect_elixir_deps(tree.root_node(), source.as_bytes(), &mut set, false);
    finalize(PathBuf::from("mix.exs"), set)
}

/// Walk the Elixir AST. When inside the `deps` definition's block, harvest the
/// leading atom of every `tuple`. `in_deps` becomes true once we descend into
/// the `do_block` of a `def`/`defp deps` call.
fn collect_elixir_deps(
    node: tree_sitter::Node,
    source: &[u8],
    set: &mut BTreeSet<String>,
    in_deps: bool,
) {
    if node.kind() == "call" && !in_deps {
        // Is this `def(p) deps do ... end`?
        if is_elixir_deps_definition(node, source) {
            // Recurse into this call's do_block with in_deps = true and stop
            // the normal descent (handled below with the flag).
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                collect_elixir_deps(child, source, set, true);
            }
            return;
        }
    }

    if in_deps && node.kind() == "tuple" {
        if let Some(atom) = first_elixir_atom(node, source) {
            if !atom.is_empty() {
                set.insert(atom);
            }
        }
        // Do not descend further into a dependency tuple — its only
        // dep-name atom is the leading one (nested keyword lists like
        // `only: :test` would otherwise add `:test`).
        return;
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_elixir_deps(child, source, set, in_deps);
    }
}

/// Recognise a `def`/`defp` call whose first argument is the identifier
/// `deps` (i.e. the `deps/0` function Mix reads).
fn is_elixir_deps_definition(node: tree_sitter::Node, source: &[u8]) -> bool {
    // The `def`/`defp` keyword is the `target` field; the function name lives
    // in an `arguments` CHILD NODE (it is NOT a named field — verified via
    // tree-sitter-elixir debug parse: `call -> [target] identifier 'defp'`,
    // `arguments 'deps'`). So locate `arguments` by node KIND, not field.
    let target = match node.child_by_field_name("target") {
        Some(t) => node_text(t, source),
        None => return false,
    };
    if target != "def" && target != "defp" {
        return false;
    }
    let mut top = node.walk();
    let args = node
        .children(&mut top)
        .find(|c| c.kind() == "arguments");
    let args = match args {
        Some(a) => a,
        None => return false,
    };
    // First argument should be `deps` (an `identifier` or a nested `call`
    // `deps(...)`). Inspect the argument subtree's leading identifier.
    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        match child.kind() {
            "identifier" => return node_text(child, source) == "deps",
            "call" => {
                if let Some(t) = child.child_by_field_name("target") {
                    return node_text(t, source) == "deps";
                }
            }
            _ => {}
        }
    }
    false
}

/// Return the leading `atom` of a tuple as a bare name (`:plug` -> `plug`).
fn first_elixir_atom(tuple: tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut cursor = tuple.walk();
    for child in tuple.children(&mut cursor) {
        if child.kind() == "atom" {
            let raw = node_text(child, source);
            let name = raw.trim_start_matches(':').to_string();
            return Some(name);
        }
    }
    None
}

// =============================================================================
// Swift — Package.swift (AST: tree-sitter-swift)
// =============================================================================

/// Parse `Package.swift` `.package(url: "…", …)` declarations.
///
/// Each dependency is a `call_expression` whose target is a
/// `prefix_expression` `.package`, with a `url:` value argument holding the
/// git URL string. The package NAME is the last path segment of the URL with
/// a trailing `.git` stripped (`.../swift-numerics` -> `swift-numerics`).
/// Local `.package(path: "…")` and name-based `.package(name:…)` forms are
/// also handled (last path segment / explicit name).
fn parse_package_swift(root: &Path) -> Option<ManifestDeps> {
    let source = std::fs::read_to_string(root.join("Package.swift")).ok()?;
    let tree = crate::ast::parser::parse(&source, Language::Swift).ok()?;
    let mut set: BTreeSet<String> = BTreeSet::new();
    collect_swift_packages(tree.root_node(), source.as_bytes(), &mut set);
    finalize(PathBuf::from("Package.swift"), set)
}

/// Walk for `.package(...)` call expressions and extract the dependency name.
fn collect_swift_packages(node: tree_sitter::Node, source: &[u8], set: &mut BTreeSet<String>) {
    if node.kind() == "call_expression" && swift_call_is_dot_package(node, source) {
        if let Some(name) = swift_package_name(node, source) {
            if !name.is_empty() {
                set.insert(name);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_swift_packages(child, source, set);
    }
}

/// Is this `call_expression`'s callee the member `.package`?
fn swift_call_is_dot_package(node: tree_sitter::Node, source: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "prefix_expression" {
            // `.package` => prefix_expression with a `.` operator and a
            // `simple_identifier` target `package`.
            let inner = node_text(child, source);
            if inner == ".package" {
                return true;
            }
            // Defensive: inspect the simple_identifier child explicitly.
            let mut ic = child.walk();
            for ich in child.children(&mut ic) {
                if ich.kind() == "simple_identifier" && node_text(ich, source) == "package" {
                    return true;
                }
            }
        }
    }
    false
}

/// Extract the dependency name from a `.package(...)` call's arguments.
fn swift_package_name(node: tree_sitter::Node, source: &[u8]) -> Option<String> {
    // Find the call_suffix -> value_arguments node.
    let value_args = find_descendant(node, "value_arguments")?;
    let mut url: Option<String> = None;
    let mut path: Option<String> = None;
    let mut name: Option<String> = None;

    let mut cursor = value_args.walk();
    for arg in value_args.children(&mut cursor) {
        if arg.kind() != "value_argument" {
            continue;
        }
        let label = arg
            .child_by_field_name("name")
            .map(|n| node_text(n, source))
            .unwrap_or_default();
        let value = arg
            .child_by_field_name("value")
            .map(|v| swift_string_value(v, source))
            .unwrap_or_default();
        match label.as_str() {
            "url" => url = Some(value),
            "path" => path = Some(value),
            "name" => name = Some(value),
            _ => {}
        }
    }

    // Priority: explicit name > url leaf > path leaf.
    if let Some(n) = name.filter(|s| !s.is_empty()) {
        return Some(n);
    }
    if let Some(u) = url.filter(|s| !s.is_empty()) {
        return Some(url_leaf_to_package(&u));
    }
    if let Some(p) = path.filter(|s| !s.is_empty()) {
        return Some(url_leaf_to_package(&p));
    }
    None
}

/// Convert a git URL or local path to a package name: last `/` segment with a
/// trailing `.git` removed.
fn url_leaf_to_package(url: &str) -> String {
    let trimmed = url.trim_end_matches('/');
    let leaf = trimmed.rsplit('/').next().unwrap_or(trimmed);
    leaf.strip_suffix(".git").unwrap_or(leaf).to_string()
}

/// Extract a Swift string-literal value's text (`line_string_literal` ->
/// `line_str_text`), tolerating the raw fallback.
fn swift_string_value(node: tree_sitter::Node, source: &[u8]) -> String {
    if node.kind() == "line_string_literal" {
        if let Some(text) = find_descendant(node, "line_str_text") {
            return node_text(text, source);
        }
    }
    node_text(node, source)
        .trim_matches('"')
        .to_string()
}

// =============================================================================
// Shared AST + filesystem helpers
// =============================================================================

/// First descendant (pre-order) with the given kind, or `None`.
fn find_descendant<'a>(node: tree_sitter::Node<'a>, kind: &str) -> Option<tree_sitter::Node<'a>> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == kind {
            return Some(child);
        }
        if let Some(found) = find_descendant(child, kind) {
            return Some(found);
        }
    }
    None
}

/// Decode a node's source text as a `String` (lossless for valid UTF-8).
fn node_text(node: tree_sitter::Node, source: &[u8]) -> String {
    std::str::from_utf8(&source[node.byte_range()])
        .unwrap_or("")
        .to_string()
}

/// Strip a line comment beginning with `marker`, respecting quoted strings.
fn strip_line_comment<'a>(line: &'a str, marker: &str) -> &'a str {
    let bytes = line.as_bytes();
    let mbytes = marker.as_bytes();
    let mut in_str = false;
    let mut quote = b'"';
    let mut i = 0;
    while i + mbytes.len() <= bytes.len() {
        let c = bytes[i];
        if in_str {
            if c == quote {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c == b'"' || c == b'\'' {
            in_str = true;
            quote = c;
            i += 1;
            continue;
        }
        if &bytes[i..i + mbytes.len()] == mbytes {
            return &line[..i];
        }
        i += 1;
    }
    line
}

/// Find all manifests with the exact file `name` under `root` (bounded walk).
///
/// Skips well-known vendor/output directories so a `node_modules/` or
/// `target/` tree never floods the result. Bounded to a reasonable depth.
fn find_manifests(root: &Path, name: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_for(root, &mut out, 0, &|p| {
        p.file_name().and_then(|s| s.to_str()) == Some(name)
    });
    out.sort();
    out
}

/// Find all files with the given extension under `root` (bounded walk).
fn find_manifests_by_ext(root: &Path, ext: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_for(root, &mut out, 0, &|p| {
        p.extension().and_then(|s| s.to_str()) == Some(ext)
    });
    out.sort();
    out
}

/// Depth-bounded directory walk collecting paths matching `pred`, skipping
/// vendor/build directories.
fn walk_for(dir: &Path, out: &mut Vec<PathBuf>, depth: usize, pred: &dyn Fn(&Path) -> bool) {
    const MAX_DEPTH: usize = 12;
    if depth > MAX_DEPTH {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let ftype = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ftype.is_dir() {
            if is_skippable_dir(&path) {
                continue;
            }
            walk_for(&path, out, depth + 1, pred);
        } else if ftype.is_file() && pred(&path) {
            out.push(path);
        }
    }
}

/// Vendor / build / VCS directories that never contain the project's own
/// authoritative manifest.
fn is_skippable_dir(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|s| s.to_str()),
        Some(
            ".git"
                | "node_modules"
                | "target"
                | "build"
                | "_build"
                | "deps"
                | "vendor"
                | ".bundle"
                | "dist"
                | ".gradle"
                | "Pods"
                | ".build"
        )
    )
}
