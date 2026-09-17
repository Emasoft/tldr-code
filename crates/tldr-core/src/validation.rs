//! Shared validation helpers for CLI and daemon handlers
//!
//! These functions reduce duplication between:
//! - CLI commands (sync, returns TldrError)
//! - Daemon handlers (async, wraps to HandlerError)
//! - MCP tools (sync, wraps to JsonRpcError)

use std::path::{Path, PathBuf};

use crate::fs::sniff::{is_probably_binary, sniff_language_from_sample, BINARY_SAMPLE_MAX};
use crate::{Language, TldrError, TldrResult};

/// Resolve the analysis language of a single-file target
/// (extensionless-targets-v1).
///
/// This is THE one helper every single-file language resolution goes through;
/// no per-command ad-hoc copies. Resolution order:
///
/// 1. **Recognized extension** → [`Language::from_path`]. Known-extension
///    behavior is byte-identical to the pre-sniff contract.
/// 2. **Missing path / directory** → `Ok(None)` — the caller keeps its
///    existing handling for those (error text, directory autodetect, …).
/// 3. **OOXML container** (`.docx`/`.xlsx`/`.pptx`, case-insensitive) →
///    `Ok(None)`. Containers are ZIP packages, not text documents: before
///    this step existed, the sniff read the archive bytes and rejected
///    `tldr structure report.docx` with "Binary file: …" BEFORE
///    `get_code_structure`'s `is_ooxml_path` early-return (ooxml-structure-
///    v1) could route the container to the OOXML extractor. `Ok(None)` is
///    the pinned contract: the structure command falls through to its
///    language fallback and the extractor keys the container on the PATH
///    predicate with `language: null` (a container is a package, NOT an XML
///    document — do NOT return `Some(Xml)`). `.docx`/`.xlsx`/`.pptx` are
///    absent from [`Language::from_path`] and must stay that way.
/// 4. **Binary content** (extensionless file OR unrecognized extension) →
///    `Err(TldrError::UnsupportedLanguage)` with "binary file" wording and
///    the standard exit code — a clean structured rejection, never a
///    mislabeled parse.
/// 5. **Extensionless text** → the content ladder (shebang → `<?xml` → Text,
///    see `fs::sniff`); an unsupported shebang yields the plain
///    "Could not detect language" error instead of the binary one.
/// 6. **Unrecognized extension with text content** (`.xyz`) → `Ok(None)` —
///    the unknown-extension negative contract is unchanged.
///
/// The sniff reads at most 64 KiB regardless of file size.
pub fn resolve_target_language(path: &Path) -> TldrResult<Option<Language>> {
    // 1. Recognized extension: unchanged semantics.
    if let Some(lang) = Language::from_path(path) {
        return Ok(Some(lang));
    }

    // 2. Only an existing regular file can be sniffed.
    if !path.is_file() {
        return Ok(None);
    }

    // 3. OOXML containers must never reach the sniff (see the doc comment for
    //    the ooxml-structure-v1 regression): the file exists here, so a
    //    `.docx`/`.xlsx`/`.pptx` path resolves to `Ok(None)` — the
    //    `get_code_structure` early-return owns the container and
    //    `language: null` is the pinned contract.
    if crate::ast::ooxml::is_ooxml_path(path) {
        return Ok(None);
    }

    // 4. One bounded content read, shared by the binary check and the ladder.
    //    An unreadable file (permissions) surfaces as the standard IoError.
    let sample = read_sample(path).map_err(TldrError::IoError)?;

    // 5. Binary content (covers `data.bin` as well as extensionless blobs).
    if is_probably_binary(&sample) {
        return Err(TldrError::UnsupportedLanguage(format!(
            "Binary file: {} — content sniffing found no text to analyze",
            path.display()
        )));
    }

    // 6. Extensionless text: the language ladder.
    if path.extension().is_none() {
        return match sniff_language_from_sample(&sample) {
            Some(lang) => Ok(Some(lang)),
            None => Err(TldrError::UnsupportedLanguage(format!(
                "Could not detect language for: {}",
                path.display()
            ))),
        };
    }

    // 7. Unrecognized extension with text content: unchanged negative.
    Ok(None)
}

/// Read up to [`BINARY_SAMPLE_MAX`] bytes of `path` for the sniff.
fn read_sample(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut buf = Vec::with_capacity(BINARY_SAMPLE_MAX.min(8192));
    let mut chunk = [0u8; 8192];
    loop {
        let n = file.read(&mut chunk)?;
        if n == 0 || buf.len() >= BINARY_SAMPLE_MAX {
            break;
        }
        let take = n.min(BINARY_SAMPLE_MAX - buf.len());
        buf.extend_from_slice(&chunk[..take]);
        if take < n {
            break;
        }
    }
    Ok(buf)
}

/// Resolve and validate a file path.
///
/// # Arguments
/// * `file` - The file path string (may be relative or absolute)
/// * `project` - Optional project root to resolve relative paths against
///
/// # Returns
/// * `Ok(PathBuf)` - Canonical path to the file
/// * `Err(TldrError::PathNotFound)` - File doesn't exist
/// * `Err(TldrError::PathTraversal)` - Path escapes project root
///
/// # Examples
///
/// ```rust,ignore
/// use tldr_core::validation::validate_file_path;
/// use std::path::Path;
///
/// // Relative path with project root
/// let result = validate_file_path("src/main.rs", Some(Path::new("/app")));
///
/// // Absolute path
/// let result = validate_file_path("/app/src/main.rs", None);
///
/// // Path traversal blocked
/// let result = validate_file_path("../escape.rs", Some(Path::new("/app/src")));
/// assert!(result.is_err()); // PathTraversal error
/// ```
pub fn validate_file_path(file: &str, project: Option<&Path>) -> TldrResult<PathBuf> {
    let path = PathBuf::from(file);

    // Resolve to absolute path
    let resolved = if path.is_absolute() {
        path.clone()
    } else if let Some(proj) = project {
        proj.join(&path)
    } else {
        std::env::current_dir()
            .map_err(TldrError::IoError)?
            .join(&path)
    };

    // Canonicalize (resolves symlinks, checks existence)
    // Use dunce for Windows compatibility (M18)
    let canonical =
        dunce::canonicalize(&resolved).map_err(|_| TldrError::PathNotFound(resolved.clone()))?;

    // Check for path traversal if project specified
    if let Some(proj) = project {
        let canonical_proj =
            dunce::canonicalize(proj).map_err(|_| TldrError::PathNotFound(proj.to_path_buf()))?;

        if !canonical.starts_with(&canonical_proj) {
            return Err(TldrError::PathTraversal(path));
        }
    }

    Ok(canonical)
}

/// Detect or parse programming language.
///
/// # Arguments
/// * `lang` - Optional explicit language string
/// * `path` - File path to detect language from (if lang is None)
///
/// # Returns
/// * `Ok(Language)` - Detected or parsed language
/// * `Err(TldrError::UnsupportedLanguage)` - Unknown language string
/// * `Err(TldrError::UnsupportedLanguage)` - Could not detect from path
///
/// extensionless-targets-v1: with no explicit language, detection first tries
/// the extension, then — through [`resolve_target_language`] — the content
/// sniff for extensionless text files (shebang → `<?xml` → Text) and the
/// binary rejection. Known-extension and unknown-extension (`.xyz`) behavior
/// is unchanged.
///
/// ooxml-structure-v1: OOXML containers (`.docx`/`.xlsx`/`.pptx`) also
/// resolve to `Ok(None)` through the helper, so sibling consumers (imports,
/// metrics, daemon handlers) keep the plain "Could not detect language"
/// error on a container — the pre-sniff unknown-extension behavior, NOT the
/// "Binary file" rejection. That is the documented per-call-site decision:
/// containers have no import/metric layer, and the structure path reaches
/// `get_code_structure`'s OOXML early-return instead.
///
/// # Examples
///
/// ```rust,ignore
/// use tldr_core::validation::detect_or_parse_language;
/// use tldr_core::Language;
/// use std::path::Path;
///
/// // Explicit language
/// let lang = detect_or_parse_language(Some("python"), Path::new("any.txt")).unwrap();
/// assert_eq!(lang, Language::Python);
///
/// // Auto-detect from extension
/// let lang = detect_or_parse_language(None, Path::new("script.py")).unwrap();
/// assert_eq!(lang, Language::Python);
///
/// // Error on unknown
/// let result = detect_or_parse_language(None, Path::new("file.xyz"));
/// assert!(result.is_err()); // UnsupportedLanguage error
/// ```
pub fn detect_or_parse_language(lang: Option<&str>, path: &Path) -> TldrResult<Language> {
    if let Some(lang_str) = lang {
        // Parse explicit language
        lang_str
            .parse()
            .map_err(|_| TldrError::UnsupportedLanguage(lang_str.to_string()))
    } else {
        // extensionless-targets-v1: extension first, then the shared
        // single-file resolution helper (content sniff for extensionless
        // text, binary rejection). `Ok(None)` from the helper — missing
        // path, directory, or unknown-extension text — keeps the historical
        // "Could not detect language" error verbatim.
        if let Some(lang) = Language::from_path(path) {
            return Ok(lang);
        }
        match resolve_target_language(path)? {
            Some(lang) => Ok(lang),
            None => Err(TldrError::UnsupportedLanguage(format!(
                "Could not detect language for: {}",
                path.display()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // =========================================================================
    // validate_file_path tests
    // =========================================================================

    #[test]
    fn test_validate_relative_with_project() {
        let temp = TempDir::new().unwrap();
        let src_dir = temp.path().join("src");
        std::fs::create_dir(&src_dir).unwrap();
        let main_rs = src_dir.join("main.rs");
        std::fs::write(&main_rs, "fn main() {}").unwrap();

        let result = validate_file_path("src/main.rs", Some(temp.path()));
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        assert!(result.unwrap().ends_with("src/main.rs"));
    }

    #[test]
    fn test_validate_absolute_path() {
        let temp = TempDir::new().unwrap();
        let file = temp.path().join("test.txt");
        std::fs::write(&file, "content").unwrap();

        let result = validate_file_path(file.to_str().unwrap(), None);
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
    }

    #[test]
    fn test_validate_not_found() {
        let result = validate_file_path("/definitely/nonexistent/path/file.rs", None);
        assert!(matches!(result, Err(TldrError::PathNotFound(_))));
    }

    #[test]
    fn test_validate_traversal_blocked() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("project");
        std::fs::create_dir(&project_dir).unwrap();
        // Create a file outside project dir
        let escape_file = temp.path().join("escape.rs");
        std::fs::write(&escape_file, "// escaped").unwrap();

        let result = validate_file_path("../escape.rs", Some(&project_dir));
        assert!(
            matches!(result, Err(TldrError::PathTraversal(_))),
            "Expected PathTraversal error, got {:?}",
            result
        );
    }

    #[test]
    fn test_validate_relative_without_project() {
        // This tests that relative paths resolve against cwd
        // We'll create a file in a temp dir and change to it
        let temp = TempDir::new().unwrap();
        let file = temp.path().join("local.txt");
        std::fs::write(&file, "content").unwrap();

        // Use absolute path since we can't change cwd easily in tests
        let result = validate_file_path(file.to_str().unwrap(), None);
        assert!(result.is_ok());
    }

    // =========================================================================
    // detect_or_parse_language tests
    // =========================================================================

    #[test]
    fn test_parse_explicit_python() {
        let result = detect_or_parse_language(Some("python"), Path::new("any.xyz"));
        assert_eq!(result.unwrap(), Language::Python);
    }

    #[test]
    fn test_parse_explicit_typescript() {
        let result = detect_or_parse_language(Some("typescript"), Path::new("any.xyz"));
        assert_eq!(result.unwrap(), Language::TypeScript);
    }

    #[test]
    fn test_parse_explicit_rust() {
        let result = detect_or_parse_language(Some("rust"), Path::new("any.xyz"));
        assert_eq!(result.unwrap(), Language::Rust);
    }

    #[test]
    fn test_parse_explicit_go() {
        let result = detect_or_parse_language(Some("go"), Path::new("any.xyz"));
        assert_eq!(result.unwrap(), Language::Go);
    }

    #[test]
    fn test_detect_python_extension() {
        let result = detect_or_parse_language(None, Path::new("script.py"));
        assert_eq!(result.unwrap(), Language::Python);
    }

    #[test]
    fn test_detect_rust_extension() {
        let result = detect_or_parse_language(None, Path::new("lib.rs"));
        assert_eq!(result.unwrap(), Language::Rust);
    }

    #[test]
    fn test_detect_typescript_extension() {
        let result = detect_or_parse_language(None, Path::new("app.ts"));
        assert_eq!(result.unwrap(), Language::TypeScript);
    }

    #[test]
    fn test_detect_go_extension() {
        let result = detect_or_parse_language(None, Path::new("main.go"));
        assert_eq!(result.unwrap(), Language::Go);
    }

    #[test]
    fn test_parse_invalid_language() {
        let result = detect_or_parse_language(Some("invalid_lang"), Path::new("any.xyz"));
        assert!(matches!(result, Err(TldrError::UnsupportedLanguage(_))));
    }

    #[test]
    fn test_detect_unknown_extension() {
        let result = detect_or_parse_language(None, Path::new("file.xyz"));
        assert!(matches!(result, Err(TldrError::UnsupportedLanguage(_))));

        // Check error message contains helpful info
        if let Err(TldrError::UnsupportedLanguage(msg)) = result {
            assert!(msg.contains("Could not detect language"));
            assert!(msg.contains("file.xyz"));
        }
    }

    #[test]
    fn test_explicit_overrides_extension() {
        // Even if file is .py, explicit "rust" should win
        let result = detect_or_parse_language(Some("rust"), Path::new("script.py"));
        assert_eq!(result.unwrap(), Language::Rust);
    }

    // =========================================================================
    // extensionless-targets-v1: resolve_target_language + sniffed detection
    // =========================================================================

    /// The `.xyz` negative is a PIN: an unknown extension with text content
    /// stays undetected even though the content is text.
    #[test]
    fn test_resolve_unknown_extension_text_is_none() {
        let temp = TempDir::new().unwrap();
        let file = temp.path().join("notes.xyz");
        std::fs::write(&file, "plain prose\n").unwrap();
        let resolved = resolve_target_language(&file).unwrap();
        assert_eq!(resolved, None, "unknown extension keeps the negative");
    }

    #[test]
    fn test_resolve_known_extension_is_unchanged() {
        let temp = TempDir::new().unwrap();
        let file = temp.path().join("app.py");
        std::fs::write(&file, "x = 1\n").unwrap();
        assert_eq!(
            resolve_target_language(&file).unwrap(),
            Some(Language::Python)
        );
    }

    #[test]
    fn test_resolve_extensionless_prose_is_text() {
        let temp = TempDir::new().unwrap();
        let file = temp.path().join("LICENSE");
        std::fs::write(&file, "PROJECT LICENSE\n\nsee https://x.y/z\n").unwrap();
        assert_eq!(
            resolve_target_language(&file).unwrap(),
            Some(Language::Text)
        );
    }

    #[test]
    fn test_resolve_extensionless_shebang_maps_language() {
        let temp = TempDir::new().unwrap();
        let file = temp.path().join("run");
        std::fs::write(&file, "#!/usr/bin/env bash\nset -e\n").unwrap();
        assert_eq!(
            resolve_target_language(&file).unwrap(),
            Some(Language::Bash)
        );
    }

    #[test]
    fn test_resolve_extensionless_xml_declaration_maps_xml() {
        let temp = TempDir::new().unwrap();
        let file = temp.path().join("sitemap");
        std::fs::write(&file, "<?xml version=\"1.0\"?>\n<urlset/>\n").unwrap();
        assert_eq!(resolve_target_language(&file).unwrap(), Some(Language::Xml));
    }

    #[test]
    fn test_resolve_binary_is_structured_error_with_binary_wording() {
        let temp = TempDir::new().unwrap();
        // Extensionless binary.
        let blob = temp.path().join("payload");
        std::fs::write(&blob, b"\x00\x01\x02\x03binary").unwrap();
        let err = resolve_target_language(&blob).unwrap_err();
        match &err {
            TldrError::UnsupportedLanguage(msg) => {
                assert!(msg.to_lowercase().contains("binary"), "message = {msg}");
                assert!(msg.contains("payload"), "message names the file");
            }
            other => panic!("expected UnsupportedLanguage, got {other:?}"),
        }
        // Unrecognized-extension binary too (`data.bin`).
        let bin = temp.path().join("data.bin");
        std::fs::write(&bin, b"\x00\x01\x02\x03binary").unwrap();
        let err = resolve_target_language(&bin).unwrap_err();
        assert!(
            matches!(&err, TldrError::UnsupportedLanguage(m) if m.to_lowercase().contains("binary")),
            "data.bin must reject as binary, got {err:?}"
        );
    }

    #[test]
    fn test_resolve_missing_file_is_none_caller_handles_it() {
        let resolved = resolve_target_language(Path::new("/definitely/missing/Makefile"));
        assert_eq!(
            resolved.unwrap(),
            None,
            "missing path keeps caller handling"
        );
    }

    #[test]
    fn test_resolve_directory_is_none() {
        let temp = TempDir::new().unwrap();
        assert_eq!(resolve_target_language(temp.path()).unwrap(), None);
    }

    #[test]
    fn test_detect_or_parse_extensionless_prose_now_resolves() {
        // detect_or_parse_language feeds imports + the daemon: an
        // extensionless text target must resolve instead of erroring.
        let temp = TempDir::new().unwrap();
        let file = temp.path().join("Makefile");
        std::fs::write(&file, "build:\n\tgcc -o app main.o\n").unwrap();
        let lang = detect_or_parse_language(None, &file).unwrap();
        assert_eq!(lang, Language::Text);
    }

    #[test]
    fn test_detect_or_parse_binary_keeps_error_with_binary_wording() {
        let temp = TempDir::new().unwrap();
        let file = temp.path().join("data.bin");
        std::fs::write(&file, b"\x00\x01\x02").unwrap();
        let err = detect_or_parse_language(None, &file).unwrap_err();
        assert!(
            matches!(&err, TldrError::UnsupportedLanguage(m) if m.to_lowercase().contains("binary")),
            "got {err:?}"
        );
    }

    #[test]
    fn test_detect_or_parse_missing_extensionless_still_errors_as_before() {
        // The pre-feature contract for a MISSING extensionless path: the
        // plain "Could not detect language" error — unchanged.
        let err =
            detect_or_parse_language(None, Path::new("/definitely/missing/Makefile")).unwrap_err();
        match &err {
            TldrError::UnsupportedLanguage(msg) => {
                assert!(msg.contains("Could not detect language"), "msg = {msg}");
            }
            other => panic!("expected UnsupportedLanguage, got {other:?}"),
        }
    }

    #[test]
    fn test_resolve_ooxml_container_is_none_never_sniffed() {
        // ooxml-structure-v1 regression: a `.docx` is a ZIP package, so the
        // binary sniff used to reject `tldr structure report.docx` with
        // "Binary file: …" BEFORE `get_code_structure`'s OOXML early-return
        // could run. The container resolves to `Ok(None)` (language: null is
        // the pinned contract) — and `data.bin` proves the binary rejection
        // still fires for genuinely binary non-OOXML files.
        let temp = TempDir::new().unwrap();
        let docx = temp.path().join("report.docx");
        std::fs::write(
            &docx,
            b"PK\x03\x04\x14\x00\x00\x00\x08\x00zip-shaped bytes\x00\x01",
        )
        .unwrap();
        assert_eq!(
            resolve_target_language(&docx).unwrap(),
            None,
            "OOXML container must not be content-sniffed as binary"
        );
        // Case-insensitive, same predicate as the extractor's early-return.
        let pptx = temp.path().join("deck.PPTX");
        std::fs::write(&pptx, b"\x00\x01\x02\x03binary").unwrap();
        assert_eq!(resolve_target_language(&pptx).unwrap(), None);
        // `.bin` is NOT an OOXML extension: the binary rejection stays.
        let bin = temp.path().join("data.bin");
        std::fs::write(&bin, b"\x00\x01\x02\x03binary").unwrap();
        assert!(resolve_target_language(&bin).is_err());
    }

    #[test]
    fn test_detect_or_parse_ooxml_container_is_unknown_extension_not_binary() {
        // Sibling-consumer contract (imports/metrics/daemon): auto-detect on
        // a container keeps the plain "Could not detect language" error —
        // the pre-sniff unknown-extension behavior — not the binary one.
        let temp = TempDir::new().unwrap();
        let xlsx = temp.path().join("book.xlsx");
        std::fs::write(&xlsx, b"PK\x03\x04\x14\x00\x00\x00\x08\x00zip bytes").unwrap();
        let err = detect_or_parse_language(None, &xlsx).unwrap_err();
        match &err {
            TldrError::UnsupportedLanguage(msg) => {
                assert!(msg.contains("Could not detect language"), "msg = {msg}");
                assert!(!msg.to_lowercase().contains("binary"), "msg = {msg}");
            }
            other => panic!("expected UnsupportedLanguage, got {other:?}"),
        }
    }
}
