//! C#-specific API surface extraction.
//!
//! C# surfaces public types and public/protected members by default.

use std::path::{Path, PathBuf};

use crate::ast::extract::extract_from_tree;
use crate::ast::parser::parse;
use crate::types::{ClassInfo, Language};
use crate::TldrResult;

use super::language_profile::strip_layout_segments;
use super::triggers::extract_triggers;
use super::types::{ApiEntry, ApiKind, ApiSurface, Location, Param, ResolvedPackage, Signature};

/// Extract the public C# API surface for a resolved package.
pub fn extract_csharp_api_surface(
    resolved: &ResolvedPackage,
    include_private: bool,
    limit: Option<usize>,
) -> TldrResult<ApiSurface> {
    let mut apis = Vec::new();

    for file_path in find_csharp_files(&resolved.root_dir) {
        apis.extend(extract_from_csharp_file(
            &file_path,
            &resolved.root_dir,
            &resolved.package_name,
            include_private,
        )?);
    }

    if let Some(max) = limit {
        apis.truncate(max);
    }

    let total = apis.len();
    Ok(ApiSurface {
        package: resolved.package_name.clone(),
        language: "csharp".to_string(),
        total,
        apis,
        files_skipped: 0,
        warnings: Vec::new(),
    })
}

fn find_csharp_files(dir: &Path) -> Vec<PathBuf> {
    if dir.is_file() {
        return dir
            .extension()
            .and_then(|ext| ext.to_str())
            .filter(|ext| *ext == "cs")
            .map(|_| vec![dir.to_path_buf()])
            .unwrap_or_default();
    }

    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if !name.starts_with('.') {
                        files.extend(find_csharp_files(&path));
                    }
                }
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("cs") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn extract_from_csharp_file(
    file_path: &Path,
    root_dir: &Path,
    package_name: &str,
    include_private: bool,
) -> TldrResult<Vec<ApiEntry>> {
    let source = std::fs::read_to_string(file_path).map_err(|e| {
        crate::error::TldrError::parse_error(
            file_path.to_path_buf(),
            None,
            format!("Cannot read: {}", e),
        )
    })?;

    let tree = parse(&source, Language::CSharp)?;
    let module_info =
        extract_from_tree(&tree, &source, Language::CSharp, file_path, Some(root_dir))?;
    let module_path = compute_csharp_module_path(file_path, root_dir, package_name);
    let relative_path = file_path
        .strip_prefix(root_dir)
        .unwrap_or(file_path)
        .to_path_buf();

    let mut apis = Vec::new();

    for class in &module_info.classes {
        if !include_private && !is_csharp_type_visible(&source, class.line_number as usize) {
            continue;
        }

        let class_name = effective_csharp_class_name(class, &source);
        let qualified_name = format!("{}.{}", module_path, class_name);
        let kind = determine_csharp_kind(class, &source);
        let is_interface = kind == ApiKind::Interface;

        apis.push(ApiEntry {
            qualified_name: qualified_name.clone(),
            kind,
            module: module_path.clone(),
            signature: None,
            docstring: class.docstring.clone().map(|doc| truncate_docstring(&doc)),
            example: Some(generate_csharp_type_example(&class_name, kind)),
            triggers: extract_triggers(&class_name, class.docstring.as_deref()),
            is_property: false,
            return_type: None,
            location: Some(Location {
                file: relative_path.clone(),
                line: class.line_number as usize,
                column: None,
            }),
        });

        for method in &class.methods {
            // Interface methods are always public by language semantics — the
            // explicit `public` modifier is omitted. Bypass the per-method
            // visibility check when the enclosing type is an interface.
            // Mirrors the Rust trait short-circuit at rust_lang.rs:L174-L180.
            if !include_private
                && !is_interface
                && !is_csharp_member_visible(&source, method.line_number as usize)
            {
                continue;
            }

            let params = convert_csharp_params(&method.params);
            let return_type = method.return_type.clone();
            let kind = if line_has_word(&source, method.line_number as usize, "static") {
                ApiKind::StaticMethod
            } else {
                ApiKind::Method
            };

            apis.push(ApiEntry {
                qualified_name: format!("{}.{}", qualified_name, method.name),
                kind,
                module: module_path.clone(),
                signature: Some(Signature {
                    params: params.clone(),
                    return_type: return_type.clone(),
                    is_async: method.is_async,
                    is_generator: false,
                }),
                docstring: method.docstring.clone().map(|doc| truncate_docstring(&doc)),
                example: Some(generate_csharp_method_example(
                    &class_name,
                    &method.name,
                    &params,
                )),
                triggers: extract_triggers(&method.name, method.docstring.as_deref()),
                is_property: false,
                return_type,
                location: Some(Location {
                    file: relative_path.clone(),
                    line: method.line_number as usize,
                    column: None,
                }),
            });
        }
    }

    Ok(apis)
}

fn compute_csharp_module_path(file_path: &Path, root_dir: &Path, package_name: &str) -> String {
    let relative = file_path.strip_prefix(root_dir).unwrap_or(file_path);
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let parts: Vec<String> = parent
        .iter()
        .map(|part| part.to_string_lossy().to_string())
        .collect();
    let parts = strip_layout_segments(Language::CSharp, Path::new(&parts.join("/")));

    if parts.is_empty() {
        package_name.to_string()
    } else {
        format!("{}.{}", package_name, parts.join("."))
    }
}

fn is_csharp_type_visible(source: &str, line_number: usize) -> bool {
    // m116-easy-mechanical-v1 (#36): tree-sitter-c-sharp starts an
    // `interface_declaration` / `class_declaration` at its FIRST
    // attribute_list, not at the `public class|interface|struct` line.
    // When a type is preceded by one or more attributes
    //   [Serializable]
    //   [Obsolete("...")]
    //   public interface IFoo
    // the visibility check on a single source line returned `false` and
    // the type was silently filtered. Scan forward from the reported
    // line through up to `MAX_FORWARD` lines, looking for `public` on
    // any line at or before the line that actually contains the
    // `class|interface|struct|record` keyword. Stop scanning the moment
    // we pass the declaration keyword line: anything beyond belongs to
    // the body.
    csharp_type_visibility_scan(source, line_number, &["public"])
}

fn is_csharp_member_visible(source: &str, line_number: usize) -> bool {
    // Members are likewise reported at their preceding attribute_list
    // line — apply the same forward scan for member visibility.
    csharp_type_visibility_scan(source, line_number, &["public", "protected"])
}

/// Scan forward from `line_number` (1-indexed) up to and including the
/// first line that contains a C# top-level declaration keyword
/// (`class` / `interface` / `struct` / `record` / a method-shape return
/// type + name), returning `true` if any of the lines contains one of
/// `words` as a whole word. The scan is intentionally narrow: real
/// attribute clusters are 1–8 lines for the common case.
fn csharp_type_visibility_scan(source: &str, line_number: usize, words: &[&str]) -> bool {
    const MAX_FORWARD: usize = 16;
    let lines: Vec<&str> = source.lines().collect();
    let start_idx = line_number.saturating_sub(1);
    if start_idx >= lines.len() {
        return false;
    }
    let end_idx = std::cmp::min(start_idx + MAX_FORWARD, lines.len());
    for idx in start_idx..end_idx {
        let line = lines[idx];
        for w in words {
            if line_text_has_word(line, w) {
                return true;
            }
        }
        // Stop scanning once we've passed the declaration keyword line.
        // `class` / `interface` / `struct` / `record` (the C# top-level
        // type-introducing keywords) signal the end of the
        // attribute-prelude region.
        if line_text_has_word(line, "class")
            || line_text_has_word(line, "interface")
            || line_text_has_word(line, "struct")
            || line_text_has_word(line, "record")
            // method or property declarations: signal end of attribute
            // prelude by the presence of `(` or `=>` or `{` paired with
            // a return-type-shaped token. Approximation by line: the
            // attribute prelude is comprised of `[...]` lines.
            || (idx > start_idx
                && !line.trim_start().starts_with('[')
                && !line.trim().is_empty())
        {
            break;
        }
    }
    false
}

fn line_text_has_word(line: &str, word: &str) -> bool {
    line.split(|ch: char| !ch.is_alphanumeric() && ch != '_')
        .any(|part| part == word)
}

fn line_has_word(source: &str, line_number: usize, word: &str) -> bool {
    source
        .lines()
        .nth(line_number.saturating_sub(1))
        .map(|line| {
            line.split(|ch: char| !ch.is_alphanumeric() && ch != '_')
                .any(|part| part == word)
        })
        .unwrap_or(false)
}

fn effective_csharp_class_name(class: &ClassInfo, source: &str) -> String {
    if !class.name.is_empty() {
        return class.name.clone();
    }

    let line = source
        .lines()
        .nth(class.line_number.saturating_sub(1) as usize)
        .unwrap_or("");
    let tokens: Vec<&str> = line
        .split(|ch: char| !ch.is_alphanumeric() && ch != '_')
        .filter(|token| !token.is_empty())
        .collect();

    for idx in 0..tokens.len() {
        match tokens[idx] {
            "class" | "struct" | "interface" => {
                if let Some(name) = tokens.get(idx + 1) {
                    return (*name).to_string();
                }
            }
            _ => {}
        }
    }

    String::new()
}

fn determine_csharp_kind(class: &ClassInfo, source: &str) -> ApiKind {
    // m116-easy-mechanical-v1 (#36): tree-sitter-c-sharp anchors
    // `interface_declaration` / `class_declaration` at the first
    // attribute_list (`[Serializable]`), not the declaration keyword
    // line. Scan forward through the attribute prelude (lines starting
    // with `[`) until we land on the actual `class|interface|struct`
    // line.
    const MAX_FORWARD: usize = 16;
    let lines: Vec<&str> = source.lines().collect();
    let start_idx = (class.line_number as usize).saturating_sub(1);
    let end_idx = std::cmp::min(start_idx + MAX_FORWARD, lines.len());

    for idx in start_idx..end_idx {
        let trimmed = lines[idx].trim_start();
        // Skip attribute_list lines (`[...]`) — they belong to the
        // prelude, not the declaration head.
        if trimmed.starts_with('[') {
            continue;
        }
        // Empty lines inside the prelude are tolerated.
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("interface ") || trimmed.contains(" interface ") {
            return ApiKind::Interface;
        } else if trimmed.starts_with("struct ") || trimmed.contains(" struct ") {
            return ApiKind::Struct;
        } else {
            return ApiKind::Class;
        }
    }
    ApiKind::Class
}

fn convert_csharp_params(raw_params: &[String]) -> Vec<Param> {
    raw_params
        .iter()
        .filter(|param| !param.is_empty())
        .map(|param| Param {
            name: param.clone(),
            type_annotation: None,
            default: None,
            is_variadic: false,
            is_keyword: false,
        })
        .collect()
}

fn truncate_docstring(doc: &str) -> String {
    let first_para = doc.split("\n\n").next().unwrap_or(doc);
    let cleaned = first_para
        .lines()
        .map(|line| line.trim())
        .collect::<Vec<_>>()
        .join(" ");
    if cleaned.len() <= 200 {
        cleaned
    } else {
        format!(
            "{}...",
            crate::util::truncate_at_char_boundary(&cleaned, 197)
        )
    }
}

fn generate_csharp_type_example(name: &str, kind: ApiKind) -> String {
    match kind {
        ApiKind::Interface => format!("{} value = default!;", name),
        ApiKind::Struct => format!("var value = new {}();", name),
        _ => format!("var value = new {}();", name),
    }
}

fn generate_csharp_method_example(class_name: &str, method_name: &str, params: &[Param]) -> String {
    let args = params
        .iter()
        .map(|param| param.name.clone())
        .collect::<Vec<_>>()
        .join(", ");
    format!("new {}().{}({})", class_name, method_name, args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_file(dir: &TempDir, rel: &str, source: &str) {
        let path = dir.path().join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, source).unwrap();
    }

    #[test]
    fn test_truncate_docstring_handles_unicode_char_boundaries() {
        // 67 × 3-byte char (U+2500) = 201 bytes. Pre-fix: panic at
        // `&cleaned[..197]` (197 % 3 = 2 → mid-codepoint). Post-fix: snap
        // down to the largest char-boundary <= 197 (= 195 bytes = 65 chars).
        let doc = "─".repeat(67);
        let truncated = truncate_docstring(&doc);
        assert!(truncated.ends_with("..."));
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());
        assert_eq!(truncated, format!("{}...", "─".repeat(65)));
    }

    #[test]
    fn test_find_csharp_files_recurses() {
        let dir = TempDir::new().unwrap();
        write_file(&dir, "src/App.cs", "public class App {}");
        write_file(&dir, "tests/AppTests.cs", "public class AppTests {}");

        let files = find_csharp_files(dir.path());
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_extract_csharp_surface_filters_non_public_members() {
        let dir = TempDir::new().unwrap();
        write_file(
            &dir,
            "src/Greeter.cs",
            r#"
public class Greeter
{
    public string Hello(string name) => name;
    protected void Hook() {}
    private void Secret() {}
}

internal class Hidden
{
    public void Skip() {}
}
"#,
        );

        let resolved = ResolvedPackage {
            root_dir: dir.path().to_path_buf(),
            package_name: "example".to_string(),
            is_pure_source: true,
            public_names: None,
        };

        let surface = extract_csharp_api_surface(&resolved, false, None).unwrap();
        let names: Vec<&str> = surface
            .apis
            .iter()
            .map(|api| api.qualified_name.as_str())
            .collect();

        assert!(names.iter().any(|name| name.ends_with("Greeter.Hello")));
        assert!(names.iter().any(|name| name.ends_with("Greeter.Hook")));
        assert!(!names.iter().any(|name| name.ends_with("Greeter.Secret")));
        assert!(!names.iter().any(|name| name.ends_with("Hidden")));
    }

    #[test]
    fn test_extract_csharp_surface_includes_private_when_requested() {
        let dir = TempDir::new().unwrap();
        write_file(
            &dir,
            "src/Greeter.cs",
            r#"
internal class Greeter
{
    private void Secret() {}
}
"#,
        );

        let resolved = ResolvedPackage {
            root_dir: dir.path().to_path_buf(),
            package_name: "example".to_string(),
            is_pure_source: true,
            public_names: None,
        };

        let surface = extract_csharp_api_surface(&resolved, true, None).unwrap();
        assert!(surface
            .apis
            .iter()
            .any(|api| api.qualified_name.ends_with("Greeter.Secret")));
    }

    #[test]
    fn test_compute_csharp_module_path_strips_nested_src_segment() {
        let root = Path::new("/repo");
        let file = Path::new("/repo/sdk/src/MySdk/Http/Client.cs");

        assert_eq!(
            compute_csharp_module_path(file, root, "example_pkg"),
            "example_pkg.sdk.MySdk.Http"
        );
    }

    #[test]
    fn test_extract_csharp_surface_interface_methods_are_public_by_default() {
        let dir = TempDir::new().unwrap();
        write_file(
            &dir,
            "src/IService.cs",
            r#"
public interface IService
{
    void Execute();
    string GetName();
    int Compute(int x);
}
"#,
        );

        let resolved = ResolvedPackage {
            root_dir: dir.path().to_path_buf(),
            package_name: "example".to_string(),
            is_pure_source: true,
            public_names: None,
        };

        // include_private = false — without the fix, interface methods are filtered out.
        let surface = extract_csharp_api_surface(&resolved, false, None).unwrap();
        let names: Vec<&str> = surface
            .apis
            .iter()
            .map(|api| api.qualified_name.as_str())
            .collect();

        // The interface itself must be present.
        assert!(
            names.iter().any(|n| n.ends_with("IService")),
            "Interface type should be in surface: {:?}",
            names
        );

        // All three interface methods must be present without --include-private.
        assert!(
            names.iter().any(|n| n.ends_with("IService.Execute")),
            "Execute should be in surface: {:?}",
            names
        );
        assert!(
            names.iter().any(|n| n.ends_with("IService.GetName")),
            "GetName should be in surface: {:?}",
            names
        );
        assert!(
            names.iter().any(|n| n.ends_with("IService.Compute")),
            "Compute should be in surface: {:?}",
            names
        );
    }
}
