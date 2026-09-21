//! AST tools: tree, structure, extract, imports
//!
//! These tools provide navigation and structural analysis of codebases.

use crate::protocol::ToolsCallResult;
use serde_json::Value;

use super::{
    get_optional_bool, get_optional_int, get_optional_string, get_optional_string_array,
    get_required_string, to_path,
};

/// Handle tldr_tree tool call
pub fn handle_tree(args: Value) -> ToolsCallResult {
    let path = match get_required_string(&args, "path") {
        Ok(p) => p,
        Err(e) => return ToolsCallResult::error(e),
    };

    let extensions = get_optional_string_array(&args, "extensions");
    let exclude_hidden = get_optional_bool(&args, "exclude_hidden").unwrap_or(true);

    let path = to_path(&path);
    if !path.exists() {
        return ToolsCallResult::error(format!("Path not found: {}", path.display()));
    }

    // Convert extensions to HashSet if provided
    let ext_set = extensions.map(|exts| {
        exts.into_iter()
            .map(|e| {
                if e.starts_with('.') {
                    e
                } else {
                    format!(".{}", e)
                }
            })
            .collect::<std::collections::HashSet<String>>()
    });

    match tldr_core::get_file_tree(&path, ext_set.as_ref(), exclude_hidden, None) {
        Ok(tree) => match serde_json::to_string_pretty(&tree) {
            Ok(json) => ToolsCallResult::text(json),
            Err(e) => ToolsCallResult::error(format!("Serialization error: {}", e)),
        },
        Err(e) => ToolsCallResult::error(format!("Error: {}", e)),
    }
}

/// Handle tldr_structure tool call
pub fn handle_structure(args: Value) -> ToolsCallResult {
    let path = match get_required_string(&args, "path") {
        Ok(p) => p,
        Err(e) => return ToolsCallResult::error(e),
    };

    let language = match get_required_string(&args, "language") {
        Ok(l) => l,
        Err(e) => return ToolsCallResult::error(e),
    };

    let max_results = get_optional_int(&args, "max_results").unwrap_or(0) as usize;

    // markup-node-tree-v1: optional `max_depth` narrows the markup element
    // tree (depth <= N, `None`-depth rows unaffected) — the additive twin of
    // the CLI's `structure --max-depth` and the daemon's structure handler.
    // Absent (or `null`) means no filtering; applied post-extraction, so the
    // underlying `get_code_structure` call is unchanged.
    let max_depth = match get_optional_int(&args, "max_depth") {
        Some(raw) => match u32::try_from(raw) {
            Ok(depth) => Some(depth),
            Err(_) => {
                return ToolsCallResult::error(format!(
                    "Invalid max_depth: {raw} (must be a non-negative integer)"
                ))
            }
        },
        None => None,
    };

    let path = to_path(&path);
    if !path.exists() {
        return ToolsCallResult::error(format!("Path not found: {}", path.display()));
    }

    let lang = match language.parse::<tldr_core::Language>() {
        Ok(l) => l,
        Err(e) => return ToolsCallResult::error(e),
    };

    match tldr_core::get_code_structure(&path, lang, max_results, None) {
        Ok(mut structure) => {
            // markup-node-tree-v1: `--max-depth` parity with the CLI's
            // direct-compute path and the daemon's structure handler — the
            // filter runs AFTER extraction (get_code_structure stays
            // depth-agnostic), mirroring crates/tldr-daemon handlers::ast.
            if let Some(max_depth) = max_depth {
                tldr_core::filter_structure_max_depth(&mut structure, max_depth);
            }
            match serde_json::to_string_pretty(&structure) {
                Ok(json) => ToolsCallResult::text(json),
                Err(e) => ToolsCallResult::error(format!("Serialization error: {}", e)),
            }
        }
        Err(e) => ToolsCallResult::error(format!("Error: {}", e)),
    }
}

/// Handle tldr_extract tool call
pub fn handle_extract(args: Value) -> ToolsCallResult {
    let file = match get_required_string(&args, "file") {
        Ok(f) => f,
        Err(e) => return ToolsCallResult::error(e),
    };

    let base_path = get_optional_string(&args, "base_path");

    let file_path = to_path(&file);
    if !file_path.exists() {
        return ToolsCallResult::error(format!("File not found: {}", file_path.display()));
    }

    let base = base_path.map(|p| to_path(&p));

    match tldr_core::extract_file(&file_path, base.as_deref()) {
        Ok(module_info) => match serde_json::to_string_pretty(&module_info) {
            Ok(json) => ToolsCallResult::text(json),
            Err(e) => ToolsCallResult::error(format!("Serialization error: {}", e)),
        },
        Err(e) => ToolsCallResult::error(format!("Error: {}", e)),
    }
}

/// Handle tldr_imports tool call
pub fn handle_imports(args: Value) -> ToolsCallResult {
    let file = match get_required_string(&args, "file") {
        Ok(f) => f,
        Err(e) => return ToolsCallResult::error(e),
    };

    let file_path = to_path(&file);
    if !file_path.exists() {
        return ToolsCallResult::error(format!("File not found: {}", file_path.display()));
    }

    // Auto-detect language from extension if not provided
    let language = get_optional_string(&args, "language");
    let lang = if let Some(l) = language {
        match l.parse::<tldr_core::Language>() {
            Ok(lang) => lang,
            Err(e) => return ToolsCallResult::error(e),
        }
    } else {
        match tldr_core::Language::from_path(&file_path) {
            Some(l) => l,
            None => {
                return ToolsCallResult::error(format!(
                    "Could not detect language for file: {}. Please specify language explicitly.",
                    file_path.display()
                ))
            }
        }
    };

    match tldr_core::get_imports(&file_path, lang) {
        Ok(imports) => match serde_json::to_string_pretty(&imports) {
            Ok(json) => ToolsCallResult::text(json),
            Err(e) => ToolsCallResult::error(format!("Serialization error: {}", e)),
        },
        Err(e) => ToolsCallResult::error(format!("Error: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_handle_tree_missing_path() {
        let result = handle_tree(json!({}));
        assert!(result.is_error == Some(true));
        assert!(result.content[0].text.contains("Missing required argument"));
    }

    #[test]
    fn test_handle_tree_path_not_found() {
        let result = handle_tree(json!({"path": "/nonexistent/path"}));
        assert!(result.is_error == Some(true));
        assert!(result.content[0].text.contains("Path not found"));
    }

    #[test]
    fn test_handle_structure_missing_language() {
        let result = handle_structure(json!({"path": "."}));
        assert!(result.is_error == Some(true));
        assert!(result.content[0].text.contains("Missing required argument"));
    }

    // -----------------------------------------------------------------------
    // markup-node-tree-v1 (FIX-2 F4): optional `max_depth` on tldr_structure
    // -----------------------------------------------------------------------

    /// The pinned HTML page (element depths: html 0, head 1, title 2, style 2,
    /// body#main 1, script 2, p 2, br 2 + one depth-less inner-CSS `selector`
    /// row) — the same shape the CLI (`structure_max_depth_v1.rs`) and the
    /// daemon (`daemon_contract_coverage_test.rs`) pins use.
    const PAGE_HTML: &str = "\
<!DOCTYPE html>
<html lang=\"en\">
  <head>
    <title>Page</title>
    <style>body { color: red; }</style>
  </head>
  <body id=\"main\">
    <script src=\"app.js\"></script>
    <p>Hello</p>
    <br/>
  </body>
</html>
";

    /// Parse a successful structure result into (name, depth) element rows.
    fn structure_element_rows(result: &ToolsCallResult) -> Vec<(String, Option<u32>)> {
        assert!(result.is_error.is_none(), "handler must succeed");
        let report: serde_json::Value =
            serde_json::from_str(&result.content[0].text).expect("structure result must be JSON");
        report["files"][0]["definitions"]
            .as_array()
            .expect("definitions array")
            .iter()
            .filter(|d| d["kind"] == "element")
            .map(|d| {
                (
                    d["name"].as_str().unwrap_or_default().to_string(),
                    d["depth"].as_u64().map(|n| n as u32),
                )
            })
            .collect()
    }

    #[test]
    fn handle_structure_max_depth_narrows_element_rows() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        std::fs::write(dir.path().join("page.html"), PAGE_HTML).expect("write fixture");
        let path = dir.path().to_str().expect("utf-8 tempdir path");

        // Unfiltered: the full element set, depths intact.
        let full = handle_structure(json!({"path": path, "language": "html"}));
        let full_elements = structure_element_rows(&full);
        assert_eq!(full_elements.len(), 8, "the full unfiltered element set");
        assert!(full_elements.iter().any(|(name, _)| name == "title"));

        // `max_depth: 1`: only depth <= 1 elements survive; the depth-less
        // selector row is unaffected (the filter narrows markup elements only).
        let filtered = handle_structure(json!({"path": path, "language": "html", "max_depth": 1}));
        let filtered_elements = structure_element_rows(&filtered);
        assert_eq!(
            filtered_elements,
            vec![
                ("html".to_string(), Some(0)),
                ("head".to_string(), Some(1)),
                ("body#main".to_string(), Some(1)),
            ],
            "max_depth 1 must keep exactly the depth <= 1 markup elements"
        );
        let defs: serde_json::Value =
            serde_json::from_str(&filtered.content[0].text).expect("filtered result must be JSON");
        assert_eq!(
            defs["files"][0]["definitions"].as_array().unwrap().len(),
            4,
            "3 elements + 1 depth-less selector row"
        );

        // `max_depth: null` behaves like the key being absent (serde(default)
        // parity with the daemon's `Option<u32>` binding).
        let nulled = handle_structure(json!({"path": path, "language": "html", "max_depth": null}));
        assert_eq!(structure_element_rows(&nulled).len(), 8, "null = no filter");

        // Negative values are rejected with a clear error, not wrapped.
        let negative = handle_structure(json!({"path": path, "language": "html", "max_depth": -1}));
        assert!(negative.is_error == Some(true));
        assert!(negative.content[0].text.contains("Invalid max_depth"));
    }

    #[test]
    fn structure_tool_schema_documents_max_depth() {
        let registry = crate::tools::ToolRegistry::new();
        let def = registry
            .list_tools()
            .into_iter()
            .find(|t| t.name == "tldr_structure")
            .expect("tldr_structure registered");
        assert!(
            def.input_schema["properties"].get("max_depth").is_some(),
            "the input schema must advertise the optional max_depth argument: {}",
            def.input_schema
        );
        // Required keys stay unchanged: max_depth is additive-optional.
        assert_eq!(
            def.input_schema["required"],
            serde_json::json!(["path", "language"])
        );
    }
}
