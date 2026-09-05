//! Parser for `luacheck --formatter plain` output.
//!
//! Luacheck plain format:
//! ```text
//!     file.lua:10:5: (W211) unused variable 'x'
//! ```

use std::path::PathBuf;

use super::super::tools::{L1Finding, ToolCategory};
use super::ParseError;

pub fn parse_luacheck_output(stdout: &str) -> Result<Vec<L1Finding>, ParseError> {
    let mut findings = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("Total:") || line.starts_with("Checking") {
            continue;
        }

        // Format: file.lua:10:5: (W211) message
        //
        // why: on Windows the path itself starts with a drive letter
        // (e.g. "C:\file.lua:10:5: msg"), whose colon would otherwise be
        // mistaken for the file/line separator and corrupt every field.
        // Split the drive prefix off first so it rides along with the path
        // instead of being consumed as part 0.
        let (drive_prefix, search_str) = if line.len() > 2
            && line.as_bytes()[0].is_ascii_alphabetic()
            && line.as_bytes()[1] == b':'
            && matches!(line.as_bytes()[2], b'\\' | b'/')
        {
            line.split_at(2)
        } else {
            ("", line)
        };
        let parts: Vec<&str> = search_str.splitn(4, ':').collect();
        if parts.len() < 4 {
            continue;
        }

        let file = format!("{}{}", drive_prefix, parts[0].trim());
        let line_num: u32 = parts[1].trim().parse().unwrap_or(0);
        let column: u32 = parts[2].trim().parse().unwrap_or(0);
        let rest = parts[3].trim();

        // Extract code like (W211) or (E011)
        let (code, message) = if rest.starts_with('(') {
            if let Some(end) = rest.find(')') {
                let code = &rest[1..end];
                let msg = rest[end + 1..].trim();
                (Some(code.to_string()), msg.to_string())
            } else {
                (None, rest.to_string())
            }
        } else {
            (None, rest.to_string())
        };

        let severity = match code.as_deref().and_then(|c| c.chars().next()) {
            Some('E') => "high".to_string(),   // errors
            Some('W') => "medium".to_string(), // warnings
            _ => "low".to_string(),
        };

        findings.push(L1Finding {
            tool: String::new(),
            category: ToolCategory::Linter,
            file: PathBuf::from(file),
            line: line_num,
            column,
            native_severity: if severity == "high" {
                "error".to_string()
            } else {
                "warning".to_string()
            },
            severity,
            message,
            code,
        });
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty() {
        assert!(parse_luacheck_output("").unwrap().is_empty());
    }

    #[test]
    fn test_parse_finding() {
        let output = "    main.lua:10:5: (W211) unused variable 'x'";
        let findings = parse_luacheck_output(output).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, PathBuf::from("main.lua"));
        assert_eq!(findings[0].line, 10);
        assert_eq!(findings[0].column, 5);
        assert_eq!(findings[0].severity, "medium");
        assert_eq!(findings[0].code, Some("W211".to_string()));
    }

    #[test]
    fn test_parse_error() {
        let output = "bad.lua:1:1: (E011) expected expression near 'end'";
        let findings = parse_luacheck_output(output).unwrap();
        assert_eq!(findings[0].severity, "high");
    }

    #[test]
    fn test_parse_skips_summary() {
        let output = "Total: 3 warnings / 1 error in 2 files";
        assert!(parse_luacheck_output(output).unwrap().is_empty());
    }
}
