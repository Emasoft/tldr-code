//! API Check command - Detect API misuse patterns
//!
//! Analyzes Python code for common API misuse patterns:
//! - Timeout issues (requests.get without timeout)
//! - Bare except clauses (catching all exceptions)
//! - Weak crypto (MD5, SHA1 for security purposes)
//! - Unclosed resources (files not using context managers)
//!
//! # Example
//!
//! ```bash
//! tldr api-check src/
//! tldr api-check src/main.py --category crypto
//! tldr api-check src/ --severity high --format text
//! ```

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;
use regex::Regex;
use tldr_core::walker::walk_project;
use tldr_core::Language;

use super::error::RemainingError;
use super::types::{
    APICheckReport, APICheckSummary, APIRule, MisuseCategory, MisuseFinding, MisuseSeverity,
};

use crate::output::OutputWriter;

// =============================================================================
// Constants
// =============================================================================

/// Maximum files to analyze in a directory
const MAX_DIRECTORY_FILES: u32 = 1000;

/// Maximum file size to analyze (10 MB)
const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApiLanguage {
    Python,
    Rust,
    Go,
    Java,
    JavaScript,
    TypeScript,
    C,
    Cpp,
    Ruby,
    Php,
    Kotlin,
    Swift,
    CSharp,
    Scala,
    Elixir,
    Lua,
    Luau,
    Ocaml,
    Solidity,
}

#[derive(Clone, Copy)]
struct RegexRuleSpec {
    id: &'static str,
    name: &'static str,
    category: MisuseCategory,
    severity: MisuseSeverity,
    description: &'static str,
    correct_usage: &'static str,
    pattern: &'static str,
    api_call: &'static str,
    message: &'static str,
    fix_suggestion: &'static str,
}

impl RegexRuleSpec {
    fn rule(self) -> APIRule {
        APIRule {
            id: self.id.to_string(),
            name: self.name.to_string(),
            category: self.category,
            severity: self.severity,
            description: self.description.to_string(),
            correct_usage: self.correct_usage.to_string(),
        }
    }
}

/// Per-rule language applicability (api-check-and-patterns-accuracy-v1,
/// P11.BUG-AGG-6). Each rule id is tied to the language(s) for which the
/// rule's pattern is meaningful. The scanner gates `check_regex_rule` and
/// `check_rule` calls through [`rule_applies_to_language`] so a JS rule
/// (e.g. `JS003 JSON.parse`) cannot fire against a `.cpp` file even if the
/// rule list were ever cross-wired by mistake. The per-file `detect_language`
/// dispatch (in [`ApiCheckArgs::run`]) is the primary gate; this is a
/// defense-in-depth backstop documented declaratively.
fn rule_applies_to_language(rule_id: &str, language: ApiLanguage) -> bool {
    // Rule-id naming follows the constants in this file (`C00x`, `CPP00x`,
    // `JS00x`, etc). Matching is exact prefix + numeric suffix to avoid
    // confusing siblings: `C` must NOT match `CPP*`/`CS*`, `LU` must NOT
    // match `LUA*` (no such id exists, but the digit-suffix rule keeps the
    // matcher robust to future renames).
    let prefix_lang: &[&str] = match language {
        ApiLanguage::Python => &["PY"],
        ApiLanguage::Rust => &["RS"],
        ApiLanguage::Go => &["GO"],
        ApiLanguage::Java => &["JV"],
        ApiLanguage::JavaScript => &["JS"],
        ApiLanguage::TypeScript => &["TS"],
        ApiLanguage::C => &["C"],
        ApiLanguage::Cpp => &["CPP"],
        ApiLanguage::Ruby => &["RB"],
        ApiLanguage::Php => &["PH"],
        ApiLanguage::Kotlin => &["KT"],
        ApiLanguage::Swift => &["SW"],
        ApiLanguage::CSharp => &["CS"],
        ApiLanguage::Scala => &["SC"],
        ApiLanguage::Elixir => &["EX"],
        ApiLanguage::Lua | ApiLanguage::Luau => &["LU"],
        ApiLanguage::Ocaml => &["OC"],
        // fix-pack-apicheck-v1 (v0.5.0 PACK-APICHECK): Solidity ERC
        // conformance rules use the `ERC00x` id family. They are
        // contract-level AST detectors (see `analyze_solidity_erc`), not
        // line-driven, so they never flow through `check_rule` /
        // `check_regex_rule`; this entry keeps the language-applicability
        // backstop consistent for the rule-id namespace regardless.
        ApiLanguage::Solidity => &["ERC"],
    };
    for prefix in prefix_lang {
        if let Some(rest) = rule_id.strip_prefix(prefix) {
            // Require digit immediately after prefix so "C" doesn't
            // match "CPP001"/"CS001".
            if rest.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                return true;
            }
        }
    }
    false
}

const GO_RULE_SPECS: &[RegexRuleSpec] = &[
    RegexRuleSpec {
        id: "GO001",
        name: "deprecated-ioutil-readfile",
        category: MisuseCategory::Resources,
        severity: MisuseSeverity::Low,
        description: "ioutil.ReadFile is deprecated and encourages unbounded whole-file reads",
        correct_usage: "Use os.ReadFile or stream with bufio.Scanner/Reader",
        pattern: r"\bioutil\.ReadFile\s*\(",
        api_call: "ioutil.ReadFile",
        message: "ioutil.ReadFile is deprecated and can load unbounded content into memory",
        fix_suggestion: "Use os.ReadFile for simple reads or bufio.Reader for bounded streaming",
    },
    RegexRuleSpec {
        id: "GO002",
        name: "http-get-without-timeout",
        category: MisuseCategory::Parameters,
        severity: MisuseSeverity::Medium,
        description: "http.Get uses the default client and provides no call-specific timeout",
        correct_usage: "Use an http.Client with Timeout or context-aware requests",
        pattern: r"\bhttp\.Get\s*\(",
        api_call: "http.Get",
        message: "http.Get without an explicit timeout can hang indefinitely",
        fix_suggestion: "Use an http.Client{Timeout: ...} or NewRequestWithContext",
    },
    RegexRuleSpec {
        id: "GO003",
        name: "exec-command",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "exec.Command is risky when arguments or executable names come from input",
        correct_usage: "Prefer direct library APIs or strictly validate allowed commands",
        pattern: r"\bexec\.Command\s*\(",
        api_call: "exec.Command",
        message: "exec.Command can enable command injection when fed user-controlled values",
        fix_suggestion: "Validate commands against an allowlist and avoid shell-like execution",
    },
    RegexRuleSpec {
        id: "GO004",
        name: "template-html-cast",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "template.HTML bypasses html/template escaping guarantees",
        correct_usage: "Pass plain strings to templates and let html/template escape them",
        pattern: r"\btemplate\.HTML\s*\(",
        api_call: "template.HTML",
        message: "template.HTML disables escaping and can introduce XSS",
        fix_suggestion: "Remove the cast and rely on html/template auto-escaping",
    },
    RegexRuleSpec {
        id: "GO005",
        name: "sql-query-without-context",
        // fix-R7-apicheck-taxonomy-v1 (v0.5.0 CLOSEOUT): this rule is about
        // context-driven cancellation/timeout propagation (QueryContext vs
        // Query), not statement ordering. `Concurrency` is the closest
        // existing bucket; `CallOrder` mis-bucketed it in summary.by_category.
        category: MisuseCategory::Concurrency,
        severity: MisuseSeverity::Medium,
        description:
            "sql.DB.Query lacks cancellation and timeout propagation compared with QueryContext",
        correct_usage: "Use db.QueryContext(ctx, query, args...)",
        pattern: r"\bsql\.Query\s*\(",
        api_call: "sql.Query",
        message: "sql.Query omits context-driven cancellation and timeout handling",
        fix_suggestion: "Use QueryContext/ExecContext with a bounded context",
    },
];

const JAVA_RULE_SPECS: &[RegexRuleSpec] = &[
    RegexRuleSpec {
        id: "JV001",
        name: "string-comparison-with-double-equals",
        // fix-R7-apicheck-taxonomy-v1 (v0.5.0 CLOSEOUT): value-vs-reference
        // equality is a logic-correctness bug, not a call-ordering issue.
        category: MisuseCategory::Correctness,
        severity: MisuseSeverity::Medium,
        description: "Using == on strings compares references instead of values",
        correct_usage: "Use value.equals(other) or Objects.equals(a, b)",
        pattern: r#"(?:".*"|\b\w+\b)\s*==\s*(?:".*"|\b\w+\b)"#,
        api_call: "==",
        message: "String comparison with == checks reference identity, not value equality",
        fix_suggestion: "Use .equals(...) or Objects.equals(...) for string values",
    },
    RegexRuleSpec {
        id: "JV002",
        name: "runtime-exec",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "Runtime.exec is dangerous with dynamic input and hard to sandbox correctly",
        correct_usage: "Use structured APIs or a ProcessBuilder with validated arguments",
        pattern: r"\bRuntime\.getRuntime\(\)\.exec\s*\(",
        api_call: "Runtime.exec",
        message: "Runtime.exec is a common command injection footgun",
        fix_suggestion: "Prefer library APIs or tightly validated ProcessBuilder arguments",
    },
    RegexRuleSpec {
        id: "JV003",
        name: "objectinputstream-deserialization",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description:
            "ObjectInputStream on untrusted data can trigger unsafe deserialization gadgets",
        correct_usage: "Use safer formats like JSON with explicit schemas",
        pattern: r"\bnew\s+ObjectInputStream\s*\(",
        api_call: "ObjectInputStream",
        message: "ObjectInputStream enables unsafe native Java deserialization",
        fix_suggestion: "Replace native object deserialization with a schema-driven format",
    },
    RegexRuleSpec {
        id: "JV004",
        name: "create-statement",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::Medium,
        description:
            "createStatement often leads to string-built SQL instead of prepared statements",
        correct_usage: "Use prepareStatement with placeholders",
        pattern: r"\bcreateStatement\s*\(",
        api_call: "createStatement",
        message: "createStatement encourages dynamic SQL and weak parameter handling",
        fix_suggestion: "Use prepareStatement with bound parameters",
    },
    RegexRuleSpec {
        id: "JV005",
        name: "system-gc-call",
        category: MisuseCategory::Resources,
        severity: MisuseSeverity::Low,
        description: "System.gc() is usually a performance smell and not a reliable memory fix",
        correct_usage: "Remove manual GC triggers and profile allocations instead",
        pattern: r"\bSystem\.gc\s*\(",
        api_call: "System.gc",
        message: "System.gc() is an unreliable manual GC hint and often harms latency",
        fix_suggestion: "Remove the call and fix the underlying allocation or lifetime issue",
    },
];

const JAVASCRIPT_RULE_SPECS: &[RegexRuleSpec] = &[
    RegexRuleSpec {
        id: "JS001",
        name: "loose-equality",
        // fix-R7-apicheck-taxonomy-v1 (v0.5.0 CLOSEOUT): coercing equality is
        // a logic-correctness bug, not a call-ordering issue.
        category: MisuseCategory::Correctness,
        severity: MisuseSeverity::Medium,
        description: "Loose equality allows coercions that frequently hide correctness bugs",
        correct_usage: "Use === / !== except in deliberately reviewed coercion cases",
        pattern: r"\s==\s|\s!=\s",
        api_call: "==",
        message: "Loose equality can coerce values unexpectedly",
        fix_suggestion: "Use === or !== and handle explicit type conversion",
    },
    RegexRuleSpec {
        id: "JS002",
        name: "parseint-without-radix",
        category: MisuseCategory::Parameters,
        severity: MisuseSeverity::Low,
        description: "parseInt without a radix is ambiguous and less explicit than required",
        correct_usage: "Use parseInt(value, 10)",
        pattern: r"\bparseInt\s*\(\s*[^,\)]+\)",
        api_call: "parseInt",
        message: "parseInt called without an explicit radix",
        fix_suggestion: "Pass a radix explicitly, usually parseInt(value, 10)",
    },
    RegexRuleSpec {
        id: "JS003",
        name: "json-parse-without-guard",
        category: MisuseCategory::ErrorHandling,
        severity: MisuseSeverity::Low,
        description: "JSON.parse throws on malformed input and should usually be guarded",
        correct_usage: "Wrap JSON.parse in try/catch when input is not fully trusted",
        pattern: r"\bJSON\.parse\s*\(",
        api_call: "JSON.parse",
        message: "JSON.parse can throw and should be guarded for untrusted input",
        fix_suggestion: "Use try/catch or validated parsing for untrusted payloads",
    },
    RegexRuleSpec {
        id: "JS004",
        name: "document-write",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "document.write is legacy, brittle, and can inject unsanitized HTML",
        correct_usage: "Use DOM APIs like textContent/appendChild instead",
        pattern: r"\bdocument\.write(?:ln)?\s*\(",
        api_call: "document.write",
        message: "document.write is unsafe and can enable XSS",
        fix_suggestion: "Use safe DOM APIs instead of writing raw HTML strings",
    },
    RegexRuleSpec {
        id: "JS005",
        name: "eval-call",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "eval executes dynamic code and should be avoided",
        correct_usage: "Use structured data parsing or explicit dispatch tables",
        pattern: r"\beval\s*\(",
        api_call: "eval",
        message: "eval executes dynamic code and creates major security risk",
        fix_suggestion: "Replace eval with data parsing or explicit function dispatch",
    },
];

const TYPESCRIPT_RULE_SPECS: &[RegexRuleSpec] = &[
    RegexRuleSpec {
        id: "TS001",
        name: "loose-equality",
        // fix-R7-apicheck-taxonomy-v1 (v0.5.0 CLOSEOUT): coercing equality is
        // a logic-correctness bug, not a call-ordering issue.
        category: MisuseCategory::Correctness,
        severity: MisuseSeverity::Medium,
        description: "Loose equality allows coercions that frequently hide correctness bugs",
        correct_usage: "Use === / !== except in deliberately reviewed coercion cases",
        pattern: r"\s==\s|\s!=\s",
        api_call: "==",
        message: "Loose equality can coerce values unexpectedly",
        fix_suggestion: "Use === or !== and handle explicit type conversion",
    },
    RegexRuleSpec {
        id: "TS002",
        name: "parseint-without-radix",
        category: MisuseCategory::Parameters,
        severity: MisuseSeverity::Low,
        description: "parseInt without a radix is ambiguous and less explicit than required",
        correct_usage: "Use parseInt(value, 10)",
        pattern: r"\bparseInt\s*\(\s*[^,\)]+\)",
        api_call: "parseInt",
        message: "parseInt called without an explicit radix",
        fix_suggestion: "Pass a radix explicitly, usually parseInt(value, 10)",
    },
    RegexRuleSpec {
        id: "TS003",
        name: "json-parse-without-guard",
        category: MisuseCategory::ErrorHandling,
        severity: MisuseSeverity::Low,
        description: "JSON.parse throws on malformed input and should usually be guarded",
        correct_usage: "Wrap JSON.parse in try/catch when input is not fully trusted",
        pattern: r"\bJSON\.parse\s*\(",
        api_call: "JSON.parse",
        message: "JSON.parse can throw and should be guarded for untrusted input",
        fix_suggestion: "Use try/catch or validated parsing for untrusted payloads",
    },
    RegexRuleSpec {
        id: "TS004",
        name: "document-write",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "document.write is legacy, brittle, and can inject unsanitized HTML",
        correct_usage: "Use DOM APIs like textContent/appendChild instead",
        pattern: r"\bdocument\.write(?:ln)?\s*\(",
        api_call: "document.write",
        message: "document.write is unsafe and can enable XSS",
        fix_suggestion: "Use safe DOM APIs instead of writing raw HTML strings",
    },
    RegexRuleSpec {
        id: "TS005",
        name: "eval-call",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "eval executes dynamic code and should be avoided",
        correct_usage: "Use structured data parsing or explicit dispatch tables",
        pattern: r"\beval\s*\(",
        api_call: "eval",
        message: "eval executes dynamic code and creates major security risk",
        fix_suggestion: "Replace eval with data parsing or explicit function dispatch",
    },
];

const C_RULE_SPECS: &[RegexRuleSpec] = &[
    RegexRuleSpec {
        id: "C001",
        name: "gets-call",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "gets cannot bound input and has been removed from the standard library",
        correct_usage: "Use fgets with an explicit buffer length",
        pattern: r"\bgets\s*\(",
        api_call: "gets",
        message: "gets is inherently unsafe and enables buffer overflows",
        fix_suggestion: "Use fgets(buffer, size, stdin) or another bounded API",
    },
    RegexRuleSpec {
        id: "C002",
        name: "strcpy-call",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "strcpy performs unbounded copies and easily overflows buffers",
        correct_usage: "Use snprintf, strlcpy, or explicit bounds checks",
        pattern: r"\bstrcpy\s*\(",
        api_call: "strcpy",
        message: "strcpy performs an unbounded copy",
        fix_suggestion: "Replace strcpy with a bounded copy strategy",
    },
    RegexRuleSpec {
        id: "C003",
        name: "sprintf-call",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "sprintf writes formatted data without a size bound",
        correct_usage: "Use snprintf with the destination buffer size",
        pattern: r"\bsprintf\s*\(",
        api_call: "sprintf",
        message: "sprintf can overflow fixed-size buffers",
        fix_suggestion: "Use snprintf(buffer, size, ...) instead",
    },
    RegexRuleSpec {
        id: "C004",
        name: "scanf-string-without-width",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "scanf with %s and no width limit can overflow the destination buffer",
        correct_usage: "Provide a width specifier or use fgets",
        pattern: r#"\bscanf\s*\(\s*"%s"#,
        api_call: "scanf",
        message: "scanf(\"%s\") reads unbounded input into a buffer",
        fix_suggestion: "Add a width limit or use fgets plus parsing",
    },
    RegexRuleSpec {
        id: "C005",
        name: "system-call",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "system executes a shell command and is dangerous with dynamic input",
        correct_usage: "Use execve-family APIs with validated arguments where possible",
        pattern: r"\bsystem\s*\(",
        api_call: "system",
        message: "system executes a shell and is a common command injection vector",
        fix_suggestion: "Avoid shell execution or tightly validate the command source",
    },
];

const CPP_RULE_SPECS: &[RegexRuleSpec] = &[
    RegexRuleSpec {
        id: "CPP001",
        name: "strcpy-call",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "strcpy performs unbounded copies and easily overflows buffers",
        correct_usage: "Use std::string, snprintf, or another bounded copy strategy",
        pattern: r"\bstrcpy\s*\(",
        api_call: "strcpy",
        message: "strcpy performs an unbounded copy",
        fix_suggestion: "Use std::string or a bounded copy API instead",
    },
    RegexRuleSpec {
        id: "CPP002",
        name: "sprintf-call",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "sprintf writes formatted data without a size bound",
        correct_usage: "Use snprintf or std::format into a bounded container",
        pattern: r"\bsprintf\s*\(",
        api_call: "sprintf",
        message: "sprintf can overflow fixed-size buffers",
        fix_suggestion: "Use snprintf or a safer formatting abstraction",
    },
    RegexRuleSpec {
        id: "CPP003",
        name: "auto-ptr",
        category: MisuseCategory::Resources,
        severity: MisuseSeverity::Medium,
        description: "std::auto_ptr is obsolete and has broken transfer semantics",
        correct_usage: "Use std::unique_ptr or std::shared_ptr",
        pattern: r"\bstd::auto_ptr\s*<",
        api_call: "std::auto_ptr",
        message: "std::auto_ptr is obsolete and unsafe by modern ownership standards",
        fix_suggestion: "Replace std::auto_ptr with std::unique_ptr or std::shared_ptr",
    },
    RegexRuleSpec {
        id: "CPP004",
        name: "raw-new",
        category: MisuseCategory::Resources,
        severity: MisuseSeverity::Medium,
        description: "Raw new often leads to leaks and exception-safety issues",
        correct_usage: "Use std::make_unique or stack allocation where possible",
        pattern: r"\bnew\s+\w",
        api_call: "new",
        message: "Raw new makes ownership and exception safety harder to reason about",
        fix_suggestion: "Use std::make_unique, containers, or stack allocation",
    },
    RegexRuleSpec {
        id: "CPP005",
        name: "system-call",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "system executes a shell command and is dangerous with dynamic input",
        correct_usage: "Use direct process APIs with validated arguments when possible",
        pattern: r"(?:\bstd::)?system\s*\(",
        api_call: "system",
        message: "system executes a shell and is a common command injection vector",
        fix_suggestion: "Avoid shell execution or tightly validate all command components",
    },
];

const RUBY_RULE_SPECS: &[RegexRuleSpec] = &[
    RegexRuleSpec {
        id: "RB001",
        name: "eval-call",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "eval executes dynamic Ruby code and should be avoided",
        correct_usage: "Use explicit dispatch or data parsing instead of dynamic code execution",
        pattern: r"\beval\s*\(",
        api_call: "eval",
        message: "eval executes dynamic code and creates major security risk",
        fix_suggestion: "Replace eval with explicit dispatch or structured parsing",
    },
    RegexRuleSpec {
        id: "RB002",
        name: "dynamic-send",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::Medium,
        description: "send can invoke arbitrary methods when fed untrusted method names",
        correct_usage: "Use public_send on a strict allowlist of method names",
        pattern: r"\.send\s*\(",
        api_call: "send",
        message: "send can dispatch to unsafe or unexpected methods",
        fix_suggestion: "Use public_send with a reviewed allowlist",
    },
    RegexRuleSpec {
        id: "RB003",
        name: "system-call",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "system executes a shell command and is dangerous with interpolated input",
        correct_usage: "Use array-form process APIs with validated arguments",
        pattern: r"\bsystem\s*\(",
        api_call: "system",
        message: "system is a common command injection footgun",
        fix_suggestion: "Avoid shell execution or pass validated argv-style arguments",
    },
    RegexRuleSpec {
        id: "RB004",
        name: "yaml-load",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "YAML.load can instantiate arbitrary objects from untrusted input",
        correct_usage: "Use YAML.safe_load with permitted classes",
        pattern: r"\bYAML\.load\s*\(",
        api_call: "YAML.load",
        message: "YAML.load can deserialize unsafe objects",
        fix_suggestion: "Use YAML.safe_load and restrict allowed classes",
    },
    RegexRuleSpec {
        id: "RB005",
        name: "marshal-load",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "Marshal.load on untrusted data is unsafe deserialization",
        correct_usage: "Use JSON or another safe, schema-checked format",
        pattern: r"\bMarshal\.load\s*\(",
        api_call: "Marshal.load",
        message: "Marshal.load performs unsafe native deserialization",
        fix_suggestion: "Replace Marshal.load with a safer serialization format",
    },
];

const PHP_RULE_SPECS: &[RegexRuleSpec] = &[
    RegexRuleSpec {
        id: "PH001",
        name: "deprecated-mysql-functions",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "mysql_* APIs are removed and encourage unsafe query construction",
        correct_usage: "Use PDO or mysqli with prepared statements",
        pattern: r"\bmysql_[a-z_]+\s*\(",
        api_call: "mysql_*",
        message: "mysql_* functions are removed and unsafe by modern standards",
        fix_suggestion: "Migrate to PDO or mysqli prepared statements",
    },
    RegexRuleSpec {
        id: "PH002",
        name: "extract-call",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::Medium,
        description: "extract pollutes local scope and can overwrite important variables",
        correct_usage: "Read array keys explicitly instead of splatting them into scope",
        pattern: r"\bextract\s*\(",
        api_call: "extract",
        message: "extract can overwrite local variables and hide data flow",
        fix_suggestion: "Assign required keys explicitly instead of using extract",
    },
    RegexRuleSpec {
        id: "PH003",
        name: "eval-call",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "eval executes dynamic PHP code and should be avoided",
        correct_usage: "Use explicit dispatch or data parsing instead of dynamic code execution",
        pattern: r"\beval\s*\(",
        api_call: "eval",
        message: "eval executes dynamic code and creates major security risk",
        fix_suggestion: "Replace eval with explicit dispatch or structured parsing",
    },
    RegexRuleSpec {
        id: "PH004",
        name: "variable-variables",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::Medium,
        description: "Variable variables make scope mutation hard to reason about",
        correct_usage: "Use associative arrays or explicit variables instead",
        pattern: r"\$\$[A-Za-z_]",
        api_call: "$$",
        message: "Variable variables obscure data flow and can enable unsafe access patterns",
        fix_suggestion: "Use an array/map or explicit variable names instead",
    },
    RegexRuleSpec {
        id: "PH005",
        name: "unserialize-call",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "unserialize on untrusted data can trigger object injection chains",
        correct_usage: "Use json_decode or a safer schema-checked format",
        pattern: r"\bunserialize\s*\(",
        api_call: "unserialize",
        message: "unserialize enables unsafe object deserialization",
        fix_suggestion: "Replace unserialize with json_decode or a safe serializer",
    },
];

const KOTLIN_RULE_SPECS: &[RegexRuleSpec] = &[
    RegexRuleSpec {
        id: "KT001",
        name: "force-unwrapped-null",
        category: MisuseCategory::ErrorHandling,
        severity: MisuseSeverity::Medium,
        description: "!! converts nullable values into runtime crashes",
        correct_usage: "Use safe calls, let, requireNotNull, or explicit branching",
        pattern: r"!!",
        api_call: "!!",
        message: "!! will throw NullPointerException on null values",
        fix_suggestion: "Use safe calls or explicit null handling instead of !!",
    },
    RegexRuleSpec {
        id: "KT002",
        name: "lateinit-var",
        category: MisuseCategory::ErrorHandling,
        severity: MisuseSeverity::Low,
        description: "lateinit shifts initialization failures to runtime",
        correct_usage: "Prefer constructor injection or nullable/state wrappers",
        pattern: r"\blateinit\s+var\b",
        api_call: "lateinit",
        message: "lateinit can fail at runtime if the property is read before initialization",
        fix_suggestion: "Prefer constructor injection or explicit nullable state",
    },
    RegexRuleSpec {
        id: "KT003",
        name: "globalscope-launch",
        category: MisuseCategory::Concurrency,
        severity: MisuseSeverity::Medium,
        description: "GlobalScope.launch escapes structured concurrency and leaks work",
        correct_usage: "Launch from a lifecycle-bound CoroutineScope",
        pattern: r"\bGlobalScope\.launch\s*\(",
        api_call: "GlobalScope.launch",
        message: "GlobalScope.launch detaches work from structured concurrency",
        fix_suggestion: "Use a lifecycle-bound CoroutineScope instead",
    },
    RegexRuleSpec {
        id: "KT004",
        name: "runtime-exec",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "Runtime.exec is dangerous with dynamic input and hard to sandbox correctly",
        correct_usage: "Use structured APIs or strictly validated ProcessBuilder arguments",
        pattern: r"\bRuntime\.getRuntime\(\)\.exec\s*\(",
        api_call: "Runtime.exec",
        message: "Runtime.exec is a common command injection footgun",
        fix_suggestion: "Prefer library APIs or tightly validated ProcessBuilder arguments",
    },
    RegexRuleSpec {
        id: "KT005",
        name: "thread-sleep",
        category: MisuseCategory::Concurrency,
        severity: MisuseSeverity::Low,
        description:
            "Thread.sleep blocks threads directly and is usually wrong in coroutine-based code",
        correct_usage: "Use delay(...) in coroutines or higher-level scheduling",
        pattern: r"\bThread\.sleep\s*\(",
        api_call: "Thread.sleep",
        message: "Thread.sleep blocks the current thread directly",
        fix_suggestion: "Use delay(...) or a proper scheduler instead",
    },
];

const SWIFT_RULE_SPECS: &[RegexRuleSpec] = &[
    RegexRuleSpec {
        id: "SW001",
        name: "forced-cast",
        category: MisuseCategory::ErrorHandling,
        severity: MisuseSeverity::Medium,
        description: "as! crashes at runtime when the cast fails",
        correct_usage: "Use as? with conditional handling",
        pattern: r"\bas!\b",
        api_call: "as!",
        message: "Forced casts crash when the runtime type is different",
        fix_suggestion: "Use as? and handle the nil case explicitly",
    },
    RegexRuleSpec {
        id: "SW002",
        name: "forced-try",
        category: MisuseCategory::ErrorHandling,
        severity: MisuseSeverity::Medium,
        description: "try! crashes when the call throws",
        correct_usage: "Use do/catch or try? with explicit fallback",
        pattern: r"\btry!\b",
        api_call: "try!",
        message: "try! crashes the process on thrown errors",
        fix_suggestion: "Use do/catch or try? and handle failure explicitly",
    },
    RegexRuleSpec {
        id: "SW003",
        name: "force-unwrap",
        category: MisuseCategory::ErrorHandling,
        severity: MisuseSeverity::Medium,
        description: "Force unwrapping optionals crashes at runtime on nil",
        correct_usage: "Use if let, guard let, or nil-coalescing",
        pattern: r"\b[A-Za-z_][A-Za-z0-9_]*!",
        api_call: "!",
        message: "Force unwraps crash when the optional is nil",
        fix_suggestion: "Use optional binding or nil-coalescing instead of force unwraps",
    },
    RegexRuleSpec {
        id: "SW004",
        name: "nskeyedunarchiver",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "Legacy NSKeyedUnarchiver APIs on untrusted data are unsafe",
        correct_usage: "Use secure decoding APIs with requiresSecureCoding",
        pattern: r"\bNSKeyedUnarchiver\.unarchiveObject",
        api_call: "NSKeyedUnarchiver",
        message: "Legacy unarchiving can deserialize unexpected object graphs",
        fix_suggestion: "Use secure coding APIs and schema-checked decoding",
    },
    RegexRuleSpec {
        id: "SW005",
        name: "fatalerror-call",
        category: MisuseCategory::ErrorHandling,
        severity: MisuseSeverity::Low,
        description:
            "fatalError terminates the process and is risky outside clearly impossible states",
        correct_usage: "Return/throw recoverable errors where possible",
        pattern: r"\bfatalError\s*\(",
        api_call: "fatalError",
        message: "fatalError terminates the process immediately",
        fix_suggestion: "Use recoverable error handling unless the state is truly unreachable",
    },
];

const CSHARP_RULE_SPECS: &[RegexRuleSpec] = &[
    RegexRuleSpec {
        id: "CS001",
        name: "binaryformatter",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "BinaryFormatter is insecure and obsolete for untrusted data",
        correct_usage: "Use System.Text.Json or another safe serializer",
        pattern: r"\bBinaryFormatter\b",
        api_call: "BinaryFormatter",
        message: "BinaryFormatter is insecure and should not be used",
        fix_suggestion: "Use System.Text.Json or another safe serializer",
    },
    RegexRuleSpec {
        id: "CS002",
        name: "gc-collect",
        category: MisuseCategory::Resources,
        severity: MisuseSeverity::Low,
        description: "GC.Collect is rarely the right fix and often harms latency",
        correct_usage: "Remove manual GC triggers and profile the real allocation issue",
        pattern: r"\bGC\.Collect\s*\(",
        api_call: "GC.Collect",
        message: "GC.Collect is an unreliable manual GC hint and often harms performance",
        fix_suggestion: "Remove the call and fix the underlying allocation issue",
    },
    RegexRuleSpec {
        id: "CS003",
        name: "task-result",
        category: MisuseCategory::Concurrency,
        severity: MisuseSeverity::Medium,
        description: "Task.Result blocks synchronously and can deadlock async flows",
        correct_usage: "Use await instead of blocking on Task.Result",
        pattern: r"\.Result\b",
        api_call: "Task.Result",
        message: "Task.Result blocks synchronously and can deadlock async contexts",
        fix_suggestion: "Use await and keep the async chain asynchronous",
    },
    RegexRuleSpec {
        id: "CS004",
        name: "task-wait",
        category: MisuseCategory::Concurrency,
        severity: MisuseSeverity::Medium,
        description: "Task.Wait blocks synchronously and can deadlock async flows",
        correct_usage: "Use await or WhenAll/WhenAny instead of blocking waits",
        pattern: r"\.Wait\s*\(",
        api_call: "Task.Wait",
        message: "Task.Wait blocks synchronously and can deadlock async contexts",
        fix_suggestion: "Use await or asynchronous coordination primitives instead",
    },
    RegexRuleSpec {
        id: "CS005",
        name: "process-start",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "Process.Start is dangerous with untrusted paths or arguments",
        correct_usage: "Use strict allowlists and avoid shell execution semantics",
        pattern: r"\bProcess\.Start\s*\(",
        api_call: "Process.Start",
        message: "Process.Start can enable command injection with untrusted inputs",
        fix_suggestion: "Validate executable and arguments against a strict allowlist",
    },
];

const SCALA_RULE_SPECS: &[RegexRuleSpec] = &[
    RegexRuleSpec {
        id: "SC001",
        name: "null-usage",
        category: MisuseCategory::ErrorHandling,
        severity: MisuseSeverity::Low,
        description: "null bypasses Scala's stronger option-based absence modeling",
        correct_usage: "Use Option instead of null",
        pattern: r"\bnull\b",
        api_call: "null",
        message: "null reintroduces runtime absence bugs into Scala code",
        fix_suggestion: "Use Option and explicit pattern matching instead",
    },
    RegexRuleSpec {
        id: "SC002",
        name: "asinstanceof-cast",
        category: MisuseCategory::ErrorHandling,
        severity: MisuseSeverity::Medium,
        description: "asInstanceOf crashes at runtime when the type assumption is wrong",
        correct_usage: "Use pattern matching or TypeTag/ClassTag-aware APIs",
        pattern: r"\basInstanceOf\[",
        api_call: "asInstanceOf",
        message: "asInstanceOf creates unchecked runtime casts",
        fix_suggestion: "Use pattern matching or safer typed abstractions",
    },
    RegexRuleSpec {
        id: "SC003",
        name: "await-result",
        category: MisuseCategory::Concurrency,
        severity: MisuseSeverity::Medium,
        description: "Await.result blocks threads and can collapse asynchronous throughput",
        correct_usage: "Compose futures asynchronously instead of blocking",
        pattern: r"\bAwait\.result\s*\(",
        api_call: "Await.result",
        message: "Await.result blocks threads and can create deadlocks or latency spikes",
        fix_suggestion: "Use map/flatMap/for-comprehensions instead of blocking",
    },
    RegexRuleSpec {
        id: "SC004",
        name: "mutable-collection",
        category: MisuseCategory::Concurrency,
        severity: MisuseSeverity::Low,
        description: "scala.collection.mutable structures are harder to reason about under concurrency",
        correct_usage: "Prefer immutable collections unless mutation is intentionally scoped",
        pattern: r"\bscala\.collection\.mutable\.",
        api_call: "scala.collection.mutable",
        message: "Mutable collections can hide shared-state bugs",
        fix_suggestion: "Prefer immutable collections or encapsulate mutation carefully",
    },
    RegexRuleSpec {
        id: "SC005",
        name: "sys-process",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "sys.process.Process executes external commands and is dangerous with input-derived values",
        correct_usage: "Use library APIs or validate commands and arguments against an allowlist",
        pattern: r"\bsys\.process\.Process\s*\(",
        api_call: "sys.process.Process",
        message: "sys.process.Process can enable command injection with untrusted input",
        fix_suggestion: "Avoid shell-style execution or strictly validate all command parts",
    },
];

const ELIXIR_RULE_SPECS: &[RegexRuleSpec] = &[
    RegexRuleSpec {
        id: "EX001",
        name: "string-to-atom",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "String.to_atom on untrusted input can exhaust the VM atom table",
        correct_usage: "Use String.to_existing_atom only for reviewed values or keep strings",
        pattern: r"\bString\.to_atom\s*\(",
        api_call: "String.to_atom",
        message: "String.to_atom can permanently grow the atom table from user input",
        fix_suggestion: "Keep values as strings or use a reviewed to_existing_atom path",
    },
    RegexRuleSpec {
        id: "EX002",
        name: "code-eval-string",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "Code.eval_string executes dynamic Elixir code and should be avoided",
        correct_usage: "Use explicit dispatch or data parsing instead of dynamic evaluation",
        pattern: r"\bCode\.eval_string\s*\(",
        api_call: "Code.eval_string",
        message: "Code.eval_string executes dynamic code and is a major security risk",
        fix_suggestion: "Replace dynamic evaluation with explicit dispatch or parsing",
    },
    RegexRuleSpec {
        id: "EX003",
        name: "binary-to-term",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: ":erlang.binary_to_term on untrusted data is unsafe deserialization",
        correct_usage: "Use safe formats like JSON or term_to_binary only for trusted data",
        pattern: r":erlang\.binary_to_term\s*\(",
        api_call: ":erlang.binary_to_term",
        message: ":erlang.binary_to_term can deserialize unsafe terms from untrusted input",
        fix_suggestion: "Use a safer serialization format for external input",
    },
    RegexRuleSpec {
        id: "EX004",
        name: "file-read-bang",
        category: MisuseCategory::ErrorHandling,
        severity: MisuseSeverity::Low,
        description: "Bang file APIs raise instead of returning tagged tuples",
        correct_usage: "Prefer File.read/1 with explicit {:ok, data} / {:error, reason} handling",
        pattern: r"\bFile\.read!\s*\(",
        api_call: "File.read!",
        message: "File.read! raises on failure instead of returning a recoverable error",
        fix_suggestion: "Use File.read/1 and handle the returned tuple explicitly",
    },
    RegexRuleSpec {
        id: "EX005",
        name: "task-await-infinity",
        category: MisuseCategory::Concurrency,
        severity: MisuseSeverity::Medium,
        description: "Task.await with :infinity can stall callers indefinitely",
        correct_usage: "Use bounded timeouts and supervised retry/cancellation behavior",
        pattern: r"\bTask\.await\s*\([^,]+,\s*:infinity\s*\)",
        api_call: "Task.await",
        message: "Task.await(..., :infinity) can block forever",
        fix_suggestion: "Use a bounded timeout and explicit failure handling",
    },
];

const LUA_RULE_SPECS: &[RegexRuleSpec] = &[
    RegexRuleSpec {
        id: "LU001",
        name: "implicit-global",
        // fix-R7-apicheck-taxonomy-v1 (v0.5.0 CLOSEOUT): leaking a global by
        // omitting `local` is a logic-correctness/scope hazard, not a
        // call-ordering issue.
        category: MisuseCategory::Correctness,
        severity: MisuseSeverity::Low,
        description: "Assigning without local leaks mutable globals and creates hidden coupling",
        correct_usage: "Declare locals explicitly with local name = ...",
        pattern: r"^[A-Za-z_][A-Za-z0-9_]*\s*=",
        api_call: "global assignment",
        message: "Implicit global assignment leaks state outside local scope",
        fix_suggestion: "Prefix the binding with local to keep scope explicit",
    },
    RegexRuleSpec {
        id: "LU002",
        name: "dynamic-load",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "load/loadstring execute dynamic Lua code and should be avoided",
        correct_usage: "Use structured parsing or explicit dispatch instead of dynamic evaluation",
        pattern: r"\b(?:loadstring|load)\s*\(",
        api_call: "load",
        message: "Dynamic code loading executes attacker-controlled Lua if fed untrusted input",
        fix_suggestion: "Replace dynamic evaluation with explicit dispatch or parsing",
    },
    RegexRuleSpec {
        id: "LU003",
        name: "os-execute",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "os.execute shells out and is dangerous with dynamic input",
        correct_usage: "Avoid shell execution or validate every command component",
        pattern: r"\bos\.execute\s*\(",
        api_call: "os.execute",
        message: "os.execute can enable command injection with untrusted input",
        fix_suggestion: "Avoid shelling out or strictly validate the command source",
    },
    RegexRuleSpec {
        id: "LU004",
        name: "io-popen",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "io.popen launches shell commands and should be treated as high risk",
        correct_usage: "Use safer process APIs or validate all command components",
        pattern: r"\bio\.popen\s*\(",
        api_call: "io.popen",
        message: "io.popen can enable command injection with untrusted input",
        fix_suggestion: "Avoid shell execution or validate every command component",
    },
    RegexRuleSpec {
        id: "LU005",
        name: "dofile-loadfile",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::Medium,
        description:
            "dofile/loadfile execute external files and are risky with user-controlled paths",
        correct_usage: "Validate file origins strictly before executing them",
        pattern: r"\b(?:dofile|loadfile)\s*\(",
        api_call: "dofile",
        message: "Executing external files is dangerous when the path is not fully trusted",
        fix_suggestion: "Avoid dynamic file execution or tightly validate trusted origins",
    },
];

const OCAML_RULE_SPECS: &[RegexRuleSpec] = &[
    RegexRuleSpec {
        id: "OC001",
        name: "marshal-from-string",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "Marshal.from_string on untrusted data is unsafe native deserialization",
        correct_usage: "Use a safe, schema-checked serialization format",
        pattern: r"\bMarshal\.from_string\b",
        api_call: "Marshal.from_string",
        message: "Marshal.from_string can deserialize unsafe values from untrusted input",
        fix_suggestion: "Use a safer serialization format for external input",
    },
    RegexRuleSpec {
        id: "OC002",
        name: "marshal-from-channel",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "Marshal.from_channel on untrusted data is unsafe native deserialization",
        correct_usage: "Use a safe, schema-checked serialization format",
        pattern: r"\bMarshal\.from_channel\b",
        api_call: "Marshal.from_channel",
        message: "Marshal.from_channel can deserialize unsafe values from untrusted input",
        fix_suggestion: "Use a safer serialization format for external input",
    },
    RegexRuleSpec {
        id: "OC003",
        name: "sys-command",
        category: MisuseCategory::Security,
        severity: MisuseSeverity::High,
        description: "Sys.command executes a shell command and is dangerous with dynamic input",
        correct_usage: "Prefer direct library APIs or validate allowed commands strictly",
        pattern: r"\bSys\.command\b",
        api_call: "Sys.command",
        message: "Sys.command can enable command injection with untrusted input",
        fix_suggestion: "Avoid shell execution or tightly validate the command source",
    },
    RegexRuleSpec {
        id: "OC004",
        name: "obj-magic",
        category: MisuseCategory::ErrorHandling,
        severity: MisuseSeverity::High,
        description: "Obj.magic bypasses the type system and can produce memory-unsound behavior",
        correct_usage: "Use typed abstractions or explicit variant handling",
        pattern: r"\bObj\.magic\b",
        api_call: "Obj.magic",
        message: "Obj.magic bypasses type safety and can create undefined behavior",
        fix_suggestion: "Refactor to a typed abstraction instead of coercing with Obj.magic",
    },
    RegexRuleSpec {
        id: "OC005",
        name: "open-in-out",
        category: MisuseCategory::Resources,
        severity: MisuseSeverity::Low,
        description: "open_in/open_out require explicit close calls and are easy to leak",
        correct_usage: "Use In_channel.with_open_* or Out_channel.with_open_* helpers",
        pattern: r"\b(?:open_in|open_out)\b",
        api_call: "open_in",
        message: "open_in/open_out require explicit close handling and are easy to leak",
        fix_suggestion: "Use with_open_* helpers to scope the channel lifetime",
    },
];

const ALL_API_LANGUAGES: &[ApiLanguage] = &[
    ApiLanguage::Python,
    ApiLanguage::Rust,
    ApiLanguage::Go,
    ApiLanguage::Java,
    ApiLanguage::JavaScript,
    ApiLanguage::TypeScript,
    ApiLanguage::C,
    ApiLanguage::Cpp,
    ApiLanguage::Ruby,
    ApiLanguage::Php,
    ApiLanguage::Kotlin,
    ApiLanguage::Swift,
    ApiLanguage::CSharp,
    ApiLanguage::Scala,
    ApiLanguage::Elixir,
    ApiLanguage::Lua,
    ApiLanguage::Luau,
    ApiLanguage::Ocaml,
    ApiLanguage::Solidity,
];

// =============================================================================
// Rule Definitions
// =============================================================================

/// Built-in Python API misuse rules
fn python_rules() -> Vec<APIRule> {
    vec![
        APIRule {
            id: "PY001".to_string(),
            name: "missing-timeout".to_string(),
            category: MisuseCategory::Parameters,
            severity: MisuseSeverity::High,
            description: "requests.get/post/etc without timeout parameter can hang indefinitely"
                .to_string(),
            correct_usage: "requests.get(url, timeout=30)".to_string(),
        },
        APIRule {
            id: "PY002".to_string(),
            name: "bare-except".to_string(),
            category: MisuseCategory::ErrorHandling,
            severity: MisuseSeverity::Medium,
            description: "Bare except clause catches all exceptions including KeyboardInterrupt"
                .to_string(),
            correct_usage: "except Exception as e:".to_string(),
        },
        APIRule {
            id: "PY003".to_string(),
            name: "weak-hash-md5".to_string(),
            category: MisuseCategory::Crypto,
            severity: MisuseSeverity::High,
            description: "MD5 is cryptographically broken, don't use for security purposes"
                .to_string(),
            correct_usage: "hashlib.sha256() or bcrypt for passwords".to_string(),
        },
        APIRule {
            id: "PY004".to_string(),
            name: "weak-hash-sha1".to_string(),
            category: MisuseCategory::Crypto,
            severity: MisuseSeverity::High,
            description: "SHA1 is cryptographically weak, don't use for security purposes"
                .to_string(),
            correct_usage: "hashlib.sha256() or stronger".to_string(),
        },
        APIRule {
            id: "PY005".to_string(),
            name: "unclosed-file".to_string(),
            category: MisuseCategory::Resources,
            severity: MisuseSeverity::Medium,
            description: "File opened without context manager may not be properly closed"
                .to_string(),
            correct_usage: "with open(path) as f:".to_string(),
        },
        APIRule {
            id: "PY006".to_string(),
            name: "insecure-random".to_string(),
            category: MisuseCategory::Security,
            severity: MisuseSeverity::High,
            description: "random module is not cryptographically secure".to_string(),
            correct_usage: "secrets.token_bytes() or secrets.token_hex()".to_string(),
        },
    ]
}

/// Built-in Rust API misuse rules
fn rust_rules() -> Vec<APIRule> {
    vec![
        APIRule {
            id: "RS001".to_string(),
            name: "mutex-lock-unwrap".to_string(),
            category: MisuseCategory::Concurrency,
            severity: MisuseSeverity::Medium,
            description: "Mutex::lock().unwrap() can panic and amplify lock contention (CWE-833)"
                .to_string(),
            correct_usage:
                "Prefer try_lock()/error handling or explicit poison recovery instead of unwrap()"
                    .to_string(),
        },
        APIRule {
            id: "RS002".to_string(),
            name: "file-open-without-context".to_string(),
            category: MisuseCategory::ErrorHandling,
            severity: MisuseSeverity::Low,
            description:
                "File::open without contextual error mapping makes failures hard to triage"
                    .to_string(),
            correct_usage:
                "File::open(path).with_context(|| format!(\"opening {}\", path.display()))?"
                    .to_string(),
        },
        APIRule {
            id: "RS003".to_string(),
            name: "unbounded-with-capacity".to_string(),
            category: MisuseCategory::Resources,
            severity: MisuseSeverity::High,
            description:
                "Vec::with_capacity fed from unbounded input can cause memory exhaustion (CWE-770)"
                    .to_string(),
            correct_usage: "Clamp capacity input before allocation (e.g. min(user_len, MAX))"
                .to_string(),
        },
        APIRule {
            id: "RS004".to_string(),
            name: "detached-tokio-spawn".to_string(),
            category: MisuseCategory::Concurrency,
            severity: MisuseSeverity::Medium,
            description: "tokio::spawn without retaining JoinHandle risks silent task failures"
                .to_string(),
            correct_usage: "Store JoinHandle values and await/join them".to_string(),
        },
        APIRule {
            id: "RS005".to_string(),
            name: "hashmap-order-dependence".to_string(),
            category: MisuseCategory::CallOrder,
            severity: MisuseSeverity::Low,
            description:
                "HashMap iteration order is non-deterministic; relying on it can break logic"
                    .to_string(),
            correct_usage:
                "Collect keys and sort them, or use BTreeMap/IndexMap when stable order is required"
                    .to_string(),
        },
        APIRule {
            id: "RS006".to_string(),
            name: "clone-in-hot-loop".to_string(),
            category: MisuseCategory::Resources,
            severity: MisuseSeverity::Low,
            description: "clone() inside loop bodies can create avoidable allocation pressure"
                .to_string(),
            correct_usage: "Borrow or move values instead of cloning in tight loops".to_string(),
        },
    ]
}

// =============================================================================
// Solidity ERC conformance rules (fix-pack-apicheck-v1, v0.5.0 PACK-APICHECK)
// =============================================================================
//
// These rules are CONTRACT-LEVEL and fully AST-driven. They never run through
// the per-line `check_rule` / `check_regex_rule` path; `analyze_file`
// dispatches Solidity files straight to `analyze_solidity_erc`, which walks
// the tree-sitter-solidity parse (`contract_declaration` /
// `interface_declaration`, `function_definition`, `event_definition`,
// `inheritance_specifier`) and matches member SIGNATURES (name + arity +
// parameter element types + return arity) against the EIP-defined surface.
//
//   * ERC001 — ERC20 conformance. A contract that CLAIMS ERC20 (inherits an
//     ERC20 base/interface, OR declares a strong subset of the ERC20 surface)
//     must expose `totalSupply / balanceOf / transfer / transferFrom /
//     approve / allowance` with the right signatures, plus the `Transfer` and
//     `Approval` events. Missing or mis-signed members are flagged.
//   * ERC002 — ERC721 conformance (`balanceOf / ownerOf / safeTransferFrom /
//     transferFrom / approve / setApprovalForAll / getApproved /
//     isApprovedForAll` + `Transfer / Approval / ApprovalForAll` events).
//   * ERC003 — SafeERC20 recommendation: a raw ERC20 `transfer` /
//     `transferFrom` call whose boolean return value is discarded (not
//     wrapped in `require(...)`, not assigned, not the RHS of a comparison).

/// One required member of an ERC interface, matched by SIGNATURE against the
/// AST (never by text). `param_types` are the canonical Solidity element
/// types of each parameter, in order; `min_returns` is the number of return
/// values the standard mandates. A function in the contract conforms to this
/// spec when its name matches, its parameter element-type sequence matches,
/// and it returns at least `min_returns` values.
#[derive(Clone, Copy)]
struct ErcMember {
    /// Canonical member name (e.g. `transfer`).
    name: &'static str,
    /// Canonical element type of each parameter, in declaration order. We
    /// compare the *element* type (`address`, `uint256`, `bool`, `bytes`)
    /// extracted from each `parameter` node's `type_name`, ignoring data
    /// location (`memory` / `calldata`) and the parameter's own name.
    param_types: &'static [&'static str],
    /// Minimum number of return values the EIP mandates.
    min_returns: usize,
}

/// An ERC standard's required member + event surface.
struct ErcStandard {
    /// Rule id emitted for conformance violations (`ERC001` / `ERC002`).
    rule_id: &'static str,
    /// Human label (`ERC20` / `ERC721`).
    label: &'static str,
    /// Base / interface names whose inheritance is a positive "claims this
    /// standard" signal (matched against `inheritance_specifier` bases).
    claim_bases: &'static [&'static str],
    /// Member names that are DISTINCTIVE to this standard — i.e. they do not
    /// also appear in the surface of a sibling ERC standard. Declaring one of
    /// these (without inheriting a base) is what marks a contract as
    /// "claiming" this standard. ERC20 and ERC721 share `balanceOf` /
    /// `transferFrom` / `approve`, so those are NOT distinctive; `allowance` /
    /// `totalSupply` distinguish ERC20, and `ownerOf` / `setApprovalForAll` /
    /// `getApproved` / `isApprovedForAll` distinguish ERC721.
    distinctive_members: &'static [&'static str],
    /// Required functions, by signature.
    functions: &'static [ErcMember],
    /// Required event names (matched against `event_definition` names).
    events: &'static [&'static str],
}

/// ERC20 surface per EIP-20.
const ERC20_STANDARD: ErcStandard = ErcStandard {
    rule_id: "ERC001",
    label: "ERC20",
    claim_bases: &["IERC20", "ERC20", "IERC20Metadata", "ERC20Upgradeable"],
    distinctive_members: &["allowance", "totalSupply"],
    functions: &[
        ErcMember { name: "totalSupply", param_types: &[], min_returns: 1 },
        ErcMember { name: "balanceOf", param_types: &["address"], min_returns: 1 },
        ErcMember { name: "transfer", param_types: &["address", "uint256"], min_returns: 1 },
        ErcMember {
            name: "transferFrom",
            param_types: &["address", "address", "uint256"],
            min_returns: 1,
        },
        ErcMember { name: "approve", param_types: &["address", "uint256"], min_returns: 1 },
        ErcMember { name: "allowance", param_types: &["address", "address"], min_returns: 1 },
    ],
    events: &["Transfer", "Approval"],
};

/// ERC721 surface per EIP-721 (core, excluding the optional metadata /
/// enumerable extensions). `safeTransferFrom` is overloaded; we require the
/// 3-arg form (the 4-arg `bytes data` overload is also part of the standard
/// but a contract exposing the 3-arg form satisfies the core requirement —
/// the overload is matched leniently by name+arity in `member_present`).
const ERC721_STANDARD: ErcStandard = ErcStandard {
    rule_id: "ERC002",
    label: "ERC721",
    claim_bases: &["IERC721", "ERC721", "ERC721Upgradeable"],
    // `ownerOf` and `getApproved` are EXCLUSIVE to ERC721 among the common
    // token standards: ERC1155 (which also has `setApprovalForAll` /
    // `isApprovedForAll`) defines neither, and its `balanceOf` takes
    // `(address, uint256)`. Restricting the distinctive set to these two
    // avoids misclassifying an ERC1155 contract as an incomplete ERC721.
    distinctive_members: &["ownerOf", "getApproved"],
    functions: &[
        ErcMember { name: "balanceOf", param_types: &["address"], min_returns: 1 },
        ErcMember { name: "ownerOf", param_types: &["uint256"], min_returns: 1 },
        ErcMember {
            name: "safeTransferFrom",
            param_types: &["address", "address", "uint256"],
            min_returns: 0,
        },
        ErcMember {
            name: "transferFrom",
            param_types: &["address", "address", "uint256"],
            min_returns: 0,
        },
        ErcMember { name: "approve", param_types: &["address", "uint256"], min_returns: 0 },
        ErcMember {
            name: "setApprovalForAll",
            param_types: &["address", "bool"],
            min_returns: 0,
        },
        ErcMember { name: "getApproved", param_types: &["uint256"], min_returns: 1 },
        ErcMember {
            name: "isApprovedForAll",
            param_types: &["address", "address"],
            min_returns: 1,
        },
    ],
    events: &["Transfer", "Approval", "ApprovalForAll"],
};

/// All ERC standards checked, in id order.
const ERC_STANDARDS: &[&ErcStandard] = &[&ERC20_STANDARD, &ERC721_STANDARD];

/// Built-in Solidity API misuse rules (ERC conformance + SafeERC20).
fn solidity_rules() -> Vec<APIRule> {
    vec![
        APIRule {
            id: "ERC001".to_string(),
            name: "erc20-conformance".to_string(),
            category: MisuseCategory::Security,
            severity: MisuseSeverity::High,
            description:
                "Contract claims ERC20 but is missing or mis-signs a required member/event"
                    .to_string(),
            correct_usage:
                "Expose totalSupply/balanceOf/transfer/transferFrom/approve/allowance with the EIP-20 signatures and emit Transfer/Approval"
                    .to_string(),
        },
        APIRule {
            id: "ERC002".to_string(),
            name: "erc721-conformance".to_string(),
            category: MisuseCategory::Security,
            severity: MisuseSeverity::High,
            description:
                "Contract claims ERC721 but is missing or mis-signs a required member/event"
                    .to_string(),
            correct_usage:
                "Expose balanceOf/ownerOf/safeTransferFrom/transferFrom/approve/setApprovalForAll/getApproved/isApprovedForAll and emit Transfer/Approval/ApprovalForAll"
                    .to_string(),
        },
        APIRule {
            id: "ERC003".to_string(),
            name: "unchecked-erc20-transfer".to_string(),
            category: MisuseCategory::Security,
            severity: MisuseSeverity::Medium,
            description:
                "Raw ERC20 transfer/transferFrom return value is discarded; non-reverting tokens fail silently"
                    .to_string(),
            correct_usage:
                "Use OpenZeppelin SafeERC20 (safeTransfer/safeTransferFrom) or wrap the call in require(...)"
                    .to_string(),
        },
    ]
}

/// Entry point: analyze a Solidity source file for ERC conformance and
/// SafeERC20 issues. Parses ONCE via tree-sitter-solidity and walks the AST;
/// returns one `MisuseFinding` per violation. On a parse failure we return no
/// findings (a parser hiccup must never produce phantom conformance errors).
fn analyze_solidity_erc(content: &str, file: &str) -> Vec<MisuseFinding> {
    let tree = match tldr_core::ast::parser::parse(content, Language::Solidity) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let rules = solidity_rules();
    let rule_by_id = |id: &str| rules.iter().find(|r| r.id == id).cloned();

    let mut findings = Vec::new();
    let root = tree.root_node();

    // Collect every top-level contract/interface declaration.
    let mut contracts = Vec::new();
    collect_solidity_contracts(root, &mut contracts);

    for contract in &contracts {
        let name = solidity_contract_name(contract, content);
        let bases = solidity_contract_bases(contract, content);
        let functions = solidity_contract_functions(contract, content);
        let events = solidity_contract_events(contract, content);

        // ERC001 / ERC002 conformance.
        for standard in ERC_STANDARDS {
            let inherits_base = bases
                .iter()
                .any(|b| standard.claim_bases.iter().any(|cb| b == cb));

            // A contract that inherits the canonical standard interface/base
            // (e.g. `contract Foo is IERC20`) DELEGATES its surface to that
            // base: the required members and events are provided by the
            // inherited interface, not necessarily redeclared in this body.
            // Without cross-file inheritance resolution we cannot prove a
            // member is genuinely absent, and flagging a non-redeclared
            // member would be a false positive on every real implementation
            // (OpenZeppelin `ERC20 is IERC20` redeclares none of the events).
            // So strict member/event conformance is only enforced for
            // SELF-CONTAINED declarations: interfaces / contracts that claim
            // the standard by declaring its DISTINCTIVE members locally but
            // do NOT inherit the canonical base.
            if inherits_base {
                continue;
            }
            if !contract_claims_standard(standard, &bases, &functions) {
                continue;
            }
            let line = contract.start_position().row as u32 + 1;
            let Some(rule) = rule_by_id(standard.rule_id) else {
                continue;
            };

            for member in standard.functions {
                if !member_present(&functions, member) {
                    findings.push(MisuseFinding {
                        file: file.to_string(),
                        line,
                        column: 1,
                        rule: rule.clone(),
                        api_call: format!("{}.{}", standard.label, member.name),
                        message: format!(
                            "{} contract `{}` is missing or mis-signs required member `{}({})`",
                            standard.label,
                            name,
                            member.name,
                            member.param_types.join(",")
                        ),
                        fix_suggestion: format!(
                            "Declare `function {}({}) ...` matching the {} standard signature",
                            member.name,
                            member.param_types.join(", "),
                            standard.label
                        ),
                        code_context: name.clone(),
                    });
                }
            }
            for ev in standard.events {
                if !events.iter().any(|e| e == ev) {
                    findings.push(MisuseFinding {
                        file: file.to_string(),
                        line,
                        column: 1,
                        rule: rule.clone(),
                        api_call: format!("{}.{}", standard.label, ev),
                        message: format!(
                            "{} contract `{}` is missing required event `{}`",
                            standard.label, name, ev
                        ),
                        fix_suggestion: format!("Declare `event {}(...)` per the {} standard", ev, standard.label),
                        code_context: name.clone(),
                    });
                }
            }
        }
    }

    // ERC003: SafeERC20 recommendation — raw transfer/transferFrom whose
    // boolean return value is discarded.
    if let Some(rule) = rule_by_id("ERC003") {
        collect_unchecked_erc20_transfers(root, content, file, &rule, &mut findings);
    }

    findings
}

/// Recursively collect every `contract_declaration` / `interface_declaration`
/// / `library_declaration` under `node`.
fn collect_solidity_contracts<'a>(node: tree_sitter::Node<'a>, out: &mut Vec<tree_sitter::Node<'a>>) {
    if matches!(
        node.kind(),
        "contract_declaration" | "interface_declaration" | "library_declaration"
    ) {
        out.push(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_solidity_contracts(child, out);
    }
}

/// Textual name of a contract/interface/library declaration.
fn solidity_contract_name(contract: &tree_sitter::Node, source: &str) -> String {
    contract
        .child_by_field_name("name")
        .map(|n| source[n.byte_range()].to_string())
        .unwrap_or_default()
}

/// Base names declared in the `is A, B` inheritance list, extracted from each
/// `inheritance_specifier`'s `ancestor` (`user_defined_type`). Mirrors
/// `crates/tldr-core/src/inheritance/solidity.rs::extract_solidity_bases`.
fn solidity_contract_bases(contract: &tree_sitter::Node, source: &str) -> Vec<String> {
    let mut bases = Vec::new();
    let mut cursor = contract.walk();
    for child in contract.children(&mut cursor) {
        if child.kind() != "inheritance_specifier" {
            continue;
        }
        let ancestor = child.child_by_field_name("ancestor").or_else(|| {
            let mut ic = child.walk();
            let kids: Vec<_> = child.children(&mut ic).collect();
            kids.into_iter().find(|c| c.kind() == "user_defined_type")
        });
        if let Some(anc) = ancestor {
            // The base name is the first identifier / member_expression in
            // the user_defined_type node.
            let mut nc = anc.walk();
            let mut pushed = false;
            for n in anc.children(&mut nc) {
                if matches!(n.kind(), "identifier" | "member_expression") {
                    bases.push(source[n.byte_range()].to_string());
                    pushed = true;
                    break;
                }
            }
            if !pushed {
                bases.push(source[anc.byte_range()].trim().to_string());
            }
        }
    }
    bases
}

/// Body node of a contract/interface/library declaration.
fn solidity_contract_body<'a>(contract: &tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
    if let Some(body) = contract.child_by_field_name("body") {
        return Some(body);
    }
    let mut cursor = contract.walk();
    for child in contract.children(&mut cursor) {
        if matches!(child.kind(), "contract_body" | "interface_body" | "library_body") {
            return Some(child);
        }
    }
    None
}

/// A function member parsed from a `function_definition`: name, ordered
/// parameter element types, and return arity.
struct SolFunction {
    name: String,
    param_types: Vec<String>,
    return_count: usize,
}

/// Collect every `function_definition` directly under the contract body,
/// parsing each into a `SolFunction` (name + parameter element types +
/// return arity). Constructors / fallback-receive are not ERC members and
/// are skipped.
///
/// fix-R7-cl4 (v0.5.0 CLOSEOUT): ALSO synthesize a `SolFunction` for every
/// `public` state-variable declaration. In Solidity, a `public` state var
/// auto-generates an external getter with the SAME name: `T public x;` →
/// `function x() returns (T)`; `mapping(K => V) public m;` →
/// `function m(K) returns (V)`; nested mappings flatten their key types in
/// order (`mapping(K1 => mapping(K2 => V)) public m;` → `function m(K1, K2)
/// returns (V)`). Without this, ERC002 falsely reported `getApproved` /
/// `isApprovedForAll` missing on contracts (e.g. solmate `ERC721.sol`) that
/// expose them as public mappings — the AST walk only saw `function_definition`
/// nodes. Returns the synthesized getters as ordinary members so
/// `member_present` / `contract_claims_standard` treat them like real
/// functions.
fn solidity_contract_functions(contract: &tree_sitter::Node, source: &str) -> Vec<SolFunction> {
    let mut out = Vec::new();
    let Some(body) = solidity_contract_body(contract) else {
        return out;
    };
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        match child.kind() {
            "function_definition" => {
                let Some(name_node) = child.child_by_field_name("name") else {
                    continue;
                };
                let name = source[name_node.byte_range()].to_string();
                let param_types = solidity_function_param_types(&child, source);
                let return_count = solidity_function_return_count(&child, source);
                out.push(SolFunction { name, param_types, return_count });
            }
            "state_variable_declaration" => {
                if let Some(getter) = solidity_public_state_var_getter(&child, source) {
                    out.push(getter);
                }
            }
            _ => {}
        }
    }
    out
}

/// Synthesize the auto-generated public getter for a `state_variable_declaration`
/// node, or `None` if the variable is not `public`. The getter's name is the
/// variable name, its parameter element types are the ordered KEY types of any
/// nested mappings (empty for a scalar/array), and it returns at least one
/// value (the mapping value type / element type), so `min_returns >= 1` ERC
/// members match.
fn solidity_public_state_var_getter(
    decl: &tree_sitter::Node,
    source: &str,
) -> Option<SolFunction> {
    // Require `public` visibility — private/internal vars have no getter.
    let mut has_public = false;
    let mut cursor = decl.walk();
    for child in decl.children(&mut cursor) {
        if child.kind() == "visibility" && source[child.byte_range()].trim() == "public" {
            has_public = true;
            break;
        }
    }
    if !has_public {
        return None;
    }
    let name_node = decl.child_by_field_name("name")?;
    let name = source[name_node.byte_range()].to_string();
    let type_node = decl.child_by_field_name("type")?;
    // Flatten nested mapping key types into the getter's parameter list.
    let mut param_types = Vec::new();
    solidity_collect_mapping_key_types(type_node, source, &mut param_types);
    Some(SolFunction {
        name,
        param_types,
        // A public getter always returns exactly one value (the value/element
        // type). We model `>= 1` so ERC members with `min_returns: 1` match.
        return_count: 1,
    })
}

/// Recursively flatten the KEY types of a (possibly nested) `mapping_type`
/// node into `out`, in declaration order. For a non-mapping type this is a
/// no-op (a scalar/array public var getter takes no parameters). Mirrors the
/// Solidity rule `mapping(K1 => mapping(K2 => V))` ⇒ getter `(K1, K2)`.
fn solidity_collect_mapping_key_types(
    type_node: tree_sitter::Node,
    source: &str,
    out: &mut Vec<String>,
) {
    // A mapping type_name has `[key_type]` and `[value_type]` fields.
    let Some(key) = type_node.child_by_field_name("key_type") else {
        return; // not a mapping → scalar/array getter, no params
    };
    out.push(normalize_solidity_type(&source[key.byte_range()]));
    if let Some(value) = type_node.child_by_field_name("value_type") {
        // Recurse into a nested mapping value to flatten further key types.
        solidity_collect_mapping_key_types(value, source, out);
    }
}

/// Ordered canonical element types of a function's parameters. Each parameter
/// is a `parameter` node; its declared type lives in the `type_name` field
/// (or first `type_name` descendant). We normalize the element type so that
/// `uint` -> `uint256` and strip data location / parameter name.
fn solidity_function_param_types(func: &tree_sitter::Node, source: &str) -> Vec<String> {
    let mut types = Vec::new();
    // Parameters live under a `parameter` list. Walk the function's direct
    // children for the first parameter group, then collect `parameter` nodes.
    // The grammar nests parameters under the function node; recurse one level
    // to find `parameter` nodes that are NOT inside the return list.
    let return_node = solidity_return_node(func);
    let mut cursor = func.walk();
    for child in func.children(&mut cursor) {
        // Skip the return parameter list so its types aren't counted as
        // input parameters.
        if Some(child.id()) == return_node.map(|n| n.id()) {
            continue;
        }
        collect_parameter_types(child, source, return_node, &mut types);
    }
    types
}

/// Recursively collect element types from every `parameter` node under
/// `node`, skipping anything inside `return_node`.
fn collect_parameter_types(
    node: tree_sitter::Node,
    source: &str,
    return_node: Option<tree_sitter::Node>,
    out: &mut Vec<String>,
) {
    if Some(node.id()) == return_node.map(|n| n.id()) {
        return;
    }
    if node.kind() == "parameter" {
        if let Some(t) = solidity_parameter_element_type(&node, source) {
            out.push(t);
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_parameter_types(child, source, return_node, out);
    }
}

/// Canonical element type of a single `parameter` node.
fn solidity_parameter_element_type(param: &tree_sitter::Node, source: &str) -> Option<String> {
    let type_node = param.child_by_field_name("type").or_else(|| {
        let mut cursor = param.walk();
        let kids: Vec<_> = param.children(&mut cursor).collect();
        kids.into_iter().find(|c| c.kind() == "type_name")
    })?;
    Some(normalize_solidity_type(&source[type_node.byte_range()]))
}

/// Normalize a Solidity type's textual form to its canonical element type:
/// strip data location keywords, array suffixes, and alias `uint`->`uint256`.
fn normalize_solidity_type(raw: &str) -> String {
    let mut t = raw.trim().to_string();
    for loc in [" memory", " calldata", " storage"] {
        if let Some(idx) = t.find(loc) {
            t.truncate(idx);
        }
    }
    let t = t.trim();
    // Element type of an array (`bytes32[]` -> `bytes32`, but we keep the
    // base type for matching; ERC signatures use scalar params).
    let base = t.split('[').next().unwrap_or(t).trim();
    match base {
        "uint" => "uint256".to_string(),
        "int" => "int256".to_string(),
        other => other.to_string(),
    }
}

/// The function's return parameter list node, if any. tree-sitter-solidity
/// emits returns as a `return_type_definition` child.
fn solidity_return_node<'a>(func: &tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
    let mut cursor = func.walk();
    let kids: Vec<_> = func.children(&mut cursor).collect();
    kids.into_iter()
        .find(|c| c.kind() == "return_type_definition")
}

/// Number of return values the function declares, by counting `parameter`
/// nodes inside the `return_type_definition`.
fn solidity_function_return_count(func: &tree_sitter::Node, source: &str) -> usize {
    let Some(ret) = solidity_return_node(func) else {
        return 0;
    };
    let mut count = 0usize;
    fn count_params(node: tree_sitter::Node, count: &mut usize) {
        if node.kind() == "parameter" {
            *count += 1;
            return;
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            count_params(child, count);
        }
    }
    count_params(ret, &mut count);
    let _ = source;
    count
}

/// Collect event names declared in the contract body (`event_definition`
/// `name` field).
fn solidity_contract_events(contract: &tree_sitter::Node, source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(body) = solidity_contract_body(contract) else {
        return out;
    };
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        if child.kind() == "event_definition" {
            if let Some(n) = child.child_by_field_name("name") {
                out.push(source[n.byte_range()].to_string());
            }
        }
    }
    out
}

/// Whether a SELF-CONTAINED declaration (one that does NOT inherit a canonical
/// base — that case is handled by the caller) claims to implement `standard`.
///
/// The signal is a DISTINCTIVE member: a function whose name belongs to this
/// standard's surface and does NOT also appear in a sibling ERC standard
/// (e.g. ERC20's `allowance` / `totalSupply`, ERC721's `ownerOf` /
/// `setApprovalForAll`). Declaring such a member is unambiguous evidence the
/// contract is trying to be this standard. We additionally require that the
/// contract declares at least 3 of the standard's members overall, so a
/// utility contract that merely happens to define an `allowance(...)` helper
/// is not mistaken for an incomplete token.
fn contract_claims_standard(
    standard: &ErcStandard,
    _bases: &[String],
    functions: &[SolFunction],
) -> bool {
    let declares_distinctive = functions
        .iter()
        .any(|f| standard.distinctive_members.iter().any(|d| f.name == *d));
    if !declares_distinctive {
        return false;
    }
    let declared = standard
        .functions
        .iter()
        .filter(|m| functions.iter().any(|f| f.name == m.name))
        .count();
    declared >= 3
}

/// Whether a member matching `spec` (name + parameter element types + return
/// arity) is present among `functions`. A function conforms when:
///   * its name matches, AND
///   * its parameter element-type sequence equals `spec.param_types`
///     (overloads with a different arity do not count), AND
///   * it returns at least `spec.min_returns` values.
fn member_present(functions: &[SolFunction], spec: &ErcMember) -> bool {
    functions.iter().any(|f| {
        f.name == spec.name
            && f.param_types.len() == spec.param_types.len()
            && f
                .param_types
                .iter()
                .zip(spec.param_types.iter())
                .all(|(got, want)| got == want)
            && f.return_count >= spec.min_returns
    })
}

/// ERC003: walk the AST for raw ERC20 `transfer` / `transferFrom` calls whose
/// boolean return value is discarded. A call is "unchecked" when its
/// `call_expression` is the WHOLE expression of an `expression_statement`
/// (i.e. `token.transfer(...);`) rather than being consumed by a
/// `require(...)`, an assignment, a return, or a comparison. Pure AST: we
/// detect the discarded-result shape via parent-node kind, never via text.
fn collect_unchecked_erc20_transfers(
    root: tree_sitter::Node,
    source: &str,
    file: &str,
    rule: &APIRule,
    findings: &mut Vec<MisuseFinding>,
) {
    fn visit(
        node: tree_sitter::Node,
        source: &str,
        file: &str,
        rule: &APIRule,
        findings: &mut Vec<MisuseFinding>,
    ) {
        // A discarded call is an `expression_statement` whose sole inner
        // expression is a `call_expression` to `<x>.transfer` /
        // `<x>.transferFrom`. tree-sitter-solidity wraps the call in one or
        // more `expression` / `primary_expression` nodes, so peel those off
        // before checking. A `require(token.transferFrom(...))` is NOT an
        // expression_statement whose direct expression is the transfer call
        // (the transfer call is nested inside the `require(...)` argument
        // list), so it is correctly excluded by this shape.
        if node.kind() == "expression_statement" {
            let inner = node.named_child(0).map(unwrap_solidity_expr_wrapper);
            if let Some(call) = inner.filter(|n| n.kind() == "call_expression") {
                if let Some(member) = erc20_transfer_member_name(&call, source) {
                    let line = call.start_position().row as u32 + 1;
                    findings.push(MisuseFinding {
                        file: file.to_string(),
                        line,
                        column: (call.start_position().column as u32) + 1,
                        rule: rule.clone(),
                        api_call: member.clone(),
                        message: format!(
                            "Return value of ERC20 `{}` is discarded; non-reverting tokens fail silently",
                            member
                        ),
                        fix_suggestion:
                            "Use SafeERC20 (safeTransfer/safeTransferFrom) or wrap in require(...)"
                                .to_string(),
                        code_context: source[node.byte_range()]
                            .lines()
                            .next()
                            .unwrap_or_default()
                            .trim()
                            .to_string(),
                    });
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            visit(child, source, file, rule, findings);
        }
    }
    visit(root, source, file, rule, findings);
}

/// Peel `expression` / `primary_expression` wrapper nodes off `n` until the
/// underlying meaningful node (`call_expression`, `member_expression`,
/// `identifier`, …) is exposed. Mirrors
/// `crates/tldr-core/src/security/solidity_vuln.rs::unwrap_expr_wrapper`.
fn unwrap_solidity_expr_wrapper(mut n: tree_sitter::Node) -> tree_sitter::Node {
    for _ in 0..6 {
        if matches!(n.kind(), "expression" | "primary_expression") {
            if let Some(c) = n.named_child(0) {
                n = c;
                continue;
            }
        }
        break;
    }
    n
}

/// If `call` is a `call_expression` whose callee is a `member_expression`
/// ending in `.transfer` / `.transferFrom`, return the member name. The
/// callee (`token.transfer`) is the first child of the `call_expression`
/// (peeled of `expression` wrappers); the member name is the LAST identifier
/// of the `member_expression` (the `a "." b` property). All navigation is via
/// AST node kinds, never string scanning.
fn erc20_transfer_member_name(call: &tree_sitter::Node, source: &str) -> Option<String> {
    let callee = call
        .child_by_field_name("function")
        .or_else(|| call.named_child(0))
        .map(unwrap_solidity_expr_wrapper)?;
    if callee.kind() != "member_expression" {
        return None;
    }
    // The property of `a.b` is the last identifier child (no `property`
    // field in this grammar fork). `member_expression` is `identifier "."
    // identifier`, so collect identifiers and take the last.
    let property = callee.child_by_field_name("property").or_else(|| {
        let mut cursor = callee.walk();
        let kids: Vec<_> = callee.children(&mut cursor).collect();
        kids.into_iter().filter(|c| c.kind() == "identifier").last()
    })?;
    let prop = source[property.byte_range()].trim();
    if prop == "transfer" || prop == "transferFrom" {
        Some(prop.to_string())
    } else {
        None
    }
}

fn regex_rule_specs_for_language(language: ApiLanguage) -> &'static [RegexRuleSpec] {
    match language {
        ApiLanguage::Python | ApiLanguage::Rust => &[],
        ApiLanguage::Go => GO_RULE_SPECS,
        ApiLanguage::Java => JAVA_RULE_SPECS,
        ApiLanguage::JavaScript => JAVASCRIPT_RULE_SPECS,
        ApiLanguage::TypeScript => TYPESCRIPT_RULE_SPECS,
        ApiLanguage::C => C_RULE_SPECS,
        ApiLanguage::Cpp => CPP_RULE_SPECS,
        ApiLanguage::Ruby => RUBY_RULE_SPECS,
        ApiLanguage::Php => PHP_RULE_SPECS,
        ApiLanguage::Kotlin => KOTLIN_RULE_SPECS,
        ApiLanguage::Swift => SWIFT_RULE_SPECS,
        ApiLanguage::CSharp => CSHARP_RULE_SPECS,
        ApiLanguage::Scala => SCALA_RULE_SPECS,
        ApiLanguage::Elixir => ELIXIR_RULE_SPECS,
        ApiLanguage::Lua | ApiLanguage::Luau => LUA_RULE_SPECS,
        ApiLanguage::Ocaml => OCAML_RULE_SPECS,
        // Solidity ERC conformance rules are not regex specs — they are
        // contract-level AST detectors handled by `analyze_solidity_erc`.
        ApiLanguage::Solidity => &[],
    }
}

fn all_api_languages() -> &'static [ApiLanguage] {
    ALL_API_LANGUAGES
}

// =============================================================================
// CLI Arguments
// =============================================================================

/// Detect API misuse patterns in code
///
/// Analyzes code for common API misuse patterns like missing timeouts,
/// bare except clauses, weak crypto usage, and unclosed resources.
///
/// # Example
///
/// ```bash
/// tldr api-check src/
/// tldr api-check src/main.py --category crypto
/// tldr api-check src/ --severity high
/// ```
#[derive(Debug, Args)]
pub struct ApiCheckArgs {
    /// File or directory to analyze (path to file or directory)
    #[arg(value_name = "path")]
    pub path: PathBuf,

    /// Filter by misuse category
    #[arg(long, value_delimiter = ',')]
    pub category: Option<Vec<MisuseCategory>>,

    /// Filter by minimum severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<MisuseSeverity>>,

    /// Output file (optional, stdout if not specified)
    #[arg(long, short = 'O')]
    pub output: Option<PathBuf>,
}

impl ApiCheckArgs {
    /// Run the api-check command
    pub fn run(
        &self,
        format: crate::output::OutputFormat,
        quiet: bool,
        global_lang: Option<Language>,
    ) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        writer.progress(&format!(
            "Checking {} for API misuse patterns...",
            self.path.display()
        ));

        // Validate path exists
        if !self.path.exists() {
            return Err(RemainingError::file_not_found(&self.path).into());
        }

        // sibling-resolver-gaps-v1 (P14.AGG14-5): the global `-l/--lang`
        // flag (defined in `Cli` and honoured by 30+ sibling commands)
        // was silently ignored by `api-check`, so
        // `tldr api-check --lang luau /tmp/repos/luau-luau` would scan
        // every `.cpp`/`.h`/`.lua`/`.luau`/`.py` file in the tree (89
        // findings across hundreds of files). P13.AGG13-10 fixed
        // `clones` for the same flag; mirror the pattern here. When the
        // global lang maps to a known `ApiLanguage`, restrict the
        // `detect_language` dispatch to only that language.
        let lang_filter: Option<ApiLanguage> = global_lang.and_then(map_language_to_api_language);

        let all_rules_count = all_api_languages()
            .iter()
            .map(|language| rules_for_language(*language).len() as u32)
            .sum();

        // Collect files to analyze
        let files = collect_files(&self.path)?;
        writer.progress(&format!("Found {} files to analyze", files.len()));

        // Analyze each file
        let mut all_findings: Vec<MisuseFinding> = Vec::new();
        let mut files_scanned = 0u32;

        for file_path in &files {
            let Some(language) = detect_language(file_path) else {
                continue;
            };
            // P14.AGG14-5: if user pinned a specific language, skip files
            // whose extension resolves to a different ApiLanguage.
            if let Some(want) = lang_filter {
                if language != want {
                    continue;
                }
            }
            let rules = rules_for_language(language);
            match analyze_file(file_path, &rules, language) {
                Ok(findings) => {
                    all_findings.extend(findings);
                    files_scanned += 1;
                }
                Err(e) => {
                    writer.progress(&format!(
                        "Warning: Failed to analyze {}: {}",
                        file_path.display(),
                        e
                    ));
                }
            }
        }

        // Apply filters
        let filtered_findings = filter_findings(
            all_findings,
            self.category.as_deref(),
            self.severity.as_deref(),
        );

        // Build summary
        let summary = build_summary(&filtered_findings, files_scanned);

        // Build report
        let report = APICheckReport {
            findings: filtered_findings,
            summary,
            rules_applied: all_rules_count,
        };

        // Write output
        if let Some(ref output_path) = self.output {
            if writer.is_text() {
                let text = format_api_check_text(&report);
                fs::write(output_path, text)?;
            } else {
                let json = serde_json::to_string_pretty(&report)?;
                fs::write(output_path, json)?;
            }
        } else if writer.is_text() {
            let text = format_api_check_text(&report);
            writer.write_text(&text)?;
        } else {
            writer.write(&report)?;
        }

        Ok(())
    }
}

// =============================================================================
// File Collection
// =============================================================================

/// Collect supported source files from a path
fn collect_files(path: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    if path.is_file() {
        if is_supported_file(path) {
            files.push(path.to_path_buf());
        }
    } else if path.is_dir() {
        for entry in walk_project(path) {
            if files.len() >= MAX_DIRECTORY_FILES as usize {
                break;
            }

            let entry_path = entry.path();
            if entry_path.is_file() && is_supported_file(entry_path) {
                // Check file size
                if let Ok(metadata) = fs::metadata(entry_path) {
                    if metadata.len() <= MAX_FILE_SIZE {
                        files.push(entry_path.to_path_buf());
                    }
                }
            }
        }
    }

    Ok(files)
}

/// Check if a path has a supported extension.
fn is_supported_file(path: &Path) -> bool {
    detect_language(path).is_some()
}

/// sibling-resolver-gaps-v1 (P14.AGG14-5): map the global `Language`
/// enum (used by the top-level `--lang/-l` flag) to the
/// `ApiLanguage` variant the api-check engine uses internally. Returns
/// `None` for languages api-check has no rule pack for, in which case
/// the caller should not apply a filter (preserve current behaviour for
/// those langs rather than blocking the run).
fn map_language_to_api_language(lang: Language) -> Option<ApiLanguage> {
    match lang {
        Language::Python => Some(ApiLanguage::Python),
        Language::Rust => Some(ApiLanguage::Rust),
        Language::Go => Some(ApiLanguage::Go),
        Language::Java => Some(ApiLanguage::Java),
        Language::JavaScript => Some(ApiLanguage::JavaScript),
        Language::TypeScript => Some(ApiLanguage::TypeScript),
        Language::C => Some(ApiLanguage::C),
        Language::Cpp => Some(ApiLanguage::Cpp),
        Language::Ruby => Some(ApiLanguage::Ruby),
        Language::Php => Some(ApiLanguage::Php),
        Language::Kotlin => Some(ApiLanguage::Kotlin),
        Language::Swift => Some(ApiLanguage::Swift),
        Language::CSharp => Some(ApiLanguage::CSharp),
        Language::Scala => Some(ApiLanguage::Scala),
        Language::Elixir => Some(ApiLanguage::Elixir),
        Language::Lua => Some(ApiLanguage::Lua),
        Language::Luau => Some(ApiLanguage::Luau),
        Language::Ocaml => Some(ApiLanguage::Ocaml),
        // fix-pack-apicheck-v1 (v0.5.0 PACK-APICHECK): Solidity now has an
        // api-check rule pack (ERC20 / ERC721 conformance + SafeERC20
        // recommendation), so `--lang solidity` maps to the Solidity
        // ApiLanguage and the per-file dispatch can filter on it.
        Language::Solidity => Some(ApiLanguage::Solidity),
    }
}

pub(crate) fn detect_language(path: &Path) -> Option<ApiLanguage> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("py") => Some(ApiLanguage::Python),
        Some("rs") => Some(ApiLanguage::Rust),
        Some("go") => Some(ApiLanguage::Go),
        Some("java") => Some(ApiLanguage::Java),
        Some("js") | Some("jsx") | Some("mjs") | Some("cjs") => Some(ApiLanguage::JavaScript),
        Some("ts") | Some("tsx") => Some(ApiLanguage::TypeScript),
        Some("c") | Some("h") => Some(ApiLanguage::C),
        Some("cpp") | Some("hpp") | Some("cc") | Some("cxx") => Some(ApiLanguage::Cpp),
        Some("rb") => Some(ApiLanguage::Ruby),
        Some("php") => Some(ApiLanguage::Php),
        Some("kt") | Some("kts") => Some(ApiLanguage::Kotlin),
        Some("swift") => Some(ApiLanguage::Swift),
        Some("cs") => Some(ApiLanguage::CSharp),
        Some("scala") => Some(ApiLanguage::Scala),
        Some("ex") | Some("exs") => Some(ApiLanguage::Elixir),
        Some("lua") => Some(ApiLanguage::Lua),
        Some("luau") => Some(ApiLanguage::Luau),
        Some("ml") | Some("mli") => Some(ApiLanguage::Ocaml),
        Some("sol") => Some(ApiLanguage::Solidity),
        _ => None,
    }
}

pub(crate) fn rules_for_language(language: ApiLanguage) -> Vec<APIRule> {
    match language {
        ApiLanguage::Python => python_rules(),
        ApiLanguage::Rust => rust_rules(),
        ApiLanguage::Solidity => solidity_rules(),
        _ => regex_rule_specs_for_language(language)
            .iter()
            .copied()
            .map(RegexRuleSpec::rule)
            .collect(),
    }
}

// =============================================================================
// Analysis Engine
// =============================================================================

/// Per-language needle set used by the file-level fast-path in
/// [`analyze_file`].
///
/// `analyze_file` previously walked every line of every collected file,
/// dispatching every rule per line. On large `.cpp`/`.h` files in mixed-
/// language repos (e.g. `luau-luau`, where the API-check command sees
/// 800+ files including 200 KB+ per-file C++ source) this was O(files ·
/// lines · rules). For `tldr api-check /tmp/repos/luau-luau` the BEFORE
/// run was ~186 s; almost all of that was scanning files that contained
/// none of the rule keywords for their language.
///
/// fastpath-extend-non-vuln-v1 (extends the M-B1 substring prefilter
/// proven in `crates/tldr-core/src/security/vuln.rs::scan_file_vulns`).
/// If a file's content contains NONE of the language's rule needles,
/// every per-line check is guaranteed to return `None`, so we can skip
/// the per-line loop entirely. The needle set is a SUPERSET of the
/// per-rule matchers — a file passing the prefilter is still subject to
/// the existing per-line precision logic (docstring filtering,
/// `find_standalone_call`, etc.), so the fast-path cannot introduce new
/// false negatives.
///
/// The needle list is derived per call from the language's rule
/// specs (extracting the substring before the first regex metachar
/// from each `pattern` so we use the longest *plain* prefix as the
/// needle). For Python and Rust — whose rules use bespoke matchers
/// rather than the regex spec table — we hard-code the list.
fn language_fastpath_needles(language: ApiLanguage) -> Vec<String> {
    match language {
        // Built-in Python rules: PY001 requests.*, PY002 except:, PY003 md5,
        // PY004 sha1, PY005 open(, PY006 random.*. Use short prefixes so we
        // don't tie this list to the precise per-rule call shapes.
        ApiLanguage::Python => ["requests.", "except:", "md5", "sha1", "open(", "random."]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        // Built-in Rust rules: RS001 Mutex, RS002 File::open, RS003
        // with_capacity, RS004 tokio::spawn, RS005 HashMap, RS006 clone(
        ApiLanguage::Rust => [
            "Mutex",
            "File::open",
            "with_capacity",
            "tokio::spawn",
            "HashMap",
            ".clone(",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect(),
        // fix-pack-apicheck-v1 (v0.5.0 PACK-APICHECK): Solidity ERC
        // conformance runs a contract-level AST pass, not the per-line
        // loop. The fast-path needle just decides whether to bother
        // parsing the file at all: any file relevant to an ERC rule
        // mentions one of these tokens (an ERC base/interface name, a
        // core surface member, or a raw `transfer` call). Files with none
        // of these cannot produce an ERC finding, so we skip the parse.
        ApiLanguage::Solidity => [
            "ERC20",
            "ERC721",
            "transfer",
            "balanceOf",
            "ownerOf",
            "totalSupply",
            "approve",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect(),
        // Regex-based languages: derive the needles automatically from
        // the static rule table by scanning each spec's `pattern` for
        // its longest plain-literal run. See `extract_literal_from_regex`
        // for the correctness contract (the returned literal is a
        // substring of every line that matches the pattern).
        _ => regex_rule_specs_for_language(language)
            .iter()
            .map(|spec| extract_literal_from_regex(spec.pattern))
            .collect(),
    }
}

/// Extract a literal substring from a regex pattern that is guaranteed
/// to appear (verbatim) in any line that matches the regex.
///
/// We walk the regex and emit the longest run of literal characters,
/// skipping anchors (`\b`, `^`, `$`), interpreting simple character
/// escapes (`\.` → `.`, `\(` → `(`), and ending the run at character-
/// class shorthands (`\s`, `\w`, `\d`, …) or quantifiers (`*`, `+`,
/// `?`, `{n}`). This is intentionally conservative: we never claim a
/// literal that the regex engine wouldn't produce. For
/// pathological / pure-quantifier patterns the result is the empty
/// string, which the caller interprets as "always admit" — preserving
/// correctness at the cost of skipping the fast-path for that rule.
///
/// **Correctness contract**: for every spec in
/// `regex_rule_specs_for_language`, the byte string returned here is a
/// substring of every input string that matches `spec.pattern`. The
/// `extract_literal_from_regex_yields_substring_present_in_match`
/// test below pins this contract.
///
/// Returns a `String` rather than `&'static str` because escaped
/// literals (`\.` → `.`) require building a buffer; for plain runs
/// without escapes this still allocates, but the cost is paid once
/// per rule per `analyze_file` call, not per line.
fn extract_literal_from_regex(pattern: &str) -> String {
    let bytes = pattern.as_bytes();
    let n = bytes.len();

    // Soundness: alternation `|` at the top level means a match could
    // come from any branch, so a literal is only safe if it appears in
    // EVERY branch. Implementing per-branch literal intersection is
    // complex; the safe fallback is to return empty (always admit) for
    // any pattern containing top-level `|`. This also handles
    // `\s==\s|\s!=\s` correctly (we previously over-reported `==`).
    let mut depth = 0i32;
    let mut k = 0usize;
    while k < n {
        match bytes[k] {
            b'\\' if k + 1 < n => k += 2,
            b'[' => {
                k += 1;
                while k < n && bytes[k] != b']' {
                    if bytes[k] == b'\\' && k + 1 < n {
                        k += 2;
                    } else {
                        k += 1;
                    }
                }
                if k < n {
                    k += 1;
                }
            }
            b'(' => {
                depth += 1;
                k += 1;
            }
            b')' => {
                depth -= 1;
                k += 1;
            }
            b'|' if depth == 0 => return String::new(),
            _ => k += 1,
        }
    }

    let mut best = String::new();
    let mut run = String::new();

    let close_run = |run: &mut String, best: &mut String| {
        if run.len() > best.len() {
            *best = run.clone();
        }
        run.clear();
    };

    let mut i = 0usize;
    while i < n {
        let b = bytes[i];
        match b {
            // Anchors `^` / `$` are invisible at match time; close run.
            b'^' | b'$' => {
                close_run(&mut run, &mut best);
                i += 1;
            }
            b'\\' if i + 1 < n => {
                let esc = bytes[i + 1];
                match esc {
                    // Word/string boundaries are invisible at match time.
                    b'b' | b'B' | b'A' | b'Z' | b'z' => {
                        close_run(&mut run, &mut best);
                        i += 2;
                    }
                    // Character-class shorthands match a single char,
                    // not a literal — close the run.
                    b's' | b'S' | b'd' | b'D' | b'w' | b'W' => {
                        close_run(&mut run, &mut best);
                        i += 2;
                    }
                    // Literal escape: `\.`, `\(`, `\$`, `\\`, … — append
                    // the escaped byte to the current run.
                    _ => {
                        run.push(esc as char);
                        i += 2;
                    }
                }
            }
            // Quantifiers eat the previous run char (because `foo*`
            // could match just `fo`, not necessarily `foo`). Close the
            // run after dropping the quantified atom.
            b'*' | b'+' | b'?' | b'{' => {
                if !run.is_empty() {
                    run.pop();
                }
                close_run(&mut run, &mut best);
                // For `{n,m}` we also need to advance past the closing
                // `}`; conservatively scan for it.
                if b == b'{' {
                    while i < n && bytes[i] != b'}' {
                        i += 1;
                    }
                }
                i += 1;
            }
            // Alternation, groups end the run.
            b'|' | b'(' | b')' | b']' => {
                close_run(&mut run, &mut best);
                // Handle `(?:`, `(?=`, `(?!` non-capturing / lookaround
                // openers: skip the `?X` so we don't treat `:` as a
                // literal.
                if b == b'(' && i + 2 < n && bytes[i + 1] == b'?' {
                    i += 3;
                } else {
                    i += 1;
                }
            }
            // Character class `[...]`: skip the entire bracketed group
            // — chars inside a class are alternatives, not literals.
            b'[' => {
                close_run(&mut run, &mut best);
                i += 1;
                // Skip any leading `^` (negated class).
                if i < n && bytes[i] == b'^' {
                    i += 1;
                }
                // Skip a literal `]` immediately after `[` or `[^`.
                if i < n && bytes[i] == b']' {
                    i += 1;
                }
                // Walk until the closing `]`, honouring `\]` escapes.
                while i < n && bytes[i] != b']' {
                    if bytes[i] == b'\\' && i + 1 < n {
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                if i < n {
                    i += 1; // consume closing `]`
                }
            }
            // Bare `.` is the regex "any char" metachar (NOT a literal).
            b'.' => {
                close_run(&mut run, &mut best);
                i += 1;
            }
            // Plain literal char extends the run.
            _ => {
                run.push(b as char);
                i += 1;
            }
        }
    }
    close_run(&mut run, &mut best);

    // Require at least 2 characters before claiming a useful literal —
    // single-char literals match too eagerly to be effective filters
    // (e.g. `==` reduces to "=" which appears in every file).
    if best.len() < 2 {
        return String::new();
    }
    best
}

/// Analyze a single file for API misuse
pub(crate) fn analyze_file(
    path: &Path,
    rules: &[APIRule],
    language: ApiLanguage,
) -> Result<Vec<MisuseFinding>> {
    // fastpath-extend-non-vuln-v1: defer to the central oversize policy
    // before reading the file. `analyze_file` reads the full content into
    // memory and per-line scans it; without a cap, a 2 MB+ generated
    // header (`*.d.ts`, `dom.generated.h`, …) can dominate the run. The
    // central policy lives in `tldr_core::fs::oversize::check_size` and
    // is shared with `parse_file_with_lang`, `walker::walk_project`'s
    // size-aware callers, and `quality::debt`.
    if let tldr_core::fs::oversize::SizeCheck::Oversize { .. } =
        tldr_core::fs::oversize::check_size(path)
    {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(path)?;

    // fastpath-extend-non-vuln-v1: per-file substring fast-path (ports
    // M-B1's `function_body_has_taint_pattern` shape from
    // `crates/tldr-core/src/security/vuln.rs`). If the file body
    // contains NONE of the language's rule needles, no per-line check
    // could fire — skip the loop entirely. Correctness contract: the
    // needle set is a SUPERSET of every per-rule matcher (see
    // `language_fastpath_needles` doc), so a clean prefilter miss is a
    // true negative. Documents-only / pure-comment files still benefit
    // because their content rarely contains the security-shape needles.
    //
    // An empty needle in the list means "always admit" (the
    // corresponding rule has no useful literal prefix — see
    // `extract_literal_needle`); we treat any empty needle as
    // unconditional admission to preserve correctness.
    let needles = language_fastpath_needles(language);
    let any_needle_admits_universally = needles.iter().any(|n| n.is_empty());
    let any_needle_hit = needles
        .iter()
        .any(|n| !n.is_empty() && content.contains(n.as_str()));
    if !needles.is_empty() && !any_needle_admits_universally && !any_needle_hit {
        return Ok(Vec::new());
    }

    // fix-pack-apicheck-v1 (v0.5.0 PACK-APICHECK): Solidity ERC conformance
    // is a CONTRACT-level analysis, not a per-line/regex scan. Dispatch to
    // the dedicated tree-sitter-driven analyzer and return its findings
    // directly — the per-line loop below has no Solidity rules to run.
    if matches!(language, ApiLanguage::Solidity) {
        let file_str = path.display().to_string();
        return Ok(analyze_solidity_erc(&content, &file_str));
    }

    let file_str = path.display().to_string();
    let mut findings = Vec::new();
    let mut prev_trimmed = String::new();
    let file_has_hashmap = matches!(language, ApiLanguage::Rust) && content.contains("HashMap");

    // fastpath-extend-non-vuln-v1: pre-compile regex rules ONCE per file
    // (NOT once per (line, rule) pair). Pre-fix, `check_regex_rule`
    // called `Regex::new(spec.pattern)` on every (line, rule) match
    // inside the per-line loop — for an 800-file mixed-language repo
    // (luau-luau: 200KB+ `.cpp` files × ~30 rules each) the regex
    // compiler dominated the wall clock (~186 s). Compiling once per
    // file collapses this to N_rules per file. We then drive the
    // per-line check with the cached `Regex` instead of re-compiling.
    let regex_specs: Vec<(&'static RegexRuleSpec, Regex)> =
        regex_rule_specs_for_language(language)
            .iter()
            .filter_map(|spec| Regex::new(spec.pattern).ok().map(|re| (spec, re)))
            .collect();

    // analysis-precision-v1, BUG-07: for Python, mark lines that are
    // function/class signatures or live inside a triple-quoted docstring
    // so per-line identifier matchers (PY003 / PY004 / PY006 / ...) skip
    // them. Pre-fix `check_sha1_usage` matched the substring `sha1(` on
    // `def _lazy_sha1(...)` (a function *signature* mentioning the name)
    // and matched `hashlib.sha1` inside a docstring (`"""... ``hashlib.sha1``
    // at runtime ..."""`), inflating PY004 from 1 real call site to 3.
    let py_line_ctx: Vec<PyLineContext> = if matches!(language, ApiLanguage::Python) {
        compute_python_line_contexts(&content)
    } else {
        Vec::new()
    };

    // api-check-and-patterns-accuracy-v1 (P11.BUG-AGG-10): for C-family
    // languages, mark lines that live inside a `/* ... */` block comment
    // so per-line identifier matchers (e.g. `C003 sprintf-call`) skip
    // them. Pre-fix the `\bsprintf\s*\(` pattern matched the *literal*
    // text `sprintf()` inside a doc-comment block (e.g.
    // `/* ... not rely on sprintf() family ... */` in
    // `/tmp/repos/c-sds/sds.c:601`), reporting it as a real call site.
    // The line-level `is_comment_line` skip only handles `//` line
    // comments; block comments need state tracking across lines.
    let block_comment_ctx: Vec<bool> = if language_uses_c_block_comments(language) {
        compute_c_block_comment_lines(&content)
    } else {
        Vec::new()
    };

    // lu001-ast-gate-v1 (v0.4.1 bug-A): for Lua and Luau, pre-compute the
    // AST context that gates LU001 `implicit-global` flagging. The
    // context holds (a) lines inside `table_constructor` nodes and (b)
    // identifiers declared `local` anywhere in the file. Other languages
    // get an empty default context — `check_regex_rule`'s LU001 branch
    // is itself language-gated so the default is never consulted for
    // non-Lua files.
    let lua_ctx: LuaApiCheckContext = if matches!(language, ApiLanguage::Lua | ApiLanguage::Luau) {
        compute_lua_api_check_context(&content, language)
    } else {
        LuaApiCheckContext::default()
    };

    // regex-cpp-apicheck-v1 (v0.5.0 REGEX-CPP): for C++, pre-compute the
    // AST context that gates CPP004 `raw-new` flagging. The context holds
    // the set of lines overlapping a real `new_expression` node. Other
    // languages get an empty default context — `check_regex_rule`'s CPP004
    // branch is itself language-gated so the default is never consulted for
    // non-C++ files.
    let cpp_ctx: CppApiCheckContext = if matches!(language, ApiLanguage::Cpp) {
        compute_cpp_api_check_context(&content, language)
    } else {
        CppApiCheckContext::default()
    };

    // fix-C5-1 (v0.5.0 AUDIT-FIX): for JavaScript/TypeScript, pre-compute the
    // AST context that gates JS005/TS005 `eval-call` flagging. The context
    // holds the set of lines carrying a genuine `eval(...)` call_expression.
    // Other languages get an empty default context — the gate in
    // `check_regex_rule` is itself language-gated so the default is never
    // consulted for non-JS/TS files.
    let js_ctx: JsApiCheckContext =
        if matches!(language, ApiLanguage::JavaScript | ApiLanguage::TypeScript) {
            compute_js_api_check_context(&content, language)
        } else {
            JsApiCheckContext::default()
        };

    // fix-R7-cl4 (v0.5.0 CLOSEOUT): per-file AST contexts for the JV001
    // (Java type-aware `==`), CS001 (C# BinaryFormatter type-use), EX001
    // (Elixir String.to_atom capture form), OC003/OC005 (OCaml call-site
    // gating) and RS003/RS005 (Rust with_capacity / HashMap-iter) rules.
    // Each is gated to its language; non-matching languages get an empty
    // default whose `parsed`/sets are never consulted off-language.
    let java_ctx: JavaApiCheckContext = if matches!(language, ApiLanguage::Java) {
        compute_java_api_check_context(&content, language)
    } else {
        JavaApiCheckContext::default()
    };
    let csharp_ctx: CSharpApiCheckContext = if matches!(language, ApiLanguage::CSharp) {
        compute_csharp_api_check_context(&content, language)
    } else {
        CSharpApiCheckContext::default()
    };
    let elixir_ctx: ElixirApiCheckContext = if matches!(language, ApiLanguage::Elixir) {
        compute_elixir_api_check_context(&content, language)
    } else {
        ElixirApiCheckContext::default()
    };
    let ocaml_ctx: OcamlApiCheckContext = if matches!(language, ApiLanguage::Ocaml) {
        let is_mli = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("mli"))
            .unwrap_or(false);
        compute_ocaml_api_check_context(&content, language, is_mli)
    } else {
        OcamlApiCheckContext::default()
    };
    let rust_api_ctx: RustApiCheckContext = if matches!(language, ApiLanguage::Rust) {
        compute_rust_api_check_context(&content, language)
    } else {
        RustApiCheckContext::default()
    };

    for (line_num, line) in content.lines().enumerate() {
        let line_number = (line_num + 1) as u32;
        let trimmed = line.trim();
        // Skip lines that live inside a `/* ... */` block (BUG-AGG-10).
        // Indices align with `content.lines()` ordering.
        if block_comment_ctx
            .get(line_num)
            .copied()
            .unwrap_or(false)
        {
            // Still update prev_trimmed so the Rust `previous_is_loop`
            // context isn't disrupted by the comment skip.
            prev_trimmed = trimmed.to_string();
            continue;
        }
        let rust_ctx = RustLineContext {
            file_has_hashmap,
            previous_line: prev_trimmed.as_str(),
            previous_is_loop: prev_trimmed.starts_with("for ")
                || prev_trimmed.starts_with("while "),
        };
        let py_ctx = py_line_ctx
            .get(line_num)
            .copied()
            .unwrap_or_default();

        // Check each rule
        for rule in rules {
            if let Some(finding) = check_rule(
                rule,
                &file_str,
                line_number,
                line,
                language,
                &rust_ctx,
                py_ctx,
                &lua_ctx,
                &cpp_ctx,
                &js_ctx,
                &java_ctx,
                &csharp_ctx,
                &elixir_ctx,
                &ocaml_ctx,
                &rust_api_ctx,
                &regex_specs,
            ) {
                findings.push(finding);
            }
        }
        prev_trimmed = trimmed.to_string();
    }

    Ok(findings)
}

/// Per-line Python context computed once per file (analysis-precision-v1, BUG-07).
///
/// Used to suppress identifier-style API misuse matchers on lines that are
/// not actual call sites:
/// - `in_docstring`: line lives inside a triple-quoted (`"""` or `'''`)
///   string literal; identifier mentions inside docstrings (e.g.
///   ``"""...``hashlib.sha1``..."""``) are documentation, not calls.
/// - `is_def_or_class_signature`: line opens a `def `/`async def `/`class `
///   signature (the line itself, not its body); identifier mentions in the
///   *name* of a function (e.g. `def _lazy_sha1(string)`) must not be
///   treated as a call to `sha1(`.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct PyLineContext {
    pub in_docstring: bool,
    pub is_def_or_class_signature: bool,
}

/// Whether `language` uses C-style `/* ... */` block comments. Used by
/// the api-check scanner to decide whether to compute per-line block-
/// comment context (api-check-and-patterns-accuracy-v1, BUG-AGG-10).
///
/// All listed languages share the C lexical tradition (block comments
/// open with `/*` and close with `*/`). Languages that use a different
/// block-comment shape (Python triple-quoted docstrings, Lua `--[[ ]]`,
/// OCaml `(* *)`, Elixir doc attribute blocks) are handled separately or
/// have their own line-level matcher in `is_comment_line`.
fn language_uses_c_block_comments(language: ApiLanguage) -> bool {
    matches!(
        language,
        ApiLanguage::Rust
            | ApiLanguage::Go
            | ApiLanguage::Java
            | ApiLanguage::JavaScript
            | ApiLanguage::TypeScript
            | ApiLanguage::C
            | ApiLanguage::Cpp
            | ApiLanguage::Kotlin
            | ApiLanguage::Swift
            | ApiLanguage::CSharp
            | ApiLanguage::Scala
            | ApiLanguage::Php
    )
}

/// For each line in `content`, return whether ANY part of the line lives
/// inside a C-style `/* ... */` block comment.
///
/// Tracks block-comment state across lines, including the case where a
/// block opens and closes on the same line (that line is treated as
/// fully inside the comment for suppression purposes — the rule's
/// regex would otherwise match on text *between* `/*` and `*/`).
///
/// String-literal awareness: this scanner is conservative. It tracks
/// double-quoted (`"..."`) and single-quoted (`'..'`) string state so a
/// `/*` inside a string doesn't open a phantom block. It does NOT handle
/// escaped quotes, raw strings, template literals, or character literals
/// with embedded escapes — those are uncommon enough in API-check rule
/// shapes that the simpler scanner suffices. When in doubt the scanner
/// errs toward NOT marking the line as comment, so the existing
/// `is_comment_line` line-comment fallback still runs.
///
/// (api-check-and-patterns-accuracy-v1, P11.BUG-AGG-10)
pub(crate) fn compute_c_block_comment_lines(content: &str) -> Vec<bool> {
    let mut out = Vec::new();
    let mut in_block = false;
    for line in content.lines() {
        let line_starts_in_block = in_block;
        let mut any_in_block = in_block;
        let bytes = line.as_bytes();
        let mut i = 0usize;
        let mut in_dq = false;
        let mut in_sq = false;
        while i < bytes.len() {
            let b = bytes[i];
            if in_block {
                // Look for closing `*/`.
                if b == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                    in_block = false;
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }
            // Outside a block comment: track strings so `/*` inside
            // `"..."` doesn't open a phantom block.
            if !in_sq && b == b'"' {
                in_dq = !in_dq;
                i += 1;
                continue;
            }
            if !in_dq && b == b'\'' {
                in_sq = !in_sq;
                i += 1;
                continue;
            }
            if !in_dq && !in_sq {
                // `//` line comment: rest of the line is comment, no
                // block-state change. Stop scanning the line.
                if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                    break;
                }
                // `/*` opens a block.
                if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
                    in_block = true;
                    any_in_block = true;
                    i += 2;
                    continue;
                }
            }
            i += 1;
        }
        // Mark the line as in-comment if it started inside one or
        // entered one anywhere on this line. The opening line of a
        // block comment counts as comment for suppression — we don't
        // want a `sprintf()` mention sitting *after* a same-line
        // `/* ... */` to be missed, but per the bug report, the more
        // common case is the *closing-line text* sitting inside the
        // block (e.g. `* not rely on sprintf() family ...`), and the
        // strictly conservative choice for either case is "skip the
        // whole line" to avoid false positives.
        let _ = line_starts_in_block; // (kept for clarity; merged into any_in_block)
        out.push(any_in_block);
    }
    out
}

/// Pre-pass: compute [`PyLineContext`] for every line of a Python file.
///
/// Tracks triple-quote state across lines (handles both `"""` and `'''`,
/// including the case where the closing triple lives on the *same* line
/// that opens it — that line is treated as fully inside a docstring for
/// suppression purposes). The detector is conservative: when in doubt
/// (e.g. nested string-literal edge cases the simple scanner cannot
/// disambiguate without a real parser), it suppresses the line, since
/// suppressing a docstring is cheaper than emitting a false positive.
///
/// This is **not** a full Python parser — it intentionally does NOT
/// understand escapes, raw strings, or f-strings. It handles the
/// docstring shape well enough to fix the BUG-07 reproducer (and the
/// vast majority of real-world docstrings) without pulling in a
/// tree-sitter pass for every line of every Python file.
pub(crate) fn compute_python_line_contexts(content: &str) -> Vec<PyLineContext> {
    let mut out = Vec::new();
    // 0 = not in docstring; 1 = in `"""`; 2 = in `'''`.
    let mut state: u8 = 0;
    for line in content.lines() {
        let stripped = strip_line_comment(line);
        let line_starts_in_docstring = state != 0;

        // Walk the line looking for triple-quote toggles.
        let bytes = stripped.as_bytes();
        let mut i = 0;
        while i + 2 < bytes.len() {
            let triple_dq = bytes[i] == b'"' && bytes[i + 1] == b'"' && bytes[i + 2] == b'"';
            let triple_sq = bytes[i] == b'\'' && bytes[i + 1] == b'\'' && bytes[i + 2] == b'\'';
            match state {
                0 if triple_dq => {
                    state = 1;
                    i += 3;
                    continue;
                }
                0 if triple_sq => {
                    state = 2;
                    i += 3;
                    continue;
                }
                1 if triple_dq => {
                    state = 0;
                    i += 3;
                    continue;
                }
                2 if triple_sq => {
                    state = 0;
                    i += 3;
                    continue;
                }
                _ => {}
            }
            i += 1;
        }
        // also handle bytes 0..2 for the trailing window
        let line_ends_in_docstring = state != 0;

        // A line is "in_docstring" if it starts inside one OR ends inside one
        // (i.e. the line opens/lives inside a triple-quoted block). A line
        // that *only contains* the opening triple-quote and content (without
        // closing) starts at state=0, ends at state=1 → marked as docstring.
        let in_docstring = line_starts_in_docstring || line_ends_in_docstring;

        let trimmed = line.trim_start();
        let is_def_or_class_signature = trimmed.starts_with("def ")
            || trimmed.starts_with("async def ")
            || trimmed.starts_with("class ");

        out.push(PyLineContext {
            in_docstring,
            is_def_or_class_signature,
        });
    }
    out
}

/// Strip a trailing `#` comment (best-effort; ignores `#` inside string
/// literals only at a syntactic level we can detect — we treat any `#`
/// outside an obvious string as a comment start). Used by
/// [`compute_python_line_contexts`] to avoid scanning triple-quotes that
/// appear inside line comments.
fn strip_line_comment(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut in_single = false;
    let mut in_double = false;
    for c in line.chars() {
        if c == '\'' && !in_double {
            in_single = !in_single;
        } else if c == '"' && !in_single {
            in_double = !in_double;
        } else if c == '#' && !in_single && !in_double {
            break;
        }
        out.push(c);
    }
    out
}

struct RustLineContext<'a> {
    file_has_hashmap: bool,
    previous_line: &'a str,
    previous_is_loop: bool,
}

/// lu001-ast-gate-v1 (v0.4.1 bug-A): per-file AST context for the Lua and
/// Luau api-check scanner. The LU001 `implicit-global` rule is regex-only
/// (`^[A-Za-z_][A-Za-z0-9_]*\s*=`) and cannot tell whether a bare `x = ...`
/// line is a fresh global, a reassignment of an earlier `local x`, or a
/// table-constructor field initialiser. Pre-fix this produced ~37.5% false
/// positives over the luau-luau corpus (1744 LU001 findings).
///
/// We pre-compute two sets per file by walking the tree-sitter parse:
///
///   - `table_constructor_line_set`: every source line (1-indexed) whose
///     byte range overlaps a `table_constructor` AST node. Field
///     initialisers `{ foo = 1, bar = 2 }` and metatable shapes
///     `setmetatable({}, { __add = fn })` live inside these nodes — their
///     keys are NOT global assignments.
///   - `local_names_in_scope`: every identifier ever declared with
///     `local` in the file (collected from `variable_declaration` nodes —
///     both the simple `local x` form and the full `local x = ...` form).
///     This is a conservative cross-scope union: if `local x` appears
///     anywhere in the file, a later `x = ...` line is treated as a
///     reassignment, not a new global. Per-scope refinement is out of
///     scope for v0.4.1.
///
/// The context is consulted ONLY for LU001 inside [`check_regex_rule`].
/// Other Lua rules (LU002–LU005) and other languages are unaffected.
///
/// The grammar node names are identical between `tree-sitter-lua` and
/// `tree-sitter-luau` (see `node-types.json` for both crates):
/// `variable_declaration` is the local-declaration form, `table_constructor`
/// holds `field` children, `assignment_statement` is the non-local
/// assignment.
#[derive(Debug, Default)]
pub(crate) struct LuaApiCheckContext {
    /// Line numbers (1-indexed) that fall inside a `table_constructor`
    /// node. A line in this set must not flag LU001 — the matched
    /// `name =` is a field key, not a global assignment.
    pub table_constructor_line_set: HashSet<u32>,
    /// All identifier names ever declared with `local` anywhere in the
    /// file. A line whose LHS identifier is in this set must not flag
    /// LU001 — it's a reassignment of a previously declared local, not
    /// a new global.
    pub local_names_in_scope: HashSet<String>,
    /// fix-C5-1 (v0.5.0 AUDIT-FIX): line numbers (1-indexed) that overlap
    /// a `comment` AST node. The line-level `is_comment_line` skip only
    /// catches `--` single-line comments; a Lua/Luau `--[[ ... ]]` *block*
    /// comment spans many lines whose interior text (`name = "x"`,
    /// `version = "1"`, lit-meta headers) matches the LU001
    /// `implicit-global` regex (`^ident =`). tree-sitter lexes the whole
    /// block as ONE `comment` node, so marking every line it overlaps is
    /// the root-cause gate. A line in this set must not flag any rule.
    pub comment_line_set: HashSet<u32>,
}

/// Build a [`LuaApiCheckContext`] by parsing `content` as Lua or Luau and
/// walking the resulting tree-sitter parse. Returns an empty context on
/// any parse failure — the gate is a precision optimisation, not a
/// correctness pre-condition, so a parse failure must NOT alter the set
/// of findings emitted for the file.
fn compute_lua_api_check_context(content: &str, language: ApiLanguage) -> LuaApiCheckContext {
    let lang = match language {
        ApiLanguage::Lua => Language::Lua,
        ApiLanguage::Luau => Language::Luau,
        _ => return LuaApiCheckContext::default(),
    };
    let tree = match tldr_core::ast::parser::parse(content, lang) {
        Ok(t) => t,
        Err(_) => return LuaApiCheckContext::default(),
    };
    let mut ctx = LuaApiCheckContext::default();
    let bytes = content.as_bytes();

    fn visit(node: tree_sitter::Node, source: &[u8], ctx: &mut LuaApiCheckContext) {
        let kind = node.kind();

        if kind == "comment" {
            // fix-C5-1: a `--[[ ... ]]` block comment is one `comment` node
            // spanning multiple lines. Mark every line it overlaps so the
            // LU001 gate suppresses the lit-meta `name = "x"` field lines
            // that match the implicit-global regex inside it. Single-line
            // `--` comments are also captured (harmless — `is_comment_line`
            // already skips those, this is belt-and-suspenders).
            let start_line = node.start_position().row as u32 + 1;
            let end_line = node.end_position().row as u32 + 1;
            for ln in start_line..=end_line {
                ctx.comment_line_set.insert(ln);
            }
            // Comments contain no locals / table constructors — no need to
            // recurse into the comment's children.
            return;
        }

        if kind == "table_constructor" {
            // Mark every line that intersects this node's byte range. Use
            // 1-indexed lines to match the api-check emission convention.
            let start_line = node.start_position().row as u32 + 1;
            let end_line = node.end_position().row as u32 + 1;
            for ln in start_line..=end_line {
                ctx.table_constructor_line_set.insert(ln);
            }
            // Still recurse — nested table_constructors and identifier
            // nodes inside fields don't introduce locals, but recursing
            // is harmless and keeps the visitor uniform.
        }

        if kind == "variable_declaration" {
            // Lua/Luau: `variable_declaration` is the `local` form. Its
            // children are either `assignment_statement` (the `local x =
            // ...` shape, with a `variable_list` inside) or
            // `variable_list` directly (the bare `local x` shape).
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                match child.kind() {
                    "assignment_statement" => {
                        // Descend into the inner variable_list to find
                        // the local identifier names.
                        let mut inner = child.walk();
                        for ic in child.children(&mut inner) {
                            if ic.kind() == "variable_list" {
                                collect_variable_list_identifiers(ic, source, ctx);
                            }
                        }
                    }
                    "variable_list" => {
                        collect_variable_list_identifiers(child, source, ctx);
                    }
                    "identifier" => {
                        // Defensive: some grammars hang identifiers
                        // directly off the declaration.
                        if let Ok(name) = std::str::from_utf8(&source[child.byte_range()]) {
                            ctx.local_names_in_scope.insert(name.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }

        // lu001-loopvar-param-binder-v1 (v0.5.0 RC5-LU001): for-loop
        // variables and function parameters are in-scope bindings, exactly
        // like a `local` declaration. A later bare `x = ...` whose LHS is one
        // of them is a reassignment of that binding, NOT an implicit global.
        // Pre-fix `visit()` harvested only `local` names, so a loop var or a
        // function parameter that was later reassigned without `local` leaked
        // as an LU001 `implicit-global` false positive. We fold them into the
        // same `local_names_in_scope` union the LU001 gate consults. The
        // grammar node names below are shared between `tree-sitter-lua` and
        // `tree-sitter-luau` (verified against both `node-types.json`); this
        // mirrors the AST shapes harvested by `extract_lua_params` /
        // `extract_luau_params` (`ast/extract.rs`).
        if kind == "for_numeric_clause" {
            // `for i = start, end[, step] do` — the loop variable is the
            // `name` field, an `identifier` node.
            if let Some(name_node) = node.child_by_field_name("name") {
                if name_node.kind() == "identifier" {
                    if let Ok(name) = std::str::from_utf8(&source[name_node.byte_range()]) {
                        ctx.local_names_in_scope.insert(name.to_string());
                    }
                }
            }
        }

        if kind == "for_generic_clause" {
            // `for k, v in iter do` — the loop variables live in a
            // `variable_list` child, the SAME node shape harvested for the
            // `local x, y = ...` form, so reuse the existing collector.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "variable_list" {
                    collect_variable_list_identifiers(child, source, ctx);
                }
            }
        }

        if kind == "parameters" {
            // Function parameters. Mirror `extract_lua_params` /
            // `extract_luau_params`: a bare `identifier` child (Lua param,
            // Luau untyped param) or a `parameter` wrapper whose first
            // `identifier` child is the name (Luau typed param `name: T`).
            // Varargs (`...` / `vararg_expression`) are not LHS identifiers
            // and are ignored.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                match child.kind() {
                    "identifier" => {
                        if let Ok(name) = std::str::from_utf8(&source[child.byte_range()]) {
                            ctx.local_names_in_scope.insert(name.to_string());
                        }
                    }
                    "parameter" => {
                        let mut inner = child.walk();
                        for ic in child.children(&mut inner) {
                            if ic.kind() == "identifier" {
                                if let Ok(name) = std::str::from_utf8(&source[ic.byte_range()])
                                {
                                    ctx.local_names_in_scope.insert(name.to_string());
                                }
                                break;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            visit(child, source, ctx);
        }
    }

    fn collect_variable_list_identifiers(
        node: tree_sitter::Node,
        source: &[u8],
        ctx: &mut LuaApiCheckContext,
    ) {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "identifier" {
                if let Ok(name) = std::str::from_utf8(&source[child.byte_range()]) {
                    ctx.local_names_in_scope.insert(name.to_string());
                }
            }
        }
    }

    visit(tree.root_node(), bytes, &mut ctx);
    ctx
}

/// regex-cpp-apicheck-v1 (v0.5.0 REGEX-CPP): per-file AST context for the
/// C++ api-check scanner. The `CPP004` `raw-new` rule is regex-only
/// (`\bnew\s+\w`). The `\bnew` word-boundary matches the literal word
/// "new" *anywhere* on a line — including inside string literals and any
/// trailing inline text the line-level `is_comment_line` skip cannot see.
/// Concretely `const char* s = "construct a new object";` matches
/// `new object` inside the string and reports a phantom raw-`new`
/// allocation.
///
/// We pre-compute one set per file by walking the tree-sitter parse:
///
///   - `new_expression_line_set`: every source line (1-indexed) whose
///     byte range overlaps a `new_expression` AST node. `new_expression`
///     is the C++ grammar's node kind for an actual `new T(...)`
///     allocation expression (see `tree-sitter-cpp` `node-types.json`).
///     Comments and string literals are lexed as `comment` /
///     `string_literal` / `raw_string_literal` nodes, so the word "new"
///     inside them never produces a `new_expression` and can never appear
///     in this set.
///
/// The context is consulted ONLY for CPP004 inside [`check_regex_rule`].
/// Other C++ rules (CPP001–CPP003, CPP005) and other languages are
/// unaffected. A parse failure yields an empty default context whose
/// `parsed` flag is `false`; the gate then falls back to the regex-only
/// behaviour rather than silently suppressing every finding (the gate is a
/// precision optimisation, not a correctness pre-condition).
#[derive(Debug, Default)]
pub(crate) struct CppApiCheckContext {
    /// Whether the file parsed successfully. When `false` (parse error or
    /// non-C++ language), the CPP004 gate falls back to regex-only
    /// behaviour so a parser hiccup cannot suppress real findings.
    pub parsed: bool,
    /// Line numbers (1-indexed) that overlap a `new_expression` node. A
    /// CPP004 regex match on a line NOT in this set is a phantom (the
    /// word "new" appeared in a comment / string literal), and must be
    /// suppressed.
    pub new_expression_line_set: HashSet<u32>,
}

/// Build a [`CppApiCheckContext`] by parsing `content` as C++ and walking
/// the resulting tree-sitter parse, collecting every line that overlaps a
/// `new_expression` node. Returns a context with `parsed = false` (and an
/// empty line set) on any parse failure or for a non-C++ language — the
/// caller then keeps the regex-only behaviour for that file.
fn compute_cpp_api_check_context(content: &str, language: ApiLanguage) -> CppApiCheckContext {
    if !matches!(language, ApiLanguage::Cpp) {
        return CppApiCheckContext::default();
    }
    let tree = match tldr_core::ast::parser::parse(content, Language::Cpp) {
        Ok(t) => t,
        Err(_) => return CppApiCheckContext::default(),
    };
    let mut ctx = CppApiCheckContext {
        parsed: true,
        new_expression_line_set: HashSet::new(),
    };

    fn visit(node: tree_sitter::Node, ctx: &mut CppApiCheckContext) {
        if node.kind() == "new_expression" {
            // Mark every line that intersects this node's byte range. Use
            // 1-indexed lines to match the api-check emission convention.
            // A `new T(...)` expression normally lives on one line, but a
            // multi-line allocation (long argument list) is covered too.
            let start_line = node.start_position().row as u32 + 1;
            let end_line = node.end_position().row as u32 + 1;
            for ln in start_line..=end_line {
                ctx.new_expression_line_set.insert(ln);
            }
            // Recurse — a `new` argument list can itself contain a nested
            // `new T(new U())`; recursing keeps the visitor uniform.
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            visit(child, ctx);
        }
    }

    visit(tree.root_node(), &mut ctx);
    ctx
}

/// fix-C5-1 (v0.5.0 AUDIT-FIX): per-file AST context for the JavaScript /
/// TypeScript api-check scanner. The `JS005` / `TS005` `eval-call` rules are
/// regex-only (`\beval\s*\(`). That word-boundary pattern matches the literal
/// text `eval(` *anywhere* on a line — including inside string literals.
/// Concretely `var xss = 'javascript:eval(document.body.innerHTML);';`
/// (js-express `test/res.redirect.js:115`) matches `eval(` inside the string
/// and reports a phantom eval call.
///
/// We pre-compute one set per file by walking the tree-sitter parse:
///
///   - `eval_call_line_set`: every source line (1-indexed) that overlaps a
///     genuine `call_expression` whose callee resolves to `eval` — either a
///     bare `identifier` named `eval` (`eval(x)`) or a `member_expression`
///     whose terminal `property_identifier` is `eval` (`window.eval(x)`).
///     String literals are lexed as `string` / `template_string` nodes and
///     comments as `comment` nodes, so `eval(` inside either never produces
///     a `call_expression` and can never appear in this set.
///
/// The context is consulted ONLY for `JS005` / `TS005` inside
/// [`check_regex_rule`]. Other JS/TS rules and other languages are
/// unaffected. A parse failure yields a context whose `parsed` flag is
/// `false`; the gate then falls back to the regex-only behaviour rather than
/// silently suppressing every finding (the gate is a precision optimisation,
/// not a correctness pre-condition — same contract as `CppApiCheckContext`).
#[derive(Debug, Default)]
pub(crate) struct JsApiCheckContext {
    /// Whether the file parsed successfully. When `false` (parse error or
    /// non-JS/TS language) the JS005/TS005 gate falls back to regex-only
    /// behaviour so a parser hiccup cannot suppress real eval calls.
    pub parsed: bool,
    /// Line numbers (1-indexed) that overlap a genuine `eval(...)`
    /// `call_expression`. A JS005/TS005 regex match on a line NOT in this
    /// set is a phantom (the text `eval(` appeared in a string literal or
    /// comment) and must be suppressed.
    pub eval_call_line_set: HashSet<u32>,
    /// fix-R7-cl4 (v0.5.0 CLOSEOUT): line numbers (1-indexed) that overlap a
    /// genuine `binary_expression` whose operator is `==` or `!=`. The
    /// `JS001`/`TS001` `loose-equality` rules are regex-only (`\s==\s|\s!=\s`)
    /// and match those tokens *inside string literals* (e.g. express.json's
    /// `'should parse when content-length != char length'`). tree-sitter lexes
    /// string interiors as `string`/`string_fragment`/`template_string` and
    /// comments as `comment`, so an operator inside either never produces a
    /// `binary_expression` and can never appear in this set. A JS001/TS001
    /// regex match on a line NOT in this set is a phantom and must be
    /// suppressed.
    pub loose_equality_line_set: HashSet<u32>,
}

/// Build a [`JsApiCheckContext`] by parsing `content` as TypeScript/JavaScript
/// (both dialects share the `tree-sitter-typescript` grammar) and walking the
/// parse, collecting every line that overlaps an `eval(...)` call. Returns a
/// context with `parsed = false` on any parse failure or for a non-JS/TS
/// language — the caller then keeps the regex-only behaviour for that file.
fn compute_js_api_check_context(content: &str, language: ApiLanguage) -> JsApiCheckContext {
    let lang = match language {
        ApiLanguage::JavaScript => Language::JavaScript,
        ApiLanguage::TypeScript => Language::TypeScript,
        _ => return JsApiCheckContext::default(),
    };
    let tree = match tldr_core::ast::parser::parse(content, lang) {
        Ok(t) => t,
        Err(_) => return JsApiCheckContext::default(),
    };
    let mut ctx = JsApiCheckContext {
        parsed: true,
        eval_call_line_set: HashSet::new(),
        loose_equality_line_set: HashSet::new(),
    };
    let bytes = content.as_bytes();

    /// Whether the `function` child of a `call_expression` resolves to a
    /// call of `eval`: a bare `identifier` named `eval`, or a
    /// `member_expression` whose terminal `property_identifier` is `eval`.
    fn callee_is_eval(func: tree_sitter::Node, source: &[u8]) -> bool {
        match func.kind() {
            "identifier" => &source[func.byte_range()] == b"eval",
            "member_expression" => func
                .child_by_field_name("property")
                .map(|p| {
                    matches!(p.kind(), "property_identifier" | "identifier")
                        && &source[p.byte_range()] == b"eval"
                })
                .unwrap_or(false),
            _ => false,
        }
    }

    fn visit(node: tree_sitter::Node, source: &[u8], ctx: &mut JsApiCheckContext) {
        // fix-R7-cl4: record the line of every genuine `==` / `!=`
        // binary_expression. The `[operator]` field carries the operator
        // token; we mark the operator's line (where the JS001/TS001 regex
        // `\s==\s|\s!=\s` matches). Operators inside string/template literals
        // are never `binary_expression` operators, so they are excluded.
        if node.kind() == "binary_expression" {
            if let Some(op) = node.child_by_field_name("operator") {
                let op_text = &source[op.byte_range()];
                if op_text == b"==" || op_text == b"!=" {
                    ctx.loose_equality_line_set
                        .insert(op.start_position().row as u32 + 1);
                }
            }
        }
        if node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                if callee_is_eval(func, source) {
                    // Mark only the callee's line(s). A multi-line argument
                    // list is irrelevant — the JS005 regex matches `eval(`
                    // which sits on the callee/open-paren line.
                    let start_line = func.start_position().row as u32 + 1;
                    let end_line = node
                        .child_by_field_name("function")
                        .map(|f| f.end_position().row as u32 + 1)
                        .unwrap_or(start_line);
                    for ln in start_line..=end_line {
                        ctx.eval_call_line_set.insert(ln);
                    }
                }
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            visit(child, source, ctx);
        }
    }

    visit(tree.root_node(), bytes, &mut ctx);
    ctx
}

/// fix-R7-cl4 (v0.5.0 CLOSEOUT): per-file AST context for the Java api-check
/// scanner. The `JV001` `string-comparison-with-double-equals` rule is
/// regex-only (`(?:".*"|\b\w+\b)\s*==\s*(?:".*"|\b\w+\b)`) and has ZERO
/// type-awareness: `\b\w+\b` matches ANY identifier or number on either side
/// of `==`, so it fires on Class-identity comparisons (`type ==
/// ResponseBody.class`, the idiomatic Java Class-singleton check), primitive
/// comparisons (`code == 204`), and array `.length == 0` checks — none of
/// which are String reference-equality bugs. On okhttp/retrofit this inflated
/// JV001 to 87 findings, 62 of them Class-identity comparisons.
///
/// We pre-compute one set per file by walking the tree-sitter-java parse:
///
///   - `string_eq_line_set`: the operator line of every `binary_expression`
///     whose operator is `==` / `!=` AND that is a *plausible String
///     comparison*. A comparison is plausible UNLESS an operand is provably
///     NOT a String, i.e. one side is:
///       * a class literal (`X.class` → `class_literal`),
///       * a numeric / char / boolean literal
///         (`decimal_integer_literal`, `hex_integer_literal`,
///         `decimal_floating_point_literal`, `character_literal`,
///         `true`/`false`),
///       * a `.length` / `.size()` field/array access (collection size, an
///         int), or
///       * the `null` literal (already covered by `line_has_null_comparison`,
///         kept here for AST completeness).
///     When neither operand is provably non-String — e.g. `s == "x"` (a
///     string literal IS a String) or `a == b` (two identifiers whose type we
///     cannot resolve without a type checker) — the line IS included, so the
///     genuine value-vs-reference heuristic is preserved (matches the
///     long-standing `name == otherName` test expectation).
///
/// The context is consulted ONLY for JV001 inside [`check_regex_rule`]. Other
/// Java rules and other languages are unaffected. A parse failure yields a
/// context whose `parsed` flag is `false`; the gate then falls back to the
/// regex-only behaviour rather than silently suppressing every finding (same
/// contract as `CppApiCheckContext` / `JsApiCheckContext`).
#[derive(Debug, Default)]
pub(crate) struct JavaApiCheckContext {
    /// Whether the file parsed successfully. When `false`, the JV001 gate
    /// falls back to regex-only behaviour.
    pub parsed: bool,
    /// Operator line numbers (1-indexed) of `==` / `!=` comparisons that are
    /// PLAUSIBLE String comparisons (neither operand provably non-String). A
    /// JV001 regex match on a line NOT in this set is a provable non-String
    /// comparison (Class identity, primitive, `.length`) and must be
    /// suppressed.
    pub string_eq_line_set: HashSet<u32>,
}

/// Whether a Java operand node is PROVABLY not a `String` (so a `==` against
/// it is not a String reference-equality bug). Conservative: returns `true`
/// only for shapes we can statically prove are non-String.
fn java_operand_is_provably_non_string(node: tree_sitter::Node, source: &[u8]) -> bool {
    match node.kind() {
        // `X.class` — a java.lang.Class singleton; `==` is the correct idiom.
        "class_literal" => true,
        // Numeric / char / boolean literals are never String.
        "decimal_integer_literal"
        | "hex_integer_literal"
        | "octal_integer_literal"
        | "binary_integer_literal"
        | "decimal_floating_point_literal"
        | "hex_floating_point_literal"
        | "character_literal"
        | "true"
        | "false" => true,
        // `null` is handled by line_has_null_comparison too; include here so a
        // `x == null` is not counted as a plausible String comparison.
        "null_literal" => true,
        // `arr.length` (field_access) / `coll.size()` (method_invocation) yield
        // an int, not a String.
        "field_access" => {
            // The `[field]` child identifier is `length` for `arr.length`.
            node.child_by_field_name("field")
                .map(|f| &source[f.byte_range()] == b"length")
                .unwrap_or(false)
        }
        "method_invocation" => {
            // `x.size()` — the `[name]` child is `size`.
            node.child_by_field_name("name")
                .map(|n| &source[n.byte_range()] == b"size")
                .unwrap_or(false)
        }
        // bug3-apicheck-java-narrow (v0.5.0 BACKLOG): a signed / negated
        // numeric literal — `-1`, `+1`, `-1.5`, `~0xFF`, `!true` — parses as a
        // `unary_expression` whose `[operand]` is the bare literal. The result
        // is an int / long / float / boolean, never a `String`, so `colon ==
        // -1` (the retrofit `RequestFactory` false positive) is not a
        // reference-equality bug. We recurse into the operand so the existing
        // literal arms decide; an identifier operand (`-x`, `!flag`) is NOT
        // provably non-String and stays conservatively unproven.
        "unary_expression" => node
            .child_by_field_name("operand")
            .map(|operand| java_operand_is_provably_non_string(operand, source))
            .unwrap_or(false),
        _ => false,
    }
}

/// Build a [`JavaApiCheckContext`] by parsing `content` as Java and walking
/// the parse, collecting the operator line of every plausible String `==` /
/// `!=` comparison. Returns `parsed = false` on parse failure or non-Java.
fn compute_java_api_check_context(content: &str, language: ApiLanguage) -> JavaApiCheckContext {
    if !matches!(language, ApiLanguage::Java) {
        return JavaApiCheckContext::default();
    }
    let tree = match tldr_core::ast::parser::parse(content, Language::Java) {
        Ok(t) => t,
        Err(_) => return JavaApiCheckContext::default(),
    };
    let mut ctx = JavaApiCheckContext {
        parsed: true,
        string_eq_line_set: HashSet::new(),
    };
    let bytes = content.as_bytes();

    fn visit(node: tree_sitter::Node, source: &[u8], ctx: &mut JavaApiCheckContext) {
        if node.kind() == "binary_expression" {
            if let Some(op) = node.child_by_field_name("operator") {
                let op_text = &source[op.byte_range()];
                if op_text == b"==" || op_text == b"!=" {
                    let left = node.child_by_field_name("left");
                    let right = node.child_by_field_name("right");
                    let provably_non_string = left
                        .map(|n| java_operand_is_provably_non_string(n, source))
                        .unwrap_or(false)
                        || right
                            .map(|n| java_operand_is_provably_non_string(n, source))
                            .unwrap_or(false);
                    if !provably_non_string {
                        ctx.string_eq_line_set
                            .insert(op.start_position().row as u32 + 1);
                    }
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            visit(child, source, ctx);
        }
    }

    visit(tree.root_node(), bytes, &mut ctx);
    ctx
}

/// fix-R7-cl4 (v0.5.0 CLOSEOUT): per-file AST context for the C# api-check
/// scanner. The `CS001` `binaryformatter` rule is regex-only
/// (`\bBinaryFormatter\b`) and matches the bare identifier anywhere — so a
/// user METHOD declared `public byte[] BinaryFormatter() {...}` is flagged as
/// use of the dangerous `System.Runtime.Serialization.BinaryFormatter` type
/// (newtonsoft-json benchmark false positives).
///
/// We pre-compute one set per file by walking the tree-sitter-c-sharp parse:
///
///   - `binaryformatter_use_line_set`: every line carrying a genuine
///     `BinaryFormatter` *type reference* — a `new BinaryFormatter()`
///     (`object_creation_expression` whose `[type]` is `BinaryFormatter`), a
///     variable/field declaration whose `[type]` is `BinaryFormatter`, or any
///     other `identifier` that is NOT the `[name]` of a `method_declaration`.
///     A `method_declaration` whose `[name]` is `BinaryFormatter` is a method
///     definition, not a type use, and is excluded.
///
/// Consulted ONLY for CS001. A parse failure yields `parsed = false` and the
/// CS001 gate falls back to regex-only behaviour.
#[derive(Debug, Default)]
pub(crate) struct CSharpApiCheckContext {
    /// Whether the file parsed successfully.
    pub parsed: bool,
    /// Lines (1-indexed) carrying a genuine `BinaryFormatter` type reference.
    /// A CS001 regex match on a line NOT in this set is a method-name
    /// collision and must be suppressed.
    pub binaryformatter_use_line_set: HashSet<u32>,
}

/// Build a [`CSharpApiCheckContext`]. Collects every line where the bare
/// identifier `BinaryFormatter` is used as a TYPE (object creation, type of a
/// declaration, or any identifier reference that is not a method name).
fn compute_csharp_api_check_context(content: &str, language: ApiLanguage) -> CSharpApiCheckContext {
    if !matches!(language, ApiLanguage::CSharp) {
        return CSharpApiCheckContext::default();
    }
    let tree = match tldr_core::ast::parser::parse(content, Language::CSharp) {
        Ok(t) => t,
        Err(_) => return CSharpApiCheckContext::default(),
    };
    let mut ctx = CSharpApiCheckContext {
        parsed: true,
        binaryformatter_use_line_set: HashSet::new(),
    };
    let bytes = content.as_bytes();

    fn is_binaryformatter(node: tree_sitter::Node, source: &[u8]) -> bool {
        matches!(node.kind(), "identifier")
            && &source[node.byte_range()] == b"BinaryFormatter"
    }

    fn visit(node: tree_sitter::Node, source: &[u8], ctx: &mut CSharpApiCheckContext) {
        // The ONLY occurrence we must exclude is the method NAME of a method
        // declaration (`public ... BinaryFormatter() {...}`). Every other
        // `BinaryFormatter` identifier is a type use (object creation type,
        // declaration type, base type, cast, etc.). So: when we reach a
        // `method_declaration`, recurse into all children EXCEPT its `[name]`.
        if node.kind() == "method_declaration" {
            let name_id = node.child_by_field_name("name").map(|n| n.id());
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if Some(child.id()) == name_id {
                    continue;
                }
                visit(child, source, ctx);
            }
            return;
        }
        if is_binaryformatter(node, source) {
            ctx.binaryformatter_use_line_set
                .insert(node.start_position().row as u32 + 1);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            visit(child, source, ctx);
        }
    }

    visit(tree.root_node(), bytes, &mut ctx);
    ctx
}

/// fix-R7-cl4 (v0.5.0 CLOSEOUT): per-file AST context for the Elixir
/// api-check scanner. The `EX001` `string-to-atom` rule is regex-only
/// (`\bString\.to_atom\s*\(`) and REQUIRES an opening paren, so it MISSES the
/// capture-operator form `&String.to_atom/1` (arity suffix, no paren) used in
/// plug's `builder.ex:382`.
///
/// We pre-compute one set per file by walking the tree-sitter-elixir parse:
///
///   - `string_to_atom_line_set`: the line of every `dot` node whose left is
///     the `alias` `String` and whose right is the `identifier` `to_atom`.
///     This `dot` node is present in BOTH the regular call
///     (`String.to_atom(p)` → `call`>`dot`) and the capture form
///     (`&String.to_atom/1` → `unary_operator`>`binary_operator`>`call`>`dot`),
///     so a single AST detector covers both syntaxes.
///
/// Consulted ONLY for EX001. A parse failure yields `parsed = false`; the
/// EX001 gate then falls back to regex-only behaviour (so the regular call
/// form is still caught even if the parse fails).
#[derive(Debug, Default)]
pub(crate) struct ElixirApiCheckContext {
    /// Whether the file parsed successfully.
    pub parsed: bool,
    /// Lines (1-indexed) carrying a `String.to_atom` reference in any form
    /// (call or capture). EX001 fires on a line if it is in this set OR (for
    /// resilience when the parse failed) the regex matched.
    pub string_to_atom_line_set: HashSet<u32>,
}

/// Build an [`ElixirApiCheckContext`]. Collects the line of every
/// `String.to_atom` dot reference (call and capture forms).
fn compute_elixir_api_check_context(content: &str, language: ApiLanguage) -> ElixirApiCheckContext {
    if !matches!(language, ApiLanguage::Elixir) {
        return ElixirApiCheckContext::default();
    }
    let tree = match tldr_core::ast::parser::parse(content, Language::Elixir) {
        Ok(t) => t,
        Err(_) => return ElixirApiCheckContext::default(),
    };
    let mut ctx = ElixirApiCheckContext {
        parsed: true,
        string_to_atom_line_set: HashSet::new(),
    };
    let bytes = content.as_bytes();

    fn visit(node: tree_sitter::Node, source: &[u8], ctx: &mut ElixirApiCheckContext) {
        if node.kind() == "dot" {
            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");
            let left_is_string = left
                .map(|n| n.kind() == "alias" && &source[n.byte_range()] == b"String")
                .unwrap_or(false);
            let right_is_to_atom = right
                .map(|n| &source[n.byte_range()] == b"to_atom")
                .unwrap_or(false);
            if left_is_string && right_is_to_atom {
                ctx.string_to_atom_line_set
                    .insert(node.start_position().row as u32 + 1);
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            visit(child, source, ctx);
        }
    }

    visit(tree.root_node(), bytes, &mut ctx);
    ctx
}

/// fix-R7-cl4 (v0.5.0 CLOSEOUT): per-file AST context for the OCaml api-check
/// scanner. `OC003` (`\bSys\.command\b`) and `OC005`
/// (`\b(?:open_in|open_out)\b`) are regex word-boundary matches with no AST
/// gate. `is_comment_line` only catches lines that START with `(*`, so the
/// 2nd+ lines of a `(** ... *)` doc comment reach the matcher
/// (`... [Sys.command]). *)`), and `.mli` `val open_in :` type signatures and
/// disabling sentinels (`let open_in = `Use_Io`) are matched as if they were
/// call sites.
///
/// We pre-compute one set per file by walking the tree-sitter-ocaml parse:
///
///   - `api_call_line_set`: the line of every `application_expression` whose
///     `[function]` is a `value_path` resolving to `open_in`, `open_out`,
///     `Sys.command`, `Marshal.from_string`, `Marshal.from_channel`, or whose
///     callee is `Obj.magic`. Only genuine *call sites* are recorded, so
///     `value_specification` (`.mli` val sigs), sentinel `let` bindings, and
///     comment mentions are all excluded (none of them are
///     `application_expression`s).
///
/// Consulted for all OCaml rules in [`check_regex_rule`]. A parse failure
/// yields `parsed = false` and the OCaml rules fall back to regex-only
/// behaviour (preserving recall when the parse fails).
#[derive(Debug, Default)]
pub(crate) struct OcamlApiCheckContext {
    /// Whether the file parsed successfully (OCaml `.ml` or `.mli`).
    pub parsed: bool,
    /// Lines (1-indexed) carrying a genuine OCaml API *call site* (an
    /// `application_expression`). An OCaml-rule regex match on a line NOT in
    /// this set is a comment / val-signature / sentinel and must be
    /// suppressed.
    pub api_call_line_set: HashSet<u32>,
}

/// Textual `value_path` of an OCaml `application_expression`'s `[function]`
/// node, normalized to the dotted form (`Sys.command`, `open_in`). Returns
/// `None` when the callee is not a `value_path`.
fn ocaml_callee_path(func: tree_sitter::Node, source: &[u8]) -> Option<String> {
    if func.kind() != "value_path" {
        return None;
    }
    std::str::from_utf8(&source[func.byte_range()])
        .ok()
        .map(|s| s.split_whitespace().collect::<String>())
}

/// Build an [`OcamlApiCheckContext`]. Collects the line of every OCaml API
/// call site that one of the OC* rules cares about. `is_mli` selects the
/// interface grammar (`.mli` files contain only `value_specification` val
/// sigs — never call sites — so the interface parse yields an empty call-site
/// set, exactly the desired suppression); `.ml` files use the implementation
/// grammar. Either way, only `application_expression` call sites are recorded,
/// so `val` signatures, sentinel `let` bindings, and comment mentions never
/// enter the set.
fn compute_ocaml_api_check_context(
    content: &str,
    language: ApiLanguage,
    is_mli: bool,
) -> OcamlApiCheckContext {
    if !matches!(language, ApiLanguage::Ocaml) {
        return OcamlApiCheckContext::default();
    }
    // `.mli` interface files are misparsed by the implementation grammar
    // (`val open_in : ...` becomes an `application_expression` whose function
    // is the keyword `val`), so use the dedicated interface grammar for them.
    // `.ml` implementation files use the standard implementation grammar via
    // tldr_core. In BOTH cases we record only genuine `application_expression`
    // call sites, so a misparse can only ever DROP a finding (fail-open), not
    // invent one.
    let tree = if is_mli {
        ocaml_interface_parse(content)
    } else {
        tldr_core::ast::parser::parse(content, Language::Ocaml).ok()
    };
    let Some(tree) = tree else {
        return OcamlApiCheckContext::default();
    };
    let mut ctx = OcamlApiCheckContext {
        parsed: true,
        api_call_line_set: HashSet::new(),
    };
    let bytes = content.as_bytes();

    // Callees the OCaml rules detect (dotted/normalized form).
    const OCAML_API_CALLEES: &[&str] = &[
        "open_in",
        "open_out",
        "Sys.command",
        "Marshal.from_string",
        "Marshal.from_channel",
        "Obj.magic",
    ];

    fn visit(node: tree_sitter::Node, source: &[u8], ctx: &mut OcamlApiCheckContext) {
        if node.kind() == "application_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                if let Some(path) = ocaml_callee_path(func, source) {
                    if OCAML_API_CALLEES.contains(&path.as_str()) {
                        ctx.api_call_line_set
                            .insert(func.start_position().row as u32 + 1);
                    }
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            visit(child, source, ctx);
        }
    }

    visit(tree.root_node(), bytes, &mut ctx);
    ctx
}

/// Parse OCaml interface (`.mli`) content via the dedicated
/// `LANGUAGE_OCAML_INTERFACE` grammar. The implementation grammar misparses
/// `val x : T` signatures (treating `val` as a function application), so `.mli`
/// files must use the interface grammar. Returns `None` if the parse fails.
/// Kept separate so the call-site detector stays grammar-agnostic.
fn ocaml_interface_parse(content: &str) -> Option<tree_sitter::Tree> {
    // `.mli` files contain only `value_specification` (val sigs), no call
    // sites, so even an interface parse yields zero entries in
    // `api_call_line_set` — which is exactly the desired suppression. We
    // attempt the interface grammar directly via tree-sitter to avoid
    // depending on a specific `Language` enum variant name.
    let mut parser = tree_sitter::Parser::new();
    let lang: tree_sitter::Language = tree_sitter_ocaml::LANGUAGE_OCAML_INTERFACE.into();
    parser.set_language(&lang).ok()?;
    parser.parse(content, None)
}

/// fix-R7-cl4 (v0.5.0 CLOSEOUT): per-file AST context for the Rust api-check
/// scanner. Two regex/substring rules need type/shape awareness:
///
///   - `RS003 unbounded-with-capacity` flagged `Vec::with_capacity(...)`
///     whenever the line text contained any of input/args/user/request/len/
///     size — so `Vec::with_capacity(existing.len())` (safe pre-sizing from an
///     already-allocated collection) was flagged as CWE-770 memory
///     exhaustion. We record the line of every `with_capacity` call whose
///     argument is SAFE (a `.len()` / `.capacity()` / `.size()` method call,
///     or a literal/const) so the RS003 substring heuristic can be suppressed
///     on those lines.
///   - `RS005 hashmap-order-dependence` flagged ANY `for ... .iter()` line in
///     a file that merely CONTAINED the substring `HashMap` anywhere. We
///     record the line of every `for` loop whose iterated receiver resolves to
///     a HashMap/HashSet binding, so RS005 only fires there (replacing the
///     file-wide `file_has_hashmap` proxy).
///
/// Consulted ONLY for RS003 / RS005. A parse failure yields `parsed = false`
/// and both rules fall back to their prior heuristic behaviour.
#[derive(Debug, Default)]
pub(crate) struct RustApiCheckContext {
    /// Whether the file parsed successfully.
    pub parsed: bool,
    /// Lines (1-indexed) of a `with_capacity(...)` call whose capacity
    /// argument is SAFE (derived from an existing collection's length, or a
    /// constant). RS003 must be suppressed on these lines.
    pub safe_with_capacity_line_set: HashSet<u32>,
    /// Lines (1-indexed) of a `for` loop iterating a receiver whose type
    /// resolves to `HashMap` / `HashSet`. RS005 fires ONLY on these lines.
    pub hashmap_iter_line_set: HashSet<u32>,
}

/// Build a [`RustApiCheckContext`] by parsing `content` as Rust and walking
/// the parse. Returns `parsed = false` on parse failure or non-Rust.
fn compute_rust_api_check_context(content: &str, language: ApiLanguage) -> RustApiCheckContext {
    if !matches!(language, ApiLanguage::Rust) {
        return RustApiCheckContext::default();
    }
    let tree = match tldr_core::ast::parser::parse(content, Language::Rust) {
        Ok(t) => t,
        Err(_) => return RustApiCheckContext::default(),
    };
    let mut ctx = RustApiCheckContext {
        parsed: true,
        safe_with_capacity_line_set: HashSet::new(),
        hashmap_iter_line_set: HashSet::new(),
    };
    let bytes = content.as_bytes();

    // Pass 1: collect identifiers whose let-binding type or initializer is a
    // HashMap / HashSet, so we can resolve the receiver of a `for` loop.
    let mut hashmap_bindings: HashSet<String> = HashSet::new();
    collect_rust_hashmap_bindings(tree.root_node(), bytes, &mut hashmap_bindings);

    fn visit(
        node: tree_sitter::Node,
        source: &[u8],
        ctx: &mut RustApiCheckContext,
        hashmap_bindings: &HashSet<String>,
    ) {
        // RS003: a `call_expression` to `*::with_capacity(arg)` whose arg is
        // safe (a `.len()`/`.capacity()`/`.size()` method call, an integer
        // literal, or a path/const) → record the line for suppression.
        if node.kind() == "call_expression" {
            if rust_call_is_with_capacity(node, source) {
                if let Some(arg) = rust_first_call_argument(node) {
                    if rust_capacity_arg_is_safe(arg, source) {
                        ctx.safe_with_capacity_line_set
                            .insert(node.start_position().row as u32 + 1);
                    }
                }
            }
        }
        // RS005: a `for_expression` whose iterated value resolves to a
        // HashMap/HashSet → record the line(s) the loop's `.iter()` call sits
        // on (the receiver's line, which is where the RS005 substring matches).
        if node.kind() == "for_expression" {
            if let Some(value) = node.child_by_field_name("value") {
                if rust_iter_receiver_is_hashmap(value, source, hashmap_bindings) {
                    // The `.iter()` text the RS005 heuristic matches lives on
                    // the iterated-value expression's line(s).
                    let start = value.start_position().row as u32 + 1;
                    let end = value.end_position().row as u32 + 1;
                    for ln in start..=end {
                        ctx.hashmap_iter_line_set.insert(ln);
                    }
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            visit(child, source, ctx, hashmap_bindings);
        }
    }

    visit(tree.root_node(), bytes, &mut ctx, &hashmap_bindings);
    ctx
}

/// Collect every identifier bound (via `let`) to a HashMap/HashSet value —
/// either by explicit type annotation (`let m: HashMap<..> = ..`) or by
/// constructor (`let m = HashMap::new()` / `HashSet::with_capacity(..)` /
/// `HashMap::from(..)`). Conservative cross-scope union (mirrors the Lua
/// local-name approach): good enough to resolve the iterated receiver of a
/// `for x in RECV.iter()` loop without full type inference.
fn collect_rust_hashmap_bindings(
    node: tree_sitter::Node,
    source: &[u8],
    out: &mut HashSet<String>,
) {
    if node.kind() == "let_declaration" {
        let pat = node.child_by_field_name("pattern");
        let ty = node.child_by_field_name("type");
        let val = node.child_by_field_name("value");
        let ty_is_hashmap = ty
            .map(|t| rust_type_text_is_hashmap(t, source))
            .unwrap_or(false);
        let val_is_hashmap = val
            .map(|v| rust_expr_constructs_hashmap(v, source))
            .unwrap_or(false);
        if ty_is_hashmap || val_is_hashmap {
            if let Some(p) = pat {
                // Simple `identifier` pattern (`let m = ...`). Tuple / struct
                // patterns are out of scope (a `for` over them is rare).
                if p.kind() == "identifier" {
                    if let Ok(name) = std::str::from_utf8(&source[p.byte_range()]) {
                        out.insert(name.to_string());
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_rust_hashmap_bindings(child, source, out);
    }
}

/// Whether a Rust type node's text names `HashMap` or `HashSet` (allowing a
/// path prefix like `std::collections::HashMap` and generic args).
fn rust_type_text_is_hashmap(ty: tree_sitter::Node, source: &[u8]) -> bool {
    let text = std::str::from_utf8(&source[ty.byte_range()]).unwrap_or("");
    // Match the type CONSTRUCTOR name, not a substring of an unrelated ident:
    // a generic_type's base is the last `::`-segment before `<`.
    let head = text.split('<').next().unwrap_or(text);
    let last_seg = head.rsplit("::").next().unwrap_or(head).trim();
    last_seg == "HashMap" || last_seg == "HashSet"
}

/// Whether a Rust expression constructs a HashMap/HashSet
/// (`HashMap::new()`, `HashSet::with_capacity(n)`, `HashMap::from(..)`,
/// `HashMap::default()`).
fn rust_expr_constructs_hashmap(expr: tree_sitter::Node, source: &[u8]) -> bool {
    // Unwrap a call_expression to its function path.
    let func = if expr.kind() == "call_expression" {
        expr.child_by_field_name("function")
    } else {
        Some(expr)
    };
    let Some(func) = func else { return false };
    let text = std::str::from_utf8(&source[func.byte_range()]).unwrap_or("");
    // `HashMap::new` → base segment before the final `::method` is `HashMap`.
    // Strip the final path segment (the method) then take the last remaining.
    let base = text.rsplitn(2, "::").nth(1).unwrap_or("");
    let last_seg = base.rsplit("::").next().unwrap_or(base).trim();
    last_seg == "HashMap" || last_seg == "HashSet"
}

/// Whether a `call_expression` calls `*::with_capacity` (any receiver type:
/// `Vec::with_capacity`, `String::with_capacity`, etc — RS003 currently only
/// fires on `Vec::with_capacity(` but the gate is receiver-agnostic).
fn rust_call_is_with_capacity(call: tree_sitter::Node, source: &[u8]) -> bool {
    let Some(func) = call.child_by_field_name("function") else {
        return false;
    };
    let text = std::str::from_utf8(&source[func.byte_range()]).unwrap_or("");
    text.rsplit("::").next().map(|s| s.trim()) == Some("with_capacity")
}

/// The first argument node of a `call_expression`, if any.
fn rust_first_call_argument(call: tree_sitter::Node) -> Option<tree_sitter::Node> {
    let args = call.child_by_field_name("arguments")?;
    // Index named children directly to avoid returning a Node that borrows a
    // local `TreeCursor` (which would not outlive this function).
    let n = args.named_child_count();
    for i in 0..n {
        if let Some(child) = args.named_child(i) {
            return Some(child);
        }
    }
    None
}

/// Whether a `with_capacity` capacity argument is SAFE (not unbounded external
/// input): a `.len()` / `.capacity()` / `.size()` method call, an integer
/// literal, or a const path (UPPER_SNAKE). Conservative: anything else (a bare
/// `request_size` param, an arithmetic expr on input) is treated as unsafe so
/// genuine unbounded allocations are still flagged.
fn rust_capacity_arg_is_safe(arg: tree_sitter::Node, source: &[u8]) -> bool {
    match arg.kind() {
        // `existing.len()` / `buf.capacity()` / `v.size()`.
        "call_expression" => {
            if let Some(func) = arg.child_by_field_name("function") {
                if func.kind() == "field_expression" {
                    let field = func
                        .child_by_field_name("field")
                        .map(|f| &source[f.byte_range()]);
                    return matches!(
                        field,
                        Some(b"len") | Some(b"capacity") | Some(b"size")
                    );
                }
            }
            false
        }
        // Numeric literal capacity (`Vec::with_capacity(256)`).
        "integer_literal" => true,
        // A const reference (`Vec::with_capacity(MAX_LEN)`) — UPPER_SNAKE
        // identifier/path is, by Rust convention, a compile-time constant.
        "identifier" => {
            let text = std::str::from_utf8(&source[arg.byte_range()]).unwrap_or("");
            !text.is_empty()
                && text
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        }
        "scoped_identifier" => {
            let text = std::str::from_utf8(&source[arg.byte_range()]).unwrap_or("");
            text.rsplit("::").next().map(|seg| {
                !seg.is_empty()
                    && seg
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            }) == Some(true)
        }
        _ => false,
    }
}

/// Whether the iterated value of a `for` loop resolves to a HashMap/HashSet.
/// Handles `for x in map.iter()` / `for x in map.iter_mut()` /
/// `for x in &map` / `for x in map` where `map` is a known HashMap binding,
/// and `for x in HashMap::new().iter()` (direct construction).
fn rust_iter_receiver_is_hashmap(
    value: tree_sitter::Node,
    source: &[u8],
    hashmap_bindings: &HashSet<String>,
) -> bool {
    // Peel a reference_expression (`for x in &map`).
    let value = if value.kind() == "reference_expression" {
        value.named_child(0).unwrap_or(value)
    } else {
        value
    };
    match value.kind() {
        // `map.iter()` / `map.iter_mut()` / `map.keys()` / `map.values()`.
        "call_expression" => {
            let Some(func) = value.child_by_field_name("function") else {
                return false;
            };
            if func.kind() == "field_expression" {
                // The receiver is the `[value]` child of the field_expression.
                if let Some(recv) = func.child_by_field_name("value") {
                    return rust_iter_receiver_is_hashmap(recv, source, hashmap_bindings);
                }
                // Or a direct construction `HashMap::new().iter()`.
            }
            // Direct construction `HashMap::new()`.
            rust_expr_constructs_hashmap(value, source)
        }
        // Bare identifier `for x in map` — resolve via known bindings.
        "identifier" => {
            let name = std::str::from_utf8(&source[value.byte_range()]).unwrap_or("");
            hashmap_bindings.contains(name)
        }
        _ => false,
    }
}

/// lu001-ast-gate-v1: extract the LHS identifier from a line that the
/// LU001 regex (`^[A-Za-z_][A-Za-z0-9_]*\s*=`) has just matched. Returns
/// `None` if the regex shape isn't present (defensive — should never
/// trigger in practice because the caller has already confirmed a regex
/// match). The leading-whitespace skip mirrors the regex's `^` which is
/// applied against the already-`trim()`ed `line_text` in `check_rule`.
fn extract_lu001_lhs_name(line_text: &str) -> Option<String> {
    let trimmed = line_text.trim_start();
    let mut end = 0usize;
    for (i, c) in trimmed.char_indices() {
        if i == 0 && !(c.is_ascii_alphabetic() || c == '_') {
            return None;
        }
        if c.is_ascii_alphanumeric() || c == '_' {
            end = i + c.len_utf8();
            continue;
        }
        break;
    }
    if end == 0 {
        return None;
    }
    Some(trimmed[..end].to_string())
}

/// Check a single rule against a line of code
#[allow(clippy::too_many_arguments)]
fn check_rule(
    rule: &APIRule,
    file: &str,
    line: u32,
    line_text: &str,
    language: ApiLanguage,
    rust_ctx: &RustLineContext<'_>,
    py_ctx: PyLineContext,
    lua_ctx: &LuaApiCheckContext,
    cpp_ctx: &CppApiCheckContext,
    js_ctx: &JsApiCheckContext,
    java_ctx: &JavaApiCheckContext,
    csharp_ctx: &CSharpApiCheckContext,
    elixir_ctx: &ElixirApiCheckContext,
    ocaml_ctx: &OcamlApiCheckContext,
    rust_api_ctx: &RustApiCheckContext,
    regex_specs: &[(&'static RegexRuleSpec, Regex)],
) -> Option<MisuseFinding> {
    let trimmed = line_text.trim();

    // api-check-and-patterns-accuracy-v1 (P11.BUG-AGG-6): defense-in-depth
    // gate. The primary dispatch (`ApiCheckArgs::run`) already restricts
    // each file to its detected language's rule set, but this explicit
    // gate ensures that even if a rule list were ever cross-wired (or if
    // a future code path bypasses `rules_for_language`), a JS rule like
    // `JS003 JSON.parse` cannot fire against a `.cpp` file.
    if !rule_applies_to_language(rule.id.as_str(), language) {
        return None;
    }

    // Skip comments
    if is_comment_line(trimmed, language) {
        return None;
    }

    // analysis-precision-v1, BUG-07: Python identifier-style rules must
    // not match docstring lines or `def`/`class` signature lines (only
    // real call sites). Apply the suppression centrally so individual
    // checkers don't have to re-implement it.
    if matches!(language, ApiLanguage::Python)
        && py_rule_skips_docstring_and_signatures(rule.id.as_str())
        && (py_ctx.in_docstring || py_ctx.is_def_or_class_signature)
    {
        return None;
    }

    match rule.id.as_str() {
        "PY001" => check_missing_timeout(rule, file, line, trimmed),
        "PY002" => check_bare_except(rule, file, line, trimmed),
        "PY003" => check_md5_usage(rule, file, line, trimmed),
        "PY004" => check_sha1_usage(rule, file, line, trimmed),
        "PY005" => check_unclosed_file(rule, file, line, trimmed),
        "PY006" => check_insecure_random(rule, file, line, trimmed),
        "RS001" => check_mutex_lock_unwrap(rule, file, line, trimmed),
        "RS002" => check_file_open_without_context(rule, file, line, trimmed),
        "RS003" => check_unbounded_with_capacity(rule, file, line, trimmed, rust_api_ctx),
        "RS004" => check_detached_tokio_spawn(rule, file, line, trimmed),
        "RS005" => {
            check_hashmap_order_dependence(rule, file, line, trimmed, rust_ctx, rust_api_ctx)
        }
        "RS006" => check_clone_in_hot_loop(rule, file, line, trimmed, rust_ctx),
        _ => check_regex_rule(
            rule,
            file,
            line,
            trimmed,
            language,
            lua_ctx,
            cpp_ctx,
            js_ctx,
            java_ctx,
            csharp_ctx,
            elixir_ctx,
            ocaml_ctx,
            regex_specs,
        ),
    }
}

/// Find an occurrence of `name(` in `line_text` that is *not* preceded by
/// an identifier character (`a-z`, `A-Z`, `0-9`, `_`). Returns the byte
/// offset of `name(` if such an occurrence exists. This rules out
/// substring matches against bigger identifiers (e.g. `_lazy_sha1(` for
/// `name = "sha1"`).
///
/// (analysis-precision-v1, BUG-07)
fn find_standalone_call(line_text: &str, name: &str) -> Option<usize> {
    let needle = format!("{}(", name);
    let bytes = line_text.as_bytes();
    let mut start = 0usize;
    while let Some(rel) = line_text[start..].find(&needle) {
        let abs = start + rel;
        let prev_ok = abs == 0
            || {
                let p = bytes[abs - 1];
                !(p.is_ascii_alphanumeric() || p == b'_')
            };
        if prev_ok {
            return Some(abs);
        }
        start = abs + 1;
    }
    None
}

/// Whether a Python rule's matcher should be suppressed on docstring /
/// `def`/`class` signature lines. Returns `true` for rules whose detection
/// is identifier-style (substring of an API name) — false for rules that
/// inherently require a body-statement context (like `PY002` bare-except,
/// which already requires `except:` syntax).
///
/// (analysis-precision-v1, BUG-07)
fn py_rule_skips_docstring_and_signatures(rule_id: &str) -> bool {
    matches!(rule_id, "PY003" | "PY004" | "PY005" | "PY006")
}

fn is_comment_line(trimmed: &str, language: ApiLanguage) -> bool {
    match language {
        ApiLanguage::Python | ApiLanguage::Ruby | ApiLanguage::Elixir => trimmed.starts_with('#'),
        ApiLanguage::Rust
        | ApiLanguage::Go
        | ApiLanguage::Java
        | ApiLanguage::JavaScript
        | ApiLanguage::TypeScript
        | ApiLanguage::C
        | ApiLanguage::Cpp
        | ApiLanguage::Kotlin
        | ApiLanguage::Swift
        | ApiLanguage::CSharp
        | ApiLanguage::Scala
        | ApiLanguage::Solidity => trimmed.starts_with("//"),
        ApiLanguage::Php => trimmed.starts_with("//") || trimmed.starts_with('#'),
        ApiLanguage::Lua | ApiLanguage::Luau => trimmed.starts_with("--"),
        ApiLanguage::Ocaml => trimmed.starts_with("(*"),
    }
}

#[allow(clippy::too_many_arguments)]
fn check_regex_rule(
    rule: &APIRule,
    file: &str,
    line: u32,
    line_text: &str,
    language: ApiLanguage,
    lua_ctx: &LuaApiCheckContext,
    cpp_ctx: &CppApiCheckContext,
    js_ctx: &JsApiCheckContext,
    java_ctx: &JavaApiCheckContext,
    csharp_ctx: &CSharpApiCheckContext,
    elixir_ctx: &ElixirApiCheckContext,
    ocaml_ctx: &OcamlApiCheckContext,
    regex_specs: &[(&'static RegexRuleSpec, Regex)],
) -> Option<MisuseFinding> {
    // fastpath-extend-non-vuln-v1: lookup the pre-compiled regex by rule id
    // (compiled ONCE per file in `analyze_file`, not once per line).
    let (spec, regex) = regex_specs.iter().find(|(spec, _)| spec.id == rule.id)?;

    // fix-R7-cl4 (v0.5.0 CLOSEOUT): EX001 `String.to_atom` has an AST
    // detector that catches BOTH the call form `String.to_atom(p)` AND the
    // capture form `&String.to_atom/1` (which the `\(`-anchored regex misses).
    // When the Elixir file parsed, drive EX001 off the AST line-set instead of
    // the regex so the capture form is caught. Fall back to the regex only
    // when the parse failed (preserve recall). Handled BEFORE the generic
    // regex match below so a capture-form line (no `(`) is not rejected.
    if rule.id == "EX001" && matches!(language, ApiLanguage::Elixir) && elixir_ctx.parsed {
        if !elixir_ctx.string_to_atom_line_set.contains(&line) {
            return None;
        }
        let column = line_text
            .find("String.to_atom")
            .map(|c| (c as u32).saturating_add(1))
            .unwrap_or(1);
        return Some(MisuseFinding {
            file: file.to_string(),
            line,
            column,
            rule: (*rule).clone(),
            api_call: spec.api_call.to_string(),
            message: spec.message.to_string(),
            fix_suggestion: spec.fix_suggestion.to_string(),
            code_context: line_text.to_string(),
        });
    }

    if !regex.is_match(line_text) {
        return None;
    }

    // fix-C5-1 (v0.5.0 AUDIT-FIX): the JS005/TS005 `eval-call` rules are
    // regex-only (`\beval\s*\(`). The `\beval` word-boundary matches the
    // literal text `eval(` anywhere on a line — including inside string
    // literals (e.g. `var xss = 'javascript:eval(...)';`). The AST pre-pass
    // populated `js_ctx` with the set of lines that carry a genuine
    // `eval(...)` call_expression; consult it here. Only fires for JS/TS —
    // other languages share neither the rule id nor the gate. When the file
    // did not parse (`js_ctx.parsed == false`) we keep the regex-only
    // behaviour so a parser hiccup cannot suppress real eval calls.
    if matches!(rule.id.as_str(), "JS005" | "TS005")
        && matches!(language, ApiLanguage::JavaScript | ApiLanguage::TypeScript)
        && js_ctx.parsed
        && !js_ctx.eval_call_line_set.contains(&line)
    {
        return None;
    }

    // regex-cpp-apicheck-v1 (v0.5.0 REGEX-CPP): the CPP004 `raw-new` rule
    // is regex-only (`\bnew\s+\w`). The `\bnew` word-boundary matches the
    // literal word "new" anywhere on a line — including inside string
    // literals (e.g. `"construct a new object"`). The AST pre-pass
    // populated `cpp_ctx` with the set of lines that carry a genuine
    // `new_expression` node; consult it here. Only fires for C++ — other
    // languages share neither the rule id nor the gate. When the file did
    // not parse (`cpp_ctx.parsed == false`) we keep the regex-only
    // behaviour so a parser hiccup cannot suppress real allocations.
    if rule.id == "CPP004"
        && matches!(language, ApiLanguage::Cpp)
        && cpp_ctx.parsed
        && !cpp_ctx.new_expression_line_set.contains(&line)
    {
        return None;
    }

    // language-specific-bugs-v1 (P14.AGG14-15): JV001
    // (`string-comparison-with-double-equals`) flags `x == y` as a
    // suspected reference-equality bug, which is correct for two String
    // operands but a false positive for the canonical Java null check
    // `if (x == null) { ... }`. The regex
    // `(?:".*"|\b\w+\b)\s*==\s*(?:".*"|\b\w+\b)` matches `null` (a
    // bareword) on either side because there is no syntactic null
    // literal exclusion. Skip the finding when one side of the `==` /
    // `!=` is the bare `null` keyword. Same idiom for C# (CS rules) is
    // not currently affected — the C# rule list does not include a
    // double-equals-string rule, so this guard is JV001-specific.
    if rule.id == "JV001" {
        // Conservative substring check: any line whose `==` / `!=` has
        // `null` immediately on either side is a null-comparison
        // idiom, not a string equality bug. (Kept as a cheap pre-gate; the
        // AST gate below subsumes it but also runs on the no-parse fallback.)
        if line_has_null_comparison(line_text) {
            return None;
        }
        // fix-R7-cl4 (v0.5.0 CLOSEOUT): type-aware AST gate. The JV001 regex
        // `(?:".*"|\b\w+\b)\s*==\s*(?:".*"|\b\w+\b)` has zero type-awareness
        // and fires on Class-identity comparisons (`type ==
        // ResponseBody.class`), primitive comparisons (`code == 204`), and
        // array `.length == 0` checks — none of which are String
        // reference-equality bugs. The AST pre-pass recorded the operator
        // line of every PLAUSIBLE String comparison (one where neither operand
        // is provably non-String). Suppress a JV001 match on a line NOT in
        // that set. When the file did not parse (`java_ctx.parsed == false`)
        // we keep the regex-only behaviour (with the null guard above).
        if matches!(language, ApiLanguage::Java)
            && java_ctx.parsed
            && !java_ctx.string_eq_line_set.contains(&line)
        {
            return None;
        }
    }

    // fix-R7-cl4 (v0.5.0 CLOSEOUT): JS001/TS001 `loose-equality` regex
    // (`\s==\s|\s!=\s`) matches `==`/`!=` tokens INSIDE string literals and
    // comments. The AST pre-pass recorded the operator line of every genuine
    // `==`/`!=` `binary_expression`; suppress a match on a line NOT in that
    // set. Fail-open on parse failure. Only fires for JS/TS.
    if matches!(rule.id.as_str(), "JS001" | "TS001")
        && matches!(language, ApiLanguage::JavaScript | ApiLanguage::TypeScript)
        && js_ctx.parsed
        && !js_ctx.loose_equality_line_set.contains(&line)
    {
        return None;
    }

    // fix-R7-cl4 (v0.5.0 CLOSEOUT): CS001 `BinaryFormatter` regex
    // (`\bBinaryFormatter\b`) matches the bare identifier — including a user
    // method NAMED `BinaryFormatter()`. The AST pre-pass recorded the lines of
    // genuine `BinaryFormatter` TYPE references (object creation / declaration
    // type / other identifier use), excluding the method-declaration name.
    // Suppress a CS001 match on a line NOT in that set. Fail-open on parse
    // failure.
    if rule.id == "CS001"
        && matches!(language, ApiLanguage::CSharp)
        && csharp_ctx.parsed
        && !csharp_ctx.binaryformatter_use_line_set.contains(&line)
    {
        return None;
    }

    // fix-R7-cl4 (v0.5.0 CLOSEOUT): OCaml OC003/OC005 (and the sibling
    // Marshal/Obj rules) are bare-word regexes that fire on `(* ... *)` doc
    // comment interiors, `.mli` `val` signatures, and disabling sentinels
    // (`let open_in = `Use_Io`). The AST pre-pass recorded the line of every
    // genuine `application_expression` call site for the OCaml APIs these
    // rules detect. Suppress an OCaml-rule match on a line NOT in that set.
    // Fail-open on parse failure. Only the OCaml rules that have a call-site
    // shape are gated (PH-style identifier rules don't apply to OCaml).
    if matches!(language, ApiLanguage::Ocaml)
        && ocaml_ctx.parsed
        && matches!(
            rule.id.as_str(),
            "OC001" | "OC002" | "OC003" | "OC004" | "OC005"
        )
        && !ocaml_ctx.api_call_line_set.contains(&line)
    {
        return None;
    }

    // lu001-ast-gate-v1 (v0.4.1 bug-A): the LU001 `implicit-global` rule
    // is regex-only and cannot tell whether a bare `x = ...` line is a
    // fresh global, a reassignment of an earlier `local x`, or a
    // table-constructor field initialiser. The AST pre-pass populated
    // `lua_ctx` with two precision sets; consult them here. Only fires
    // for Lua / Luau — other languages share the rule-id namespace via
    // `rule_applies_to_language` but no other LU* rule needs this gate.
    // fix-C5-1 (v0.5.0 AUDIT-FIX): suppress ANY Lua/Luau rule on a line that
    // lives inside a `--[[ ... ]]` block comment. The line-level
    // `is_comment_line` skip in `check_rule` only catches `--` single-line
    // comments; a multi-line block comment's interior lines (`name = "x"`,
    // `version = "1"` lit-meta headers) reach here and would otherwise match
    // LU001's implicit-global regex. tree-sitter lexes the whole block as one
    // `comment` node, so `comment_line_set` carries every line it spans.
    if matches!(language, ApiLanguage::Lua | ApiLanguage::Luau)
        && lua_ctx.comment_line_set.contains(&line)
    {
        return None;
    }

    if rule.id == "LU001" && matches!(language, ApiLanguage::Lua | ApiLanguage::Luau) {
        // Skip table-constructor lines: `{ foo = 1, bar = 2 }` matches
        // the LU001 regex on the inner lines, but `foo`/`bar` are
        // field keys, not global assignments.
        if lua_ctx.table_constructor_line_set.contains(&line) {
            return None;
        }
        // Skip reassignment of previously declared locals: if `local x`
        // appears anywhere in the file, treat `x = ...` as a local
        // reassignment rather than a new global.
        if let Some(name) = extract_lu001_lhs_name(line_text) {
            if lua_ctx.local_names_in_scope.contains(&name) {
                return None;
            }
        }
    }

    // scala-column-unification-v1 (v0.4.1 bug-B): `regex.find().map(m.start())`
    // is the 0-indexed byte offset within the trimmed line. Promote to a
    // 1-indexed column to agree with `tldr definition` / `tldr references`.
    // The `None` branch falls back to 1 (the start of the line) rather than 0
    // because no `m.start()` arm exists when the regex didn't match — and a
    // 0-column finding is meaningless for downstream tools.
    let m = regex.find(line_text);
    let column = m
        .map(|m| (m.start() as u32).saturating_add(1))
        .unwrap_or(1);
    // fix-R7-cl4 (v0.5.0 CLOSEOUT): for the loose-equality rules (JV001 /
    // JS001 / TS001) the spec hardcodes `api_call: "=="`, so a matched `!=`
    // was mislabeled `==`. Derive the reported operator from the actual match
    // text (`==` or `!=`) instead of the static spec value. Other rules keep
    // their declarative `spec.api_call`.
    let api_call = if matches!(rule.id.as_str(), "JV001" | "JS001" | "TS001") {
        m.map(|mm| {
            let matched = mm.as_str();
            if matched.contains("!=") {
                "!=".to_string()
            } else {
                "==".to_string()
            }
        })
        .unwrap_or_else(|| spec.api_call.to_string())
    } else {
        spec.api_call.to_string()
    };
    Some(MisuseFinding {
        file: file.to_string(),
        line,
        column,
        rule: (*rule).clone(),
        api_call,
        message: spec.message.to_string(),
        fix_suggestion: spec.fix_suggestion.to_string(),
        code_context: line_text.to_string(),
    })
}

/// language-specific-bugs-v1 (P14.AGG14-15): true when `line_text` contains
/// a `==` or `!=` operator with the literal keyword `null` on at least
/// one side. Used to suppress JV001 false positives on canonical Java
/// null checks.
fn line_has_null_comparison(line_text: &str) -> bool {
    // Walk the line character by character, finding each `==` / `!=`
    // occurrence (ignoring `===` which Java doesn't have but other langs
    // do) and inspecting a small window on both sides for the bareword
    // `null`. We check for word-boundary `null` rather than a raw
    // substring so identifiers like `notnull` / `nullable` don't trigger.
    let bytes = line_text.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let is_eq = bytes[i] == b'=' && bytes[i + 1] == b'=';
        let is_neq = bytes[i] == b'!' && bytes[i + 1] == b'=';
        if !is_eq && !is_neq {
            i += 1;
            continue;
        }
        // Skip `===` chains (defense in depth — should not appear in Java).
        if is_eq && bytes.get(i + 2) == Some(&b'=') {
            i += 3;
            continue;
        }
        // Inspect ~16 chars to the left and right for word-boundary `null`.
        let lo = i.saturating_sub(16);
        let hi = (i + 2 + 16).min(bytes.len());
        let left = std::str::from_utf8(&bytes[lo..i]).unwrap_or("");
        let right = std::str::from_utf8(&bytes[i + 2..hi]).unwrap_or("");
        if has_word_null(left) || has_word_null(right) {
            return true;
        }
        i += 2;
    }
    false
}

/// True when `s` contains the bareword `null` with word boundaries
/// (i.e. not preceded or followed by an alphanumeric / underscore).
fn has_word_null(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i + 4 <= bytes.len() {
        if &bytes[i..i + 4] == b"null" {
            let before_ok = i == 0
                || !bytes[i - 1].is_ascii_alphanumeric() && bytes[i - 1] != b'_';
            let after_ok = i + 4 == bytes.len()
                || !bytes[i + 4].is_ascii_alphanumeric() && bytes[i + 4] != b'_';
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Check for requests without timeout
fn check_missing_timeout(
    rule: &APIRule,
    file: &str,
    line: u32,
    line_text: &str,
) -> Option<MisuseFinding> {
    // Look for requests.get/post/put/delete/patch without timeout
    let request_patterns = [
        "requests.get(",
        "requests.post(",
        "requests.put(",
        "requests.delete(",
        "requests.patch(",
        "requests.head(",
        "requests.options(",
    ];

    for pattern in &request_patterns {
        if line_text.contains(pattern) && !line_text.contains("timeout") {
            let column = line_text.find(pattern).unwrap_or(0) as u32;
            return Some(MisuseFinding {
                file: file.to_string(),
                line,
                column,
                rule: rule.clone(),
                api_call: pattern.trim_end_matches('(').to_string(),
                message: format!(
                    "{} called without timeout parameter",
                    pattern.trim_end_matches('(')
                ),
                fix_suggestion: format!("Add timeout parameter: {}url, timeout=30)", pattern),
                code_context: line_text.to_string(),
            });
        }
    }

    None
}

/// Check for bare except clause
fn check_bare_except(
    rule: &APIRule,
    file: &str,
    line: u32,
    line_text: &str,
) -> Option<MisuseFinding> {
    // Look for "except:" without an exception type
    // Match "except:" but not "except SomeException:" or "except Exception as e:"
    if line_text.starts_with("except:") || line_text.contains(" except:") {
        let column = line_text.find("except:").unwrap_or(0) as u32;
        return Some(MisuseFinding {
            file: file.to_string(),
            line,
            column,
            rule: rule.clone(),
            api_call: "except".to_string(),
            message: "Bare except clause catches all exceptions including KeyboardInterrupt and SystemExit".to_string(),
            fix_suggestion: "Use 'except Exception as e:' to catch only program exceptions".to_string(),
            code_context: line_text.to_string(),
        });
    }

    None
}

/// Check for MD5 usage
fn check_md5_usage(
    rule: &APIRule,
    file: &str,
    line: u32,
    line_text: &str,
) -> Option<MisuseFinding> {
    // analysis-precision-v1, BUG-07: require either the `hashlib.md5`
    // qualified form (with the leading dot, so `hashlib.md5(...)` matches
    // but `_my_hashlib.md5_helper` does not) OR a *standalone* `md5(`
    // call — i.e. `md5(` not preceded by an identifier character. This
    // blocks substring matches against function names that *contain*
    // `md5` (e.g. `def compute_md5(...)`).
    let has_qualified = line_text.contains("hashlib.md5");
    let has_standalone_call = find_standalone_call(line_text, "md5").is_some();
    if has_qualified || has_standalone_call {
        let column = line_text
            .find("hashlib.md5")
            .or_else(|| find_standalone_call(line_text, "md5"))
            .unwrap_or(0) as u32;
        return Some(MisuseFinding {
            file: file.to_string(),
            line,
            column,
            rule: rule.clone(),
            api_call: "hashlib.md5".to_string(),
            message: "MD5 is cryptographically broken and should not be used for security purposes"
                .to_string(),
            fix_suggestion: "Use hashlib.sha256() or stronger. For passwords, use bcrypt or argon2"
                .to_string(),
            code_context: line_text.to_string(),
        });
    }

    None
}

/// Check for SHA1 usage
fn check_sha1_usage(
    rule: &APIRule,
    file: &str,
    line: u32,
    line_text: &str,
) -> Option<MisuseFinding> {
    // analysis-precision-v1, BUG-07: require either the `hashlib.sha1`
    // qualified form (with the leading dot) OR a *standalone* `sha1(`
    // call — i.e. `sha1(` not preceded by an identifier character. This
    // blocks substring matches against function names that *contain*
    // `sha1` (e.g. `def _lazy_sha1(string)` from flask's
    // `src/flask/sessions.py:276`, which was the original BUG-07 FP).
    let has_qualified = line_text.contains("hashlib.sha1");
    let has_standalone_call = find_standalone_call(line_text, "sha1").is_some();
    if has_qualified || has_standalone_call {
        let column = line_text
            .find("hashlib.sha1")
            .or_else(|| find_standalone_call(line_text, "sha1"))
            .unwrap_or(0) as u32;
        return Some(MisuseFinding {
            file: file.to_string(),
            line,
            column,
            rule: rule.clone(),
            api_call: "hashlib.sha1".to_string(),
            message: "SHA1 is cryptographically weak and should not be used for security purposes"
                .to_string(),
            fix_suggestion: "Use hashlib.sha256() or stronger".to_string(),
            code_context: line_text.to_string(),
        });
    }

    None
}

/// Check for unclosed file
fn check_unclosed_file(
    rule: &APIRule,
    file: &str,
    line: u32,
    line_text: &str,
) -> Option<MisuseFinding> {
    // Look for "open(" that's not after "with "
    // This is a simplified check - a proper implementation would use AST
    if line_text.contains("open(")
        && !line_text.contains("with ")
        && !line_text.starts_with("with ")
    {
        // Check if it's an assignment (f = open(...))
        if line_text.contains("= open(") || line_text.contains("=open(") {
            let column = line_text.find("open(").unwrap_or(0) as u32;
            return Some(MisuseFinding {
                file: file.to_string(),
                line,
                column,
                rule: rule.clone(),
                api_call: "open".to_string(),
                message: "File opened without context manager may not be properly closed"
                    .to_string(),
                fix_suggestion: "Use 'with open(path) as f:' to ensure file is closed".to_string(),
                code_context: line_text.to_string(),
            });
        }
    }

    None
}

/// Check for insecure random usage
fn check_insecure_random(
    rule: &APIRule,
    file: &str,
    line: u32,
    line_text: &str,
) -> Option<MisuseFinding> {
    // Look for random.* usage that might be for security
    let insecure_patterns = [
        "random.randint(",
        "random.random(",
        "random.choice(",
        "random.randrange(",
    ];

    // Only flag if it looks like it's being used for security
    // (contains words like token, secret, password, key)
    let security_indicators = ["token", "secret", "password", "key", "auth", "session"];

    for pattern in &insecure_patterns {
        if line_text.contains(pattern) {
            // Check if the line or nearby context suggests security use
            let line_lower = line_text.to_lowercase();
            for indicator in &security_indicators {
                if line_lower.contains(indicator) {
                    let column = line_text.find(pattern).unwrap_or(0) as u32;
                    return Some(MisuseFinding {
                        file: file.to_string(),
                        line,
                        column,
                        rule: rule.clone(),
                        api_call: pattern.trim_end_matches('(').to_string(),
                        message: format!(
                            "{} is not cryptographically secure, don't use for security purposes",
                            pattern.trim_end_matches('(')
                        ),
                        fix_suggestion:
                            "Use secrets.token_bytes() or secrets.token_hex() for security"
                                .to_string(),
                        code_context: line_text.to_string(),
                    });
                }
            }
        }
    }

    None
}

/// Check for poisoned mutex lock unwrap.
fn check_mutex_lock_unwrap(
    rule: &APIRule,
    file: &str,
    line: u32,
    line_text: &str,
) -> Option<MisuseFinding> {
    if line_text.contains(".lock().unwrap()") {
        let column = line_text.find(".lock().unwrap()").unwrap_or(0) as u32;
        return Some(MisuseFinding {
            file: file.to_string(),
            line,
            column,
            rule: rule.clone(),
            api_call: "Mutex::lock".to_string(),
            message:
                "Mutex::lock().unwrap() can panic on poisoned locks and hide deadlock behavior"
                    .to_string(),
            fix_suggestion:
                "Handle lock errors explicitly (match/if let), or use try_lock with backoff"
                    .to_string(),
            code_context: line_text.to_string(),
        });
    }
    None
}

/// Check for File::open without context propagation.
fn check_file_open_without_context(
    rule: &APIRule,
    file: &str,
    line: u32,
    line_text: &str,
) -> Option<MisuseFinding> {
    if line_text.contains("File::open(")
        && !line_text.contains(".context(")
        && !line_text.contains(".with_context(")
        && !line_text.contains("map_err(")
    {
        let column = line_text.find("File::open(").unwrap_or(0) as u32;
        return Some(MisuseFinding {
            file: file.to_string(),
            line,
            column,
            rule: rule.clone(),
            api_call: "File::open".to_string(),
            message: "File::open used without contextual error mapping".to_string(),
            fix_suggestion:
                "Wrap errors with context (with_context/context/map_err) before propagating"
                    .to_string(),
            code_context: line_text.to_string(),
        });
    }
    None
}

/// Check for capacity allocations sourced from unbounded input.
///
/// fix-R7-cl4 (v0.5.0 CLOSEOUT): the substring heuristic (`input`/`args`/
/// `user`/`request`/`len`/`size`) fired on `Vec::with_capacity(existing.len())`
/// — safe pre-sizing from an already-allocated collection — because `.len()`
/// contains the substring `len`. The AST pre-pass (`rust_api_ctx`) recorded
/// the line of every `with_capacity` call whose argument is provably SAFE (a
/// `.len()`/`.capacity()`/`.size()` method call, an integer literal, or a
/// const). We suppress the heuristic on those lines. `len`/`size` are removed
/// from the marker list so the heuristic no longer self-triggers on `.len()`
/// even on the parse-failure fallback path.
fn check_unbounded_with_capacity(
    rule: &APIRule,
    file: &str,
    line: u32,
    line_text: &str,
    rust_api_ctx: &RustApiCheckContext,
) -> Option<MisuseFinding> {
    if line_text.contains("Vec::with_capacity(") {
        // AST gate: a provably-safe capacity argument (e.g. `existing.len()`)
        // is not unbounded external input. Skip it. Fail-open when the file
        // did not parse (the tightened marker list below still applies).
        if rust_api_ctx.parsed && rust_api_ctx.safe_with_capacity_line_set.contains(&line) {
            return None;
        }
        let line_lower = line_text.to_lowercase();
        // `len`/`size` removed (analysis root-cause #4): they matched `.len()`
        // on safe pre-sizing. The remaining markers name unbounded external
        // sources.
        let user_input_markers = ["input", "args", "user", "request"];
        if user_input_markers.iter().any(|m| line_lower.contains(m)) {
            let column = line_text.find("Vec::with_capacity(").unwrap_or(0) as u32;
            return Some(MisuseFinding {
                file: file.to_string(),
                line,
                column,
                rule: rule.clone(),
                api_call: "Vec::with_capacity".to_string(),
                message: "Vec::with_capacity appears to use unbounded external input".to_string(),
                fix_suggestion:
                    "Clamp requested capacity with a hard upper bound before allocation".to_string(),
                code_context: line_text.to_string(),
            });
        }
    }
    None
}

/// Check for detached tokio tasks.
fn check_detached_tokio_spawn(
    rule: &APIRule,
    file: &str,
    line: u32,
    line_text: &str,
) -> Option<MisuseFinding> {
    if line_text.contains("tokio::spawn(")
        && !line_text.contains('=')
        && !line_text.contains("handles.push")
    {
        let column = line_text.find("tokio::spawn(").unwrap_or(0) as u32;
        return Some(MisuseFinding {
            file: file.to_string(),
            line,
            column,
            rule: rule.clone(),
            api_call: "tokio::spawn".to_string(),
            message: "tokio::spawn used without keeping JoinHandle".to_string(),
            fix_suggestion: "Store JoinHandle values and await them to surface task errors"
                .to_string(),
            code_context: line_text.to_string(),
        });
    }
    None
}

/// Check for map iteration order assumptions.
///
/// fix-R7-cl4 (v0.5.0 CLOSEOUT): the prior heuristic flagged ANY
/// `for ... .iter()` line in a file that merely CONTAINED the substring
/// `HashMap` anywhere (`rust_ctx.file_has_hashmap`), so iterating a slice/Vec
/// (deterministic order) in a file that names HashMap once was a false
/// positive (ripgrep: 10/10 FPs). The AST pre-pass (`rust_api_ctx`) resolved
/// the iterated receiver's type and recorded only the lines whose `for` loop
/// iterates a genuine HashMap/HashSet binding. We require the line to be in
/// that set. When the file did not parse we fail-open to the old file-wide
/// heuristic (preserving recall).
fn check_hashmap_order_dependence(
    rule: &APIRule,
    file: &str,
    line: u32,
    line_text: &str,
    rust_ctx: &RustLineContext<'_>,
    rust_api_ctx: &RustApiCheckContext,
) -> Option<MisuseFinding> {
    let looks_like_iteration = line_text.contains(".iter()")
        && (line_text.contains("for ") || rust_ctx.previous_line.starts_with("for "));
    // AST-resolved receiver gate: fire only when the iterated receiver is a
    // HashMap/HashSet. Fail-open (old file-wide proxy) when the parse failed.
    let receiver_is_hashmap = if rust_api_ctx.parsed {
        rust_api_ctx.hashmap_iter_line_set.contains(&line)
    } else {
        rust_ctx.file_has_hashmap
    };
    let looks_like_hashmap_iteration = looks_like_iteration && receiver_is_hashmap;
    if looks_like_hashmap_iteration {
        let column = line_text.find(".iter()").unwrap_or(0) as u32;
        return Some(MisuseFinding {
            file: file.to_string(),
            line,
            column,
            rule: rule.clone(),
            api_call: "HashMap::iter".to_string(),
            message: "Potential logic dependence on HashMap iteration order".to_string(),
            fix_suggestion: "Use BTreeMap/IndexMap or sort keys before ordered operations"
                .to_string(),
            code_context: line_text.to_string(),
        });
    }
    None
}

/// Check for clone usage in loop bodies.
fn check_clone_in_hot_loop(
    rule: &APIRule,
    file: &str,
    line: u32,
    line_text: &str,
    rust_ctx: &RustLineContext<'_>,
) -> Option<MisuseFinding> {
    if line_text.contains(".clone()")
        && (line_text.contains("for ") || line_text.contains("while ") || rust_ctx.previous_is_loop)
    {
        let column = line_text.find(".clone()").unwrap_or(0) as u32;
        return Some(MisuseFinding {
            file: file.to_string(),
            line,
            column,
            rule: rule.clone(),
            api_call: "clone".to_string(),
            message: "clone() in loop context may create avoidable allocation overhead".to_string(),
            fix_suggestion: "Prefer borrowing/references or move semantics inside hot loops"
                .to_string(),
            code_context: line_text.to_string(),
        });
    }
    None
}

// =============================================================================
// Filtering
// =============================================================================

/// Filter findings by category and severity
fn filter_findings(
    findings: Vec<MisuseFinding>,
    categories: Option<&[MisuseCategory]>,
    severities: Option<&[MisuseSeverity]>,
) -> Vec<MisuseFinding> {
    findings
        .into_iter()
        .filter(|f| {
            // Category filter
            if let Some(cats) = categories {
                if !cats.contains(&f.rule.category) {
                    return false;
                }
            }

            // Severity filter
            if let Some(sevs) = severities {
                if !sevs.contains(&f.rule.severity) {
                    return false;
                }
            }

            true
        })
        .collect()
}

// =============================================================================
// Summary Building
// =============================================================================

/// Render a `MisuseCategory` using the same snake_case form as serde
/// serialization (schema-naming-and-units-v1). Keeping summary keys in sync
/// with `findings[].rule.category` lets consumers join the two without
/// ad-hoc normalization.
fn serialize_misuse_category(cat: &MisuseCategory) -> String {
    match cat {
        MisuseCategory::CallOrder => "call_order".to_string(),
        MisuseCategory::ErrorHandling => "error_handling".to_string(),
        MisuseCategory::Parameters => "parameters".to_string(),
        MisuseCategory::Resources => "resources".to_string(),
        MisuseCategory::Crypto => "crypto".to_string(),
        MisuseCategory::Concurrency => "concurrency".to_string(),
        MisuseCategory::Security => "security".to_string(),
        MisuseCategory::Correctness => "correctness".to_string(),
    }
}

/// Render a `MisuseSeverity` using the same snake_case form as serde
/// serialization (schema-naming-and-units-v1).
fn serialize_misuse_severity(sev: &MisuseSeverity) -> String {
    match sev {
        MisuseSeverity::Info => "info".to_string(),
        MisuseSeverity::Low => "low".to_string(),
        MisuseSeverity::Medium => "medium".to_string(),
        MisuseSeverity::High => "high".to_string(),
    }
}

/// Build summary from findings
fn build_summary(findings: &[MisuseFinding], files_scanned: u32) -> APICheckSummary {
    let mut by_category: HashMap<String, u32> = HashMap::new();
    let mut by_severity: HashMap<String, u32> = HashMap::new();
    let mut apis_checked: Vec<String> = Vec::new();

    for finding in findings {
        // Count by category — use snake_case serde representation so the
        // summary key matches what is emitted on `findings[].rule.category`
        // (schema-naming-and-units-v1). Previously `format!("{:?}", ...).to_lowercase()`
        // produced collapsed-case keys like `errorhandling` while the per-finding
        // detail used `error_handling`, forcing consumers to normalize.
        let cat_str = serialize_misuse_category(&finding.rule.category);
        *by_category.entry(cat_str).or_insert(0) += 1;

        // Count by severity — use snake_case serde representation for the same reason.
        let sev_str = serialize_misuse_severity(&finding.rule.severity);
        *by_severity.entry(sev_str).or_insert(0) += 1;

        // Track APIs
        if !apis_checked.contains(&finding.api_call) {
            apis_checked.push(finding.api_call.clone());
        }
    }

    APICheckSummary {
        total_findings: findings.len() as u32,
        by_category,
        by_severity,
        apis_checked,
        files_scanned,
    }
}

// =============================================================================
// Output Formatting
// =============================================================================

/// Format report as human-readable text
fn format_api_check_text(report: &APICheckReport) -> String {
    let mut output = String::new();

    output.push_str("=== API Check Report ===\n\n");

    // Summary
    output.push_str(&format!(
        "Files scanned: {}\n",
        report.summary.files_scanned
    ));
    output.push_str(&format!("Rules applied: {}\n", report.rules_applied));
    output.push_str(&format!(
        "Total findings: {}\n\n",
        report.summary.total_findings
    ));

    // By severity
    if !report.summary.by_severity.is_empty() {
        output.push_str("By Severity:\n");
        for (severity, count) in &report.summary.by_severity {
            output.push_str(&format!("  {}: {}\n", severity, count));
        }
        output.push('\n');
    }

    // By category
    if !report.summary.by_category.is_empty() {
        output.push_str("By Category:\n");
        for (category, count) in &report.summary.by_category {
            output.push_str(&format!("  {}: {}\n", category, count));
        }
        output.push('\n');
    }

    // Findings
    if !report.findings.is_empty() {
        output.push_str("Findings:\n");
        output.push_str(&"-".repeat(60));
        output.push('\n');

        for finding in &report.findings {
            output.push_str(&format!(
                "[{:?}] {} ({})\n",
                finding.rule.severity, finding.rule.name, finding.rule.id
            ));
            output.push_str(&format!(
                "  Location: {}:{}:{}\n",
                finding.file, finding.line, finding.column
            ));
            output.push_str(&format!("  API: {}\n", finding.api_call));
            output.push_str(&format!("  Message: {}\n", finding.message));
            output.push_str(&format!("  Fix: {}\n", finding.fix_suggestion));
            if !finding.code_context.is_empty() {
                output.push_str(&format!("  Context: {}\n", finding.code_context.trim()));
            }
            output.push('\n');
        }
    } else {
        output.push_str("No API misuse patterns detected.\n");
    }

    output
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_python_rules_defined() {
        let rules = python_rules();
        assert!(!rules.is_empty());
        assert!(rules.iter().any(|r| r.id == "PY001")); // missing-timeout
        assert!(rules.iter().any(|r| r.id == "PY002")); // bare-except
        assert!(rules.iter().any(|r| r.id == "PY003")); // weak-hash-md5
        assert!(rules.iter().any(|r| r.id == "PY005")); // unclosed-file
    }

    #[test]
    fn test_rust_rules_defined() {
        let rules = rust_rules();
        assert!(!rules.is_empty());
        assert!(rules.iter().any(|r| r.id == "RS001"));
        assert!(rules.iter().any(|r| r.id == "RS002"));
        assert!(rules.iter().any(|r| r.id == "RS003"));
        assert!(rules.iter().any(|r| r.id == "RS004"));
        assert!(rules.iter().any(|r| r.id == "RS005"));
        assert!(rules.iter().any(|r| r.id == "RS006"));
    }

    #[test]
    fn test_all_supported_languages_have_rules() {
        for language in all_api_languages() {
            let rules = rules_for_language(*language);
            assert!(
                !rules.is_empty(),
                "expected at least one api-check rule for {:?}",
                language
            );
        }
    }

    #[test]
    fn test_detect_language_extended_extensions() {
        let cases = [
            ("main.go", ApiLanguage::Go),
            ("Main.java", ApiLanguage::Java),
            ("app.js", ApiLanguage::JavaScript),
            ("component.tsx", ApiLanguage::TypeScript),
            ("main.c", ApiLanguage::C),
            ("main.cpp", ApiLanguage::Cpp),
            ("app.rb", ApiLanguage::Ruby),
            ("index.php", ApiLanguage::Php),
            ("Main.kt", ApiLanguage::Kotlin),
            ("main.swift", ApiLanguage::Swift),
            ("Program.cs", ApiLanguage::CSharp),
            ("Main.scala", ApiLanguage::Scala),
            ("app.ex", ApiLanguage::Elixir),
            ("main.lua", ApiLanguage::Lua),
            ("game.luau", ApiLanguage::Luau),
            ("main.ml", ApiLanguage::Ocaml),
        ];

        for (path, expected) in cases {
            assert_eq!(detect_language(Path::new(path)), Some(expected), "{path}");
        }
    }

    #[test]
    fn test_check_missing_timeout() {
        let rule = &python_rules()[0]; // PY001

        // Should detect
        let finding = check_missing_timeout(rule, "test.py", 1, "response = requests.get(url)");
        assert!(finding.is_some());

        // Should not detect (has timeout)
        let finding = check_missing_timeout(
            rule,
            "test.py",
            1,
            "response = requests.get(url, timeout=30)",
        );
        assert!(finding.is_none());
    }

    #[test]
    fn test_check_bare_except() {
        let rule = &python_rules()[1]; // PY002

        // Should detect
        let finding = check_bare_except(rule, "test.py", 1, "except:");
        assert!(finding.is_some());

        // Should not detect (has exception type)
        let finding = check_bare_except(rule, "test.py", 1, "except Exception:");
        assert!(finding.is_none());
    }

    #[test]
    fn test_check_md5_usage() {
        let rule = &python_rules()[2]; // PY003

        // Should detect
        let finding = check_md5_usage(rule, "test.py", 1, "hash = hashlib.md5(data)");
        assert!(finding.is_some());

        // Should not detect
        let finding = check_md5_usage(rule, "test.py", 1, "hash = hashlib.sha256(data)");
        assert!(finding.is_none());
    }

    #[test]
    fn test_check_unclosed_file() {
        let rule = &python_rules()[4]; // PY005

        // Should detect
        let finding = check_unclosed_file(rule, "test.py", 1, "f = open('data.txt')");
        assert!(finding.is_some());

        // Should not detect (using context manager)
        let finding = check_unclosed_file(rule, "test.py", 1, "with open('data.txt') as f:");
        assert!(finding.is_none());
    }

    #[test]
    fn test_filter_by_category() {
        let findings = vec![
            MisuseFinding {
                file: "test.py".to_string(),
                line: 1,
                column: 0,
                rule: APIRule {
                    id: "PY001".to_string(),
                    name: "test".to_string(),
                    category: MisuseCategory::Parameters,
                    severity: MisuseSeverity::High,
                    description: "test".to_string(),
                    correct_usage: "test".to_string(),
                },
                api_call: "test".to_string(),
                message: "test".to_string(),
                fix_suggestion: "test".to_string(),
                code_context: "test".to_string(),
            },
            MisuseFinding {
                file: "test.py".to_string(),
                line: 2,
                column: 0,
                rule: APIRule {
                    id: "PY003".to_string(),
                    name: "test".to_string(),
                    category: MisuseCategory::Crypto,
                    severity: MisuseSeverity::High,
                    description: "test".to_string(),
                    correct_usage: "test".to_string(),
                },
                api_call: "test".to_string(),
                message: "test".to_string(),
                fix_suggestion: "test".to_string(),
                code_context: "test".to_string(),
            },
        ];

        let filtered = filter_findings(findings, Some(&[MisuseCategory::Crypto]), None);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].rule.category, MisuseCategory::Crypto);
    }

    #[test]
    fn test_build_summary() {
        let findings = vec![MisuseFinding {
            file: "test.py".to_string(),
            line: 1,
            column: 0,
            rule: APIRule {
                id: "PY001".to_string(),
                name: "test".to_string(),
                category: MisuseCategory::Parameters,
                severity: MisuseSeverity::High,
                description: "test".to_string(),
                correct_usage: "test".to_string(),
            },
            api_call: "requests.get".to_string(),
            message: "test".to_string(),
            fix_suggestion: "test".to_string(),
            code_context: "test".to_string(),
        }];

        let summary = build_summary(&findings, 5);
        assert_eq!(summary.total_findings, 1);
        assert_eq!(summary.files_scanned, 5);
        assert!(summary.apis_checked.contains(&"requests.get".to_string()));
    }

    #[test]
    fn test_collect_files_includes_rust() {
        let temp = TempDir::new().unwrap();
        let py = temp.path().join("a.py");
        let rs = temp.path().join("b.rs");
        let go = temp.path().join("c.go");
        let txt = temp.path().join("c.txt");
        fs::write(&py, "print('ok')").unwrap();
        fs::write(&rs, "fn main() {}").unwrap();
        fs::write(&go, "package main").unwrap();
        fs::write(&txt, "ignore").unwrap();

        let files = collect_files(temp.path()).unwrap();
        assert!(files.iter().any(|f| f.ends_with("a.py")));
        assert!(files.iter().any(|f| f.ends_with("b.rs")));
        assert!(files.iter().any(|f| f.ends_with("c.go")));
        assert!(!files.iter().any(|f| f.ends_with("c.txt")));
    }

    #[test]
    fn test_check_mutex_lock_unwrap() {
        let rule = &rust_rules()[0];
        let finding =
            check_mutex_lock_unwrap(rule, "lib.rs", 10, "let guard = shared.lock().unwrap();");
        assert!(finding.is_some());
    }

    #[test]
    fn test_check_file_open_without_context() {
        let rule = &rust_rules()[1];
        let finding = check_file_open_without_context(rule, "lib.rs", 8, "let f = File::open(p)?;");
        assert!(finding.is_some());

        let contextual = check_file_open_without_context(
            rule,
            "lib.rs",
            9,
            "let f = File::open(p).with_context(|| \"open\".to_string())?;",
        );
        assert!(contextual.is_none());
    }

    #[test]
    fn test_check_unbounded_with_capacity() {
        let rule = &rust_rules()[2];
        // Parse-failure fallback context (parsed=false) → relies on the
        // tightened marker list. `len` was removed from the markers, so a bare
        // `len` identifier no longer self-triggers; use an `input`-named arg to
        // exercise the unbounded-input path.
        let ctx = RustApiCheckContext::default();
        let finding = check_unbounded_with_capacity(
            rule,
            "lib.rs",
            12,
            "let v = Vec::with_capacity(input_len);",
            &ctx,
        );
        assert!(finding.is_some());

        let bounded = check_unbounded_with_capacity(
            rule,
            "lib.rs",
            13,
            "let v = Vec::with_capacity(256);",
            &ctx,
        );
        assert!(bounded.is_none());
    }

    #[test]
    fn test_check_tokio_spawn_detached() {
        let rule = &rust_rules()[3];
        let detached = check_detached_tokio_spawn(
            rule,
            "lib.rs",
            3,
            "tokio::spawn(async move { work().await; });",
        );
        let tracked = check_detached_tokio_spawn(
            rule,
            "lib.rs",
            4,
            "let handle = tokio::spawn(async move { work().await; });",
        );
        assert!(detached.is_some());
        assert!(tracked.is_none());
    }

    #[test]
    fn test_check_hashmap_order_dependence() {
        let rule = &rust_rules()[4];
        let ctx = RustLineContext {
            file_has_hashmap: true,
            previous_line: "for (k, v) in map",
            previous_is_loop: true,
        };
        // Parse-failure fallback (parsed=false) → falls back to the file-wide
        // `file_has_hashmap` proxy, preserving the original behaviour here.
        let api_ctx = RustApiCheckContext::default();
        let finding =
            check_hashmap_order_dependence(rule, "lib.rs", 12, "    .iter()", &ctx, &api_ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn test_check_clone_in_hot_loop() {
        let rule = &rust_rules()[5];
        let ctx = RustLineContext {
            file_has_hashmap: false,
            previous_line: "for item in items {",
            previous_is_loop: true,
        };
        let finding = check_clone_in_hot_loop(rule, "lib.rs", 20, "value.clone()", &ctx);
        assert!(finding.is_some());
    }

    fn assert_language_findings(
        filename: &str,
        language: ApiLanguage,
        source: &str,
        expected_rule_id: &str,
    ) {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join(filename);
        fs::write(&path, source).unwrap();
        let rules = rules_for_language(language);
        let findings = analyze_file(&path, &rules, language).unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule.id == expected_rule_id),
            "expected {expected_rule_id} for {filename}, got {:?}",
            findings
                .iter()
                .map(|f| f.rule.id.clone())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_extended_language_rule_detection() {
        let cases = [
            (
                "main.go",
                ApiLanguage::Go,
                "data, _ := ioutil.ReadFile(path)",
                "GO001",
            ),
            (
                "Main.java",
                ApiLanguage::Java,
                "if (name == otherName) { }",
                "JV001",
            ),
            ("app.js", ApiLanguage::JavaScript, "if (a == b) {}", "JS001"),
            ("app.ts", ApiLanguage::TypeScript, "if (a == b) {}", "TS001"),
            ("main.c", ApiLanguage::C, "gets(buffer);", "C001"),
            (
                "main.cpp",
                ApiLanguage::Cpp,
                "std::auto_ptr<Foo> p;",
                "CPP003",
            ),
            ("app.rb", ApiLanguage::Ruby, "eval(params[:code])", "RB001"),
            (
                "index.php",
                ApiLanguage::Php,
                "unserialize($payload);",
                "PH005",
            ),
            ("Main.kt", ApiLanguage::Kotlin, "val name = user!!", "KT001"),
            (
                "main.swift",
                ApiLanguage::Swift,
                "let name = value!",
                "SW003",
            ),
            (
                "Program.cs",
                ApiLanguage::CSharp,
                "var x = task.Result;",
                "CS003",
            ),
            (
                "Main.scala",
                ApiLanguage::Scala,
                "val casted = value.asInstanceOf[String]",
                "SC002",
            ),
            (
                "app.ex",
                ApiLanguage::Elixir,
                "String.to_atom(param)",
                "EX001",
            ),
            ("main.lua", ApiLanguage::Lua, "value = 1", "LU001"),
            ("game.luau", ApiLanguage::Luau, "os.execute(cmd)", "LU003"),
            ("main.ml", ApiLanguage::Ocaml, "Obj.magic value", "OC004"),
        ];

        for (filename, language, source, expected_rule_id) in cases {
            assert_language_findings(filename, language, source, expected_rule_id);
        }
    }

    // fastpath-extend-non-vuln-v1 — verify the file-level fast-path
    // does not strip findings from a normal-input fixture.
    #[test]
    fn test_fastpath_extension_no_perf_regression_on_normal_input() {
        use std::time::Instant;

        let temp = TempDir::new().unwrap();
        let root = temp.path();

        // Mixed-language fixture covering each rule needle path:
        // - Python `requests.` (PY001) and `hashlib.md5` (PY003)
        // - Rust `Mutex` (RS001) and `with_capacity` (RS003)
        // - Go `ioutil.ReadFile` (GO001)
        // - JavaScript `eval` (JS005)
        // - Files with NO needle hits — must be cleanly skipped.
        fs::write(
            root.join("py_hits.py"),
            "import requests\nrequests.get('http://x')\nimport hashlib\nh = hashlib.md5(b'x').hexdigest()\n",
        )
        .unwrap();
        fs::write(
            root.join("rs_hits.rs"),
            "use std::sync::Mutex;\nlet lock = Mutex::new(0);\nlet v: Vec<u8> = Vec::with_capacity(input);\n",
        )
        .unwrap();
        fs::write(
            root.join("go_hits.go"),
            "package main\nimport \"io/ioutil\"\nfunc f() { _, _ = ioutil.ReadFile(\"/etc/passwd\") }\n",
        )
        .unwrap();
        fs::write(
            root.join("js_hits.js"),
            "function f(s) { eval(s); }\n",
        )
        .unwrap();
        // File with no rule needles — cleanly skipped by the fast-path.
        fs::write(
            root.join("py_no_hits.py"),
            "def add(a, b):\n    return a + b\n\nif __name__ == '__main__':\n    print(add(1, 2))\n",
        )
        .unwrap();

        let files = [
            (root.join("py_hits.py"), ApiLanguage::Python, true),
            (root.join("rs_hits.rs"), ApiLanguage::Rust, true),
            (root.join("go_hits.go"), ApiLanguage::Go, true),
            (root.join("js_hits.js"), ApiLanguage::JavaScript, true),
            (root.join("py_no_hits.py"), ApiLanguage::Python, false),
        ];

        let start = Instant::now();
        for (path, lang, expect_findings) in files {
            let rules = rules_for_language(lang);
            let findings = analyze_file(&path, &rules, lang).unwrap();
            if expect_findings {
                assert!(
                    !findings.is_empty(),
                    "expected findings for {:?} (rule keyword present in source)",
                    path.file_name()
                );
            } else {
                // No needle in the source: fast-path returns empty.
                // Some rules (e.g. PY002 bare-except) might still match
                // unrelated lines, but in this fixture none do.
                assert!(
                    findings.is_empty(),
                    "expected no findings for {:?}, got {:?}",
                    path.file_name(),
                    findings.iter().map(|f| f.rule.id.clone()).collect::<Vec<_>>()
                );
            }
        }
        let elapsed = start.elapsed();
        // 5-file run including I/O and per-file regex compile must
        // complete well under 2 s — pre-fix this could time out on
        // slow CI; post-fix it should be milliseconds.
        assert!(
            elapsed.as_secs() < 2,
            "fastpath-extend-non-vuln-v1: 5-file fixture took {:?}, expected <2s",
            elapsed
        );
    }

    // fastpath-extend-non-vuln-v1 — pin the correctness contract for
    // `extract_literal_from_regex`: the literal returned for every
    // built-in regex rule must be a substring of the rule's
    // `api_call`-equivalent positive sample.
    #[test]
    fn test_extract_literal_from_regex_recovers_useful_needles() {
        // Cases: (regex_pattern, expected_literal_substring_or_empty,
        //         positive_sample_that_must_contain_the_literal)
        let cases: &[(&str, &str, &str)] = &[
            (r"\bioutil\.ReadFile\s*\(", "ioutil.ReadFile", "x := ioutil.ReadFile(p)"),
            (r"\bunserialize\s*\(", "unserialize", "unserialize($x);"),
            (r"\beval\s*\(", "eval", "eval(s)"),
            (
                r"\bRuntime\.getRuntime\(\)\.exec\s*\(",
                "Runtime.getRuntime().exec",
                "Runtime.getRuntime().exec(c)",
            ),
            // Pure-symbol patterns: empty literal → "always admit".
            (r"\s==\s|\s!=\s", "", "if (a == b)"),
            // Pure char-class pattern: empty literal.
            (r"\b[A-Za-z_][A-Za-z0-9_]*!", "", "value!"),
        ];
        for (pattern, expected, sample) in cases {
            let literal = extract_literal_from_regex(pattern);
            assert_eq!(
                literal.as_str(),
                *expected,
                "pattern {:?} should yield literal {:?}",
                pattern,
                expected
            );
            if !literal.is_empty() {
                assert!(
                    sample.contains(literal.as_str()),
                    "literal {:?} from pattern {:?} must be a substring of positive sample {:?}",
                    literal,
                    pattern,
                    sample
                );
            }
        }
    }

    // fastpath-extend-non-vuln-v1 — verify the language-fastpath needle
    // list is non-empty for every supported language (or contains an
    // empty string for the always-admit fallback).
    #[test]
    fn test_language_fastpath_needles_cover_all_languages() {
        for &lang in all_api_languages() {
            let needles = language_fastpath_needles(lang);
            assert!(
                !needles.is_empty(),
                "language {:?} has no fastpath needles",
                lang
            );
        }
    }

    // =====================================================================
    // fix-C5-1 (v0.5.0 AUDIT-FIX): api-check AST-ify — JS005 eval-call must
    // not fire inside string literals, LU001 must not fire inside Lua
    // `--[[ ]]` block comments.
    // =====================================================================

    fn write_tmp(dir: &TempDir, name: &str, content: &str) -> PathBuf {
        let p = dir.path().join(name);
        std::fs::write(&p, content).unwrap();
        p
    }

    /// RED→GREEN: `eval(` appearing *inside a string literal* is not a real
    /// call and must not trigger JS005. Mirrors js-express
    /// `test/res.redirect.js:115-116`
    /// (`var xss = 'javascript:eval(document.body.innerHTML=...);'`).
    #[test]
    fn test_js005_eval_in_string_literal_not_flagged() {
        let dir = TempDir::new().unwrap();
        let src = "function f() {\n  var xss = 'javascript:eval(document.body.innerHTML);';\n  var enc = \"x:eval(y)\";\n}\n";
        let path = write_tmp(&dir, "redirect.js", src);
        let rules = rules_for_language(ApiLanguage::JavaScript);
        let findings = analyze_file(&path, &rules, ApiLanguage::JavaScript).unwrap();
        let js005: Vec<_> = findings.iter().filter(|f| f.rule.id == "JS005").collect();
        assert!(
            js005.is_empty(),
            "JS005 must not fire on eval() inside string literals, got {:?}",
            js005.iter().map(|f| (f.line, &f.code_context)).collect::<Vec<_>>()
        );
    }

    /// Guard against over-suppression: a genuine top-level `eval(userInput)`
    /// call MUST still be flagged by JS005.
    #[test]
    fn test_js005_real_eval_call_still_flagged() {
        let dir = TempDir::new().unwrap();
        let src = "function f(userInput) {\n  eval(userInput);\n}\n";
        let path = write_tmp(&dir, "real.js", src);
        let rules = rules_for_language(ApiLanguage::JavaScript);
        let findings = analyze_file(&path, &rules, ApiLanguage::JavaScript).unwrap();
        let js005: Vec<_> = findings.iter().filter(|f| f.rule.id == "JS005").collect();
        assert_eq!(
            js005.len(),
            1,
            "a real eval() call must still be flagged, got {:?}",
            js005.iter().map(|f| f.line).collect::<Vec<_>>()
        );
        assert_eq!(js005[0].line, 2);
    }

    /// The TS variant of the eval rule (TS005) shares the gate.
    #[test]
    fn test_ts005_eval_in_string_literal_not_flagged() {
        let dir = TempDir::new().unwrap();
        let src = "const s: string = 'do not eval(this)';\n";
        let path = write_tmp(&dir, "x.ts", src);
        let rules = rules_for_language(ApiLanguage::TypeScript);
        let findings = analyze_file(&path, &rules, ApiLanguage::TypeScript).unwrap();
        assert!(
            findings.iter().all(|f| f.rule.id != "TS005"),
            "TS005 must not fire on eval() inside a string literal"
        );
    }

    /// Direct unit test on the JS eval call-site context builder: only the
    /// line carrying a real `call_expression` to `eval` is in the set.
    #[test]
    fn test_js_eval_context_only_real_call_lines() {
        let src = "var s = 'eval(x)';\neval(y);\nwindow.eval(z);\n";
        let ctx = compute_js_api_check_context(src, ApiLanguage::JavaScript);
        assert!(ctx.parsed, "expected a successful parse");
        assert!(
            !ctx.eval_call_line_set.contains(&1),
            "line 1 (eval inside string) must NOT be an eval call-site"
        );
        assert!(
            ctx.eval_call_line_set.contains(&2),
            "line 2 (real eval call) must be an eval call-site"
        );
        assert!(
            ctx.eval_call_line_set.contains(&3),
            "line 3 (window.eval member call) must be an eval call-site"
        );
    }

    /// RED→GREEN: LU001 implicit-global must not fire on `name = "..."`
    /// lines that live inside a Lua `--[[ ]]` block comment (lit-meta
    /// headers). Mirrors lua-luvit `deps/ustring.lua:19-24`.
    #[test]
    fn test_lu001_block_comment_not_flagged() {
        let dir = TempDir::new().unwrap();
        let src = "--[[lit-meta\n  name = \"luvit/ustring\"\n  version = \"2.0.3\"\n  license = \"Apache 2\"\n]]\n\nlocal x = 1\n";
        let path = write_tmp(&dir, "ustring.lua", src);
        let rules = rules_for_language(ApiLanguage::Lua);
        let findings = analyze_file(&path, &rules, ApiLanguage::Lua).unwrap();
        let lu001: Vec<_> = findings.iter().filter(|f| f.rule.id == "LU001").collect();
        assert!(
            lu001.is_empty(),
            "LU001 must not fire inside a --[[ ]] block comment, got {:?}",
            lu001.iter().map(|f| (f.line, &f.code_context)).collect::<Vec<_>>()
        );
    }

    /// Guard: a genuine top-level implicit global outside any comment MUST
    /// still be flagged by LU001. Use a scalar RHS (`42`) so the
    /// pre-existing table-constructor gate (lu001-ast-gate-v1) does not also
    /// apply — this isolates the comment-line gate added in fix-C5-1.
    #[test]
    fn test_lu001_real_implicit_global_still_flagged() {
        let dir = TempDir::new().unwrap();
        let src = "GLOBAL_COUNTER = 42\n";
        let path = write_tmp(&dir, "g.lua", src);
        let rules = rules_for_language(ApiLanguage::Lua);
        let findings = analyze_file(&path, &rules, ApiLanguage::Lua).unwrap();
        let lu001: Vec<_> = findings.iter().filter(|f| f.rule.id == "LU001").collect();
        assert_eq!(
            lu001.len(),
            1,
            "a real implicit global must still be flagged, got {:?}",
            lu001.iter().map(|f| f.line).collect::<Vec<_>>()
        );
    }

    /// Direct unit test on the Lua comment line-set: the block-comment span
    /// is captured (multi-line `comment` node), normal code lines are not.
    #[test]
    fn test_lua_comment_line_set_covers_block_comment() {
        let src = "--[[lit-meta\n  name = \"x\"\n]]\nlocal a = 1\n";
        let ctx = compute_lua_api_check_context(src, ApiLanguage::Lua);
        assert!(ctx.comment_line_set.contains(&1), "line 1 (--[[) in block comment");
        assert!(ctx.comment_line_set.contains(&2), "line 2 (name = ...) in block comment");
        assert!(ctx.comment_line_set.contains(&3), "line 3 (]]) in block comment");
        assert!(
            !ctx.comment_line_set.contains(&4),
            "line 4 (local a = 1) is real code, not a comment"
        );
    }

    /// lu001-loopvar-param-binder-v1 (v0.5.0 RC5-LU001): a bare `x = ...`
    /// assignment whose LHS is a **for-loop variable** (numeric or generic)
    /// or a **function parameter** is a reassignment of an in-scope binding,
    /// NOT an implicit global. Pre-fix `visit()` only harvested `local`
    /// declarations, so the for-loop loop var and the function param leaked
    /// as LU001 implicit-global false positives.
    ///
    /// GENERALIZATION GATE (anti-treadmill): this single fixture exercises
    /// EVERY variant in the symptom class at once —
    ///   - a `local` reassign (`total = ...`, must STAY suppressed),
    ///   - a numeric-for loop var (`i = ...`, `for_numeric_clause`),
    ///   - a generic-for loop var (`name = ...`, `for_generic_clause`),
    ///   - a function parameter (`factor = ...`, `parameters`),
    /// and asserts that ONLY the genuine top-level implicit global
    /// (`REAL_GLOBAL = 5`) survives. A fix that closes only one variant
    /// fails this test.
    const LU001_LOOPVAR_PARAM_SRC: &str = "local function process(items, factor)\n\tlocal total = 0\n\tfor i = 1, #items do\n\t\ti = i + 0\n\t\ttotal = total + items[i]\n\tend\n\tfor _, name in ipairs(items) do\n\t\tname = tostring(name)\n\t\tprint(name)\n\tend\n\tfactor = factor or 1\n\treturn total\nend\n\nREAL_GLOBAL = 5\n";

    #[test]
    fn test_lu001_loopvar_and_param_reassign_not_flagged_luau() {
        let dir = TempDir::new().unwrap();
        let path = write_tmp(&dir, "process.luau", LU001_LOOPVAR_PARAM_SRC);
        let rules = rules_for_language(ApiLanguage::Luau);
        let findings = analyze_file(&path, &rules, ApiLanguage::Luau).unwrap();
        let lu001: Vec<_> = findings.iter().filter(|f| f.rule.id == "LU001").collect();
        assert_eq!(
            lu001.len(),
            1,
            "only the genuine implicit global must be flagged; loop vars + params + local reassign must be suppressed, got {:?}",
            lu001.iter().map(|f| (f.line, &f.code_context)).collect::<Vec<_>>()
        );
        assert!(
            lu001[0].code_context.contains("REAL_GLOBAL"),
            "the surviving finding must be the real global REAL_GLOBAL, got {:?}",
            lu001[0].code_context
        );
    }

    /// The LU001 rule + its AST context builder are shared between Lua and
    /// Luau (same grammar node names). The same fixture must therefore
    /// suppress the same FP class under the plain-Lua language path.
    #[test]
    fn test_lu001_loopvar_and_param_reassign_not_flagged_lua() {
        let dir = TempDir::new().unwrap();
        let path = write_tmp(&dir, "process.lua", LU001_LOOPVAR_PARAM_SRC);
        let rules = rules_for_language(ApiLanguage::Lua);
        let findings = analyze_file(&path, &rules, ApiLanguage::Lua).unwrap();
        let lu001: Vec<_> = findings.iter().filter(|f| f.rule.id == "LU001").collect();
        assert_eq!(
            lu001.len(),
            1,
            "Lua path must also suppress loop vars + params + local reassign, got {:?}",
            lu001.iter().map(|f| (f.line, &f.code_context)).collect::<Vec<_>>()
        );
        assert!(
            lu001[0].code_context.contains("REAL_GLOBAL"),
            "the surviving finding must be the real global REAL_GLOBAL, got {:?}",
            lu001[0].code_context
        );
    }

    /// Direct unit test on the context builder: numeric-for vars, generic-for
    /// vars, and function params must all land in `local_names_in_scope`
    /// alongside the `local`-declared name, for BOTH Lua and Luau.
    #[test]
    fn test_lua_context_collects_loop_vars_and_params() {
        for lang in [ApiLanguage::Lua, ApiLanguage::Luau] {
            let ctx = compute_lua_api_check_context(LU001_LOOPVAR_PARAM_SRC, lang);
            for name in ["total", "i", "name", "factor"] {
                assert!(
                    ctx.local_names_in_scope.contains(name),
                    "{:?}: expected in-scope binding {:?} in local_names_in_scope, got {:?}",
                    lang,
                    name,
                    ctx.local_names_in_scope
                );
            }
            // A genuine global must NOT be harvested as an in-scope binding.
            assert!(
                !ctx.local_names_in_scope.contains("REAL_GLOBAL"),
                "{:?}: REAL_GLOBAL is a global, not an in-scope binding",
                lang
            );
        }
    }

    // =====================================================================
    // fix-R7-cl4 (v0.5.0 CLOSEOUT): api-check AST-driven precision fixes.
    // Each rule below was a regex/substring heuristic that "sees text, not
    // syntax/types". The fixes add a per-file tree-sitter context (mirroring
    // the established js_ctx / cpp_ctx / lua_ctx pattern) and gate the rule
    // through it. Tests pin BOTH the FP-suppression and the genuine-detection
    // guard (RED→GREEN, no #[ignore], no weakened assertion).
    // =====================================================================

    fn ids_for(findings: &[MisuseFinding], id: &str) -> Vec<u32> {
        findings
            .iter()
            .filter(|f| f.rule.id == id)
            .map(|f| f.line)
            .collect()
    }

    // ---- JV001: type-aware Java string `==` -----------------------------

    /// JV001 must NOT fire on a Class-identity comparison (`type == Foo.class`),
    /// a primitive-int comparison (`code == 204`), or an array `.length == 0`
    /// check. These are the okhttp/retrofit false positives.
    #[test]
    fn test_jv001_class_and_primitive_comparisons_not_flagged() {
        let dir = TempDir::new().unwrap();
        let src = "class C {\n  void m() {\n    if (type == ResponseBody.class) { }\n    if (code == 204 || code == 205) { }\n    if (arr.length == 0) { }\n  }\n}\n";
        let path = write_tmp(&dir, "OkHttpCall.java", src);
        let rules = rules_for_language(ApiLanguage::Java);
        let findings = analyze_file(&path, &rules, ApiLanguage::Java).unwrap();
        assert!(
            ids_for(&findings, "JV001").is_empty(),
            "JV001 must not fire on Class-identity / primitive / .length comparisons, got lines {:?}",
            ids_for(&findings, "JV001")
        );
    }

    /// Guard: a comparison with a string literal operand is a genuine
    /// reference-equality bug and MUST still be flagged.
    #[test]
    fn test_jv001_string_literal_comparison_still_flagged() {
        let dir = TempDir::new().unwrap();
        let src = "class C {\n  void m(String s) {\n    if (s == \"hello\") { }\n  }\n}\n";
        let path = write_tmp(&dir, "S.java", src);
        let rules = rules_for_language(ApiLanguage::Java);
        let findings = analyze_file(&path, &rules, ApiLanguage::Java).unwrap();
        assert_eq!(
            ids_for(&findings, "JV001"),
            vec![3],
            "JV001 must still flag `s == \"hello\"`"
        );
    }

    /// Guard: two bare identifiers compared with `==` remain flagged (the
    /// existing high-recall heuristic — type cannot be resolved, but neither
    /// operand is provably non-String). This preserves
    /// `test_extended_language_rule_detection`'s `name == otherName` case.
    #[test]
    fn test_jv001_two_identifiers_still_flagged() {
        let dir = TempDir::new().unwrap();
        let src = "class C {\n  void m() {\n    if (name == otherName) { }\n  }\n}\n";
        let path = write_tmp(&dir, "I.java", src);
        let rules = rules_for_language(ApiLanguage::Java);
        let findings = analyze_file(&path, &rules, ApiLanguage::Java).unwrap();
        assert_eq!(
            ids_for(&findings, "JV001"),
            vec![3],
            "JV001 must still flag two-identifier == comparison"
        );
    }

    /// Direct unit test on the Java comparison context builder.
    #[test]
    fn test_java_string_eq_context_excludes_nonstring_operands() {
        let src = "class C { void m() {\n  boolean a = type == ResponseBody.class;\n  boolean b = code == 204;\n  boolean c = s == \"x\";\n  boolean d = p == q;\n} }\n";
        let ctx = compute_java_api_check_context(src, ApiLanguage::Java);
        assert!(ctx.parsed, "expected successful parse");
        assert!(!ctx.string_eq_line_set.contains(&2), "class-literal cmp excluded");
        assert!(!ctx.string_eq_line_set.contains(&3), "primitive int cmp excluded");
        assert!(ctx.string_eq_line_set.contains(&4), "string-literal cmp included");
        assert!(ctx.string_eq_line_set.contains(&5), "two-identifier cmp included");
    }

    /// bug3-apicheck-java-narrow (v0.5.0 BACKLOG): JV001 must NOT fire when one
    /// operand is a UNARY numeric literal (`-1`, `colon == -1`, `-1.5`). A
    /// signed/negated number is an int / long / float, never a `String`, so a
    /// `==` against it is not a reference-equality bug. The corpus false
    /// positive was `colon == -1` in retrofit's `RequestFactory.java`. Pre-fix,
    /// `java_operand_is_provably_non_string` had no `unary_expression` arm, so a
    /// `-1` (parsed as `unary_expression` with a `decimal_integer_literal`
    /// operand) fell through to `_ => false` and the comparison looked plausible.
    ///
    /// GENERALIZATION GATE (anti-treadmill): one fixture exercises every variant
    /// in the symptom class at once — a unary literal in the LHS position
    /// (`-1 == colon`), the RHS position (`colon == -1`), and a floating-point
    /// literal (`colon == -1.5`) — while the genuine-detection guards stay
    /// flagged: the string-literal comparison (`s == "x"`) AND the DEFERRED
    /// id==id comparison (`name == otherName`, whose suppression needs
    /// type-inference and is intentionally out of scope here). A fix that closes
    /// only one operand position fails this test.
    #[test]
    fn test_jv001_unary_numeric_literal_not_flagged() {
        let dir = TempDir::new().unwrap();
        let src = "class C {\n  void m(int colon, String s, String name, String otherName) {\n    boolean a = -1 == colon;\n    boolean b = colon == -1;\n    boolean c = colon == -1.5;\n    boolean d = s == \"x\";\n    boolean e = name == otherName;\n  }\n}\n";
        let path = write_tmp(&dir, "RequestFactory.java", src);
        let rules = rules_for_language(ApiLanguage::Java);
        let findings = analyze_file(&path, &rules, ApiLanguage::Java).unwrap();
        assert_eq!(
            ids_for(&findings, "JV001"),
            vec![6, 7],
            "JV001 must suppress unary-numeric-literal comparisons (lines 3-5) yet still flag the genuine string-literal (line 6) and the deferred id==id (line 7) cases, got {:?}",
            ids_for(&findings, "JV001")
        );
    }

    /// Direct unit test on the Java comparison context builder: a
    /// `unary_expression` numeric-literal operand (`-1`, `-1.5`) is provably
    /// non-String in BOTH operand positions, so its operator line is excluded
    /// from `string_eq_line_set`.
    #[test]
    fn test_java_string_eq_context_excludes_unary_numeric_literal() {
        let src = "class C { void m(int colon) {\n  boolean a = -1 == colon;\n  boolean b = colon == -1;\n  boolean c = colon == -1.5;\n} }\n";
        let ctx = compute_java_api_check_context(src, ApiLanguage::Java);
        assert!(ctx.parsed, "expected successful parse");
        assert!(!ctx.string_eq_line_set.contains(&2), "unary `-1` in LHS position excluded");
        assert!(!ctx.string_eq_line_set.contains(&3), "unary `-1` in RHS position excluded");
        assert!(!ctx.string_eq_line_set.contains(&4), "unary `-1.5` float in RHS position excluded");
    }

    // ---- JS001/TS001: loose equality only inside real expressions -------

    /// JS001 must NOT fire on `!=` / `==` that lives inside a string literal
    /// (express.json's `'should parse when content-length != char length'`).
    #[test]
    fn test_js001_operator_in_string_literal_not_flagged() {
        let dir = TempDir::new().unwrap();
        let src = "function f() {\n  var msg = 'should parse when content-length != char length';\n}\n";
        let path = write_tmp(&dir, "express.json.js", src);
        let rules = rules_for_language(ApiLanguage::JavaScript);
        let findings = analyze_file(&path, &rules, ApiLanguage::JavaScript).unwrap();
        assert!(
            ids_for(&findings, "JS001").is_empty(),
            "JS001 must not fire on != inside a string literal, got {:?}",
            ids_for(&findings, "JS001")
        );
    }

    /// Guard: a genuine loose-equality `==` MUST still be flagged, and the
    /// emitted api_call must reflect the matched operator.
    #[test]
    fn test_js001_real_loose_equality_still_flagged_with_correct_api_call() {
        let dir = TempDir::new().unwrap();
        let src = "function f(a, b) {\n  if (a == b) {}\n  if (a != b) {}\n}\n";
        let path = write_tmp(&dir, "eq.js", src);
        let rules = rules_for_language(ApiLanguage::JavaScript);
        let findings = analyze_file(&path, &rules, ApiLanguage::JavaScript).unwrap();
        let js001: Vec<_> = findings.iter().filter(|f| f.rule.id == "JS001").collect();
        assert_eq!(js001.len(), 2, "both loose-equality lines must be flagged");
        // api_call must be derived from the matched operator, not hardcoded.
        let eq = js001.iter().find(|f| f.line == 2).unwrap();
        let neq = js001.iter().find(|f| f.line == 3).unwrap();
        assert_eq!(eq.api_call, "==", "== line must report api_call ==");
        assert_eq!(neq.api_call, "!=", "!= line must report api_call != (was mislabeled ==)");
    }

    /// TS001 shares the gate.
    #[test]
    fn test_ts001_operator_in_string_literal_not_flagged() {
        let dir = TempDir::new().unwrap();
        let src = "const s: string = 'a == b is a string';\n";
        let path = write_tmp(&dir, "x.ts", src);
        let rules = rules_for_language(ApiLanguage::TypeScript);
        let findings = analyze_file(&path, &rules, ApiLanguage::TypeScript).unwrap();
        assert!(
            ids_for(&findings, "TS001").is_empty(),
            "TS001 must not fire on == inside a string literal"
        );
    }

    /// Direct unit test on the JS loose-equality context: only real
    /// binary_expression operator lines are in the set, not string interiors.
    #[test]
    fn test_js_loose_equality_context_only_real_operators() {
        let src = "var s = 'x == y';\nif (a == b) {}\nif (c != d) {}\n";
        let ctx = compute_js_api_check_context(src, ApiLanguage::JavaScript);
        assert!(ctx.parsed, "expected successful parse");
        assert!(!ctx.loose_equality_line_set.contains(&1), "string interior excluded");
        assert!(ctx.loose_equality_line_set.contains(&2), "real == included");
        assert!(ctx.loose_equality_line_set.contains(&3), "real != included");
    }

    // ---- taxonomy: correct category buckets ----------------------------

    /// fix-R7-apicheck-taxonomy-v1: loose-equality / string-== / implicit-global
    /// must NOT be bucketed under `call_order`.
    #[test]
    fn test_taxonomy_correctness_rules_not_call_order() {
        // JV001
        assert_eq!(
            JAVA_RULE_SPECS.iter().find(|s| s.id == "JV001").unwrap().category,
            MisuseCategory::Correctness
        );
        // JS001 / TS001
        assert_eq!(
            JAVASCRIPT_RULE_SPECS.iter().find(|s| s.id == "JS001").unwrap().category,
            MisuseCategory::Correctness
        );
        assert_eq!(
            TYPESCRIPT_RULE_SPECS.iter().find(|s| s.id == "TS001").unwrap().category,
            MisuseCategory::Correctness
        );
        // LU001
        assert_eq!(
            LUA_RULE_SPECS.iter().find(|s| s.id == "LU001").unwrap().category,
            MisuseCategory::Correctness
        );
        // GO005 → Concurrency (cancellation/context), not CallOrder
        assert_eq!(
            GO_RULE_SPECS.iter().find(|s| s.id == "GO005").unwrap().category,
            MisuseCategory::Concurrency
        );
        // RS005 legitimately stays CallOrder.
        assert_eq!(
            rust_rules().iter().find(|r| r.id == "RS005").unwrap().category,
            MisuseCategory::CallOrder
        );
    }

    /// `correctness` must round-trip through the snake_case serializer used
    /// for summary.by_category keys.
    #[test]
    fn test_correctness_category_serializes_snake_case() {
        assert_eq!(serialize_misuse_category(&MisuseCategory::Correctness), "correctness");
    }

    // ---- RS003: with_capacity from an existing collection length -------

    /// RS003 must NOT fire on `Vec::with_capacity(existing.len())` — safe
    /// pre-sizing from an already-allocated in-memory collection.
    #[test]
    fn test_rs003_with_capacity_from_len_not_flagged() {
        let dir = TempDir::new().unwrap();
        let src = "fn f(existing: &[u8]) {\n    let mut v = Vec::with_capacity(existing.len());\n    let _ = &mut v;\n}\n";
        let path = write_tmp(&dir, "hiargs.rs", src);
        let rules = rules_for_language(ApiLanguage::Rust);
        let findings = analyze_file(&path, &rules, ApiLanguage::Rust).unwrap();
        assert!(
            ids_for(&findings, "RS003").is_empty(),
            "RS003 must not fire on with_capacity(x.len()), got {:?}",
            ids_for(&findings, "RS003")
        );
    }

    /// Guard: with_capacity sourced from a bare unbounded input identifier
    /// (no `.len()`) MUST still be flagged.
    #[test]
    fn test_rs003_with_capacity_from_unbounded_input_still_flagged() {
        let dir = TempDir::new().unwrap();
        let src = "fn f(request_size: usize) {\n    let v: Vec<u8> = Vec::with_capacity(request_size);\n    let _ = v;\n}\n";
        let path = write_tmp(&dir, "alloc.rs", src);
        let rules = rules_for_language(ApiLanguage::Rust);
        let findings = analyze_file(&path, &rules, ApiLanguage::Rust).unwrap();
        assert_eq!(
            ids_for(&findings, "RS003"),
            vec![2],
            "RS003 must still flag with_capacity(request_size)"
        );
    }

    // ---- RS005: iterate a real HashMap, not any .iter() ----------------

    /// RS005 must NOT fire on `for &x in slice.iter()` where the receiver is a
    /// slice/Vec, even if the file mentions HashMap elsewhere (ripgrep FP).
    #[test]
    fn test_rs005_slice_iteration_not_flagged() {
        let dir = TempDir::new().unwrap();
        let src = "use std::collections::HashMap;\nfn f(flags: &[u8]) {\n    let _m: HashMap<u8, u8> = HashMap::new();\n    for &flag in flags.iter() {\n        let _ = flag;\n    }\n}\n";
        let path = write_tmp(&dir, "defs.rs", src);
        let rules = rules_for_language(ApiLanguage::Rust);
        let findings = analyze_file(&path, &rules, ApiLanguage::Rust).unwrap();
        assert!(
            ids_for(&findings, "RS005").is_empty(),
            "RS005 must not fire iterating a slice, got {:?}",
            ids_for(&findings, "RS005")
        );
    }

    /// Guard: iterating a genuine HashMap binding MUST still be flagged.
    #[test]
    fn test_rs005_real_hashmap_iteration_still_flagged() {
        let dir = TempDir::new().unwrap();
        let src = "use std::collections::HashMap;\nfn f() {\n    let map: HashMap<u8, u8> = HashMap::new();\n    for (k, v) in map.iter() {\n        let _ = (k, v);\n    }\n}\n";
        let path = write_tmp(&dir, "real_map.rs", src);
        let rules = rules_for_language(ApiLanguage::Rust);
        let findings = analyze_file(&path, &rules, ApiLanguage::Rust).unwrap();
        assert_eq!(
            ids_for(&findings, "RS005"),
            vec![4],
            "RS005 must still flag iteration over a real HashMap"
        );
    }

    // ---- CS001: BinaryFormatter type-use vs method name ----------------

    /// CS001 must NOT fire on a user method *named* `BinaryFormatter()`.
    #[test]
    fn test_cs001_method_named_binaryformatter_not_flagged() {
        let dir = TempDir::new().unwrap();
        let src = "class X {\n    public TestClass BinaryFormatter() { return null; }\n    public byte[] BinaryFormatter2() { return null; }\n}\n";
        let path = write_tmp(&dir, "Bench.cs", src);
        let rules = rules_for_language(ApiLanguage::CSharp);
        let findings = analyze_file(&path, &rules, ApiLanguage::CSharp).unwrap();
        assert!(
            ids_for(&findings, "CS001").is_empty(),
            "CS001 must not fire on a method named BinaryFormatter, got {:?}",
            ids_for(&findings, "CS001")
        );
    }

    /// Guard: a genuine `new BinaryFormatter()` instantiation MUST still fire.
    #[test]
    fn test_cs001_real_binaryformatter_use_still_flagged() {
        let dir = TempDir::new().unwrap();
        let src = "class X {\n    void m() {\n        var f = new BinaryFormatter();\n        var _ = f;\n    }\n}\n";
        let path = write_tmp(&dir, "Use.cs", src);
        let rules = rules_for_language(ApiLanguage::CSharp);
        let findings = analyze_file(&path, &rules, ApiLanguage::CSharp).unwrap();
        assert_eq!(
            ids_for(&findings, "CS001"),
            vec![3],
            "CS001 must still flag new BinaryFormatter()"
        );
    }

    // ---- EX001: capture-operator form of String.to_atom ----------------

    /// EX001 must ALSO catch the capture form `&String.to_atom/1` (no paren),
    /// which the `\(`-anchored regex missed (plug builder.ex:382).
    #[test]
    fn test_ex001_capture_form_flagged() {
        let dir = TempDir::new().unwrap();
        let src = "defmodule M do\n  def f(list) do\n    Enum.map(list, &String.to_atom/1)\n  end\nend\n";
        let path = write_tmp(&dir, "builder.ex", src);
        let rules = rules_for_language(ApiLanguage::Elixir);
        let findings = analyze_file(&path, &rules, ApiLanguage::Elixir).unwrap();
        assert_eq!(
            ids_for(&findings, "EX001"),
            vec![3],
            "EX001 must flag the &String.to_atom/1 capture form"
        );
    }

    /// Guard: the normal call form still fires (no regression).
    #[test]
    fn test_ex001_call_form_still_flagged() {
        let dir = TempDir::new().unwrap();
        let src = "defmodule M do\n  def f(p) do\n    String.to_atom(p)\n  end\nend\n";
        let path = write_tmp(&dir, "call.ex", src);
        let rules = rules_for_language(ApiLanguage::Elixir);
        let findings = analyze_file(&path, &rules, ApiLanguage::Elixir).unwrap();
        assert_eq!(
            ids_for(&findings, "EX001"),
            vec![3],
            "EX001 must still flag String.to_atom(p)"
        );
    }

    // ---- OCaml OC003/OC005: real call sites only -----------------------

    /// OC005 must NOT fire on `.mli` `val open_in :` signatures, nor on a
    /// sentinel `let open_in = `Use_Io` binding, nor on a comment mention.
    #[test]
    fn test_oc005_val_sig_and_sentinel_not_flagged() {
        let dir = TempDir::new().unwrap();
        // .mli val sigs:
        let mli = "val open_in : string -> in_channel\nval open_out : string -> out_channel\n";
        let mli_path = write_tmp(&dir, "io_intf.mli", mli);
        let rules = rules_for_language(ApiLanguage::Ocaml);
        let findings = analyze_file(&mli_path, &rules, ApiLanguage::Ocaml).unwrap();
        assert!(
            ids_for(&findings, "OC005").is_empty(),
            "OC005 must not fire on .mli val signatures, got {:?}",
            ids_for(&findings, "OC005")
        );
        // sentinel disabling binding:
        let sentinel = "let open_in = `Use_Io\nlet open_out = `Use_Io\n";
        let s_path = write_tmp(&dir, "no_io.ml", sentinel);
        let findings = analyze_file(&s_path, &rules, ApiLanguage::Ocaml).unwrap();
        assert!(
            ids_for(&findings, "OC005").is_empty(),
            "OC005 must not fire on a sentinel `let open_in = `Use_Io` binding, got {:?}",
            ids_for(&findings, "OC005")
        );
    }

    /// OC003 must NOT fire on a `[Sys.command]` mention inside a `(** ... *)`
    /// doc comment (string.mli:123 — interior line of a multi-line comment).
    #[test]
    fn test_oc003_comment_mention_not_flagged() {
        let dir = TempDir::new().unwrap();
        let src = "(** This calls the system shell\n    (eg by using [Sys.command]). *)\nlet x = 1\n";
        let path = write_tmp(&dir, "string.ml", src);
        let rules = rules_for_language(ApiLanguage::Ocaml);
        let findings = analyze_file(&path, &rules, ApiLanguage::Ocaml).unwrap();
        assert!(
            ids_for(&findings, "OC003").is_empty(),
            "OC003 must not fire on [Sys.command] inside a doc comment, got {:?}",
            ids_for(&findings, "OC003")
        );
    }

    /// Guard: genuine `open_in`/`Sys.command` call sites MUST still fire.
    #[test]
    fn test_oc003_oc005_real_call_sites_still_flagged() {
        let dir = TempDir::new().unwrap();
        let src = "let read () =\n  let ic = open_in \"f\" in\n  ignore (Sys.command \"ls\");\n  ic\n";
        let path = write_tmp(&dir, "real.ml", src);
        let rules = rules_for_language(ApiLanguage::Ocaml);
        let findings = analyze_file(&path, &rules, ApiLanguage::Ocaml).unwrap();
        assert_eq!(
            ids_for(&findings, "OC005"),
            vec![2],
            "OC005 must still flag a real open_in call"
        );
        assert_eq!(
            ids_for(&findings, "OC003"),
            vec![3],
            "OC003 must still flag a real Sys.command call"
        );
    }

    // ---- ERC002: Solidity public state-var auto-getters ----------------

    /// ERC002 must NOT report `getApproved` / `isApprovedForAll` missing when
    /// they are provided as `public` mapping auto-getters (solmate ERC721.sol).
    #[test]
    fn test_erc002_public_mapping_autogetters_satisfy_interface() {
        let dir = TempDir::new().unwrap();
        let src = "// SPDX-License-Identifier: MIT\ncontract ERC721 {\n    mapping(address => uint256) public balanceOf;\n    mapping(uint256 => address) public ownerOf;\n    mapping(uint256 => address) public getApproved;\n    mapping(address => mapping(address => bool)) public isApprovedForAll;\n    function transferFrom(address from, address to, uint256 id) public {}\n    function safeTransferFrom(address from, address to, uint256 id) public {}\n    function approve(address spender, uint256 id) public {}\n    function setApprovalForAll(address operator, bool approved) public {}\n    event Transfer(address indexed from, address indexed to, uint256 indexed id);\n    event Approval(address indexed owner, address indexed spender, uint256 indexed id);\n    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);\n}\n";
        let path = write_tmp(&dir, "ERC721.sol", src);
        let findings = analyze_solidity_erc(src, path.to_str().unwrap());
        let missing_getapproved = findings.iter().any(|f| {
            f.rule.id == "ERC002" && f.api_call.contains("getApproved")
        });
        let missing_isapproved = findings.iter().any(|f| {
            f.rule.id == "ERC002" && f.api_call.contains("isApprovedForAll")
        });
        assert!(
            !missing_getapproved,
            "ERC002 must not report getApproved missing — it is a public mapping auto-getter"
        );
        assert!(
            !missing_isapproved,
            "ERC002 must not report isApprovedForAll missing — it is a public mapping auto-getter"
        );
    }

    /// Direct unit test: a public mapping state variable is collected as a
    /// synthesized getter SolFunction with the right param types / return.
    #[test]
    fn test_solidity_public_mapping_synthesizes_getter() {
        let src = "contract C {\n    mapping(uint256 => address) public getApproved;\n    mapping(address => mapping(address => bool)) public isApprovedForAll;\n    uint256 public totalSupply;\n    uint256 private hidden;\n}\n";
        let tree = tldr_core::ast::parser::parse(src, Language::Solidity).unwrap();
        let mut contracts = Vec::new();
        collect_solidity_contracts(tree.root_node(), &mut contracts);
        let functions = solidity_contract_functions(&contracts[0], src);
        let get_approved = functions.iter().find(|f| f.name == "getApproved");
        assert!(get_approved.is_some(), "getApproved getter must be synthesized");
        let ga = get_approved.unwrap();
        assert_eq!(ga.param_types, vec!["uint256".to_string()], "getApproved(uint256)");
        assert!(ga.return_count >= 1, "getApproved returns the value type");

        let is_approved = functions.iter().find(|f| f.name == "isApprovedForAll").unwrap();
        assert_eq!(
            is_approved.param_types,
            vec!["address".to_string(), "address".to_string()],
            "nested mapping flattens to (address, address)"
        );
        assert!(is_approved.return_count >= 1);

        let total = functions.iter().find(|f| f.name == "totalSupply").unwrap();
        assert!(total.param_types.is_empty(), "scalar getter takes no params");
        assert!(total.return_count >= 1);

        // A `private` state var does NOT auto-generate a public getter.
        assert!(
            functions.iter().all(|f| f.name != "hidden"),
            "private state var must not synthesize a getter"
        );
    }
}
