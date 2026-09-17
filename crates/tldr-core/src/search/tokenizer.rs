//! Code-aware tokenizer for BM25 search
//!
//! Tokenizes code identifiers by splitting:
//! - camelCase: `processData` -> `["process", "data"]`
//! - snake_case: `process_data` -> `["process", "data"]`
//! - PascalCase: `ProcessData` -> `["process", "data"]`
//! - SCREAMING_CASE: `PROCESS_DATA` -> `["process", "data"]`
//! - digit boundaries: `OAuth2Provider` -> `["oauth", "provider"]`,
//!   `APIv2` -> `["api", "v2"]`, `Base64Encoder` -> `["base", "64", "encoder"]`
//!   (issue #84; lone digits are dropped by `min_length`)
//!
//! # Mitigation M11
//! This tokenizer must match the Python implementation exactly to ensure
//! BM25 search results have >= 80% overlap.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Code-aware tokenizer for BM25 search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tokenizer {
    /// Stopwords to filter out
    stopwords: HashSet<String>,
    /// Minimum token length
    min_length: usize,
}

impl Default for Tokenizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Tokenizer {
    /// Create a new tokenizer with default settings
    pub fn new() -> Self {
        Self {
            stopwords: Self::default_stopwords(),
            min_length: 2,
        }
    }

    /// Create a tokenizer with custom stopwords
    pub fn with_stopwords(stopwords: HashSet<String>) -> Self {
        Self {
            stopwords,
            min_length: 2,
        }
    }

    /// Default stopwords for code search
    ///
    /// Includes common programming keywords that don't add semantic value
    fn default_stopwords() -> HashSet<String> {
        [
            // Common programming keywords
            "def",
            "class",
            "function",
            "fn",
            "func",
            "pub",
            "private",
            "public",
            "static",
            "const",
            "let",
            "var",
            "mut",
            "if",
            "else",
            "elif",
            "then",
            "for",
            "while",
            "do",
            "loop",
            "break",
            "continue",
            "return",
            "yield",
            "try",
            "catch",
            "except",
            "finally",
            "throw",
            "raise",
            "import",
            "from",
            "export",
            "module",
            "package",
            "use",
            "require",
            "include",
            "with",
            "as",
            "in",
            "is",
            "not",
            "and",
            "or",
            "true",
            "false",
            "null",
            "none",
            "nil",
            "self",
            "this",
            "super",
            "new",
            "delete",
            "sizeof",
            "typeof",
            "instanceof",
            // Common short words
            "a",
            "an",
            "the",
            "to",
            "of",
            "on",
            "at",
            "by",
            "it",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    /// Tokenize a string into searchable tokens
    ///
    /// # Example
    /// ```
    /// use tldr_core::search::tokenizer::Tokenizer;
    ///
    /// let tokenizer = Tokenizer::new();
    /// let tokens = tokenizer.tokenize("processUserData_v2");
    /// assert!(tokens.contains(&"process".to_string()));
    /// assert!(tokens.contains(&"user".to_string()));
    /// assert!(tokens.contains(&"data".to_string()));
    /// ```
    pub fn tokenize(&self, text: &str) -> Vec<String> {
        let mut tokens = Vec::new();

        // First, split on whitespace and punctuation
        for word in Self::split_on_delimiters(text) {
            // Then split camelCase and snake_case
            for token in self.split_identifier(&word) {
                let lower = token.to_lowercase();

                // Filter by length and stopwords
                if lower.len() >= self.min_length && !self.stopwords.contains(&lower) {
                    tokens.push(lower);
                }
            }
        }

        tokens
    }

    /// Tokenize and return unique tokens
    pub fn tokenize_unique(&self, text: &str) -> HashSet<String> {
        self.tokenize(text).into_iter().collect()
    }

    /// Split text on whitespace and punctuation delimiters
    fn split_on_delimiters(text: &str) -> Vec<String> {
        let mut result = Vec::new();
        let mut current = String::new();

        for ch in text.chars() {
            if ch.is_alphanumeric() || ch == '_' {
                current.push(ch);
            } else if !current.is_empty() {
                result.push(std::mem::take(&mut current));
            }
        }

        if !current.is_empty() {
            result.push(current);
        }

        result
    }

    /// Split a single identifier by camelCase, snake_case, and digit boundaries
    ///
    /// Examples:
    /// - `processData` -> `["process", "Data"]`
    /// - `process_data` -> `["process", "data"]`
    /// - `ProcessUserData` -> `["Process", "User", "Data"]`
    /// - `HTTPRequest` -> `["HTTP", "Request"]`
    /// - `OAuth2Provider` -> `["OAuth", "2", "Provider"]` (issue #84)
    /// - `APIv2` -> `["API", "v2"]`
    /// - `JSONv3Parser` -> `["JSON", "v3", "Parser"]`
    ///
    /// # Boundary rules (issue #84)
    ///
    /// A new token starts before the current character when:
    ///
    /// 1. **Underscore** — snake_case delimiter.
    /// 2. **lower→upper** — camelCase boundary (`processData`).
    /// 3. **Acronym→word** — uppercase followed by lowercase, with more than
    ///    one char accumulated (`HTTPRequest` -> `HTTP` | `Request`). The
    ///    `current.len() > 1` guard keeps single-letter PascalCase prefixes
    ///    (`IService`) whole (issue #8). This rule is skipped when the
    ///    following lowercase char starts a *version marker* (`v` + digit),
    ///    because `v2` is not a word start (`HTTPv2` must not split into
    ///    `HTT` + `Pv2`).
    /// 4. **letter→digit** — split when the accumulated token is at least
    ///    `min_length` chars (`OAuth2` -> `OAuth` + `2`, `Base64` ->
    ///    `Base` + `64`). Short letter runs stay glued to their digits so
    ///    version suffixes like `v2` and `x86` survive as single tokens,
    ///    preserving the pre-existing `processUserData_v2` -> `v2`
    ///    convention.
    /// 5. **Version marker** — a lowercase `v` preceded by an uppercase char
    ///    and followed by a digit starts a new token (`APIv2` -> `API` +
    ///    `v2`, `JSONv3Parser` -> `JSON` + `v3` + `Parser`).
    /// 6. **digit→letter** — a digit run always ends before a following
    ///    letter (`OAuth2Provider` -> `OAuth` + `2` + `Provider`).
    ///
    /// Before rule 4/6 existed, `OAuth2Provider` tokenized as
    /// `["oauth2", "provider"]`: a query for `oauth` had no term to match in
    /// the BM25 index and returned zero results (issue #84).
    fn split_identifier(&self, word: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut current = String::new();
        let mut prev_was_upper = false;
        let mut prev_was_underscore = false;

        let chars: Vec<char> = word.chars().collect();

        for (i, &ch) in chars.iter().enumerate() {
            if ch == '_' {
                // Underscore is a delimiter in snake_case
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
                prev_was_underscore = true;
                prev_was_upper = false;
                continue;
            }

            let is_upper = ch.is_uppercase();
            let is_digit = ch.is_ascii_digit();
            let next = chars.get(i + 1).copied();
            let next_is_lower = next.map(|c| c.is_lowercase()).unwrap_or(false);
            let next_is_digit = next.map(|c| c.is_ascii_digit()).unwrap_or(false);
            // A lowercase 'v' immediately followed by a digit is a version
            // marker (`v2`, `v3`), not the start of a word.
            let next_is_version_marker = next == Some('v')
                && chars
                    .get(i + 2)
                    .map(|c| c.is_ascii_digit())
                    .unwrap_or(false);
            let prev_is_digit = current
                .chars()
                .last()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false);

            // Start new token on the boundary rules documented above.
            let should_split = !current.is_empty()
                && (prev_was_underscore
                    || !prev_was_upper && is_upper
                    || (is_upper && next_is_lower && !next_is_version_marker && current.len() > 1)
                    || (is_digit && !prev_is_digit && current.len() >= self.min_length)
                    || (!is_digit && prev_is_digit)
                    || (ch == 'v' && prev_was_upper && next_is_digit));

            if should_split {
                tokens.push(std::mem::take(&mut current));
            }

            current.push(ch);
            prev_was_upper = is_upper;
            prev_was_underscore = false;
        }

        if !current.is_empty() {
            tokens.push(current);
        }

        tokens
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize_camel_case() {
        let tokenizer = Tokenizer::new();
        let tokens = tokenizer.tokenize("processData");
        assert!(tokens.contains(&"process".to_string()));
        assert!(tokens.contains(&"data".to_string()));
    }

    #[test]
    fn test_tokenize_snake_case() {
        let tokenizer = Tokenizer::new();
        let tokens = tokenizer.tokenize("process_data");
        assert!(tokens.contains(&"process".to_string()));
        assert!(tokens.contains(&"data".to_string()));
    }

    #[test]
    fn test_tokenize_pascal_case() {
        let tokenizer = Tokenizer::new();
        let tokens = tokenizer.tokenize("ProcessUserData");
        assert!(tokens.contains(&"process".to_string()));
        assert!(tokens.contains(&"user".to_string()));
        assert!(tokens.contains(&"data".to_string()));
    }

    #[test]
    fn test_tokenize_http_abbreviation() {
        let tokenizer = Tokenizer::new();
        let tokens = tokenizer.tokenize("HTTPRequest");
        assert!(tokens.contains(&"http".to_string()));
        assert!(tokens.contains(&"request".to_string()));
    }

    #[test]
    fn test_tokenize_mixed() {
        let tokenizer = Tokenizer::new();
        let tokens = tokenizer.tokenize("processUserData_v2");
        assert!(tokens.contains(&"process".to_string()));
        assert!(tokens.contains(&"user".to_string()));
        assert!(tokens.contains(&"data".to_string()));
        assert!(tokens.contains(&"v2".to_string()));
    }

    #[test]
    fn test_tokenize_filters_stopwords() {
        let tokenizer = Tokenizer::new();
        let tokens = tokenizer.tokenize("def processData");
        // "def" should be filtered as stopword
        assert!(!tokens.contains(&"def".to_string()));
        assert!(tokens.contains(&"process".to_string()));
        assert!(tokens.contains(&"data".to_string()));
    }

    #[test]
    fn test_tokenize_case_insensitive() {
        let tokenizer = Tokenizer::new();
        let tokens = tokenizer.tokenize("PROCESS_DATA");
        assert!(tokens.contains(&"process".to_string()));
        assert!(tokens.contains(&"data".to_string()));
    }

    #[test]
    fn test_split_identifier_simple() {
        let tokenizer = Tokenizer::new();
        let parts = tokenizer.split_identifier("processData");
        assert_eq!(parts, vec!["process", "Data"]);
    }

    #[test]
    fn test_split_identifier_snake() {
        let tokenizer = Tokenizer::new();
        let parts = tokenizer.split_identifier("process_data");
        assert_eq!(parts, vec!["process", "data"]);
    }

    /// Regression test for issue #8 — single-letter PascalCase prefixes
    /// (e.g. `IService`, `XRequest`) must NOT be split at the first
    /// character. The pre-existing `is_upper && next_is_lower` rule
    /// incorrectly produced `["I", "Service"]`, and tokenize() then
    /// dropped `"I"` via the `min_length >= 2` filter, removing the
    /// canonical `iservice` token entirely.
    #[test]
    fn test_tokenize_single_letter_pascal_prefix() {
        let tokenizer = Tokenizer::new();
        let upper_tokens = tokenizer.tokenize("IService");
        let lower_tokens = tokenizer.tokenize("iservice");

        assert!(
            upper_tokens.contains(&"iservice".to_string()),
            "tokenize(\"IService\") must yield canonical 'iservice' token; got: {:?}",
            upper_tokens
        );
        assert!(
            lower_tokens.contains(&"iservice".to_string()),
            "tokenize(\"iservice\") must yield 'iservice' token; got: {:?}",
            lower_tokens
        );
    }

    /// Regression test for issue #8 — guard must preserve the existing
    /// HTTPRequest-style boundary (multi-letter uppercase run followed by
    /// upper+lower transition). Splits at the LAST uppercase letter.
    #[test]
    fn test_tokenize_http_abbreviation_still_splits() {
        let tokenizer = Tokenizer::new();
        let tokens = tokenizer.tokenize("HTTPRequest");
        assert!(
            tokens.contains(&"http".to_string()) && tokens.contains(&"request".to_string()),
            "HTTPRequest must still split into ['http','request']; got: {:?}",
            tokens
        );
    }

    // =========================================================================
    // Issue #84 — digit boundaries and version markers
    // =========================================================================

    /// Issue #84: `OAuth2Provider` must yield an `oauth` token so a BM25
    /// query for `oauth` can match. Pre-fix it tokenized as
    /// `["oauth2", "provider"]` (digit glued to the acronym) and the query
    /// `oauth` had no term to match — zero results.
    #[test]
    fn test_tokenize_oauth2_provider_emits_oauth() {
        let tokenizer = Tokenizer::new();
        let tokens = tokenizer.tokenize("OAuth2Provider");
        assert!(
            tokens.contains(&"oauth".to_string()),
            "tokenize(\"OAuth2Provider\") must yield an 'oauth' token; got: {:?}",
            tokens
        );
        assert!(
            tokens.contains(&"provider".to_string()),
            "tokenize(\"OAuth2Provider\") must yield 'provider'; got: {:?}",
            tokens
        );
    }

    /// Issue #84 codebase-inconsistency cluster: acronym + version marker
    /// must split into the acronym and the `vN` marker.
    #[test]
    fn test_tokenize_acronym_version_marker() {
        let tokenizer = Tokenizer::new();

        let tokens = tokenizer.tokenize("APIv2");
        assert_eq!(
            tokens,
            vec!["api".to_string(), "v2".to_string()],
            "APIv2 must split into api + v2; got: {:?}",
            tokens
        );

        let tokens = tokenizer.tokenize("JSONv3Parser");
        assert_eq!(
            tokens,
            vec!["json".to_string(), "v3".to_string(), "parser".to_string()],
            "JSONv3Parser must split into json + v3 + parser; got: {:?}",
            tokens
        );

        let tokens = tokenizer.tokenize("HTTPv2");
        assert_eq!(
            tokens,
            vec!["http".to_string(), "v2".to_string()],
            "HTTPv2 must split into http + v2 (pre-fix: htt + pv2); got: {:?}",
            tokens
        );
    }

    /// Issue #84: `ProjectCallGraphV2` must expose both `graph` and `v2`
    /// (pre-fix the digit glued to `graph` producing `graphv2`, so a query
    /// for `graph` missed it).
    #[test]
    fn test_tokenize_pascal_case_with_version_suffix() {
        let tokenizer = Tokenizer::new();
        let tokens = tokenizer.tokenize("ProjectCallGraphV2");
        assert_eq!(
            tokens,
            vec![
                "project".to_string(),
                "call".to_string(),
                "graph".to_string(),
                "v2".to_string()
            ],
            "ProjectCallGraphV2 must split into project + call + graph + v2; got: {:?}",
            tokens
        );
    }

    /// Digit boundaries in the middle of an identifier: the letter run ends
    /// before the digits and the digits end before the next letter.
    #[test]
    fn test_tokenize_digit_boundaries() {
        let tokenizer = Tokenizer::new();

        let tokens = tokenizer.tokenize("Base64Encoder");
        assert_eq!(
            tokens,
            vec!["base".to_string(), "64".to_string(), "encoder".to_string()],
            "got: {:?}",
            tokens
        );

        // `UTF8` -> utf + 8; the lone `8` is dropped by min_length=2.
        let tokens = tokenizer.tokenize("UTF8");
        assert_eq!(tokens, vec!["utf".to_string()], "got: {:?}", tokens);
    }

    /// Short letter runs keep their digit suffix so version markers like
    /// `v2` (and `x86`) survive as single tokens — this pins the
    /// pre-existing `processUserData_v2` -> `v2` convention that rule 4's
    /// length guard preserves.
    #[test]
    fn test_tokenize_short_letter_run_keeps_digit_suffix() {
        let tokenizer = Tokenizer::new();

        assert_eq!(
            tokenizer.tokenize("v2"),
            vec!["v2".to_string()],
            "bare v2 must stay a single token"
        );
        assert_eq!(
            tokenizer.tokenize("x86"),
            vec!["x86".to_string()],
            "x86 must stay a single token"
        );
    }
}
