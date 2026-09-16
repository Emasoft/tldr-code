//! Naming convention pattern detection
//!
//! Detects naming conventions for:
//! - Functions: snake_case, camelCase
//! - Classes: PascalCase
//! - Constants: UPPER_SNAKE_CASE
//!
//! Calculates consistency score and flags violations.

use std::collections::HashMap;

use super::signals::{NamingCase, PatternSignals};
use crate::types::{NamingConvention, NamingPattern, NamingViolation};

/// Convert signals to naming pattern
pub fn signals_to_pattern(signals: &PatternSignals) -> Option<NamingPattern> {
    let naming = &signals.naming;

    if !naming.has_signals() {
        return None;
    }

    // Determine majority convention for each category
    let functions = detect_majority_convention(&naming.function_names);
    let classes = detect_majority_convention(&naming.class_names);
    let constants = detect_majority_convention(&naming.constant_names);

    // Calculate consistency score
    let function_consistency = calculate_consistency(&naming.function_names, &functions);
    let class_consistency = calculate_consistency(&naming.class_names, &classes);
    let constant_consistency = calculate_consistency(&naming.constant_names, &constants);

    let total_items =
        naming.function_names.len() + naming.class_names.len() + naming.constant_names.len();
    let consistency_score = if total_items > 0 {
        let fn_weight = naming.function_names.len() as f64 / total_items as f64;
        let cls_weight = naming.class_names.len() as f64 / total_items as f64;
        let const_weight = naming.constant_names.len() as f64 / total_items as f64;

        function_consistency * fn_weight
            + class_consistency * cls_weight
            + constant_consistency * const_weight
    } else {
        0.0
    };

    // Detect violations
    let mut violations = Vec::new();
    violations.extend(find_violations(&naming.function_names, &functions));
    violations.extend(find_violations(&naming.class_names, &classes));
    violations.extend(find_violations(&naming.constant_names, &constants));

    // Detect private prefix
    let private_prefix = naming
        .private_prefixes
        .iter()
        .max_by_key(|(_, count)| *count)
        .map(|(prefix, _)| prefix.clone());

    Some(NamingPattern {
        functions: naming_case_to_convention(functions),
        classes: naming_case_to_convention(classes),
        constants: naming_case_to_convention(constants),
        private_prefix,
        consistency_score,
        violations,
    })
}

/// Specificity score for naming-case tie-breaking.
///
/// naming-majority-determinism-v1: when two cases tie on count, prefer
/// the *concrete* convention (snake_case, camelCase, PascalCase,
/// UPPER_SNAKE_CASE) over the *degenerate* single-word forms
/// (`LowerAlpha`, `UpperAlpha`). Reason: degenerate variants are a
/// SUBSET of concrete conventions; when both forms exist in the same
/// category, the concrete majority is the natural target convention.
/// A class-name set `[UserService(Pascal), E1(UpperAlpha)]` reports
/// majority `PascalCase`, with `E1` (`UpperAlpha`) compatible-but-not-
/// identical via [`is_compatible`].
fn naming_case_specificity(case: NamingCase) -> u32 {
    match case {
        // Concrete conventions (highest specificity).
        NamingCase::SnakeCase => 4,
        NamingCase::CamelCase => 4,
        NamingCase::PascalCase => 4,
        NamingCase::UpperSnakeCase => 4,
        // Degenerate single-word forms (lower specificity).
        NamingCase::LowerAlpha => 2,
        NamingCase::UpperAlpha => 2,
        // Unknown is filtered out before this is called.
        NamingCase::Unknown => 0,
    }
}

/// Stable secondary tie-break order for naming cases.
///
/// naming-majority-determinism-v1: when count AND specificity tie,
/// pick by a fixed enum-variant order so identical inputs always
/// produce identical outputs. Lower key = preferred.
fn naming_case_sort_key(case: NamingCase) -> u32 {
    match case {
        NamingCase::SnakeCase => 0,
        NamingCase::CamelCase => 1,
        NamingCase::PascalCase => 2,
        NamingCase::UpperSnakeCase => 3,
        NamingCase::LowerAlpha => 4,
        NamingCase::UpperAlpha => 5,
        NamingCase::Unknown => 99,
    }
}

/// Detect the majority naming convention from a list of names.
///
/// naming-majority-determinism-v1: replaces a non-deterministic
/// `HashMap<NamingCase, usize>` + `max_by_key(count)` reduction with
/// a deterministic tie-break ordering. The bug surfaced as a
/// regression from `language-coverage-fixes-v1` (commit ef5f6cf):
/// when a class-name set tied 1×`PascalCase` + 1×`UpperAlpha`, the
/// HashMap iteration order non-deterministically chose `UpperAlpha`
/// in roughly half of runs, producing a spurious self-violation entry
/// `{name:"UserService", expected:"pascal_case", actual:"pascal_case"}`
/// once `UpperAlpha` was collapsed to `PascalCase` by
/// [`naming_case_to_convention`]. The flake had ~33% pass rate on
/// the `test_n4_patterns_naming_no_single_word_violations` test.
///
/// The fix sorts tied variants by:
/// 1. Count (descending) — primary criterion.
/// 2. Specificity (descending) — concrete conventions win over
///    degenerate single-word forms.
/// 3. `naming_case_sort_key` (ascending) — fully stable secondary
///    tie-break.
fn detect_majority_convention(names: &[(String, NamingCase, String, u32)]) -> NamingCase {
    if names.is_empty() {
        return NamingCase::Unknown;
    }

    let mut counts: HashMap<NamingCase, usize> = HashMap::new();
    for (_, case, _, _) in names {
        if *case != NamingCase::Unknown {
            *counts.entry(*case).or_insert(0) += 1;
        }
    }

    counts
        .into_iter()
        // Sort key: (count, specificity, Reverse(sort_key)).
        // `max_by_key` picks the lexicographically-largest tuple, so
        // higher count wins, then higher specificity, then LOWER
        // sort_key (via `Reverse`) wins.
        .max_by_key(|(case, count)| {
            (
                *count,
                naming_case_specificity(*case),
                std::cmp::Reverse(naming_case_sort_key(*case)),
            )
        })
        .map(|(case, _)| case)
        .unwrap_or(NamingCase::Unknown)
}

/// Calculate consistency score for a set of names against expected convention
///
/// language-coverage-fixes-v1 (P4.BUG-N4): use the same
/// [`is_compatible`] predicate as `find_violations` so that
/// degenerate single-word identifiers (`LowerAlpha`, `UpperAlpha`)
/// don't drag the consistency score down. Without this, a Java
/// codebase whose majority is `CamelCase` would have its score
/// proportionally reduced for every method named `print` or `clone`.
fn calculate_consistency(
    names: &[(String, NamingCase, String, u32)],
    expected: &NamingCase,
) -> f64 {
    if names.is_empty() || *expected == NamingCase::Unknown {
        return 0.0;
    }

    let matching = names
        .iter()
        .filter(|(_, case, _, _)| is_compatible(*case, *expected))
        .count();
    matching as f64 / names.len() as f64
}

/// Returns true when `actual` should be considered compatible with
/// `expected` and therefore NOT flagged as a violation.
///
/// language-coverage-fixes-v1 (P4.BUG-N4): single-word degenerate
/// identifiers are compatible with multiple conventions:
///
/// - `LowerAlpha` (e.g. `print`, `value`): compatible with
///   `SnakeCase`, `CamelCase`, and `LowerAlpha` itself. A single
///   lowercase word is the degenerate form of both snake_case
///   (zero underscores) and camelCase (no second word).
/// - `UpperAlpha` (e.g. `E1`, `K`, `URL`): compatible with
///   `PascalCase`, `UpperSnakeCase`, and `UpperAlpha` itself. A
///   single uppercase word is the degenerate form of both pascal
///   (single word) and upper-snake (no underscores).
///
/// Without this rule the classifier emitted false positives like
/// `{"name":"print","expected":"camel_case","actual":"snake_case"}`
/// and `{"name":"E1","expected":"pascal_case","actual":"upper_snake_case"}`
/// — both visibly nonsensical because neither name has an
/// underscore.
fn is_compatible(actual: NamingCase, expected: NamingCase) -> bool {
    if actual == expected {
        return true;
    }
    matches!(
        (actual, expected),
        (
            NamingCase::LowerAlpha,
            NamingCase::SnakeCase | NamingCase::CamelCase | NamingCase::LowerAlpha,
        ) | (
            NamingCase::UpperAlpha,
            NamingCase::PascalCase | NamingCase::UpperSnakeCase | NamingCase::UpperAlpha,
        )
    )
}

/// Find violations (names not matching the expected convention)
fn find_violations(
    names: &[(String, NamingCase, String, u32)],
    expected: &NamingCase,
) -> Vec<NamingViolation> {
    if *expected == NamingCase::Unknown {
        return Vec::new();
    }

    names
        .iter()
        // language-coverage-fixes-v1 (P4.BUG-N4): use `is_compatible`
        // so single-word `LowerAlpha` / `UpperAlpha` identifiers
        // aren't flagged as violations against camelCase/PascalCase
        // expectations they degenerate into.
        .filter(|(_, case, _, _)| *case != NamingCase::Unknown && !is_compatible(*case, *expected))
        // AGG13-18 (quality-metrics-and-schema-v1): PHP magic methods
        // (`__construct`, `__invoke`, `__toString`, `__call`, etc.)
        // are language-mandated dunders that start with exactly `__`
        // followed by an ASCII letter. The leading double-underscore
        // made them register as `SnakeCase`, which the audit flagged
        // as snake_case violations against a project's dominant
        // `CamelCase` convention. Allow-list any name that matches
        // the strict PHP magic-method shape (`__` + alpha-leading
        // identifier). Plain leading underscores (`_helper`) are NOT
        // allow-listed. Python-style trailing-`__` dunders
        // (`__init__`) are also covered by this predicate via the
        // generic prefix-only check.
        .filter(|(name, _, _, _)| !is_magic_dunder(name))
        .map(|(name, case, file, line)| NamingViolation {
            name: name.clone(),
            expected: naming_case_to_convention(*expected),
            actual: naming_case_to_convention(*case),
            file: file.clone(),
            // schema-cleanup-v1 BUG-10: line number now plumbed
            // through from the AST start_position via the
            // 4-tuple stored in NamingSignals.
            line: *line,
        })
        .collect()
}

/// AGG13-18: true iff `name` matches the language-mandated magic-method
/// dunder shape: starts with exactly `__` followed by an ASCII letter,
/// and the third character is not another underscore. This precisely
/// matches PHP magic methods (`__construct`, `__invoke`, `__toString`,
/// `__call`) and Python dunders (`__init__`, `__repr__`). It rejects
/// plain leading-underscore privates (`_helper`, `__helper_local`).
fn is_magic_dunder(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() > 2 && bytes[0] == b'_' && bytes[1] == b'_' && bytes[2].is_ascii_alphabetic()
}

/// Convert internal NamingCase to public NamingConvention
fn naming_case_to_convention(case: NamingCase) -> NamingConvention {
    match case {
        NamingCase::SnakeCase => NamingConvention::SnakeCase,
        NamingCase::CamelCase => NamingConvention::CamelCase,
        NamingCase::PascalCase => NamingConvention::PascalCase,
        NamingCase::UpperSnakeCase => NamingConvention::UpperSnakeCase,
        // language-coverage-fixes-v1 (P4.BUG-N4): degenerate
        // single-word forms surface as the closest "natural"
        // convention so JSON output remains stable for clients
        // that only know the canonical four conventions.
        // `LowerAlpha` → `SnakeCase` (zero-underscore degenerate),
        // `UpperAlpha` → `PascalCase` (single-word pascal). These
        // mappings are only used when the name IS the majority
        // convention; the violation filter (`is_compatible`)
        // keeps them out of the `violations` array regardless.
        NamingCase::LowerAlpha => NamingConvention::SnakeCase,
        NamingCase::UpperAlpha => NamingConvention::PascalCase,
        NamingCase::Unknown => NamingConvention::Mixed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_signals_returns_none() {
        let signals = PatternSignals::default();
        assert!(signals_to_pattern(&signals).is_none());
    }

    #[test]
    fn test_snake_case_functions_detected() {
        let mut signals = PatternSignals::default();
        signals.naming.function_names.push((
            "find_user_by_id".to_string(),
            NamingCase::SnakeCase,
            "service.py".to_string(),
            0,
        ));
        signals.naming.function_names.push((
            "get_all_users".to_string(),
            NamingCase::SnakeCase,
            "service.py".to_string(),
            0,
        ));
        signals.naming.function_names.push((
            "create_user".to_string(),
            NamingCase::SnakeCase,
            "service.py".to_string(),
            0,
        ));

        let pattern = signals_to_pattern(&signals).unwrap();
        assert_eq!(pattern.functions, NamingConvention::SnakeCase);
        assert!(pattern.consistency_score >= 0.9);
    }

    #[test]
    fn test_pascal_case_classes_detected() {
        let mut signals = PatternSignals::default();
        signals.naming.class_names.push((
            "UserService".to_string(),
            NamingCase::PascalCase,
            "service.py".to_string(),
            0,
        ));
        signals.naming.class_names.push((
            "OrderRepository".to_string(),
            NamingCase::PascalCase,
            "repo.py".to_string(),
            0,
        ));

        let pattern = signals_to_pattern(&signals).unwrap();
        assert_eq!(pattern.classes, NamingConvention::PascalCase);
    }

    #[test]
    fn test_upper_snake_case_constants_detected() {
        let mut signals = PatternSignals::default();
        signals.naming.constant_names.push((
            "MAX_RETRY_COUNT".to_string(),
            NamingCase::UpperSnakeCase,
            "config.py".to_string(),
            0,
        ));
        signals.naming.constant_names.push((
            "DEFAULT_TIMEOUT".to_string(),
            NamingCase::UpperSnakeCase,
            "config.py".to_string(),
            0,
        ));

        let pattern = signals_to_pattern(&signals).unwrap();
        assert_eq!(pattern.constants, NamingConvention::UpperSnakeCase);
    }

    #[test]
    fn test_violation_detected() {
        let mut signals = PatternSignals::default();
        signals.naming.function_names.push((
            "find_user".to_string(),
            NamingCase::SnakeCase,
            "service.py".to_string(),
            0,
        ));
        signals.naming.function_names.push((
            "getUser".to_string(), // Violation!
            NamingCase::CamelCase,
            "service.py".to_string(),
            0,
        ));
        signals.naming.function_names.push((
            "create_user".to_string(),
            NamingCase::SnakeCase,
            "service.py".to_string(),
            0,
        ));

        let pattern = signals_to_pattern(&signals).unwrap();
        assert!(!pattern.violations.is_empty());
        assert_eq!(pattern.violations[0].name, "getUser");
        assert_eq!(pattern.violations[0].expected, NamingConvention::SnakeCase);
        assert_eq!(pattern.violations[0].actual, NamingConvention::CamelCase);
    }
}
