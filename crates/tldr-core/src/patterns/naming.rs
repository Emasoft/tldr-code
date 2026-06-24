//! Naming convention pattern detection
//!
//! Detects naming conventions for:
//! - Functions: snake_case, camelCase
//! - Classes: PascalCase
//! - Constants: UPPER_SNAKE_CASE
//!
//! Calculates consistency score and flags violations.

use std::collections::HashMap;
use std::path::Path;

use super::signals::{NamingCase, PatternSignals};
use crate::types::{NamingConvention, NamingPattern, NamingViolation};

/// R7 cluster[9] #25/#26: exclude identifiers declared in TEST files from
/// the naming-convention determination. Test code routinely follows a
/// different convention than the library it exercises — most acutely C++
/// gtest, whose PascalCase `TEST(...)`/fixture helpers outnumbered a
/// snake_case library (cpp-fmt: 42 test `.cc` files vs 19 source files),
/// flipping the GLOBAL function-convention majority to `pascal_case` and
/// flagging every real snake_case library function as a violation.
///
/// Scoped to patterns naming (this function only) so the file walk and
/// every other command are untouched. Uses the canonical
/// [`crate::analysis::clones::is_test_file`] matcher (the same one the
/// `smells` command uses to drop test findings).
///
/// FALLBACK: if filtering would leave a category EMPTY (a test-only input,
/// e.g. the synthetic `detect_signals` fixtures whose file is literally
/// `test_file`), the full set is used so the convention does not vanish.
fn filter_out_test_files(
    names: &[(String, NamingCase, String, u32)],
) -> Vec<(String, NamingCase, String, u32)> {
    let non_test: Vec<(String, NamingCase, String, u32)> = names
        .iter()
        .filter(|(_, _, file, _)| !crate::analysis::clones::is_test_file(Path::new(file)))
        .cloned()
        .collect();
    if non_test.is_empty() {
        names.to_vec()
    } else {
        non_test
    }
}

/// Convert signals to naming pattern
pub fn signals_to_pattern(signals: &PatternSignals) -> Option<NamingPattern> {
    let naming = &signals.naming;

    if !naming.has_signals() {
        return None;
    }

    // R7 cluster[9] #25/#26: drop test-file identifiers from the
    // convention computation (see `filter_out_test_files`).
    let src_function_names = filter_out_test_files(&naming.function_names);
    let src_class_names = filter_out_test_files(&naming.class_names);
    let src_constant_names = filter_out_test_files(&naming.constant_names);

    // reg-go-extract-v1: when the function bucket is majority-exempt
    // (Go's visibility-driven convention), its identifiers are still
    // recorded in `function_names` for raw extraction, but their
    // correctness is evaluated per-visibility through the precomputed
    // path — NOT against a single project-wide majority. Excluding them
    // from the global-majority function-convention computation here is
    // what prevents the minority visibility group from being flagged as
    // a false-positive violation.
    let function_majority_exempt = naming.function_majority_exempt;
    let function_names_for_majority: &[(String, NamingCase, String, u32)] =
        if function_majority_exempt {
            &[]
        } else {
            &src_function_names
        };

    // Determine majority convention for each category
    let functions = detect_majority_convention(function_names_for_majority);
    let classes = detect_majority_convention(&src_class_names);
    let constants = detect_majority_convention(&src_constant_names);

    // Calculate consistency score
    let function_consistency = calculate_consistency(function_names_for_majority, &functions);
    let class_consistency = calculate_consistency(&src_class_names, &classes);
    let constant_consistency = calculate_consistency(&src_constant_names, &constants);

    // pack-patterns-v1: identifiers evaluated under the per-identifier
    // (precomputed) convention path — e.g. Go funcs, whose
    // visibility-driven convention is checked directly rather than via a
    // single global majority. Their consistency is simply
    // `(total - genuine_violations) / total`. This keeps a pure-Go
    // project from collapsing to a 0.0 consistency score (which would
    // filter out the whole naming pattern, hiding the very violations we
    // computed).
    let precomputed_total = naming.precomputed_total;
    let precomputed_violation_count = naming
        .precomputed_violations
        .iter()
        .filter(|(name, actual, expected, _, _)| {
            !is_magic_dunder(name) && !is_compatible(*actual, *expected)
        })
        .count();
    let precomputed_consistency = if precomputed_total > 0 {
        (precomputed_total.saturating_sub(precomputed_violation_count)) as f64
            / precomputed_total as f64
    } else {
        0.0
    };

    // reg-go-extract-v1: exempt function_names contribute to consistency
    // ONLY through `precomputed_consistency` (the per-visibility score),
    // so they must not also be weighted via the global-majority path here
    // (double counting). When exempt, the global function bucket is empty.
    let global_function_len = function_names_for_majority.len();
    let total_items =
        global_function_len + src_class_names.len() + src_constant_names.len() + precomputed_total;
    let consistency_score = if total_items > 0 {
        let fn_weight = global_function_len as f64 / total_items as f64;
        let cls_weight = src_class_names.len() as f64 / total_items as f64;
        let const_weight = src_constant_names.len() as f64 / total_items as f64;
        let pre_weight = precomputed_total as f64 / total_items as f64;

        function_consistency * fn_weight
            + class_consistency * cls_weight
            + constant_consistency * const_weight
            + precomputed_consistency * pre_weight
    } else {
        0.0
    };

    // Detect violations
    //
    // reg-go-extract-v1: skip the global-majority violation pass over the
    // function bucket when it is majority-exempt (Go). Its genuine
    // per-visibility violations are appended below from
    // `precomputed_violations`; running `find_violations` here would flag
    // the minority visibility group (e.g. exported PascalCase funcs in a
    // camelCase-majority package) as false positives.
    let mut violations = Vec::new();
    violations.extend(find_violations(function_names_for_majority, &functions));
    violations.extend(find_violations(&src_class_names, &classes));
    violations.extend(find_violations(&src_constant_names, &constants));

    // pack-patterns-v1: append directly-computed violations from
    // languages whose convention is NOT a single global majority (Go's
    // visibility-driven exported-PascalCase / unexported-camelCase rule).
    // These are already filtered to genuine violations by the language
    // profile, so we surface them verbatim — but still allow-list magic
    // dunders and degenerate single-word compatibility for safety.
    for (name, actual, expected, file, line) in &naming.precomputed_violations {
        if is_magic_dunder(name) || is_compatible(*actual, *expected) {
            continue;
        }
        violations.push(NamingViolation {
            name: name.clone(),
            expected: naming_case_to_convention(*expected),
            actual: naming_case_to_convention(*actual),
            file: file.clone(),
            line: *line,
        });
    }

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

    // T4 (v0.5.0 AUDIT-FIX): fold degenerate single-word forms into the
    // concrete conventions they are compatible with BEFORE picking the
    // majority. `LowerAlpha` (e.g. `get`, `use`) is the zero-underscore
    // degenerate of BOTH `snake_case` and `camelCase`; `UpperAlpha`
    // (e.g. `URL`, `E1`) is the degenerate of BOTH `PascalCase` and
    // `UPPER_SNAKE_CASE`. Pre-fix, degenerate forms were counted as
    // their own bucket and — when numerically dominant — out-voted the
    // genuine concrete convention, then collapsed to a single arbitrary
    // side (`LowerAlpha → snake_case`, `UpperAlpha → pascal_case`).
    //
    // On js-express that produced a 123×`LowerAlpha` vs 82×`CamelCase`
    // plurality that wrongly resolved to `snake_case`, flagging 48
    // idiomatic camelCase names as violations. Likewise luau-roact's
    // method bodies (after colon-split) are camelCase-dominant but
    // LowerAlpha-plural.
    //
    // The fold credits each degenerate count to whichever CONCRETE
    // sibling is actually present. Concrete conventions decide the
    // winner; degenerate forms only reinforce, never override. If NO
    // concrete convention is present, we fall back to the raw
    // count/specificity tie-break (so an all-degenerate set still
    // resolves deterministically via `naming_case_to_convention`).
    let concrete_present = counts.keys().any(|c| naming_case_specificity(*c) == 4);
    if concrete_present {
        let lower_alpha = counts.get(&NamingCase::LowerAlpha).copied().unwrap_or(0);
        let upper_alpha = counts.get(&NamingCase::UpperAlpha).copied().unwrap_or(0);

        // Effective support per concrete convention = its own count plus
        // the count of every degenerate form compatible with it.
        let concrete_cases = [
            NamingCase::SnakeCase,
            NamingCase::CamelCase,
            NamingCase::PascalCase,
            NamingCase::UpperSnakeCase,
        ];
        return concrete_cases
            .into_iter()
            .filter_map(|case| {
                let base = counts.get(&case).copied().unwrap_or(0);
                if base == 0 {
                    return None;
                }
                let degenerate = match case {
                    NamingCase::SnakeCase | NamingCase::CamelCase => lower_alpha,
                    NamingCase::PascalCase | NamingCase::UpperSnakeCase => upper_alpha,
                    _ => 0,
                };
                Some((case, base + degenerate))
            })
            // Tie-break: higher effective support, then a stable
            // `sort_key` (snake < camel < pascal < upper_snake) so
            // identical inputs always pick the same winner.
            .max_by_key(|(case, support)| {
                (*support, std::cmp::Reverse(naming_case_sort_key(*case)))
            })
            .map(|(case, _)| case)
            .unwrap_or(NamingCase::Unknown);
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
    match (actual, expected) {
        (
            NamingCase::LowerAlpha,
            NamingCase::SnakeCase | NamingCase::CamelCase | NamingCase::LowerAlpha,
        ) => true,
        (
            NamingCase::UpperAlpha,
            NamingCase::PascalCase | NamingCase::UpperSnakeCase | NamingCase::UpperAlpha,
        ) => true,
        _ => false,
    }
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
        .filter(|(_, case, _, _)| {
            *case != NamingCase::Unknown && !is_compatible(*case, *expected)
        })
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
    bytes.len() > 2
        && bytes[0] == b'_'
        && bytes[1] == b'_'
        && bytes[2].is_ascii_alphabetic()
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

    /// T4 (v0.5.0 AUDIT-FIX): a camelCase-dominant function set must
    /// resolve to `camel_case` with ZERO false-positive violations,
    /// even when single-word degenerate identifiers (`LowerAlpha`, e.g.
    /// `use`, `get`) are the numeric plurality.
    ///
    /// Root cause (pre-fix): `detect_majority_convention` counted
    /// `LowerAlpha` as its own bucket. On js-express the plurality was
    /// 123×`LowerAlpha` vs 82×`CamelCase`, so the degenerate bucket won
    /// and collapsed to `snake_case` via `naming_case_to_convention`,
    /// producing a flood of 48 spurious `expected snake_case, got
    /// camel_case` violations on idiomatic names like `loadUser`.
    /// `LowerAlpha` is the zero-underscore degenerate form of BOTH
    /// snake_case and camelCase, so it must reinforce whichever
    /// CONCRETE convention is present rather than out-voting it.
    #[test]
    fn test_camelcase_dominant_with_degenerate_plurality() {
        let mut signals = PatternSignals::default();
        // Concrete camelCase functions (the genuine convention).
        for n in ["loadUser", "andRestrictTo", "initializeRedis", "getEmptyTime"] {
            signals.naming.function_names.push((
                n.to_string(),
                NamingCase::CamelCase,
                "app.js".to_string(),
                1,
            ));
        }
        // More-numerous single-word lowercase names (degenerate; compatible
        // with both snake_case and camelCase). These must NOT swing the
        // majority to snake_case.
        for n in ["get", "set", "use", "send", "json", "next", "end"] {
            signals.naming.function_names.push((
                n.to_string(),
                NamingCase::LowerAlpha,
                "app.js".to_string(),
                1,
            ));
        }

        let pattern = signals_to_pattern(&signals).unwrap();
        assert_eq!(
            pattern.functions,
            NamingConvention::CamelCase,
            "camelCase-dominant set with a LowerAlpha plurality must resolve to \
             camel_case (LowerAlpha is the degenerate form of camelCase, not a \
             separate snake_case majority). Got {:?}",
            pattern.functions
        );
        assert!(
            pattern.violations.is_empty(),
            "no false-positive violations expected for a clean camelCase set; got {:?}",
            pattern.violations
        );
    }

    /// T4 (v0.5.0 AUDIT-FIX): the inverse direction — a snake_case
    /// project with a LowerAlpha plurality must still resolve to
    /// `snake_case` (degenerate reinforces the present concrete winner).
    #[test]
    fn test_snakecase_dominant_with_degenerate_plurality() {
        let mut signals = PatternSignals::default();
        for n in ["find_user_by_id", "get_all_users", "create_user"] {
            signals.naming.function_names.push((
                n.to_string(),
                NamingCase::SnakeCase,
                "service.py".to_string(),
                1,
            ));
        }
        for n in ["get", "set", "save", "load", "run", "stop"] {
            signals.naming.function_names.push((
                n.to_string(),
                NamingCase::LowerAlpha,
                "service.py".to_string(),
                1,
            ));
        }

        let pattern = signals_to_pattern(&signals).unwrap();
        assert_eq!(
            pattern.functions,
            NamingConvention::SnakeCase,
            "snake_case-dominant set with a LowerAlpha plurality must resolve to \
             snake_case; got {:?}",
            pattern.functions
        );
        assert!(
            pattern.violations.is_empty(),
            "no false-positive violations expected; got {:?}",
            pattern.violations
        );
    }

    /// T4 (v0.5.0 AUDIT-FIX): with no concrete convention present at all
    /// (pure single-word lowercase), the majority falls back to the
    /// degenerate-derived `snake_case` (zero-underscore default). This
    /// pins the fallback so the fold logic does not regress the
    /// all-degenerate case.
    #[test]
    fn test_pure_degenerate_falls_back_to_snake() {
        let mut signals = PatternSignals::default();
        for n in ["get", "set", "use", "run"] {
            signals.naming.function_names.push((
                n.to_string(),
                NamingCase::LowerAlpha,
                "x.lua".to_string(),
                1,
            ));
        }
        let pattern = signals_to_pattern(&signals).unwrap();
        assert_eq!(pattern.functions, NamingConvention::SnakeCase);
    }
}
