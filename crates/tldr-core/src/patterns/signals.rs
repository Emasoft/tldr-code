//! Pattern signals - Accumulated signals from single AST walk
//!
//! This module defines the PatternSignals struct that collects all pattern
//! signals during a single AST traversal, avoiding multiple passes.

use crate::types::Evidence;
use std::collections::{HashMap, HashSet};

/// Accumulated signals from a single AST walk
#[derive(Debug, Clone, Default)]
pub struct PatternSignals {
    /// Soft delete signals
    pub soft_delete: SoftDeleteSignals,
    /// Error handling signals
    pub error_handling: ErrorHandlingSignals,
    /// Naming convention signals
    pub naming: NamingSignals,
    // schema-cleanup-v1 BUG-10: each NamingSignals tuple now carries
    // a 4th `line: u32` element so that `patterns.naming.violations[]`
    // can plumb the source line through to the public schema instead
    // of always reporting line 0.
    /// Resource management signals
    pub resource_management: ResourceManagementSignals,
    /// Validation signals
    pub validation: ValidationSignals,
    /// Test idiom signals
    pub test_idioms: TestIdiomSignals,
    /// Import pattern signals
    pub import_patterns: ImportPatternSignals,
    /// Type coverage signals
    pub type_coverage: TypeCoverageSignals,
    /// API convention signals
    pub api_conventions: ApiConventionSignals,
    /// Async pattern signals
    pub async_patterns: AsyncPatternSignals,
    /// Language-specific extension signals not covered by standard schema.
    /// Key format: "category.field_name" (e.g., "pattern_matching.arm_count").
    pub extensions: HashMap<String, Vec<Evidence>>,
    /// Concrete AST-grounded design-pattern occurrences (GoF /
    /// language-idiomatic) — pack-patterns-v1 (v0.5.0 PACK-PATTERNS).
    pub design_patterns: DesignPatternSignals,
}

/// Raw design-pattern hits accumulated during the single AST walk.
///
/// Each entry is the fully-formed [`crate::types::DesignPattern`] minus
/// any cross-file dedup (the miner dedups + sorts after aggregation).
/// We store the public type directly so the miner can roll the field up
/// verbatim — there is no lossy intermediate representation.
#[derive(Debug, Clone, Default)]
pub struct DesignPatternSignals {
    /// Detected pattern occurrences in AST-discovery order.
    pub hits: Vec<crate::types::DesignPattern>,
}

impl DesignPatternSignals {
    /// Merge design-pattern hits from another instance.
    pub fn merge(&mut self, other: &DesignPatternSignals) {
        self.hits.extend(other.hits.iter().cloned());
    }

    /// Record a detected design pattern occurrence.
    #[allow(clippy::too_many_arguments)]
    pub fn push_pattern(
        &mut self,
        pattern: impl Into<String>,
        category: impl Into<String>,
        language: impl Into<String>,
        subject: impl Into<String>,
        file: impl Into<String>,
        line: u32,
        evidence: impl Into<String>,
    ) {
        self.hits.push(crate::types::DesignPattern {
            pattern: pattern.into(),
            category: category.into(),
            language: language.into(),
            subject: subject.into(),
            file: file.into(),
            line,
            evidence: evidence.into(),
        });
    }
}

impl PatternSignals {
    /// Merge signals from another PatternSignals instance
    pub fn merge(&mut self, other: &PatternSignals) {
        self.soft_delete.merge(&other.soft_delete);
        self.error_handling.merge(&other.error_handling);
        self.naming.merge(&other.naming);
        self.resource_management.merge(&other.resource_management);
        self.validation.merge(&other.validation);
        self.test_idioms.merge(&other.test_idioms);
        self.import_patterns.merge(&other.import_patterns);
        self.type_coverage.merge(&other.type_coverage);
        self.api_conventions.merge(&other.api_conventions);
        self.async_patterns.merge(&other.async_patterns);
        self.design_patterns.merge(&other.design_patterns);
        for (key, values) in &other.extensions {
            self.extensions
                .entry(key.clone())
                .or_default()
                .extend(values.clone());
        }
    }
}

// =============================================================================
// Soft Delete Signals
// =============================================================================

/// Signals related to soft delete patterns detected during AST traversal.
#[derive(Debug, Clone, Default)]
pub struct SoftDeleteSignals {
    /// Fields named is_deleted (weight: +0.4)
    pub is_deleted_fields: Vec<Evidence>,
    /// Fields named deleted_at (weight: +0.4)
    pub deleted_at_fields: Vec<Evidence>,
    /// Query filters on delete fields (weight: +0.2)
    pub delete_query_filters: Vec<Evidence>,
    /// ORM paranoid annotations (weight: +0.3)
    pub paranoid_annotations: Vec<Evidence>,
}

impl SoftDeleteSignals {
    /// Merge signals from another `SoftDeleteSignals` instance into this one.
    pub fn merge(&mut self, other: &SoftDeleteSignals) {
        self.is_deleted_fields
            .extend(other.is_deleted_fields.clone());
        self.deleted_at_fields
            .extend(other.deleted_at_fields.clone());
        self.delete_query_filters
            .extend(other.delete_query_filters.clone());
        self.paranoid_annotations
            .extend(other.paranoid_annotations.clone());
    }

    /// Returns true if any soft delete signals have been collected.
    pub fn has_signals(&self) -> bool {
        !self.is_deleted_fields.is_empty()
            || !self.deleted_at_fields.is_empty()
            || !self.delete_query_filters.is_empty()
            || !self.paranoid_annotations.is_empty()
    }

    /// Calculate confidence score (0.0-1.0) based on accumulated soft delete signals.
    pub fn calculate_confidence(&self) -> f64 {
        let mut confidence: f64 = 0.0;
        if !self.is_deleted_fields.is_empty() {
            confidence += 0.4;
        }
        if !self.deleted_at_fields.is_empty() {
            confidence += 0.4;
        }
        if !self.delete_query_filters.is_empty() {
            confidence += 0.2;
        }
        if !self.paranoid_annotations.is_empty() {
            confidence += 0.3;
        }
        confidence.min(1.0)
    }
}

// =============================================================================
// Error Handling Signals
// =============================================================================

/// Signals related to error handling patterns detected during AST traversal.
#[derive(Debug, Clone, Default)]
pub struct ErrorHandlingSignals {
    /// Python try/except blocks (weight: +0.3)
    pub try_except_blocks: Vec<Evidence>,
    /// Python custom Exception classes (weight: +0.4)
    pub custom_exceptions: Vec<(String, Evidence)>,
    /// Rust Result<T, E> return types (weight: +0.4)
    pub result_types: Vec<Evidence>,
    /// Rust ? operator usage (weight: +0.3)
    pub question_mark_ops: Vec<Evidence>,
    /// Go if err != nil pattern (weight: +0.4)
    pub err_nil_checks: Vec<Evidence>,
    /// TypeScript try/catch blocks (weight: +0.3)
    pub try_catch_blocks: Vec<Evidence>,
    /// Custom error enum definitions
    pub error_enums: Vec<(String, Evidence)>,
}

impl ErrorHandlingSignals {
    /// Merge signals from another `ErrorHandlingSignals` instance into this one.
    pub fn merge(&mut self, other: &ErrorHandlingSignals) {
        self.try_except_blocks
            .extend(other.try_except_blocks.clone());
        self.custom_exceptions
            .extend(other.custom_exceptions.clone());
        self.result_types.extend(other.result_types.clone());
        self.question_mark_ops
            .extend(other.question_mark_ops.clone());
        self.err_nil_checks.extend(other.err_nil_checks.clone());
        self.try_catch_blocks.extend(other.try_catch_blocks.clone());
        self.error_enums.extend(other.error_enums.clone());
    }

    /// Returns true if any error handling signals have been collected.
    pub fn has_signals(&self) -> bool {
        !self.try_except_blocks.is_empty()
            || !self.custom_exceptions.is_empty()
            || !self.result_types.is_empty()
            || !self.question_mark_ops.is_empty()
            || !self.err_nil_checks.is_empty()
            || !self.try_catch_blocks.is_empty()
            || !self.error_enums.is_empty()
    }

    /// Calculate confidence score (0.0-1.0) based on accumulated error handling signals.
    pub fn calculate_confidence(&self) -> f64 {
        let mut confidence: f64 = 0.0;
        if !self.try_except_blocks.is_empty() || !self.try_catch_blocks.is_empty() {
            confidence += 0.3;
        }
        if !self.custom_exceptions.is_empty() || !self.error_enums.is_empty() {
            confidence += 0.4;
        }
        if !self.result_types.is_empty() {
            confidence += 0.4;
        }
        if !self.question_mark_ops.is_empty() {
            confidence += 0.3;
        }
        if !self.err_nil_checks.is_empty() {
            confidence += 0.4;
        }
        confidence.min(1.0)
    }
}

// =============================================================================
// Naming Signals
// =============================================================================

/// Signals related to naming convention patterns detected during AST traversal.
#[derive(Debug, Clone, Default)]
pub struct NamingSignals {
    /// Function names with their detected case
    /// Tuple: (name, case, file, line)
    pub function_names: Vec<(String, NamingCase, String, u32)>,
    /// Class names with their detected case
    /// Tuple: (name, case, file, line)
    pub class_names: Vec<(String, NamingCase, String, u32)>,
    /// Constant names with their detected case
    /// Tuple: (name, case, file, line)
    pub constant_names: Vec<(String, NamingCase, String, u32)>,
    /// Private member prefix detection
    pub private_prefixes: HashMap<String, usize>, // prefix -> count
    /// pack-patterns-v1: directly-computed naming violations for
    /// languages whose convention is NOT a single global majority.
    ///
    /// Go is the motivating case: its naming convention is
    /// VISIBILITY-driven (exported PascalCase vs unexported camelCase),
    /// so a single project-wide majority is meaningless — feeding all
    /// funcs into one bucket flagged whichever visibility group was the
    /// minority. Languages with a per-identifier expected convention
    /// emit violations here, and the miner appends them verbatim to the
    /// `NamingPattern.violations` output (after the global-majority
    /// violations). Tuple: `(name, actual_case, expected_case, file, line)`.
    pub precomputed_violations: Vec<(String, NamingCase, NamingCase, String, u32)>,
    /// pack-patterns-v1: count of identifiers evaluated under the
    /// per-identifier (precomputed) convention path. Used to compute a
    /// real consistency score: `(total - violations) / total`. Without
    /// this, a pure-Go project (whose funcs bypass `function_names`)
    /// would have an empty global bucket and a 0.0 consistency score,
    /// causing the whole naming pattern — including the violations — to
    /// be filtered out by the confidence gate.
    pub precomputed_total: usize,
    /// reg-go-extract-v1: when `true`, the `function_names` bucket holds
    /// identifiers whose naming convention is per-identifier (NOT a single
    /// project-wide majority) and whose genuine violations are computed
    /// directly into `precomputed_violations`.
    ///
    /// Go is the motivating case: its convention is VISIBILITY-driven
    /// (exported PascalCase vs unexported camelCase), both legitimate in
    /// the same package. The funcs are still recorded in `function_names`
    /// so raw extraction (snapshot/equivalence) works, but the global
    /// `find_violations` majority comparison must be SKIPPED for this
    /// bucket — otherwise the minority visibility group is flagged as a
    /// false positive (24 such false positives on go-httprouter). The
    /// per-visibility violations already live in `precomputed_violations`.
    pub function_majority_exempt: bool,
}

/// Detected naming case convention for an identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamingCase {
    /// Lowercase with underscores: `my_function`
    SnakeCase,
    /// Lowercase first, then capitalized words: `myFunction`
    CamelCase,
    /// Capitalized words without separators: `MyClass`
    PascalCase,
    /// All uppercase with underscores: `MAX_VALUE`
    UpperSnakeCase,
    /// Single lowercase word, no underscores: `print`, `value2`.
    ///
    /// language-coverage-fixes-v1 (P4.BUG-N4): a single-word
    /// lowercase identifier is *compatible* with both `snake_case`
    /// (degenerate, zero-underscore form) and `camelCase`
    /// (degenerate, no-second-word form). Reporting it as
    /// `SnakeCase` (the previous behaviour) caused spurious
    /// "expected camelCase, got snake_case" violations in Java and
    /// other camelCase codebases. The violation emitter treats
    /// `LowerAlpha` as compatible with both conventions.
    LowerAlpha,
    /// Single uppercase word, no underscores: `E1`, `K`, `URL`.
    ///
    /// language-coverage-fixes-v1 (P4.BUG-N4): compatible with
    /// `PascalCase` (single uppercase word IS pascal-degenerate)
    /// and `UPPER_SNAKE_CASE` (single uppercase word IS
    /// upper-snake-degenerate). The previous classifier returned
    /// `UpperSnakeCase` regardless, producing spurious violations
    /// against PascalCase class-name expectations on names like
    /// `E1`.
    UpperAlpha,
    /// Could not determine naming convention
    Unknown,
}

impl NamingSignals {
    /// Merge signals from another `NamingSignals` instance into this one.
    pub fn merge(&mut self, other: &NamingSignals) {
        self.function_names.extend(other.function_names.clone());
        self.class_names.extend(other.class_names.clone());
        self.constant_names.extend(other.constant_names.clone());
        self.precomputed_violations
            .extend(other.precomputed_violations.clone());
        self.precomputed_total += other.precomputed_total;
        // reg-go-extract-v1: once any merged source uses the
        // per-identifier (visibility-driven) convention path, the merged
        // function bucket must stay exempt from the global-majority
        // violation pass.
        self.function_majority_exempt |= other.function_majority_exempt;
        for (prefix, count) in &other.private_prefixes {
            *self.private_prefixes.entry(prefix.clone()).or_insert(0) += count;
        }
    }

    /// Returns true if any naming signals have been collected.
    pub fn has_signals(&self) -> bool {
        !self.function_names.is_empty()
            || !self.class_names.is_empty()
            || !self.constant_names.is_empty()
            || !self.precomputed_violations.is_empty()
    }
}

/// Detect naming case from an identifier
pub fn detect_naming_case(name: &str) -> NamingCase {
    if name.is_empty() {
        return NamingCase::Unknown;
    }

    // Skip dunder methods and single char names
    if name.starts_with("__") && name.ends_with("__") {
        return NamingCase::Unknown;
    }
    if name.len() == 1 {
        return NamingCase::Unknown;
    }

    // language-coverage-fixes-v1 (P4.BUG-N4): require ≥1 underscore
    // before classifying as snake_case / UPPER_SNAKE_CASE. Without
    // this guard, `print` was classified as `SnakeCase` and `E1` as
    // `UpperSnakeCase`, producing spurious "expected camelCase, got
    // snake_case" violations against camelCase Java codebases (and
    // similar against PascalCase class expectations on `E1`-style
    // names). Single-word degenerate names get their own `LowerAlpha`
    // / `UpperAlpha` variants which the violation emitter treats as
    // compatible with both adjacent conventions.

    // UPPER_SNAKE_CASE: all uppercase WITH underscores.
    if name.contains('_')
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
    {
        return NamingCase::UpperSnakeCase;
    }

    // snake_case: lowercase WITH underscores.
    if name.contains('_')
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
    {
        return NamingCase::SnakeCase;
    }

    // Single-word lowercase / uppercase (no underscore): emit the
    // dedicated degenerate variants so the violation emitter can
    // treat them as compatible with multiple conventions.
    if name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name.chars().any(|c| c.is_ascii_lowercase())
    {
        return NamingCase::LowerAlpha;
    }
    if name
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        && name.chars().any(|c| c.is_ascii_uppercase())
    {
        return NamingCase::UpperAlpha;
    }

    // PascalCase: starts with uppercase, no underscores (except at start for private)
    let check_name = name.trim_start_matches('_');
    if !check_name.is_empty() {
        let first = check_name.chars().next().unwrap();
        if first.is_ascii_uppercase() && !check_name.contains('_') {
            return NamingCase::PascalCase;
        }

        // camelCase: starts with lowercase, no underscores, has uppercase
        if first.is_ascii_lowercase()
            && !check_name.contains('_')
            && check_name.chars().any(|c| c.is_ascii_uppercase())
        {
            return NamingCase::CamelCase;
        }
    }

    NamingCase::Unknown
}

// =============================================================================
// Resource Management Signals
// =============================================================================

/// Signals related to resource management patterns detected during AST traversal.
#[derive(Debug, Clone, Default)]
pub struct ResourceManagementSignals {
    /// Python context managers (with statements)
    pub context_managers: Vec<Evidence>,
    /// Python __enter__/__exit__ methods
    pub enter_exit_methods: Vec<Evidence>,
    /// Go defer statements
    pub defer_statements: Vec<Evidence>,
    /// Rust Drop trait implementations
    pub drop_impls: Vec<Evidence>,
    /// TypeScript/JS try/finally blocks
    pub try_finally_blocks: Vec<Evidence>,
    /// Explicit close calls
    pub close_calls: Vec<Evidence>,
}

impl ResourceManagementSignals {
    /// Merge signals from another `ResourceManagementSignals` instance into this one.
    pub fn merge(&mut self, other: &ResourceManagementSignals) {
        self.context_managers.extend(other.context_managers.clone());
        self.enter_exit_methods
            .extend(other.enter_exit_methods.clone());
        self.defer_statements.extend(other.defer_statements.clone());
        self.drop_impls.extend(other.drop_impls.clone());
        self.try_finally_blocks
            .extend(other.try_finally_blocks.clone());
        self.close_calls.extend(other.close_calls.clone());
    }

    /// Returns true if any resource management signals have been collected.
    pub fn has_signals(&self) -> bool {
        !self.context_managers.is_empty()
            || !self.enter_exit_methods.is_empty()
            || !self.defer_statements.is_empty()
            || !self.drop_impls.is_empty()
            || !self.try_finally_blocks.is_empty()
            || !self.close_calls.is_empty()
    }

    /// Calculate confidence score (0.0-1.0) based on accumulated resource management signals.
    pub fn calculate_confidence(&self) -> f64 {
        let mut confidence: f64 = 0.0;
        if !self.context_managers.is_empty() {
            confidence += 0.4;
        }
        if !self.enter_exit_methods.is_empty() {
            confidence += 0.3;
        }
        if !self.defer_statements.is_empty() {
            confidence += 0.4;
        }
        if !self.drop_impls.is_empty() {
            confidence += 0.4;
        }
        if !self.try_finally_blocks.is_empty() {
            confidence += 0.3;
        }
        if !self.close_calls.is_empty() {
            confidence += 0.2;
        }
        confidence.min(1.0)
    }
}

// =============================================================================
// Validation Signals
// =============================================================================

/// Signals related to input validation patterns detected during AST traversal.
#[derive(Debug, Clone, Default)]
pub struct ValidationSignals {
    /// Pydantic BaseModel inheritance (weight: +0.5)
    pub pydantic_models: Vec<Evidence>,
    /// Zod schema definitions (weight: +0.5)
    pub zod_schemas: Vec<Evidence>,
    /// Guard clauses at function start (weight: +0.3)
    pub guard_clauses: Vec<Evidence>,
    /// Assert statements (weight: +0.2)
    pub assert_statements: Vec<Evidence>,
    /// Type validation (isinstance, typeof) (weight: +0.2)
    pub type_checks: Vec<Evidence>,
    /// Marshmallow/Cerberus/other validators
    pub other_validators: Vec<(String, Evidence)>,
}

impl ValidationSignals {
    /// Merge signals from another `ValidationSignals` instance into this one.
    pub fn merge(&mut self, other: &ValidationSignals) {
        self.pydantic_models.extend(other.pydantic_models.clone());
        self.zod_schemas.extend(other.zod_schemas.clone());
        self.guard_clauses.extend(other.guard_clauses.clone());
        self.assert_statements
            .extend(other.assert_statements.clone());
        self.type_checks.extend(other.type_checks.clone());
        self.other_validators.extend(other.other_validators.clone());
    }

    /// Returns true if any validation signals have been collected.
    pub fn has_signals(&self) -> bool {
        !self.pydantic_models.is_empty()
            || !self.zod_schemas.is_empty()
            || !self.guard_clauses.is_empty()
            || !self.assert_statements.is_empty()
            || !self.type_checks.is_empty()
            || !self.other_validators.is_empty()
    }

    /// Calculate confidence score (0.0-1.0) based on accumulated validation signals.
    pub fn calculate_confidence(&self) -> f64 {
        let mut confidence: f64 = 0.0;
        if !self.pydantic_models.is_empty() {
            confidence += 0.5;
        }
        if !self.zod_schemas.is_empty() {
            confidence += 0.5;
        }
        if !self.guard_clauses.is_empty() {
            confidence += 0.3;
        }
        if !self.assert_statements.is_empty() {
            confidence += 0.2;
        }
        if !self.type_checks.is_empty() {
            confidence += 0.2;
        }
        if !self.other_validators.is_empty() {
            confidence += 0.3;
        }
        confidence.min(1.0)
    }
}

// =============================================================================
// Test Idiom Signals
// =============================================================================

/// Signals related to test idiom patterns detected during AST traversal.
#[derive(Debug, Clone, Default)]
pub struct TestIdiomSignals {
    /// pytest fixtures (weight: +0.4)
    pub pytest_fixtures: Vec<Evidence>,
    /// mock.patch usage (weight: +0.3)
    pub mock_patches: Vec<Evidence>,
    /// Jest describe/it blocks (weight: +0.4)
    pub jest_blocks: Vec<Evidence>,
    /// Go table-driven tests (weight: +0.4)
    pub go_table_tests: Vec<Evidence>,
    /// Arrange-Act-Assert structure indicators
    pub aaa_patterns: Vec<Evidence>,
    /// Test function count
    pub test_function_count: usize,
    /// Detected framework name
    pub detected_framework: Option<String>,
}

impl TestIdiomSignals {
    /// Merge signals from another `TestIdiomSignals` instance into this one.
    pub fn merge(&mut self, other: &TestIdiomSignals) {
        self.pytest_fixtures.extend(other.pytest_fixtures.clone());
        self.mock_patches.extend(other.mock_patches.clone());
        self.jest_blocks.extend(other.jest_blocks.clone());
        self.go_table_tests.extend(other.go_table_tests.clone());
        self.aaa_patterns.extend(other.aaa_patterns.clone());
        self.test_function_count += other.test_function_count;
        if self.detected_framework.is_none() {
            self.detected_framework = other.detected_framework.clone();
        }
    }

    /// Returns true if any test idiom signals have been collected.
    pub fn has_signals(&self) -> bool {
        !self.pytest_fixtures.is_empty()
            || !self.mock_patches.is_empty()
            || !self.jest_blocks.is_empty()
            || !self.go_table_tests.is_empty()
            || !self.aaa_patterns.is_empty()
            || self.test_function_count > 0
    }

    /// Calculate confidence score (0.0-1.0) based on accumulated test idiom signals.
    pub fn calculate_confidence(&self) -> f64 {
        let mut confidence: f64 = 0.0;
        if !self.pytest_fixtures.is_empty() {
            confidence += 0.4;
        }
        if !self.mock_patches.is_empty() {
            confidence += 0.3;
        }
        if !self.jest_blocks.is_empty() {
            confidence += 0.4;
        }
        if !self.go_table_tests.is_empty() {
            confidence += 0.4;
        }
        if !self.aaa_patterns.is_empty() {
            confidence += 0.3;
        }
        confidence.min(1.0)
    }
}

// =============================================================================
// Import Pattern Signals
// =============================================================================

/// Signals related to import organization patterns detected during AST traversal.
#[derive(Debug, Clone, Default)]
pub struct ImportPatternSignals {
    /// Absolute imports
    pub absolute_imports: Vec<(String, String)>, // (module, file)
    /// Relative imports
    pub relative_imports: Vec<(String, String)>,
    /// Star imports (from x import *)
    pub star_imports: Vec<Evidence>,
    /// Import aliases
    pub aliases: HashMap<String, String>, // module -> alias
    /// Import groupings detected (file -> groups)
    pub groupings: Vec<ImportGrouping>,
}

/// Grouping of imports detected in a single file, organized by origin.
#[derive(Debug, Clone)]
pub struct ImportGrouping {
    /// File path where the imports were found.
    pub file: String,
    /// Standard library imports.
    pub stdlib_imports: Vec<String>,
    /// Third-party (external dependency) imports.
    pub third_party_imports: Vec<String>,
    /// Local (project-internal) imports.
    pub local_imports: Vec<String>,
}

impl ImportPatternSignals {
    /// Merge signals from another `ImportPatternSignals` instance into this one.
    pub fn merge(&mut self, other: &ImportPatternSignals) {
        self.absolute_imports.extend(other.absolute_imports.clone());
        self.relative_imports.extend(other.relative_imports.clone());
        self.star_imports.extend(other.star_imports.clone());
        self.aliases.extend(other.aliases.clone());
        self.groupings.extend(other.groupings.clone());
    }

    /// Returns true if any import pattern signals have been collected.
    pub fn has_signals(&self) -> bool {
        !self.absolute_imports.is_empty()
            || !self.relative_imports.is_empty()
            || !self.star_imports.is_empty()
    }
}

// =============================================================================
// Type Coverage Signals
// =============================================================================

/// Signals related to type annotation coverage detected during AST traversal.
#[derive(Debug, Clone, Default)]
pub struct TypeCoverageSignals {
    /// Typed function parameters
    pub typed_params: usize,
    /// Untyped function parameters
    pub untyped_params: usize,
    /// Typed return types
    pub typed_returns: usize,
    /// Untyped return types
    pub untyped_returns: usize,
    /// Typed variables
    pub typed_variables: usize,
    /// Untyped variables
    pub untyped_variables: usize,
    /// TypeVar/Generic usage
    pub generic_usage: Vec<Evidence>,
    /// Common generic patterns found
    pub generic_patterns: HashSet<String>,
}

impl TypeCoverageSignals {
    /// Merge signals from another `TypeCoverageSignals` instance into this one.
    pub fn merge(&mut self, other: &TypeCoverageSignals) {
        self.typed_params += other.typed_params;
        self.untyped_params += other.untyped_params;
        self.typed_returns += other.typed_returns;
        self.untyped_returns += other.untyped_returns;
        self.typed_variables += other.typed_variables;
        self.untyped_variables += other.untyped_variables;
        self.generic_usage.extend(other.generic_usage.clone());
        self.generic_patterns.extend(other.generic_patterns.clone());
    }

    /// Returns true if any type coverage signals have been collected.
    pub fn has_signals(&self) -> bool {
        self.typed_params > 0
            || self.typed_returns > 0
            || self.typed_variables > 0
            || self.untyped_params > 0
            || self.untyped_returns > 0
    }

    /// Calculate the ratio of typed function signatures to total (params + returns).
    pub fn calculate_function_coverage(&self) -> f64 {
        let total =
            self.typed_params + self.untyped_params + self.typed_returns + self.untyped_returns;
        if total == 0 {
            return 0.0;
        }
        (self.typed_params + self.typed_returns) as f64 / total as f64
    }

    /// Calculate the ratio of typed variables to total variables.
    pub fn calculate_variable_coverage(&self) -> f64 {
        let total = self.typed_variables + self.untyped_variables;
        if total == 0 {
            return 0.0;
        }
        self.typed_variables as f64 / total as f64
    }

    /// Calculate the overall ratio of all typed items to total items.
    pub fn calculate_overall_coverage(&self) -> f64 {
        let total_typed = self.typed_params + self.typed_returns + self.typed_variables;
        let total_untyped = self.untyped_params + self.untyped_returns + self.untyped_variables;
        let total = total_typed + total_untyped;
        if total == 0 {
            return 0.0;
        }
        total_typed as f64 / total as f64
    }
}

// =============================================================================
// API Convention Signals
// =============================================================================

/// Signals related to API convention patterns detected during AST traversal.
#[derive(Debug, Clone, Default)]
pub struct ApiConventionSignals {
    /// FastAPI decorators
    pub fastapi_decorators: Vec<Evidence>,
    /// Flask route decorators
    pub flask_decorators: Vec<Evidence>,
    /// Express route handlers
    pub express_routes: Vec<Evidence>,
    /// RESTful naming patterns
    pub restful_patterns: Vec<Evidence>,
    /// ORM model definitions
    pub orm_models: Vec<(String, Evidence)>, // (orm_name, evidence)
    /// GraphQL definitions
    pub graphql_defs: Vec<Evidence>,
}

impl ApiConventionSignals {
    /// Merge signals from another `ApiConventionSignals` instance into this one.
    pub fn merge(&mut self, other: &ApiConventionSignals) {
        self.fastapi_decorators
            .extend(other.fastapi_decorators.clone());
        self.flask_decorators.extend(other.flask_decorators.clone());
        self.express_routes.extend(other.express_routes.clone());
        self.restful_patterns.extend(other.restful_patterns.clone());
        self.orm_models.extend(other.orm_models.clone());
        self.graphql_defs.extend(other.graphql_defs.clone());
    }

    /// Returns true if any API convention signals have been collected.
    pub fn has_signals(&self) -> bool {
        !self.fastapi_decorators.is_empty()
            || !self.flask_decorators.is_empty()
            || !self.express_routes.is_empty()
            || !self.restful_patterns.is_empty()
            || !self.orm_models.is_empty()
            || !self.graphql_defs.is_empty()
    }

    /// Calculate confidence score (0.0-1.0) based on accumulated API convention signals.
    pub fn calculate_confidence(&self) -> f64 {
        let mut confidence: f64 = 0.0;
        if !self.fastapi_decorators.is_empty() {
            confidence += 0.5;
        }
        if !self.flask_decorators.is_empty() {
            confidence += 0.5;
        }
        if !self.express_routes.is_empty() {
            confidence += 0.5;
        }
        if !self.restful_patterns.is_empty() {
            confidence += 0.3;
        }
        if !self.orm_models.is_empty() {
            confidence += 0.4;
        }
        if !self.graphql_defs.is_empty() {
            confidence += 0.4;
        }
        confidence.min(1.0)
    }

    /// Detect the primary web framework based on collected signals.
    pub fn detect_framework(&self) -> Option<String> {
        if !self.fastapi_decorators.is_empty() {
            return Some("fastapi".to_string());
        }
        if !self.flask_decorators.is_empty() {
            return Some("flask".to_string());
        }
        if !self.express_routes.is_empty() {
            return Some("express".to_string());
        }
        None
    }

    /// Detect the ORM framework based on collected model signals.
    pub fn detect_orm(&self) -> Option<String> {
        self.orm_models.first().map(|(orm, _)| orm.clone())
    }
}

// =============================================================================
// Async Pattern Signals
// =============================================================================

/// Signals related to async/concurrency patterns detected during AST traversal.
#[derive(Debug, Clone, Default)]
pub struct AsyncPatternSignals {
    /// async/await keywords
    pub async_await: Vec<Evidence>,
    /// Go goroutines (go keyword)
    pub goroutines: Vec<Evidence>,
    /// Tokio runtime usage
    pub tokio_usage: Vec<Evidence>,
    /// Sync primitives (mutex, channel, semaphore)
    pub sync_primitives: Vec<(String, Evidence)>,
    /// Thread spawn patterns
    pub thread_spawns: Vec<Evidence>,
}

impl AsyncPatternSignals {
    /// Merge signals from another `AsyncPatternSignals` instance into this one.
    pub fn merge(&mut self, other: &AsyncPatternSignals) {
        self.async_await.extend(other.async_await.clone());
        self.goroutines.extend(other.goroutines.clone());
        self.tokio_usage.extend(other.tokio_usage.clone());
        self.sync_primitives.extend(other.sync_primitives.clone());
        self.thread_spawns.extend(other.thread_spawns.clone());
    }

    /// Returns true if any async pattern signals have been collected.
    pub fn has_signals(&self) -> bool {
        !self.async_await.is_empty()
            || !self.goroutines.is_empty()
            || !self.tokio_usage.is_empty()
            || !self.sync_primitives.is_empty()
            || !self.thread_spawns.is_empty()
    }

    /// Calculate confidence score (0.0-1.0) based on accumulated async pattern signals.
    pub fn calculate_confidence(&self) -> f64 {
        let mut confidence: f64 = 0.0;
        if !self.async_await.is_empty() {
            confidence += 0.4;
        }
        if !self.goroutines.is_empty() {
            confidence += 0.5;
        }
        if !self.tokio_usage.is_empty() {
            confidence += 0.5;
        }
        if !self.sync_primitives.is_empty() {
            confidence += 0.3;
        }
        if !self.thread_spawns.is_empty() {
            confidence += 0.3;
        }
        confidence.min(1.0)
    }
}
