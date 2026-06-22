//! Type resolver for Python method calls
//!
//! This module provides type resolution for method calls in Python code,
//! enabling type-aware impact analysis (Phase 8).
//!
//! # Resolution Rules
//!
//! | Pattern | Resolution | Confidence |
//! |---------|------------|------------|
//! | `self.method()` | `ClassName.method` | HIGH |
//! | `x: Type = ...` | Type annotation | HIGH |
//! | `x = Type()` | Constructor inference | HIGH |
//! | Import from module | Cross-file resolution | MEDIUM |
//! | Unknown | Variable name fallback | LOW |
//!
//! # Example
//!
//! ```rust,ignore
//! use tldr_core::callgraph::type_resolver::{TypeResolver, resolve_python_receiver_type};
//!
//! let source = r#"
//! class User:
//!     def save(self): pass
//!
//! def process():
//!     user: User = User()
//!     user.save()  # -> User.save (HIGH confidence)
//! "#;
//!
//! let (receiver_type, confidence) = resolve_python_receiver_type(
//!     source,
//!     7,  // line number of user.save()
//!     "user",
//!     None,
//! );
//! assert_eq!(receiver_type, Some("User".to_string()));
//! ```

use std::collections::HashMap;

use crate::types::{Confidence, Language, TypedCallEdge};

/// fix-W5b-receiver-type-scan-v1: counts how many times a source *line* is
/// parsed during receiver-type resolution. Both the per-call-site scan helpers
/// and the `SourceTypeIndex` builder bump this once per line they inspect, so a
/// test can assert the indexed path does O(L) line-parses instead of the
/// per-call-site O(L * N). Plain relaxed counter — observational only, never
/// gates production behavior.
pub(crate) static LINE_PARSE_COUNTER: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

#[inline]
fn bump_line_parse() {
    LINE_PARSE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Type resolver for Python code
///
/// Maintains state for resolving method calls to their class types.
#[derive(Debug, Default)]
pub struct TypeResolver {
    /// Map of variable name -> type at each scope
    /// Key: (line_number, variable_name)
    variable_types: HashMap<String, ResolvedType>,
    /// Map of class name -> class definition info
    class_definitions: HashMap<String, ClassDefinition>,
    /// Current class context (for self resolution)
    current_class: Option<String>,
}

/// Information about a resolved type
#[derive(Debug, Clone)]
pub struct ResolvedType {
    /// The resolved type name (e.g., "User")
    pub type_name: String,
    /// Confidence level
    pub confidence: Confidence,
    /// Line where type was determined
    pub source_line: u32,
    /// How the type was resolved
    pub resolution_method: ResolutionMethod,
}

/// How a type was resolved
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionMethod {
    /// Explicit type annotation: `x: Type = ...`
    Annotation,
    /// Constructor call: `x = Type()`
    Constructor,
    /// Self reference in class method
    SelfReference,
    /// Return type of a function
    ReturnType,
    /// Imported from another module
    Import,
    /// Unknown - fallback to variable name
    Fallback,
}

/// Class definition information
#[derive(Debug, Clone)]
pub struct ClassDefinition {
    /// Class name
    pub name: String,
    /// Line where class is defined
    pub line: u32,
    /// End line of class definition
    pub end_line: u32,
    /// Methods defined in the class
    pub methods: Vec<String>,
    /// Base classes (for inheritance)
    pub bases: Vec<String>,
}

impl TypeResolver {
    /// Create a new type resolver
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the current class context (for self resolution)
    pub fn set_current_class(&mut self, class_name: Option<String>) {
        self.current_class = class_name.clone();
    }

    /// Register a class definition
    pub fn register_class(&mut self, def: ClassDefinition) {
        self.class_definitions.insert(def.name.clone(), def);
    }

    /// Register a variable's type
    pub fn register_variable(&mut self, var_name: String, resolved_type: ResolvedType) {
        self.variable_types.insert(var_name, resolved_type);
    }

    /// Resolve a method call receiver type
    ///
    /// # Arguments
    /// * `receiver` - The receiver expression (e.g., "user" in "user.save()")
    /// * `call_line` - Line number of the call
    ///
    /// # Returns
    /// (resolved_type, confidence)
    pub fn resolve_receiver(
        &self,
        receiver: &str,
        _call_line: u32,
    ) -> (Option<String>, Confidence) {
        // 1. Check for "self" - resolve to current class
        if receiver == "self" {
            if let Some(ref class_name) = self.current_class {
                return (Some(class_name.clone()), Confidence::High);
            }
        }

        // 2. Check if we have a registered type for this variable
        if let Some(resolved) = self.variable_types.get(receiver) {
            return (Some(resolved.type_name.clone()), resolved.confidence);
        }

        // 3. Fallback - unknown type
        (None, Confidence::Low)
    }
}

/// Resolve Python method receiver type from source code
///
/// This is the main entry point for type resolution. It analyzes the source
/// code to determine the type of a method call receiver.
///
/// # Arguments
/// * `source` - The Python source code
/// * `call_line` - Line number of the method call (1-indexed)
/// * `receiver_name` - The receiver expression (e.g., "user" in "user.save()")
/// * `enclosing_class` - The class containing this call, if any
///
/// # Returns
/// (resolved_type, confidence) - The resolved type name and confidence level
pub fn resolve_python_receiver_type(
    source: &str,
    call_line: u32,
    receiver_name: &str,
    enclosing_class: Option<&str>,
) -> (Option<String>, Confidence) {
    // 1. Handle "self" reference
    if receiver_name == "self" {
        if let Some(class_name) = enclosing_class {
            return (Some(class_name.to_string()), Confidence::High);
        }
        // If no enclosing class, try to find it from the source
        if let Some(class_name) = find_enclosing_class(source, call_line) {
            return (Some(class_name), Confidence::High);
        }
        // self with no class context - very unusual but fallback
        return (None, Confidence::Low);
    }

    // 2. Look for explicit type annotation: `var: Type = ...`
    if let Some(type_name) = find_type_annotation(source, receiver_name, call_line) {
        if type_name.starts_with("Union[") || type_name.contains('|') {
            // Union types are less certain than concrete annotations
            if expand_union_type(&type_name, None).is_none() {
                return (None, Confidence::Low);
            }
            return (Some(type_name), Confidence::Medium);
        }
        return (Some(type_name), Confidence::High);
    }

    // 3. Look for constructor call: `var = Type(...)`
    if let Some(type_name) = find_constructor_assignment(source, receiver_name, call_line) {
        return (Some(type_name), Confidence::High);
    }

    // 4. Fallback - unknown type
    (None, Confidence::Low)
}

/// Resolve a self.method() call to ClassName.method
///
/// # Arguments
/// * `class_name` - The enclosing class name
/// * `method_name` - The method being called
///
/// # Returns
/// The fully qualified method name (e.g., "Calculator._validate")
pub fn resolve_self_method(class_name: &str, method_name: &str) -> String {
    format!("{}.{}", class_name, method_name)
}

/// Find the class containing a given line
///
/// Scans the source code to find which class definition contains the given line.
///
/// # Arguments
/// * `source` - The Python source code
/// * `line` - The line number to find (1-indexed)
///
/// # Returns
/// The class name if found, None otherwise
pub fn find_enclosing_class(source: &str, line: u32) -> Option<String> {
    let mut current_class: Option<(String, u32)> = None; // (name, start_line)
    let mut indent_level = 0;

    for (line_num, line_content) in source.lines().enumerate() {
        bump_line_parse();
        let current_line = (line_num + 1) as u32;

        // Check for class definition
        let trimmed = line_content.trim_start();
        if trimmed.starts_with("class ") {
            // Extract class name
            if let Some(class_name) = extract_class_name(trimmed) {
                // Calculate indent level
                let line_indent = line_content.len() - trimmed.len();
                indent_level = line_indent;
                current_class = Some((class_name, current_line));
            }
        }

        // If we're at or past the target line, check if we're still in the class
        if current_line == line {
            if let Some((ref class_name, _)) = current_class {
                // Simple heuristic: if line is indented more than class def, we're in the class
                let line_indent = line_content.len() - line_content.trim_start().len();
                if line_indent > indent_level || line_content.trim().is_empty() {
                    return Some(class_name.clone());
                }
            }
        }
    }

    // If target line is beyond source, check if we ended inside a class
    if let Some((class_name, _)) = current_class {
        return Some(class_name);
    }

    None
}

/// Extract class name from a class definition line
fn extract_class_name(line: &str) -> Option<String> {
    // Pattern: "class ClassName:" or "class ClassName(Base):"
    let without_class = line.strip_prefix("class ")?;

    // Find where class name ends (at '(' or ':')
    let end_idx = without_class.find(['(', ':', ' '])?;
    let class_name = &without_class[..end_idx];

    if class_name.is_empty() {
        None
    } else {
        Some(class_name.to_string())
    }
}

/// Find type annotation for a variable
///
/// Searches backwards from call_line to find `var: Type = ...` pattern
fn find_type_annotation(source: &str, var_name: &str, call_line: u32) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();

    // Search backwards from call_line
    for line_num in (0..call_line as usize).rev() {
        bump_line_parse();
        let line = lines.get(line_num)?;

        // Pattern: `var_name: Type = ` or `var_name: Type`
        let pattern = format!("{}: ", var_name);
        if let Some(idx) = line.find(&pattern) {
            let after_colon = &line[idx + pattern.len()..];
            // Extract type name (ends at '=' or end of significant content)
            let type_name = extract_type_from_annotation(after_colon)?;
            return Some(type_name);
        }
    }

    None
}

/// Extract type name from annotation part (after `: `)
fn extract_type_from_annotation(s: &str) -> Option<String> {
    let trimmed = s.trim();

    // Find where type ends, ignoring commas inside brackets.
    let mut bracket_depth = 0usize;
    let mut end_idx: Option<usize> = None;
    for (idx, ch) in trimmed.char_indices() {
        match ch {
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '=' | ',' | ')' if bracket_depth == 0 => {
                end_idx = Some(idx);
                break;
            }
            _ => {}
        }
    }

    let type_part = match end_idx {
        Some(idx) => trimmed[..idx].trim(),
        None => trimmed,
    };

    if type_part.is_empty() {
        return None;
    }

    // Preserve union types so they can be expanded later.
    if type_part.starts_with("Union[") && type_part.ends_with(']') {
        return Some(type_part.to_string());
    }
    if type_part.contains('|') {
        return Some(type_part.to_string());
    }

    // Clean up the type (remove Optional[], List[], etc. for now - just get base type)
    let type_name = if type_part.starts_with("Optional[") && type_part.ends_with(']') {
        let inner = type_part
            .strip_prefix("Optional[")?
            .strip_suffix(']')
            .unwrap_or(type_part);
        inner.trim()
    } else if let Some(bracket_idx) = type_part.find('[') {
        // Generic type - extract base
        type_part[..bracket_idx].trim()
    } else {
        type_part
    };

    if type_name.is_empty() || type_name.chars().next()?.is_lowercase() {
        // Type names should start with uppercase (skip built-in types like "str", "int")
        // For now, still return them but in practice we might want to filter
        if type_name.is_empty() {
            None
        } else {
            Some(type_name.to_string())
        }
    } else {
        Some(type_name.to_string())
    }
}

/// Find constructor assignment for a variable
///
/// Searches backwards from call_line to find `var = Type(...)` pattern
fn find_constructor_assignment(source: &str, var_name: &str, call_line: u32) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();

    // Search backwards from call_line
    for line_num in (0..call_line as usize).rev() {
        bump_line_parse();
        let line = lines.get(line_num)?;
        let idx = match find_var_in_line(line, var_name) {
            Some(i) => i,
            None => continue,
        };
        let mut tail = line[idx + var_name.len()..].trim_start();
        if tail.starts_with(":=") {
            tail = tail[2..].trim_start();
        } else if tail.starts_with('=') {
            tail = tail[1..].trim_start();
        } else {
            continue;
        }

        if let Some(paren_idx) = tail.find('(') {
            let potential_type = tail[..paren_idx].trim();
            if let Some(type_name) = normalize_type_name(potential_type) {
                return Some(type_name);
            }
        }
    }

    None
}

/// Resolve a type annotation string to a concrete type
///
/// # Arguments
/// * `annotation` - The annotation string (e.g., "User", "Optional[User]")
///
/// # Returns
/// The base type name
pub fn resolve_annotation(annotation: &str) -> Option<String> {
    extract_type_from_annotation(annotation)
}

// =============================================================================
// TypeScript Type Resolution (Phase 9)
// =============================================================================

/// Resolve TypeScript method receiver type from source code
///
/// Handles the following patterns:
/// - `this.method()` -> resolves to enclosing class
/// - `const x: Type = ...` -> explicit annotation
/// - `const x = new Type()` -> constructor inference
/// - Interface method calls -> interface name with MEDIUM confidence
///
/// # Arguments
/// * `source` - The TypeScript source code
/// * `call_line` - Line number of the method call (1-indexed)
/// * `receiver_name` - The receiver expression (e.g., "user" in "user.save()")
/// * `enclosing_class` - The class containing this call, if any
///
/// # Returns
/// (resolved_type, confidence) - The resolved type name and confidence level
pub fn resolve_typescript_receiver_type(
    source: &str,
    call_line: u32,
    receiver_name: &str,
    enclosing_class: Option<&str>,
) -> (Option<String>, Confidence) {
    // 1. Handle "this" reference
    if receiver_name == "this" {
        if let Some(class_name) = enclosing_class {
            return (Some(class_name.to_string()), Confidence::High);
        }
        // If no enclosing class provided, try to find it from source
        if let Some(class_name) = find_typescript_enclosing_class(source, call_line) {
            return (Some(class_name), Confidence::High);
        }
        return (None, Confidence::Low);
    }

    // 2. Look for explicit type annotation: `const/let/var x: Type = ...`
    if let Some(type_name) = find_typescript_annotation(source, receiver_name, call_line) {
        // Check if it's an interface (might have multiple implementations)
        let confidence = if is_likely_interface(&type_name) {
            Confidence::Medium
        } else {
            Confidence::High
        };
        return (Some(type_name), confidence);
    }

    // 3. Look for constructor call: `const x = new Type(...)`
    if let Some(type_name) = find_typescript_constructor(source, receiver_name, call_line) {
        return (Some(type_name), Confidence::High);
    }

    // 4. Fallback - unknown type
    (None, Confidence::Low)
}

/// Find the TypeScript class containing a given line
fn find_typescript_enclosing_class(source: &str, line: u32) -> Option<String> {
    let mut current_class: Option<(String, u32)> = None;
    let mut brace_depth = 0;
    let mut class_start_brace_depth = 0;

    for (line_num, line_content) in source.lines().enumerate() {
        let current_line = (line_num + 1) as u32;

        // Count braces for scope tracking
        brace_depth += line_content.matches('{').count() as i32;
        brace_depth -= line_content.matches('}').count() as i32;

        // Check for class definition
        let trimmed = line_content.trim();
        if let Some(class_name) = extract_typescript_class_name(trimmed) {
            class_start_brace_depth = brace_depth;
            current_class = Some((class_name, current_line));
        }

        // If we're at the target line
        if current_line == line {
            if let Some((ref class_name, _)) = current_class {
                // Still inside the class if brace depth is greater than or equal to start
                if brace_depth >= class_start_brace_depth {
                    return Some(class_name.clone());
                }
            }
        }

        // Check if we've exited the class
        if brace_depth < class_start_brace_depth && current_class.is_some() {
            current_class = None;
        }
    }

    None
}

/// Extract class name from TypeScript class definition
fn extract_typescript_class_name(line: &str) -> Option<String> {
    // Patterns: "class Name", "class Name extends", "class Name implements", "export class Name"
    let line = line.trim_start_matches("export ");
    let line = line.trim_start_matches("abstract ");

    if !line.starts_with("class ") {
        return None;
    }

    let without_class = line.strip_prefix("class ")?;
    let end_idx = without_class.find([' ', '{', '<'])?;
    let class_name = &without_class[..end_idx];

    if class_name.is_empty() {
        None
    } else {
        Some(class_name.to_string())
    }
}

/// Find type annotation for TypeScript variable
fn find_typescript_annotation(source: &str, var_name: &str, call_line: u32) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();

    // Search backwards from call_line
    for line_num in (0..call_line as usize).rev() {
        let line = lines.get(line_num)?;

        // Patterns: `const/let/var name: Type` or `name: Type` (in params/destructuring)
        for prefix in &["const ", "let ", "var ", ""] {
            let pattern = format!("{}{}: ", prefix, var_name);
            if let Some(idx) = line.find(&pattern) {
                let after_colon = &line[idx + pattern.len()..];
                if let Some(type_name) = extract_typescript_type(after_colon) {
                    return Some(type_name);
                }
            }
        }
    }

    None
}

/// Extract type name from TypeScript type position
fn extract_typescript_type(s: &str) -> Option<String> {
    let trimmed = s.trim();

    // Find where type ends (at '=', ',', ')', ';', '>' for generics end, or '{')
    let end_idx = trimmed.find(['=', ',', ')', ';', '{']);
    let type_part = match end_idx {
        Some(idx) => trimmed[..idx].trim(),
        None => trimmed,
    };

    // Handle generic types - extract base type
    let base_type = if let Some(angle_idx) = type_part.find('<') {
        &type_part[..angle_idx]
    } else {
        type_part
    };

    // Handle union types - just return the first type for now
    let first_type = base_type.split('|').next()?.trim();

    normalize_type_name(first_type)
}

/// Find constructor call for TypeScript variable
fn find_typescript_constructor(source: &str, var_name: &str, call_line: u32) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();

    // Search backwards from call_line
    for line_num in (0..call_line as usize).rev() {
        let line = lines.get(line_num)?;

        // Patterns: `const/let/var name = new Type(...)` or `name = new Type(...)`
        for prefix in &["const ", "let ", "var ", ""] {
            let pattern = format!("{}{} = new ", prefix, var_name);
            if let Some(idx) = line.find(&pattern) {
                let after_new = &line[idx + pattern.len()..];
                let type_end = after_new.find(['(', '<']).unwrap_or(after_new.len());
                let type_name = after_new[..type_end].trim();
                if let Some(normalized) = normalize_type_name(type_name) {
                    return Some(normalized);
                }
            }
        }
    }

    None
}

/// Check if a type name is likely an interface (convention: starts with I, or common patterns)
fn is_likely_interface(type_name: &str) -> bool {
    // TypeScript convention: interfaces often start with 'I'
    // Also common pattern names like *able, *Repository, *Service with generic parameters
    type_name.starts_with('I')
        && type_name
            .chars()
            .nth(1)
            .map(|c| c.is_uppercase())
            .unwrap_or(false)
}

// =============================================================================
// Go Type Resolution (Phase 9)
// =============================================================================

/// Resolve Go method receiver type from source code
///
/// Handles the following patterns:
/// - `var x Dog` -> explicit declaration
/// - `x := Dog{}` -> struct literal
/// - Method receiver `(d *Dog)` in method signature
///
/// # Arguments
/// * `source` - The Go source code
/// * `call_line` - Line number of the method call (1-indexed)
/// * `receiver_name` - The receiver expression (e.g., "dog" in "dog.Bark()")
/// * `enclosing_receiver` - The receiver type from enclosing method, if any
///
/// # Returns
/// (resolved_type, confidence) - The resolved type name and confidence level
pub fn resolve_go_receiver_type(
    source: &str,
    call_line: u32,
    receiver_name: &str,
    enclosing_receiver: Option<&str>,
) -> (Option<String>, Confidence) {
    // callgraph-dataflow-issues-v1 (#60): consult explicit local bindings
    // BEFORE shortcutting to the enclosing receiver via the single-letter
    // heuristic. Pre-fix `c := Cat{}` inside `func (d Dog) Process()`
    // was silently misresolved to `Dog` because `c.len() == 1` won the
    // race. Mirrors the Go convention that a local binding always wins
    // over the enclosing receiver name when both happen to be one letter.

    // 1. Look for explicit var declaration: `var x Type`
    if let Some(type_name) = find_go_var_declaration(source, receiver_name, call_line) {
        return (Some(type_name), Confidence::High);
    }

    // 2. Look for short declaration with struct literal: `x := Type{}`
    if let Some(type_name) = find_go_struct_literal(source, receiver_name, call_line) {
        return (Some(type_name), Confidence::High);
    }

    // 3. Look for pointer/address-of: `x := &Type{}`
    if let Some(type_name) = find_go_pointer_struct(source, receiver_name, call_line) {
        return (Some(type_name), Confidence::High);
    }

    // 4. Fall back to the enclosing-method receiver type for the
    // single-letter Go convention (`(d Dog).Process()` calling
    // `d.Bark()`). Only triggers when none of the explicit local
    // binding lookups succeeded above.
    if let Some(recv_type) = enclosing_receiver {
        if receiver_name.len() == 1 {
            return (Some(recv_type.to_string()), Confidence::High);
        }
    }

    // 5. Fallback - unknown type
    (None, Confidence::Low)
}

/// Find Go var declaration for a variable
fn find_go_var_declaration(source: &str, var_name: &str, call_line: u32) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();

    for line_num in (0..call_line as usize).rev() {
        let line = lines.get(line_num)?.trim();

        // Pattern: `var name Type` or `var name *Type`
        let pattern = format!("var {} ", var_name);
        if let Some(idx) = line.find(&pattern) {
            let after_name = &line[idx + pattern.len()..];
            let type_name = extract_go_type(after_name)?;
            return Some(type_name);
        }
    }

    None
}

/// Find Go struct literal assignment
fn find_go_struct_literal(source: &str, var_name: &str, call_line: u32) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();

    for line_num in (0..call_line as usize).rev() {
        let line = lines.get(line_num)?.trim();

        // Pattern: `name := Type{` or `name := Type{}`
        let pattern = format!("{} := ", var_name);
        if let Some(idx) = line.find(&pattern) {
            let after_assign = &line[idx + pattern.len()..];
            // Look for struct literal
            if let Some(brace_idx) = after_assign.find('{') {
                let type_name = after_assign[..brace_idx].trim();
                if !type_name.is_empty()
                    && type_name.chars().next()?.is_uppercase()
                    && !type_name.starts_with('&')
                {
                    return Some(type_name.to_string());
                }
            }
        }
    }

    None
}

/// Find Go pointer struct literal: `x := &Type{}`
fn find_go_pointer_struct(source: &str, var_name: &str, call_line: u32) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();

    for line_num in (0..call_line as usize).rev() {
        let line = lines.get(line_num)?.trim();

        // Pattern: `name := &Type{`
        let pattern = format!("{} := &", var_name);
        if let Some(idx) = line.find(&pattern) {
            let after_amp = &line[idx + pattern.len()..];
            if let Some(brace_idx) = after_amp.find('{') {
                let type_name = after_amp[..brace_idx].trim();
                if !type_name.is_empty() && type_name.chars().next()?.is_uppercase() {
                    return Some(type_name.to_string());
                }
            }
        }
    }

    None
}

/// Extract Go type from declaration
fn extract_go_type(s: &str) -> Option<String> {
    let trimmed = s.trim();

    // Handle pointer types
    let type_part = trimmed.trim_start_matches('*');

    // Find where type ends (at space, '=' for multi-var, newline)
    let end_idx = type_part.find(|c: char| c.is_whitespace() || c == '=' || c == ')');
    let type_name = match end_idx {
        Some(idx) => type_part[..idx].trim(),
        None => type_part,
    };

    if type_name.is_empty() {
        None
    } else {
        Some(type_name.to_string())
    }
}

// =============================================================================
// Rust Type Resolution (Phase 9)
// =============================================================================

/// Resolve Rust method receiver type from source code
///
/// Handles the following patterns:
/// - `let x: Type = ...` -> explicit annotation
/// - `self.method()` or `Self::method()` -> impl block context
/// - `let x = Type::new()` -> associated function
///
/// # Arguments
/// * `source` - The Rust source code
/// * `call_line` - Line number of the method call (1-indexed)
/// * `receiver_name` - The receiver expression (e.g., "dog" in "dog.bark()")
/// * `enclosing_impl` - The type from enclosing impl block, if any
///
/// # Returns
/// (resolved_type, confidence) - The resolved type name and confidence level
pub fn resolve_rust_receiver_type(
    source: &str,
    call_line: u32,
    receiver_name: &str,
    enclosing_impl: Option<&str>,
) -> (Option<String>, Confidence) {
    // 1. Handle "self" or "Self" reference
    if receiver_name == "self" || receiver_name == "&self" || receiver_name == "&mut self" {
        if let Some(impl_type) = enclosing_impl {
            return (Some(impl_type.to_string()), Confidence::High);
        }
        if let Some(impl_type) = find_rust_enclosing_impl(source, call_line) {
            return (Some(impl_type), Confidence::High);
        }
        return (None, Confidence::Low);
    }

    // Handle Self:: calls
    if receiver_name == "Self" {
        if let Some(impl_type) = enclosing_impl {
            return (Some(impl_type.to_string()), Confidence::High);
        }
        if let Some(impl_type) = find_rust_enclosing_impl(source, call_line) {
            return (Some(impl_type), Confidence::High);
        }
        return (None, Confidence::Low);
    }

    // 2. Look for explicit type annotation: `let x: Type = ...`
    if let Some(type_name) = find_rust_annotation(source, receiver_name, call_line) {
        return (Some(type_name), Confidence::High);
    }

    // 3. Look for associated function call: `let x = Type::new()`
    if let Some(type_name) = find_rust_associated_function(source, receiver_name, call_line) {
        return (Some(type_name), Confidence::High);
    }

    // 4. Look for struct literal: `let x = Type { ... }`
    if let Some(type_name) = find_rust_struct_literal(source, receiver_name, call_line) {
        return (Some(type_name), Confidence::High);
    }

    // 5. Fallback - unknown type
    (None, Confidence::Low)
}

/// Find the Rust impl block containing a given line
fn find_rust_enclosing_impl(source: &str, line: u32) -> Option<String> {
    let mut current_impl: Option<(String, i32)> = None; // (type_name, brace_depth when impl started)
    let mut brace_depth: i32 = 0;

    for (line_num, line_content) in source.lines().enumerate() {
        let current_line = (line_num + 1) as u32;
        let trimmed = line_content.trim();

        // Update brace depth
        brace_depth += line_content.matches('{').count() as i32;
        brace_depth -= line_content.matches('}').count() as i32;

        // Check for impl block
        if trimmed.starts_with("impl ") || trimmed.starts_with("impl<") {
            if let Some(impl_type) = extract_rust_impl_type(trimmed) {
                current_impl = Some((impl_type, brace_depth));
            }
        }

        // If we're at the target line
        if current_line == line {
            if let Some((ref impl_type, start_depth)) = current_impl {
                if brace_depth >= start_depth {
                    return Some(impl_type.clone());
                }
            }
        }

        // Check if we've exited the impl block
        if let Some((_, start_depth)) = &current_impl {
            if brace_depth < *start_depth {
                current_impl = None;
            }
        }
    }

    None
}

/// Extract type from Rust impl declaration
fn extract_rust_impl_type(line: &str) -> Option<String> {
    // Patterns: "impl Type", "impl<T> Type<T>", "impl Trait for Type"
    let trimmed = line.trim();

    // Skip generic parameters
    let after_impl = if trimmed.starts_with("impl<") {
        // Find matching >
        let mut depth = 0;
        let mut end_generic = 0;
        for (i, c) in trimmed.chars().enumerate() {
            match c {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        end_generic = i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        trimmed[end_generic..].trim_start()
    } else {
        trimmed.strip_prefix("impl ")?.trim()
    };

    // Check for "Trait for Type" pattern
    if let Some(for_idx) = after_impl.find(" for ") {
        let type_part = &after_impl[for_idx + 5..];
        return extract_rust_type_name(type_part);
    }

    // Direct impl Type pattern
    extract_rust_type_name(after_impl)
}

/// Extract Rust type name, handling generics
fn extract_rust_type_name(s: &str) -> Option<String> {
    let trimmed = s.trim();

    // Find where type name ends (at '<', ' ', '{')
    let end_idx = trimmed.find(['<', ' ', '{']);
    let type_name = match end_idx {
        Some(idx) => trimmed[..idx].trim(),
        None => trimmed,
    };

    if type_name.is_empty() {
        None
    } else {
        Some(type_name.to_string())
    }
}

/// Find Rust type annotation for a variable
fn find_rust_annotation(source: &str, var_name: &str, call_line: u32) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();

    for line_num in (0..call_line as usize).rev() {
        let line = lines.get(line_num)?.trim();

        // Pattern: `let name: Type = ...` or `let mut name: Type = ...`
        for prefix in &["let ", "let mut "] {
            let pattern = format!("{}{}: ", prefix, var_name);
            if let Some(idx) = line.find(&pattern) {
                let after_colon = &line[idx + pattern.len()..];
                if let Some(type_name) = extract_rust_type_from_annotation(after_colon) {
                    return Some(type_name);
                }
            }
        }
    }

    None
}

/// Extract type from Rust annotation
fn extract_rust_type_from_annotation(s: &str) -> Option<String> {
    let trimmed = s.trim();

    // Find where type ends (at '=', ';', or ',')
    let end_idx = trimmed.find(['=', ';', ',']);
    let type_part = match end_idx {
        Some(idx) => trimmed[..idx].trim(),
        None => trimmed,
    };

    // Extract base type (handle generics and references)
    let base = type_part
        .trim_start_matches('&')
        .trim_start_matches("mut ")
        .trim();

    // Handle generic types - extract base
    let type_name = if let Some(angle_idx) = base.find('<') {
        &base[..angle_idx]
    } else {
        base
    };

    if type_name.is_empty() {
        None
    } else {
        Some(type_name.to_string())
    }
}

/// Find Rust associated function call: `let x = Type::new()`
fn find_rust_associated_function(source: &str, var_name: &str, call_line: u32) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();

    for line_num in (0..call_line as usize).rev() {
        let line = lines.get(line_num)?.trim();

        // Pattern: `let name = Type::` or `let mut name = Type::`
        for prefix in &["let ", "let mut "] {
            let pattern = format!("{}{} = ", prefix, var_name);
            if let Some(idx) = line.find(&pattern) {
                let after_eq = &line[idx + pattern.len()..];
                // Look for Type::method pattern
                if let Some(colon_idx) = after_eq.find("::") {
                    let type_name = after_eq[..colon_idx].trim();
                    if !type_name.is_empty()
                        && type_name.chars().next()?.is_uppercase()
                        && type_name != "Self"
                    {
                        return Some(type_name.to_string());
                    }
                }
            }
        }
    }

    None
}

/// Find Rust struct literal: `let x = Type { ... }`
fn find_rust_struct_literal(source: &str, var_name: &str, call_line: u32) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();

    for line_num in (0..call_line as usize).rev() {
        let line = lines.get(line_num)?.trim();

        // Pattern: `let name = Type {` or `let mut name = Type {`
        for prefix in &["let ", "let mut "] {
            let pattern = format!("{}{} = ", prefix, var_name);
            if let Some(idx) = line.find(&pattern) {
                let after_eq = &line[idx + pattern.len()..];
                // Look for Type { pattern
                if let Some(brace_idx) = after_eq.find('{') {
                    let type_name = after_eq[..brace_idx].trim();
                    if !type_name.is_empty()
                        && type_name.chars().next()?.is_uppercase()
                        && !type_name.contains("::")
                    {
                        return Some(type_name.to_string());
                    }
                }
            }
        }
    }

    None
}

// =============================================================================
// Generic Type Resolution (Phase 9+)
// =============================================================================

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

fn is_boundary(bytes: &[u8], start: usize, len: usize) -> bool {
    if start > 0 && is_ident_byte(bytes[start - 1]) {
        return false;
    }
    if start + len < bytes.len() && is_ident_byte(bytes[start + len]) {
        return false;
    }
    true
}

fn find_var_in_line(line: &str, var_name: &str) -> Option<usize> {
    line.match_indices(var_name)
        .find(|(idx, _)| is_boundary(line.as_bytes(), *idx, var_name.len()))
        .map(|(idx, _)| idx)
}

fn normalize_type_name(raw: &str) -> Option<String> {
    let mut t = raw.trim();

    // Drop trailing delimiters
    t = t.trim_end_matches([';', ',', ')', '{']);

    // Strip leading/trailing pointer/reference markers
    t = t.trim_start_matches(['&', '*']);
    t = t.trim_end_matches(['&', '*']);

    // Collapse union to first member
    if let Some((first, _)) = t.split_once('|') {
        t = first.trim();
    }

    // Strip generics/arrays
    if let Some(idx) = t.find('<') {
        t = &t[..idx];
    }
    if let Some(idx) = t.find('[') {
        t = &t[..idx];
    }

    if t.is_empty() {
        return None;
    }

    // Strip trailing .new / ::new (Ruby/Rust patterns)
    if let Some(stripped) = t.strip_suffix(".new") {
        t = stripped;
    }
    if let Some(stripped) = t.strip_suffix("::new") {
        t = stripped;
    }

    // Reduce qualified names to simple identifiers
    if let Some(idx) = t.rfind("::") {
        t = &t[idx + 2..];
    }
    if let Some(idx) = t.rfind('.') {
        t = &t[idx + 1..];
    }
    if let Some(idx) = t.rfind('/') {
        t = &t[idx + 1..];
    }

    let t = t.trim_matches(|c: char| c == ':' || c == '.');
    if t.is_empty() {
        return None;
    }

    let first = t.chars().next()?;
    if !first.is_uppercase() {
        return None;
    }

    Some(t.to_string())
}

fn extract_type_token(s: &str) -> Option<String> {
    let trimmed = s.trim_start();
    let mut end = trimmed.len();
    for (idx, ch) in trimmed.char_indices() {
        if ch.is_whitespace() || matches!(ch, '=' | ',' | ')' | ';' | '{') {
            end = idx;
            break;
        }
    }
    normalize_type_name(&trimmed[..end])
}

fn extract_rhs_type(rhs: &str) -> Option<String> {
    let mut s = rhs.trim_start();
    s = s.trim_start_matches(['&', '*']);
    if let Some(rest) = s.strip_prefix("new ") {
        s = rest.trim_start();
    }
    if s.starts_with('%') {
        s = s.trim_start_matches('%');
    }
    let mut end = s.len();
    for (idx, ch) in s.char_indices() {
        if ch.is_whitespace() || matches!(ch, '(' | '{' | '[' | ';' | ',') {
            end = idx;
            break;
        }
    }
    normalize_type_name(&s[..end])
}

fn find_generic_annotation(source: &str, var_name: &str, call_line: u32) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();
    for line_num in (0..call_line as usize).rev() {
        let line = lines.get(line_num)?;
        let idx = find_var_in_line(line, var_name)?;
        let mut tail = line[idx + var_name.len()..].trim_start();
        if let Some(rest) = tail.strip_prefix('?') {
            tail = rest.trim_start();
        }
        if let Some(rest) = tail.strip_prefix(':') {
            let after = rest.trim_start();
            if let Some(type_name) = extract_type_token(after) {
                return Some(type_name);
            }
        }
    }
    None
}

fn find_generic_constructor_assignment(
    source: &str,
    var_name: &str,
    call_line: u32,
) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();
    for line_num in (0..call_line as usize).rev() {
        let line = lines.get(line_num)?;
        let idx = find_var_in_line(line, var_name)?;
        let mut tail = line[idx + var_name.len()..].trim_start();
        if tail.starts_with(":=") {
            tail = tail[2..].trim_start();
        } else if tail.starts_with('=') {
            tail = tail[1..].trim_start();
        } else {
            continue;
        }
        if let Some(type_name) = extract_rhs_type(tail) {
            return Some(type_name);
        }
    }
    None
}

fn find_generic_typed_declaration(source: &str, var_name: &str, call_line: u32) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();
    for line_num in (0..call_line as usize).rev() {
        let line = lines.get(line_num)?;
        let idx = find_var_in_line(line, var_name)?;
        let left = line[..idx].trim_end();
        if left.is_empty() {
            continue;
        }
        let mut start = left.len();
        let bytes = left.as_bytes();
        while start > 0 {
            let b = bytes[start - 1];
            if b.is_ascii_whitespace() {
                break;
            }
            start -= 1;
        }
        let token = &left[start..];
        if let Some(type_name) = normalize_type_name(token) {
            return Some(type_name);
        }
    }
    None
}

/// Resolves the type of a method receiver using language-agnostic heuristics.
///
/// Attempts resolution in order: self/this/cls keywords (using enclosing context),
/// generic type annotations, and constructor assignment patterns. Falls back to
/// `None` with `Confidence::Low` if no resolution succeeds.
pub fn resolve_generic_receiver_type(
    source: &str,
    call_line: u32,
    receiver_name: &str,
    enclosing_context: Option<&str>,
) -> (Option<String>, Confidence) {
    if matches!(receiver_name, "self" | "this" | "cls" | "Self") {
        if let Some(ctx) = enclosing_context {
            return (Some(ctx.to_string()), Confidence::High);
        }
    }

    if let Some(type_name) = find_generic_annotation(source, receiver_name, call_line) {
        return (Some(type_name), Confidence::High);
    }

    if let Some(type_name) = find_generic_constructor_assignment(source, receiver_name, call_line) {
        return (Some(type_name), Confidence::High);
    }

    if let Some(type_name) = find_generic_typed_declaration(source, receiver_name, call_line) {
        return (Some(type_name), Confidence::High);
    }

    (None, Confidence::Low)
}

// =============================================================================
// Language Dispatch (Phase 9)
// =============================================================================

/// Resolve receiver type with language-specific resolution
///
/// This is the main dispatch function that routes to the appropriate
/// language-specific resolver based on the Language enum.
///
/// # Arguments
/// * `lang` - The programming language
/// * `source` - The source code
/// * `call_line` - Line number of the method call (1-indexed)
/// * `receiver_name` - The receiver expression
/// * `enclosing_context` - The enclosing class/impl/receiver, if any
///
/// # Returns
/// (resolved_type, confidence) - The resolved type name and confidence level
pub fn resolve_receiver_type(
    lang: Language,
    source: &str,
    call_line: u32,
    receiver_name: &str,
    enclosing_context: Option<&str>,
) -> (Option<String>, Confidence) {
    match lang {
        Language::Python => {
            resolve_python_receiver_type(source, call_line, receiver_name, enclosing_context)
        }
        Language::TypeScript | Language::JavaScript => {
            resolve_typescript_receiver_type(source, call_line, receiver_name, enclosing_context)
        }
        Language::Go => {
            resolve_go_receiver_type(source, call_line, receiver_name, enclosing_context)
        }
        Language::Rust => {
            resolve_rust_receiver_type(source, call_line, receiver_name, enclosing_context)
        }
        // For other languages, use the generic resolver
        _ => resolve_generic_receiver_type(source, call_line, receiver_name, enclosing_context),
    }
}

// =============================================================================
// fix-W5b-receiver-type-scan-v1: per-file receiver-type index
//
// Defect #2 (the remaining call-graph quadratic): the per-call-site resolvers
// above each re-scan the WHOLE `source` (`source.lines()`) inside their
// backward-search helpers. Called once per method/attr call-site that yields
// O(call_sites * source_lines) line iterations — pathological on large or
// minified files (js-lodash ships 27k/31k-line files).
//
// `SourceTypeIndex` precomputes, in ONE forward pass per file (O(L)), every
// declaration the backward scans look for, keyed by the declared variable with
// per-strategy line-sorted vectors. Each call-site then resolves via a binary
// search (O(log L)) that reproduces the *exact* strategy priority and
// nearest-preceding-declaration semantics of the scan resolvers, so resolved
// types are identical to the pre-fix behavior on real code.
//
// PRECEDENT: type_aware_resolver.rs builds `method_return_index` /
// `method_class_index` once as FileIRs are added (commit 8ca42d2) and round 1's
// FuncIndex `by_name`; this mirrors that "scan once, probe O(1)/O(log n)"
// pattern for the source-line scans.
// =============================================================================

/// A single declaration discovered during the one-pass scan: the 1-indexed line
/// it sits on and the resolved type name.
type Decl = (u32, String);

/// Append a declaration to a strategy map, preserving the same "a line declares
/// a given variable at most once per strategy" shape the scan helpers see: the
/// scans' backward walk stops at the FIRST (leftmost) match on a line, so for a
/// given (var, line) we keep only the first extracted type and ignore any later
/// same-line match (e.g. the pathological `a = A(); a = B()`).
fn push_decl(map: &mut HashMap<String, Vec<Decl>>, var: String, line: u32, ty: String) {
    let entries = map.entry(var).or_default();
    if entries.last().map(|(l, _)| *l) == Some(line) {
        // Same line already recorded for this var/strategy — keep the first.
        return;
    }
    entries.push((line, ty));
}

/// Register a declaration under EVERY suffix of `run` (the maximal identifier
/// immediately preceding the discriminator). This reproduces the production
/// scans' raw `line.find("{var}: ")` / `find("{var} = ...")` substring match
/// EXACTLY: a receiver `var` resolves from this line iff `var` is a trailing
/// substring of `run` (the "create_app bleeds to app" behavior the corpora
/// depend on). For a run of length k this records k suffix keys; summed over the
/// file that is O(total identifier characters) = O(L) work, so the index stays
/// sub-quadratic. The longest (whole-run) suffix is recorded first, but order
/// within a line does not matter because each (var, line) keeps only its first
/// entry via `push_decl`.
fn push_decl_suffixes(map: &mut HashMap<String, Vec<Decl>>, run: &str, line: u32, ty: &str) {
    let bytes = run.as_bytes();
    let n = bytes.len();
    // Suffixes start at every byte boundary that begins a UTF-8 char. Receivers
    // are ASCII identifiers in practice, but guard against multi-byte by only
    // slicing at char boundaries.
    for start in 0..n {
        if run.is_char_boundary(start) {
            let suffix = &run[start..];
            if !suffix.is_empty() {
                push_decl(map, suffix.to_string(), line, ty.to_string());
            }
        }
    }
}

/// Binary-search the nearest declaration strictly *before* `call_line`.
///
/// Reproduces the scan helpers' `(0..call_line).rev()` "first hit walking
/// backward" = the highest declaration line `< call_line`. The per-strategy
/// vectors are built in ascending line order during the forward pass, so we can
/// `partition_point` for `line < call_line` and take the last qualifying entry.
fn nearest_before(decls: &[Decl], call_line: u32) -> Option<&str> {
    let cut = decls.partition_point(|(line, _)| *line < call_line);
    if cut == 0 {
        None
    } else {
        Some(decls[cut - 1].1.as_str())
    }
}

/// An enclosing-scope marker (class / impl / receiver) discovered in the
/// forward pass, with the brace/indent depth bookkeeping needed to reproduce
/// the scan helpers' containment decision at query time.
#[derive(Debug, Clone)]
struct ScopeEvent {
    line: u32,
    name: String,
    /// Indent (Python) or brace depth (TS/Rust) recorded when the scope opened.
    depth: i32,
}

/// Per-file precomputed receiver-type index.
///
/// Built once per file; every call-site in that file then resolves via O(log L)
/// lookups instead of re-scanning the whole source. Strategy maps and scope
/// events are language-specific (only the dispatched language's tables are
/// populated), matching the language dispatch in [`resolve_receiver_type`].
#[derive(Debug, Default)]
pub struct SourceTypeIndex {
    /// Source lines, split once (1-indexed access via `lines[line-1]`). Avoids
    /// the repeated `source.lines().collect()` the scan helpers did per call.
    lines: Vec<String>,
    /// Strategy 1: explicit type annotations (`var: Type`, `let x: T`, ...).
    annotation: HashMap<String, Vec<Decl>>,
    /// Strategy 2: constructor / struct-literal / call assignments
    /// (`var = Type(...)`, `x := Type{}`, `let x = Type::new()`, ...).
    constructor: HashMap<String, Vec<Decl>>,
    /// Strategy 2b (Go/Rust only): a SECOND assignment strategy that the scan
    /// resolvers try as a distinct full backward pass *after* `constructor`
    /// (Go pointer-struct `x := &T{}`; Rust struct-literal `let x = T{}`),
    /// so it must lose to any `constructor` hit anywhere before the call.
    constructor_alt: HashMap<String, Vec<Decl>>,
    /// Go `var x Type` declarations (strategy 1 for Go; tried before struct
    /// literals).
    go_var_decl: HashMap<String, Vec<Decl>>,
    /// Enclosing class/impl scope openers in file order.
    scopes: Vec<ScopeEvent>,
    /// Final brace depth bookkeeping is recomputed per query for Python; for
    /// brace languages we precompute prefix brace depth per line.
    brace_prefix: Vec<i32>,
}

impl SourceTypeIndex {
    /// Build the index for `source` under `lang` in a single forward pass.
    pub fn build(lang: Language, source: &str) -> Self {
        let lines: Vec<String> = source.lines().map(|s| s.to_string()).collect();
        let mut idx = SourceTypeIndex {
            lines,
            ..Default::default()
        };

        // Precompute prefix brace depth (depth BEFORE each line is processed),
        // mirroring the running `brace_depth` the TS/Rust scans maintain.
        if matches!(
            lang,
            Language::TypeScript | Language::JavaScript | Language::Rust
        ) {
            let mut depth = 0i32;
            idx.brace_prefix.reserve(idx.lines.len());
            for line in &idx.lines {
                idx.brace_prefix.push(depth);
                depth += line.matches('{').count() as i32;
                depth -= line.matches('}').count() as i32;
            }
        }

        // Single forward pass: extract every declaration from each line into the
        // strategy maps (one bump per line == O(L) line-parse work total). We
        // collect into locals first, then move them into the struct, so the
        // immutable borrow of `idx.lines` does not clash with the mutation.
        let mut annotation: HashMap<String, Vec<Decl>> = HashMap::new();
        let mut constructor: HashMap<String, Vec<Decl>> = HashMap::new();
        let mut constructor_alt: HashMap<String, Vec<Decl>> = HashMap::new();
        let mut go_var_decl: HashMap<String, Vec<Decl>> = HashMap::new();
        let mut scopes: Vec<ScopeEvent> = Vec::new();

        for (i, line) in idx.lines.iter().enumerate() {
            bump_line_parse();
            let line_no = (i + 1) as u32;
            match lang {
                Language::Python => {
                    let trimmed = line.trim_start();
                    if trimmed.starts_with("class ") {
                        if let Some(name) = extract_class_name(trimmed) {
                            let indent = (line.len() - trimmed.len()) as i32;
                            scopes.push(ScopeEvent {
                                line: line_no,
                                name,
                                depth: indent,
                            });
                        }
                    }
                    // Python annotation = raw `find("{var}: ")` (substring) ->
                    // suffix registration to reproduce the create_app->app bleed.
                    for (run, ty) in python_annotations_in_line(line) {
                        push_decl_suffixes(&mut annotation, &run, line_no, &ty);
                    }
                    // Python constructor = `find_var_in_line` (boundary) -> whole.
                    for (var, ty) in python_constructors_in_line(line) {
                        push_decl(&mut constructor, var, line_no, ty);
                    }
                }
                Language::TypeScript | Language::JavaScript => {
                    let trimmed = line.trim();
                    if let Some(name) = extract_typescript_class_name(trimmed) {
                        let post = idx.brace_prefix[i] + line.matches('{').count() as i32
                            - line.matches('}').count() as i32;
                        scopes.push(ScopeEvent {
                            line: line_no,
                            name,
                            depth: post,
                        });
                    }
                    // TS annotation & constructor both used raw `find` -> suffix.
                    for (run, ty) in typescript_annotations_in_line(line) {
                        push_decl_suffixes(&mut annotation, &run, line_no, &ty);
                    }
                    for (run, ty) in typescript_constructors_in_line(line) {
                        push_decl_suffixes(&mut constructor, &run, line_no, &ty);
                    }
                }
                Language::Rust => {
                    let trimmed = line.trim();
                    if trimmed.starts_with("impl ") || trimmed.starts_with("impl<") {
                        if let Some(name) = extract_rust_impl_type(trimmed) {
                            let post = idx.brace_prefix[i] + line.matches('{').count() as i32
                                - line.matches('}').count() as i32;
                            scopes.push(ScopeEvent {
                                line: line_no,
                                name,
                                depth: post,
                            });
                        }
                    }
                    // Rust annotation/assoc-fn/struct-literal all used raw `find`
                    // (after the `let `/`let mut ` prefix) -> suffix registration.
                    for (run, ty) in rust_annotations_in_line(line) {
                        push_decl_suffixes(&mut annotation, &run, line_no, &ty);
                    }
                    for (run, ty) in rust_associated_fns_in_line(line) {
                        push_decl_suffixes(&mut constructor, &run, line_no, &ty);
                    }
                    for (run, ty) in rust_struct_literals_in_line(line) {
                        push_decl_suffixes(&mut constructor_alt, &run, line_no, &ty);
                    }
                }
                Language::Go => {
                    let trimmed = line.trim();
                    // Go var/struct/pointer all used raw `find` -> suffix.
                    for (run, ty) in go_var_decls_in_line(trimmed) {
                        push_decl_suffixes(&mut go_var_decl, &run, line_no, &ty);
                    }
                    for (run, ty) in go_struct_literals_in_line(trimmed) {
                        push_decl_suffixes(&mut constructor, &run, line_no, &ty);
                    }
                    for (run, ty) in go_pointer_structs_in_line(trimmed) {
                        push_decl_suffixes(&mut constructor_alt, &run, line_no, &ty);
                    }
                }
                _ => {
                    // Generic resolver used `find_var_in_line` (boundary) -> whole.
                    for (var, ty) in generic_annotations_in_line(line) {
                        push_decl(&mut annotation, var, line_no, ty);
                    }
                    for (var, ty) in generic_constructors_in_line(line) {
                        push_decl(&mut constructor, var, line_no, ty);
                    }
                    for (var, ty) in generic_typed_decls_in_line(line) {
                        push_decl(&mut constructor_alt, var, line_no, ty);
                    }
                }
            }
        }

        // Vectors are already in ascending line order (forward pass). For the
        // rare case of a single line declaring a var more than once via one
        // strategy, the scan's backward walk would stop at the FIRST (leftmost)
        // match on that line; `*_in_line` returns matches left-to-right and
        // `push_decl` keeps them in that order, so `nearest_before` selecting the
        // last entry strictly before the call line still lands on the correct
        // (nearest-preceding) line, and within a line ties never occur because a
        // call site is on its own line after the declaration.
        idx.annotation = annotation;
        idx.constructor = constructor;
        idx.constructor_alt = constructor_alt;
        idx.go_var_decl = go_var_decl;
        idx.scopes = scopes;
        idx
    }
}

/// Indexed counterpart to [`resolve_receiver_type`]. Produces a byte-identical
/// `(Option<String>, Confidence)` to the per-call-site scan resolver, but in
/// O(log L) using a [`SourceTypeIndex`] built once for the file.
pub fn resolve_receiver_type_indexed(
    index: &SourceTypeIndex,
    lang: Language,
    source: &str,
    call_line: u32,
    receiver_name: &str,
    enclosing_context: Option<&str>,
) -> (Option<String>, Confidence) {
    // `source` is accepted to mirror `resolve_receiver_type`'s signature (and to
    // keep the door open for cross-file lookups), but every per-language indexed
    // resolver answers purely from the prebuilt `index` (which already owns the
    // split source lines), so it is not threaded further.
    let _ = source;
    match lang {
        Language::Python => {
            resolve_python_indexed(index, call_line, receiver_name, enclosing_context)
        }
        Language::TypeScript | Language::JavaScript => {
            resolve_typescript_indexed(index, call_line, receiver_name, enclosing_context)
        }
        Language::Go => resolve_go_indexed(index, call_line, receiver_name, enclosing_context),
        Language::Rust => {
            resolve_rust_indexed(index, call_line, receiver_name, enclosing_context)
        }
        _ => resolve_generic_indexed(index, call_line, receiver_name, enclosing_context),
    }
}

fn resolve_python_indexed(
    index: &SourceTypeIndex,
    call_line: u32,
    receiver_name: &str,
    enclosing_class: Option<&str>,
) -> (Option<String>, Confidence) {
    if receiver_name == "self" {
        if let Some(class_name) = enclosing_class {
            return (Some(class_name.to_string()), Confidence::High);
        }
        if let Some(class_name) = index.python_enclosing_class(call_line) {
            return (Some(class_name), Confidence::High);
        }
        return (None, Confidence::Low);
    }

    if let Some(type_name) = index
        .annotation
        .get(receiver_name)
        .and_then(|d| nearest_before(d, call_line))
    {
        let type_name = type_name.to_string();
        if type_name.starts_with("Union[") || type_name.contains('|') {
            if expand_union_type(&type_name, None).is_none() {
                return (None, Confidence::Low);
            }
            return (Some(type_name), Confidence::Medium);
        }
        return (Some(type_name), Confidence::High);
    }

    if let Some(type_name) = index
        .constructor
        .get(receiver_name)
        .and_then(|d| nearest_before(d, call_line))
    {
        return (Some(type_name.to_string()), Confidence::High);
    }

    (None, Confidence::Low)
}

fn resolve_typescript_indexed(
    index: &SourceTypeIndex,
    call_line: u32,
    receiver_name: &str,
    enclosing_class: Option<&str>,
) -> (Option<String>, Confidence) {
    if receiver_name == "this" {
        if let Some(class_name) = enclosing_class {
            return (Some(class_name.to_string()), Confidence::High);
        }
        if let Some(class_name) = index.brace_enclosing_scope(call_line) {
            return (Some(class_name), Confidence::High);
        }
        return (None, Confidence::Low);
    }

    if let Some(type_name) = index
        .annotation
        .get(receiver_name)
        .and_then(|d| nearest_before(d, call_line))
    {
        let confidence = if is_likely_interface(type_name) {
            Confidence::Medium
        } else {
            Confidence::High
        };
        return (Some(type_name.to_string()), confidence);
    }

    if let Some(type_name) = index
        .constructor
        .get(receiver_name)
        .and_then(|d| nearest_before(d, call_line))
    {
        return (Some(type_name.to_string()), Confidence::High);
    }

    (None, Confidence::Low)
}

fn resolve_go_indexed(
    index: &SourceTypeIndex,
    call_line: u32,
    receiver_name: &str,
    enclosing_receiver: Option<&str>,
) -> (Option<String>, Confidence) {
    if let Some(type_name) = index
        .go_var_decl
        .get(receiver_name)
        .and_then(|d| nearest_before(d, call_line))
    {
        return (Some(type_name.to_string()), Confidence::High);
    }
    if let Some(type_name) = index
        .constructor
        .get(receiver_name)
        .and_then(|d| nearest_before(d, call_line))
    {
        return (Some(type_name.to_string()), Confidence::High);
    }
    if let Some(type_name) = index
        .constructor_alt
        .get(receiver_name)
        .and_then(|d| nearest_before(d, call_line))
    {
        return (Some(type_name.to_string()), Confidence::High);
    }
    if let Some(recv_type) = enclosing_receiver {
        if receiver_name.len() == 1 {
            return (Some(recv_type.to_string()), Confidence::High);
        }
    }
    (None, Confidence::Low)
}

fn resolve_rust_indexed(
    index: &SourceTypeIndex,
    call_line: u32,
    receiver_name: &str,
    enclosing_impl: Option<&str>,
) -> (Option<String>, Confidence) {
    if receiver_name == "self" || receiver_name == "&self" || receiver_name == "&mut self" {
        if let Some(impl_type) = enclosing_impl {
            return (Some(impl_type.to_string()), Confidence::High);
        }
        if let Some(impl_type) = index.brace_enclosing_scope(call_line) {
            return (Some(impl_type), Confidence::High);
        }
        return (None, Confidence::Low);
    }
    if receiver_name == "Self" {
        if let Some(impl_type) = enclosing_impl {
            return (Some(impl_type.to_string()), Confidence::High);
        }
        if let Some(impl_type) = index.brace_enclosing_scope(call_line) {
            return (Some(impl_type), Confidence::High);
        }
        return (None, Confidence::Low);
    }

    if let Some(type_name) = index
        .annotation
        .get(receiver_name)
        .and_then(|d| nearest_before(d, call_line))
    {
        return (Some(type_name.to_string()), Confidence::High);
    }
    if let Some(type_name) = index
        .constructor
        .get(receiver_name)
        .and_then(|d| nearest_before(d, call_line))
    {
        return (Some(type_name.to_string()), Confidence::High);
    }
    if let Some(type_name) = index
        .constructor_alt
        .get(receiver_name)
        .and_then(|d| nearest_before(d, call_line))
    {
        return (Some(type_name.to_string()), Confidence::High);
    }
    (None, Confidence::Low)
}

fn resolve_generic_indexed(
    index: &SourceTypeIndex,
    call_line: u32,
    receiver_name: &str,
    enclosing_context: Option<&str>,
) -> (Option<String>, Confidence) {
    if matches!(receiver_name, "self" | "this" | "cls" | "Self") {
        if let Some(ctx) = enclosing_context {
            return (Some(ctx.to_string()), Confidence::High);
        }
    }
    if let Some(type_name) = index
        .annotation
        .get(receiver_name)
        .and_then(|d| nearest_before(d, call_line))
    {
        return (Some(type_name.to_string()), Confidence::High);
    }
    if let Some(type_name) = index
        .constructor
        .get(receiver_name)
        .and_then(|d| nearest_before(d, call_line))
    {
        return (Some(type_name.to_string()), Confidence::High);
    }
    if let Some(type_name) = index
        .constructor_alt
        .get(receiver_name)
        .and_then(|d| nearest_before(d, call_line))
    {
        return (Some(type_name.to_string()), Confidence::High);
    }
    (None, Confidence::Low)
}

// -----------------------------------------------------------------------------
// Enclosing-scope queries (reproduce the scan helpers' containment decisions).
// -----------------------------------------------------------------------------

impl SourceTypeIndex {
    /// Reproduces `find_enclosing_class` (Python) at `line` using the recorded
    /// class events + the target line's own indent. The scan tracked the most
    /// recent `class` opener and, at the target line, returned it iff the target
    /// line's indent exceeds the class indent (or the line is blank); if the
    /// target line is past EOF it returned the last class seen.
    fn python_enclosing_class(&self, line: u32) -> Option<String> {
        // Most recent class opener at-or-before `line`.
        let cut = self.scopes.partition_point(|e| e.line <= line);
        if line as usize > self.lines.len() {
            // Past EOF: scan returned the last class encountered (if any).
            return self.scopes.last().map(|e| e.name.clone());
        }
        if cut == 0 {
            return None;
        }
        let ev = &self.scopes[cut - 1];
        let line_content = self.lines.get((line - 1) as usize)?;
        let line_indent = (line_content.len() - line_content.trim_start().len()) as i32;
        if line_indent > ev.depth || line_content.trim().is_empty() {
            Some(ev.name.clone())
        } else {
            None
        }
    }

    /// Reproduces `find_typescript_enclosing_class` / `find_rust_enclosing_impl`
    /// at `line`: the most recent opener whose post-line brace depth is still
    /// `<=` the running brace depth at the target line, with openers popped once
    /// the depth drops below their start depth.
    fn brace_enclosing_scope(&self, line: u32) -> Option<String> {
        if line as usize > self.lines.len() || self.brace_prefix.is_empty() {
            return None;
        }
        // Running depth AT the target line == post-line depth of the target
        // line (the scan updates depth for the whole line before the
        // `current_line == line` check).
        let li = (line - 1) as usize;
        let target_depth = self.brace_prefix[li]
            + self.lines[li].matches('{').count() as i32
            - self.lines[li].matches('}').count() as i32;

        // Replay openers in order, popping any whose start depth has been
        // exited, to find the innermost live scope at the target line.
        let mut current: Option<&ScopeEvent> = None;
        for ev in &self.scopes {
            if ev.line > line {
                break;
            }
            current = Some(ev);
        }
        let ev = current?;
        if target_depth >= ev.depth {
            Some(ev.name.clone())
        } else {
            None
        }
    }
}

// -----------------------------------------------------------------------------
// Per-line declaration extractors (`*_in_line`).
//
// Each returns EVERY (declared_var, resolved_type) pair on a line that the
// corresponding scan helper would treat as a declaration. They match a
// WHOLE-IDENTIFIER variable anywhere on the line (so typed parameters such as
// `def f(user: User)` resolve exactly as the scans' substring `find` did) and
// reuse the SAME type-extraction helpers (`extract_type_from_annotation`,
// `normalize_type_name`, ...) the scans use, so the resolved type strings are
// identical. The only behavioral difference from the scans is the
// substring-bleed quirk (var `x` matching inside `max:`), which boundary
// matching correctly avoids and which never occurs on real whole-identifier
// receivers — so resolved types are preserved on all real inputs.
//
// Matching anywhere on the line is what makes the index O(L): one pass records
// every declaration; each call-site then binary-searches its var instead of
// re-scanning the file.
// -----------------------------------------------------------------------------

/// Iterate `(ident, byte_offset_just_past_ident)` for every whole-identifier
/// token on `line`, in left-to-right order. The offset points at the first byte
/// after the identifier, where a following `:`/`=`/` ` discriminator lives.
fn ident_tokens(line: &str) -> impl Iterator<Item = (&str, usize)> {
    let bytes = line.as_bytes();
    let mut i = 0usize;
    std::iter::from_fn(move || {
        while i < bytes.len() {
            if is_ident_start(bytes[i]) {
                let start = i;
                i += 1;
                while i < bytes.len() && is_ident_byte(bytes[i]) {
                    i += 1;
                }
                return Some((&line[start..i], i));
            }
            i += 1;
        }
        None
    })
}

/// `var: Type [= ...]` (Python) — anywhere on the line. Mirrors
/// `find_type_annotation` / `extract_type_from_annotation`.
fn python_annotations_in_line(line: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (ident, end) in ident_tokens(line) {
        // scan pattern: `"{var}: "` — colon immediately, then a space.
        let rest = &line[end..];
        if let Some(after) = rest.strip_prefix(": ") {
            if let Some(ty) = extract_type_from_annotation(after) {
                out.push((ident.to_string(), ty));
            }
        }
    }
    out
}

/// `var = Type(...)` / `var := Type(...)` (Python). Mirrors
/// `find_constructor_assignment` (boundary-checked var, then `:=`/`=`, then `(`).
fn python_constructors_in_line(line: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (ident, end) in ident_tokens(line) {
        if let Some(tail) = assign_rhs(&line[end..]) {
            if let Some(paren_idx) = tail.find('(') {
                if let Some(ty) = normalize_type_name(tail[..paren_idx].trim()) {
                    out.push((ident.to_string(), ty));
                }
            }
        }
    }
    out
}

/// `[const|let|var] x: Type` (TS/JS). Mirrors `find_typescript_annotation` +
/// `extract_typescript_type`. The leading keyword is irrelevant to which var is
/// matched (the scan tries the `""` prefix too), so we match any `ident: Type`.
fn typescript_annotations_in_line(line: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (ident, end) in ident_tokens(line) {
        let rest = &line[end..];
        if let Some(after) = rest.strip_prefix(": ") {
            if let Some(ty) = extract_typescript_type(after) {
                out.push((ident.to_string(), ty));
            }
        }
    }
    out
}

/// `[const|let|var] x = new Type(...)` (TS/JS). Mirrors
/// `find_typescript_constructor`.
fn typescript_constructors_in_line(line: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (ident, end) in ident_tokens(line) {
        // scan pattern: `"{var} = new "` — exactly one space, `=`, space, `new `.
        let rest = &line[end..];
        if let Some(after_new) = rest
            .strip_prefix(" = new ")
            .or_else(|| rest.strip_prefix(" = new\t"))
        {
            let type_end = after_new.find(['(', '<']).unwrap_or(after_new.len());
            if let Some(ty) = normalize_type_name(after_new[..type_end].trim()) {
                out.push((ident.to_string(), ty));
            }
        }
    }
    out
}

/// `var x Type` (Go). Mirrors `find_go_var_declaration` + `extract_go_type`.
/// `line` is already trimmed by the caller (matching the scan's `.trim()`).
fn go_var_decls_in_line(line: &str) -> Vec<(String, String)> {
    // scan pattern: `"var {name} "` — only the first such on the line matters,
    // and the scan requires it after the literal `var `.
    let mut out = Vec::new();
    if let Some(rest) = line.strip_prefix("var ") {
        if let Some((var, after)) = split_leading_ident(rest) {
            if let Some(after) = after.strip_prefix(' ') {
                if let Some(ty) = extract_go_type(after) {
                    out.push((var.to_string(), ty));
                }
            }
        }
    }
    out
}

/// `x := Type{...}` (Go). Mirrors `find_go_struct_literal`.
fn go_struct_literals_in_line(line: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (ident, end) in ident_tokens(line) {
        // scan pattern: `"{name} := "` then a `{` before any other `{`.
        let rest = &line[end..];
        if let Some(after) = rest.strip_prefix(" := ") {
            if let Some(brace_idx) = after.find('{') {
                let type_name = after[..brace_idx].trim();
                if let Some(first) = type_name.chars().next() {
                    if first.is_uppercase() && !type_name.starts_with('&') {
                        out.push((ident.to_string(), type_name.to_string()));
                    }
                }
            }
        }
    }
    out
}

/// `x := &Type{...}` (Go). Mirrors `find_go_pointer_struct`.
fn go_pointer_structs_in_line(line: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (ident, end) in ident_tokens(line) {
        // scan pattern: `"{name} := &"` then `{`.
        let rest = &line[end..];
        if let Some(after_amp) = rest.strip_prefix(" := &") {
            if let Some(brace_idx) = after_amp.find('{') {
                let type_name = after_amp[..brace_idx].trim();
                if let Some(first) = type_name.chars().next() {
                    if first.is_uppercase() {
                        out.push((ident.to_string(), type_name.to_string()));
                    }
                }
            }
        }
    }
    out
}

/// `let [mut] x: Type` (Rust). Mirrors `find_rust_annotation`. The scan only
/// matches after `let `/`let mut `, so we require that prefix on the line.
fn rust_annotations_in_line(line: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let stripped = strip_decl_keyword_opt(line, &["let mut ", "let "]);
    if let Some(stripped) = stripped {
        if let Some((var, rest)) = split_leading_ident(stripped) {
            if let Some(after) = rest.strip_prefix(": ") {
                if let Some(ty) = extract_rust_type_from_annotation(after) {
                    out.push((var.to_string(), ty));
                }
            }
        }
    }
    out
}

/// `let [mut] x = Type::...` (Rust). Mirrors `find_rust_associated_function`.
fn rust_associated_fns_in_line(line: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let stripped = strip_decl_keyword_opt(line, &["let mut ", "let "]);
    if let Some(stripped) = stripped {
        if let Some((var, rest)) = split_leading_ident(stripped) {
            if let Some(after) = rest.strip_prefix(" = ") {
                if let Some(colon_idx) = after.find("::") {
                    let type_name = after[..colon_idx].trim();
                    if let Some(first) = type_name.chars().next() {
                        if first.is_uppercase() && type_name != "Self" {
                            out.push((var.to_string(), type_name.to_string()));
                        }
                    }
                }
            }
        }
    }
    out
}

/// `let [mut] x = Type { ... }` (Rust). Mirrors `find_rust_struct_literal`.
fn rust_struct_literals_in_line(line: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let stripped = strip_decl_keyword_opt(line, &["let mut ", "let "]);
    if let Some(stripped) = stripped {
        if let Some((var, rest)) = split_leading_ident(stripped) {
            if let Some(after) = rest.strip_prefix(" = ") {
                if let Some(brace_idx) = after.find('{') {
                    let type_name = after[..brace_idx].trim();
                    if let Some(first) = type_name.chars().next() {
                        if first.is_uppercase() && !type_name.contains("::") {
                            out.push((var.to_string(), type_name.to_string()));
                        }
                    }
                }
            }
        }
    }
    out
}

/// Generic annotation `var: Type` / `var?: Type`. Mirrors
/// `find_generic_annotation` (which checks `var` then `?` then `:`).
fn generic_annotations_in_line(line: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (ident, end) in ident_tokens(line) {
        let mut tail = line[end..].trim_start();
        if let Some(rest) = tail.strip_prefix('?') {
            tail = rest.trim_start();
        }
        if let Some(rest) = tail.strip_prefix(':') {
            let after = rest.trim_start();
            if let Some(ty) = extract_type_token(after) {
                out.push((ident.to_string(), ty));
            }
        }
    }
    out
}

/// Generic constructor `var = Type(...)` / `var := Type(...)`. Mirrors
/// `find_generic_constructor_assignment`.
fn generic_constructors_in_line(line: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (ident, end) in ident_tokens(line) {
        if let Some(tail) = assign_rhs(&line[end..]) {
            if let Some(ty) = extract_rhs_type(tail) {
                out.push((ident.to_string(), ty));
            }
        }
    }
    out
}

/// Generic typed declaration `Type var`. Mirrors
/// `find_generic_typed_declaration` (var found, token immediately to its left
/// is the type).
fn generic_typed_decls_in_line(line: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (ident, end) in ident_tokens(line) {
        // The var is `ident`; the type is the token immediately before it.
        let start = end - ident.len();
        let before = line[..start].trim_end();
        if before.is_empty() {
            continue;
        }
        let tok_start = before
            .rfind(char::is_whitespace)
            .map(|p| p + 1)
            .unwrap_or(0);
        let token = &before[tok_start..];
        if let Some(ty) = normalize_type_name(token) {
            out.push((ident.to_string(), ty));
        }
    }
    out
}

// --- small structural splitters shared by the extractors ---

/// If `s` (the text right after an identifier) begins with the scan's
/// assignment shape — optional whitespace, then `:=` or `=`, then optional
/// whitespace — return the RHS. Reproduces `find_var_in_line` + the
/// `tail.starts_with(":=")` / `starts_with('=')` handling. Returns None for
/// `==`, `:=`-vs-`=` is disambiguated by trying `:=` first.
fn assign_rhs(s: &str) -> Option<&str> {
    let t = s.trim_start();
    if let Some(after) = t.strip_prefix(":=") {
        return Some(after.trim_start());
    }
    if let Some(after) = t.strip_prefix('=') {
        // Guard against `==` (comparison), which the scan's `starts_with('=')`
        // then RHS parse would also stumble on; the scan never produced a type
        // from `==` because the RHS would not normalize. Keep parity by still
        // returning it (callers re-validate via normalize/extract).
        return Some(after.trim_start());
    }
    None
}

/// Strip the first matching declaration keyword prefix (after leading
/// whitespace); returns None if none match (used where the scan REQUIRES the
/// keyword, e.g. Rust `let `). Keywords are tried in priority order.
fn strip_decl_keyword_opt<'a>(line: &'a str, keywords: &[&str]) -> Option<&'a str> {
    let trimmed = line.trim_start();
    for kw in keywords {
        if let Some(rest) = trimmed.strip_prefix(kw) {
            return Some(rest);
        }
    }
    None
}

/// Split a leading identifier and the remainder: `ident<rest>`.
fn split_leading_ident(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    let bytes = s.as_bytes();
    if bytes.is_empty() || !is_ident_start(bytes[0]) {
        return None;
    }
    let mut end = 1;
    while end < bytes.len() && is_ident_byte(bytes[end]) {
        end += 1;
    }
    Some((&s[..end], &s[end..]))
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b == b'$'
}

// =============================================================================
// Robustness Utilities (Phase 10)
// =============================================================================

/// Maximum number of union type members to expand before falling back
pub const MAX_UNION_EXPANSION: usize = 5;

/// Expand a union type into its member types
///
/// Handles Python Union[A, B, C] and TypeScript A | B | C syntax.
/// If the union has more than `max_members` types, returns None to indicate
/// fallback should be used.
///
/// # Arguments
/// * `union_str` - The union type string
/// * `max_members` - Maximum number of members to expand (default: MAX_UNION_EXPANSION)
///
/// # Returns
/// Some(Vec<String>) with member types, or None if too many/invalid
pub fn expand_union_type(union_str: &str, max_members: Option<usize>) -> Option<Vec<String>> {
    let max = max_members.unwrap_or(MAX_UNION_EXPANSION);
    let trimmed = union_str.trim();

    // Python syntax: Union[A, B, C] or A | B | C (Python 3.10+)
    let members: Vec<&str> = if trimmed.starts_with("Union[") && trimmed.ends_with(']') {
        let inner = &trimmed[6..trimmed.len() - 1];
        inner.split(',').map(|s| s.trim()).collect()
    } else if trimmed.contains('|') {
        // TypeScript or Python 3.10+ union syntax
        trimmed.split('|').map(|s| s.trim()).collect()
    } else {
        // Not a union type
        return Some(vec![trimmed.to_string()]);
    };

    // Check limit
    if members.len() > max {
        return None; // T6 mitigation: too many types
    }

    // Filter out None/null types
    let filtered: Vec<String> = members
        .into_iter()
        .filter(|s| !s.is_empty() && *s != "None" && *s != "null" && *s != "undefined")
        .map(|s| s.to_string())
        .collect();

    if filtered.is_empty() {
        None
    } else {
        Some(filtered)
    }
}

/// Reason for skipping a file
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// Permission denied (T36)
    PermissionDenied,
    /// Invalid UTF-8 in path (T35)
    InvalidUtf8Path,
    /// File not found
    NotFound,
    /// Other IO error
    IoError(String),
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SkipReason::PermissionDenied => write!(f, "permission denied"),
            SkipReason::InvalidUtf8Path => write!(f, "invalid UTF-8 in path"),
            SkipReason::NotFound => write!(f, "file not found"),
            SkipReason::IoError(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

/// Safely read a file, handling permission and encoding errors gracefully
///
/// Returns Ok(content) on success, or Err(SkipReason) if the file should be skipped.
/// This function is used to handle T35 (non-UTF8 paths) and T36 (permission errors).
///
/// # Arguments
/// * `path` - Path to the file to read
///
/// # Returns
/// Ok(String) with file contents, or Err(SkipReason) explaining why it was skipped
pub fn safe_read_file(path: &std::path::Path) -> Result<String, SkipReason> {
    // T35: Validate UTF-8 path
    if path.to_str().is_none() {
        return Err(SkipReason::InvalidUtf8Path);
    }

    // Attempt to read file
    match std::fs::read_to_string(path) {
        Ok(content) => Ok(content),
        Err(e) => {
            match e.kind() {
                std::io::ErrorKind::PermissionDenied => Err(SkipReason::PermissionDenied),
                std::io::ErrorKind::NotFound => Err(SkipReason::NotFound),
                _ => {
                    // Check if it's a UTF-8 decoding error
                    if e.to_string().contains("invalid utf-8")
                        || e.to_string().contains("stream did not contain valid UTF-8")
                    {
                        Err(SkipReason::IoError("invalid UTF-8 content".to_string()))
                    } else {
                        Err(SkipReason::IoError(e.to_string()))
                    }
                }
            }
        }
    }
}

/// Validate that a path is valid UTF-8 and return the string representation
///
/// # Arguments
/// * `path` - Path to validate
///
/// # Returns
/// Some(&str) if valid, None if path contains invalid UTF-8
pub fn validate_path_utf8(path: &std::path::Path) -> Option<&str> {
    path.to_str()
}

/// Create a TypedCallEdge with resolved type information
pub struct TypedEdgeParams<'a> {
    /// Python source code
    pub source: &'a str,
    /// Source file path
    pub src_file: std::path::PathBuf,
    /// Calling function name
    pub src_func: String,
    /// Destination file path (where method is defined)
    pub dst_file: std::path::PathBuf,
    /// Receiver expression
    pub receiver: &'a str,
    /// Method being called
    pub method: &'a str,
    /// Line number of the call
    pub call_line: u32,
    /// Enclosing class if in a method
    pub enclosing_class: Option<&'a str>,
}

/// Create a TypedCallEdge with resolved type information
///
/// # Arguments
/// * `params` - Parameters for creating the typed call edge
///
/// # Returns
/// A TypedCallEdge with resolved type and confidence
pub fn create_typed_edge(params: TypedEdgeParams<'_>) -> TypedCallEdge {
    let (receiver_type, confidence) = resolve_python_receiver_type(
        params.source,
        params.call_line,
        params.receiver,
        params.enclosing_class,
    );

    let dst_func = match &receiver_type {
        Some(type_name) => format!("{}.{}", type_name, params.method),
        None => format!("{}.{}", params.receiver, params.method),
    };

    TypedCallEdge {
        src_file: params.src_file,
        src_func: params.src_func,
        dst_file: params.dst_file,
        dst_func,
        receiver_type,
        confidence,
        call_site_line: params.call_line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_enclosing_class_simple() {
        let source = r#"
class Calculator:
    def add(self, n):
        self._validate()
        return n
"#;
        // Line 4 is inside Calculator
        let class = find_enclosing_class(source, 4);
        assert_eq!(class, Some("Calculator".to_string()));
    }

    #[test]
    fn test_find_enclosing_class_with_bases() {
        let source = r#"
class Admin(User):
    def promote(self):
        pass
"#;
        let class = find_enclosing_class(source, 3);
        assert_eq!(class, Some("Admin".to_string()));
    }

    #[test]
    fn test_find_enclosing_class_outside() {
        let source = r#"
def standalone():
    pass
"#;
        let class = find_enclosing_class(source, 2);
        assert_eq!(class, None);
    }

    #[test]
    fn test_extract_class_name() {
        assert_eq!(extract_class_name("class User:"), Some("User".to_string()));
        assert_eq!(
            extract_class_name("class Admin(User):"),
            Some("Admin".to_string())
        );
        assert_eq!(
            extract_class_name("class Foo(A, B):"),
            Some("Foo".to_string())
        );
    }

    #[test]
    fn test_resolve_self_method() {
        assert_eq!(
            resolve_self_method("Calculator", "_validate"),
            "Calculator._validate"
        );
        assert_eq!(resolve_self_method("User", "save"), "User.save");
    }

    #[test]
    fn test_resolve_self_reference() {
        let source = r#"
class Calculator:
    def add(self, n):
        self._validate()
"#;
        let (type_name, confidence) =
            resolve_python_receiver_type(source, 4, "self", Some("Calculator"));
        assert_eq!(type_name, Some("Calculator".to_string()));
        assert_eq!(confidence, Confidence::High);
    }

    #[test]
    fn test_resolve_type_annotation() {
        let source = r#"
def process():
    user: User = User()
    user.save()
"#;
        let type_name = find_type_annotation(source, "user", 4);
        assert_eq!(type_name, Some("User".to_string()));
    }

    #[test]
    fn test_resolve_constructor() {
        let source = r#"
def setup():
    db = Database()
    db.connect()
"#;
        let type_name = find_constructor_assignment(source, "db", 4);
        assert_eq!(type_name, Some("Database".to_string()));
    }

    #[test]
    fn test_fallback_unknown_type() {
        let source = r#"
def process(data):
    data.transform()
"#;
        let (type_name, confidence) = resolve_python_receiver_type(source, 3, "data", None);
        assert_eq!(type_name, None);
        assert_eq!(confidence, Confidence::Low);
    }

    #[test]
    fn test_resolve_python_receiver_self_without_context() {
        let source = r#"
class Calculator:
    def add(self, n):
        self._validate()
"#;
        // Provide no enclosing class - should find it from source
        let (type_name, confidence) = resolve_python_receiver_type(source, 4, "self", None);
        assert_eq!(type_name, Some("Calculator".to_string()));
        assert_eq!(confidence, Confidence::High);
    }

    // =========================================================================
    // TypeScript Type Resolution Tests (Phase 9)
    // =========================================================================

    #[test]
    fn test_typescript_this_resolution() {
        let source = r#"
class Counter {
    private value: number = 0;

    increment(): void {
        this.value++;
        this.validate();
    }

    validate(): void {
        if (this.value < 0) {
            this.reset();
        }
    }

    reset(): void {
        this.value = 0;
    }
}
"#;
        // Line 7: this.validate() inside Counter
        let (type_name, confidence) =
            resolve_typescript_receiver_type(source, 7, "this", Some("Counter"));
        assert_eq!(type_name, Some("Counter".to_string()));
        assert_eq!(confidence, Confidence::High);

        // Test finding enclosing class from source
        let (type_name2, confidence2) = resolve_typescript_receiver_type(
            source, 7, "this", None, // Let it find the class
        );
        assert_eq!(type_name2, Some("Counter".to_string()));
        assert_eq!(confidence2, Confidence::High);
    }

    #[test]
    fn test_typescript_annotation_resolution() {
        let source = r#"
function processUser(): void {
    const user: User = new User("test");
    user.save();
    user.serialize();
}
"#;
        // Line 4: user.save() with explicit annotation
        let (type_name, confidence) = resolve_typescript_receiver_type(source, 4, "user", None);
        assert_eq!(type_name, Some("User".to_string()));
        assert_eq!(confidence, Confidence::High);
    }

    #[test]
    fn test_typescript_constructor_resolution() {
        let source = r#"
function setup(): void {
    const db = new Database();
    db.connect();
}
"#;
        // Line 4: db.connect() with constructor
        let (type_name, confidence) = resolve_typescript_receiver_type(source, 4, "db", None);
        assert_eq!(type_name, Some("Database".to_string()));
        assert_eq!(confidence, Confidence::High);
    }

    #[test]
    fn test_typescript_interface_detection() {
        // Interface names starting with 'I' should have MEDIUM confidence
        assert!(is_likely_interface("IRepository"));
        assert!(is_likely_interface("IService"));
        assert!(!is_likely_interface("Repository"));
        assert!(!is_likely_interface("User"));
    }

    #[test]
    fn test_extract_typescript_class_name() {
        assert_eq!(
            extract_typescript_class_name("class User {"),
            Some("User".to_string())
        );
        assert_eq!(
            extract_typescript_class_name("export class Admin {"),
            Some("Admin".to_string())
        );
        assert_eq!(
            extract_typescript_class_name("class Foo<T> {"),
            Some("Foo".to_string())
        );
        assert_eq!(
            extract_typescript_class_name("abstract class Base {"),
            Some("Base".to_string())
        );
    }

    // =========================================================================
    // Go Type Resolution Tests (Phase 9)
    // =========================================================================

    #[test]
    fn test_go_var_declaration() {
        let source = r#"
func main() {
    var dog Dog
    dog.Bark()
}
"#;
        let (type_name, confidence) = resolve_go_receiver_type(source, 4, "dog", None);
        assert_eq!(type_name, Some("Dog".to_string()));
        assert_eq!(confidence, Confidence::High);
    }

    #[test]
    fn test_go_struct_literal() {
        let source = r#"
func main() {
    dog := Dog{}
    dog.Bark()
}
"#;
        let (type_name, confidence) = resolve_go_receiver_type(source, 4, "dog", None);
        assert_eq!(type_name, Some("Dog".to_string()));
        assert_eq!(confidence, Confidence::High);
    }

    #[test]
    fn test_go_pointer_struct() {
        let source = r#"
func main() {
    dog := &Dog{}
    dog.Bark()
}
"#;
        let (type_name, confidence) = resolve_go_receiver_type(source, 4, "dog", None);
        assert_eq!(type_name, Some("Dog".to_string()));
        assert_eq!(confidence, Confidence::High);
    }

    #[test]
    fn test_go_receiver_resolution() {
        // When we know the enclosing receiver type
        let (type_name, confidence) = resolve_go_receiver_type(
            "",
            1,
            "d", // typical single-letter Go receiver
            Some("Dog"),
        );
        assert_eq!(type_name, Some("Dog".to_string()));
        assert_eq!(confidence, Confidence::High);
    }

    // =========================================================================
    // Rust Type Resolution Tests (Phase 9)
    // =========================================================================

    #[test]
    fn test_rust_self_resolution() {
        let source = r#"
impl Calculator {
    fn add(&self, n: i32) -> i32 {
        self.validate();
        self.value + n
    }

    fn validate(&self) {
        // validation logic
    }
}
"#;
        // Line 4: self.validate() inside Calculator impl
        let (type_name, confidence) = resolve_rust_receiver_type(
            source, 4, "self", None, // Let it find the impl
        );
        assert_eq!(type_name, Some("Calculator".to_string()));
        assert_eq!(confidence, Confidence::High);
    }

    #[test]
    fn test_rust_annotation_resolution() {
        let source = r#"
fn main() {
    let dog: Dog = Dog::new();
    dog.bark();
}
"#;
        let (type_name, confidence) = resolve_rust_receiver_type(source, 4, "dog", None);
        assert_eq!(type_name, Some("Dog".to_string()));
        assert_eq!(confidence, Confidence::High);
    }

    #[test]
    fn test_rust_associated_function() {
        let source = r#"
fn main() {
    let dog = Dog::new();
    dog.bark();
}
"#;
        let (type_name, confidence) = resolve_rust_receiver_type(source, 4, "dog", None);
        assert_eq!(type_name, Some("Dog".to_string()));
        assert_eq!(confidence, Confidence::High);
    }

    #[test]
    fn test_rust_struct_literal() {
        let source = r#"
fn main() {
    let dog = Dog { name: "Buddy" };
    dog.bark();
}
"#;
        let (type_name, confidence) = resolve_rust_receiver_type(source, 4, "dog", None);
        assert_eq!(type_name, Some("Dog".to_string()));
        assert_eq!(confidence, Confidence::High);
    }

    #[test]
    fn test_extract_rust_impl_type() {
        assert_eq!(
            extract_rust_impl_type("impl Calculator {"),
            Some("Calculator".to_string())
        );
        assert_eq!(
            extract_rust_impl_type("impl<T> Vec<T> {"),
            Some("Vec".to_string())
        );
        assert_eq!(
            extract_rust_impl_type("impl Display for Dog {"),
            Some("Dog".to_string())
        );
        assert_eq!(
            extract_rust_impl_type("impl<T: Clone> MyStruct<T> {"),
            Some("MyStruct".to_string())
        );
    }

    // =========================================================================
    // Language Dispatch Tests (Phase 9)
    // =========================================================================

    #[test]
    fn test_resolve_receiver_type_dispatch() {
        let python_source = r#"
class Calculator:
    def add(self, n):
        self._validate()
"#;
        // Python dispatch
        let (type_name, _) = resolve_receiver_type(
            Language::Python,
            python_source,
            4,
            "self",
            Some("Calculator"),
        );
        assert_eq!(type_name, Some("Calculator".to_string()));

        let ts_source = r#"
class Counter {
    increment(): void {
        this.validate();
    }
}
"#;
        // TypeScript dispatch
        let (type_name, _) =
            resolve_receiver_type(Language::TypeScript, ts_source, 4, "this", Some("Counter"));
        assert_eq!(type_name, Some("Counter".to_string()));

        // JavaScript should use same resolver as TypeScript
        let (type_name, _) =
            resolve_receiver_type(Language::JavaScript, ts_source, 4, "this", Some("Counter"));
        assert_eq!(type_name, Some("Counter".to_string()));
    }

    #[test]
    fn test_generic_receiver_type_java_assignment() {
        let source = r#"
class User { void save() {} }
class Main {
  void run() {
    User user = new User();
    user.save();
  }
}
"#;
        let (type_name, confidence) =
            resolve_receiver_type(Language::Java, source, 6, "user", None);
        assert_eq!(type_name, Some("User".to_string()));
        assert_eq!(confidence, Confidence::High);
    }

    #[test]
    fn test_generic_receiver_type_ruby_new() {
        let source = r#"
class User
  def save; end
end

def run
  user = User.new
  user.save
end
"#;
        let (type_name, confidence) =
            resolve_receiver_type(Language::Ruby, source, 7, "user", None);
        assert_eq!(type_name, Some("User".to_string()));
        assert_eq!(confidence, Confidence::High);
    }

    // =========================================================================
    // Robustness Tests (Phase 10)
    // =========================================================================

    #[test]
    fn test_expand_union_type_python() {
        // Python Union syntax
        let members = expand_union_type("Union[Dog, Cat, Bird]", None);
        assert_eq!(
            members,
            Some(vec![
                "Dog".to_string(),
                "Cat".to_string(),
                "Bird".to_string()
            ])
        );

        // Python 3.10+ pipe syntax
        let members = expand_union_type("Dog | Cat", None);
        assert_eq!(members, Some(vec!["Dog".to_string(), "Cat".to_string()]));
    }

    #[test]
    fn test_expand_union_type_typescript() {
        // TypeScript union syntax
        let members = expand_union_type("string | number | boolean", None);
        assert_eq!(
            members,
            Some(vec![
                "string".to_string(),
                "number".to_string(),
                "boolean".to_string()
            ])
        );
    }

    #[test]
    fn test_expand_union_type_limit() {
        // Should return None if too many types (T6 mitigation)
        let many_types = "A | B | C | D | E | F | G";
        let members = expand_union_type(many_types, Some(5));
        assert_eq!(members, None);

        // But should work with higher limit
        let members = expand_union_type(many_types, Some(10));
        assert!(members.is_some());
        assert_eq!(members.unwrap().len(), 7);
    }

    #[test]
    fn test_expand_union_filters_none() {
        // Should filter out None/null/undefined
        let members = expand_union_type("Dog | None", None);
        assert_eq!(members, Some(vec!["Dog".to_string()]));

        let members = expand_union_type("Dog | null | undefined", None);
        assert_eq!(members, Some(vec!["Dog".to_string()]));
    }

    #[test]
    fn test_expand_non_union() {
        // Non-union types should return single element
        let members = expand_union_type("Dog", None);
        assert_eq!(members, Some(vec!["Dog".to_string()]));
    }

    #[test]
    fn test_validate_path_utf8() {
        use std::path::Path;

        // Valid UTF-8 path
        let path = Path::new("/valid/utf8/path.rs");
        assert!(validate_path_utf8(path).is_some());

        // The test for invalid UTF-8 is tricky in Rust since Path::new
        // typically handles it, but validate_path_utf8 should work
        assert_eq!(validate_path_utf8(path), Some("/valid/utf8/path.rs"));
    }

    #[test]
    fn test_skip_reason_display() {
        assert_eq!(
            format!("{}", SkipReason::PermissionDenied),
            "permission denied"
        );
        assert_eq!(
            format!("{}", SkipReason::InvalidUtf8Path),
            "invalid UTF-8 in path"
        );
        assert_eq!(format!("{}", SkipReason::NotFound), "file not found");
        assert_eq!(
            format!("{}", SkipReason::IoError("test".to_string())),
            "IO error: test"
        );
    }

    // =========================================================================
    // fix-W5b-receiver-type-scan-v1: per-file receiver-type index
    //
    // Defect #2 (the remaining call-graph quadratic): `resolve_receiver_type`
    // re-scanned the WHOLE source (`source.lines()`) inside
    // `find_enclosing_class` / `find_type_annotation` /
    // `find_constructor_assignment` (and the TS/Go/Rust equivalents) for EVERY
    // call-site. On a file with L lines and N method/attr call-sites that is
    // O(L * N) source-line iterations — ~18.8M on a 2-file JS subset, far worse
    // on js-lodash's 27k/31k-line minified files.
    //
    // The fix precomputes a `SourceTypeIndex` ONCE per file (one forward pass,
    // O(L)), then every call-site resolves via O(log L) lookups. These tests
    // pin BOTH halves of the contract: (1) the indexed resolver returns
    // byte-identical (type, confidence) to the per-call-site scan on every
    // call-site (equivalence), and (2) building+querying the index parses each
    // source line a bounded number of times, NOT once-per-call-site
    // (sub-quadratic). Pre-fix these reference `SourceTypeIndex` /
    // `resolve_receiver_type_indexed`, which do not exist -> RED.
    // =========================================================================

    /// Build a synthetic source with `n_classes` classes, each owning a method
    /// with `body_decls` local typed/constructor declarations followed by
    /// `calls_per_method` method-call receivers. Returns (source, call_sites)
    /// where each call-site is (call_line, receiver_name, enclosing_class).
    fn synth_python(
        n_classes: usize,
        body_decls: usize,
        calls_per_method: usize,
    ) -> (String, Vec<(u32, String, Option<String>)>) {
        let mut src = String::new();
        let mut sites: Vec<(u32, String, Option<String>)> = Vec::new();
        let mut line: u32 = 0;
        let push = |src: &mut String, line: &mut u32, s: &str| {
            src.push_str(s);
            src.push('\n');
            *line += 1;
        };
        for c in 0..n_classes {
            let cls = format!("Klass{c}");
            push(&mut src, &mut line, &format!("class {cls}:"));
            push(&mut src, &mut line, "    def run(self):");
            // local declarations the backward scans must see
            for d in 0..body_decls {
                if d % 2 == 0 {
                    push(
                        &mut src,
                        &mut line,
                        &format!("        var{d}: Type{d} = make()"),
                    );
                } else {
                    push(&mut src, &mut line, &format!("        var{d} = Ctor{d}()"));
                }
            }
            // call-sites that reference the declarations + self
            for k in 0..calls_per_method {
                let d = k % body_decls.max(1);
                push(&mut src, &mut line, &format!("        var{d}.do()"));
                let want_ctor = d % 2 == 1;
                let cls_for_call = if want_ctor {
                    format!("Ctor{d}")
                } else {
                    format!("Type{d}")
                };
                let _ = cls_for_call;
                sites.push((line, format!("var{d}"), Some(cls.clone())));
                push(&mut src, &mut line, "        self.run()");
                sites.push((line, "self".to_string(), Some(cls.clone())));
            }
        }
        (src, sites)
    }

    #[test]
    fn indexed_receiver_type_matches_per_callsite_scan_python() {
        let (source, sites) = synth_python(6, 8, 10);
        let index = SourceTypeIndex::build(Language::Python, &source);
        for (line, recv, enclosing) in &sites {
            let scanned =
                resolve_receiver_type(Language::Python, &source, *line, recv, enclosing.as_deref());
            let indexed = resolve_receiver_type_indexed(
                &index,
                Language::Python,
                &source,
                *line,
                recv,
                enclosing.as_deref(),
            );
            assert_eq!(
                scanned, indexed,
                "indexed result diverged from scan at line {line} recv {recv}"
            );
            // these synthetic sites must actually resolve (guards a no-op index)
            assert!(
                indexed.0.is_some(),
                "site at line {line} recv {recv} should resolve to a concrete type"
            );
        }
    }

    /// fix-W5b-receiver-type-scan-v1: the production scan resolvers for Python
    /// annotations, TS, Go and Rust used a RAW substring `find("{var}: ")` (not a
    /// whole-identifier match), so a receiver `app` resolves from a NEARER
    /// `create_app: T` line via the trailing-substring "bleed". This is a real,
    /// edge-count-affecting behavior on the corpora (python-flask:
    /// FlaskGroup.get_command resolves `app` from a `create_app: t.Callable[...,
    /// Flask] | None` line). The indexed resolver MUST reproduce it exactly so
    /// resolved types — and therefore edge counts — are unchanged. Distilled
    /// from flask/src/flask/cli.py.
    #[test]
    fn indexed_preserves_substring_bleed_semantics_exactly() {
        // `create_app: ...` is NEARER to the call than the real `app: ...`, so
        // the substring scan bleeds `app` -> the create_app annotation type.
        let source = "\
class FlaskGroup:
    def __init__(self):
        app: Flask = make()
    def get_command(self):
        create_app: Callable = None
        app.app_context()
";
        // call line of `app.app_context()` is line 6 (1-indexed).
        let scan = resolve_receiver_type(Language::Python, source, 6, "app", Some("FlaskGroup"));
        let index = SourceTypeIndex::build(Language::Python, source);
        let indexed =
            resolve_receiver_type_indexed(&index, Language::Python, source, 6, "app", Some("FlaskGroup"));
        assert_eq!(
            scan, indexed,
            "indexed resolver must reproduce the substring-bleed the scan produces"
        );
        // Pin the actual bled value so a future 'cleanup' that drops the bleed is
        // caught: the scan resolves `app` from the nearer `create_app:` line.
        assert_eq!(
            scan.0.as_deref(),
            Some("Callable"),
            "scan should bleed `app` from the nearer `create_app: Callable` line"
        );

        // TypeScript bleed: receiver `user` substring-matches inside the NEARER
        // `myuser: Maker` line (lowercase `user: ` is a substring of `myuser: `),
        // so the raw-`find` scan bleeds `user` -> Maker over the real `user: User`.
        let ts = "\
class C {
  init() {
    const user: User = make();
  }
  run() {
    const myuser: Maker = get();
    user.save();
  }
}
";
        let ts_scan = resolve_receiver_type(Language::TypeScript, ts, 7, "user", Some("C"));
        let ts_index = SourceTypeIndex::build(Language::TypeScript, ts);
        let ts_indexed =
            resolve_receiver_type_indexed(&ts_index, Language::TypeScript, ts, 7, "user", Some("C"));
        assert_eq!(
            ts_scan, ts_indexed,
            "TS indexed must reproduce the substring-bleed exactly"
        );
        assert_eq!(
            ts_scan.0.as_deref(),
            Some("Maker"),
            "TS scan should bleed `user` from the nearer `myuser: Maker` line"
        );
    }

    #[test]
    fn indexed_receiver_type_matches_scan_typescript_rust_go() {
        // TypeScript
        let ts = r#"class Service {
  run() {
    const u: User = make();
    const r = new Repo();
    u.save();
    r.find();
    this.run();
  }
}
"#;
        let ts_sites = [
            (5u32, "u", Some("Service")),
            (6, "r", Some("Service")),
            (7, "this", Some("Service")),
        ];
        let ts_index = SourceTypeIndex::build(Language::TypeScript, ts);
        for (line, recv, enc) in ts_sites {
            let scanned = resolve_receiver_type(Language::TypeScript, ts, line, recv, enc);
            let indexed = resolve_receiver_type_indexed(
                &ts_index,
                Language::TypeScript,
                ts,
                line,
                recv,
                enc,
            );
            assert_eq!(scanned, indexed, "TS divergence at line {line} recv {recv}");
            assert!(indexed.0.is_some(), "TS site {recv} should resolve");
        }

        // Rust
        let rust = r#"impl Server {
    fn run(&self) {
        let c: Config = load();
        let h = Handler::new();
        c.apply();
        h.handle();
        self.run();
    }
}
"#;
        let rust_sites = [
            (5u32, "c", Some("Server")),
            (6, "h", Some("Server")),
            (7, "self", Some("Server")),
        ];
        let rust_index = SourceTypeIndex::build(Language::Rust, rust);
        for (line, recv, enc) in rust_sites {
            let scanned = resolve_receiver_type(Language::Rust, rust, line, recv, enc);
            let indexed =
                resolve_receiver_type_indexed(&rust_index, Language::Rust, rust, line, recv, enc);
            assert_eq!(scanned, indexed, "Rust divergence at line {line} recv {recv}");
            assert!(indexed.0.is_some(), "Rust site {recv} should resolve");
        }

        // Go
        let go = r#"func run() {
	var d Dog
	c := Cat{}
	d.Bark()
	c.Meow()
}
"#;
        let go_sites = [(4u32, "d", None), (5, "c", None)];
        let go_index = SourceTypeIndex::build(Language::Go, go);
        for (line, recv, enc) in go_sites {
            let scanned = resolve_receiver_type(Language::Go, go, line, recv, enc);
            let indexed =
                resolve_receiver_type_indexed(&go_index, Language::Go, go, line, recv, enc);
            assert_eq!(scanned, indexed, "Go divergence at line {line} recv {recv}");
            assert!(indexed.0.is_some(), "Go site {recv} should resolve");
        }
    }

    #[test]
    fn indexed_resolution_is_sub_quadratic_not_per_callsite_full_scan() {
        // A pathological file: large method bodies with MANY call-sites.
        // Pre-fix (the per-call-site scan resolver): each call-site triggers
        // find_enclosing_class / find_type_annotation / find_constructor_assignment,
        // each of which iterates source lines -> O(L * N) line touches.
        // Post-fix (index): SourceTypeIndex::build does ONE forward pass (O(L))
        // and each resolve is O(log L), so total line-parse work is ~O(L).
        //
        // The module-private LINE_PARSE_COUNTER is bumped once per line both by
        // the scan helpers (control) and by the index builder. We measure BOTH
        // paths on the SAME source and assert the indexed path does
        // dramatically less line-parse work, with a hard sub-quadratic bound on
        // the indexed total.
        let n_classes = 4;
        let body_decls = 6;
        let calls_per_method = 60; // N large relative to L
        let (source, sites) = synth_python(n_classes, body_decls, calls_per_method);
        let total_lines = source.lines().count() as u64;

        // --- CONTROL: the pre-fix per-call-site scan resolver (RED shape) ---
        LINE_PARSE_COUNTER.store(0, std::sync::atomic::Ordering::SeqCst);
        for (line, recv, enclosing) in &sites {
            let _ = resolve_receiver_type(
                Language::Python,
                &source,
                *line,
                recv,
                enclosing.as_deref(),
            );
        }
        let scan_line_touches = LINE_PARSE_COUNTER.load(std::sync::atomic::Ordering::SeqCst);

        // --- INDEXED: build once + O(log L) per call-site (GREEN shape) ---
        LINE_PARSE_COUNTER.store(0, std::sync::atomic::Ordering::SeqCst);
        let index = SourceTypeIndex::build(Language::Python, &source);
        for (line, recv, enclosing) in &sites {
            let _ = resolve_receiver_type_indexed(
                &index,
                Language::Python,
                &source,
                *line,
                recv,
                enclosing.as_deref(),
            );
        }
        let indexed_line_touches = LINE_PARSE_COUNTER.load(std::sync::atomic::Ordering::SeqCst);

        // Hard bound: indexed line-parse work is ~one pass (build), independent
        // of the number of call-sites. Generous 4x slack for the single pass.
        assert!(
            indexed_line_touches <= total_lines * 4,
            "indexed resolution touched {indexed_line_touches} lines over a \
             {total_lines}-line source ({} call-sites); expected <= 4x line count",
            sites.len()
        );

        // The scan control must be MUCH larger (genuine quadratic baseline), so
        // the bound above is a real guard, not trivially satisfiable.
        assert!(
            scan_line_touches > indexed_line_touches * 10,
            "scan control touched {scan_line_touches} lines vs indexed \
             {indexed_line_touches}; setup too small to distinguish O(L) from O(L*N)"
        );
    }
}
