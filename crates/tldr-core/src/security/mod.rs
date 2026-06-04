//! Security analysis module - Phase 8
//!
//! This module provides security vulnerability detection:
//! - Secret scanning (API keys, passwords, private keys)
//! - Vulnerability detection via taint analysis (SQL injection, XSS, command injection)
//!
//! # References
//! - OWASP Top 10
//! - CWE/SANS Top 25

pub mod ast_utils;
pub mod secrets;
// v0.5.0 SOL-011 solidity-vuln-v1: AST-pattern detectors for top-5 Solidity
// vulnerabilities (tx.origin, shadowing-state, suicidal, unchecked-lowlevel,
// locked-ether). Crate-internal — surfaced via `vuln::scan_file_vulns`.
pub(crate) mod solidity_vuln;
pub mod taint;
pub mod vuln;

// Taint analysis tests (CFG-based taint tracking)
#[cfg(test)]
mod taint_tests;

pub use secrets::{scan_secrets, SecretFinding, SecretsReport, Severity};
pub use taint::{
    compute_taint, compute_taint_with_tree, detect_sanitizer_ast, detect_sinks_ast,
    detect_sources_ast, SanitizerType, TaintFlow, TaintInfo, TaintSink, TaintSinkType, TaintSource,
    TaintSourceType,
};
pub use vuln::{scan_vulnerabilities, VulnFinding, VulnReport, VulnType};
