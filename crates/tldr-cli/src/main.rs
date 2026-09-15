//! TLDR CLI - Token-efficient code analysis tool
//!
//! A Rust implementation of the TLDR code analysis tool providing:
//! - File tree traversal (`tree`)
//! - Code structure extraction (`structure`)
//! - Cross-file call graph building (`calls`)
//! - Impact analysis (`impact`)
//! - Dead code detection (`dead`)
//! - Reaching definitions (`reaching-defs`)
//! - Available expressions / CSE detection (`available`)
//! - Program slicing (`slice`)
//! - Token-based search with BM25 ranking + structure / call-graph signals (`search`); pass `--regex` for literal regex matching
//! - LLM context generation (`context`)
//! - Code smell detection (`smells`)
//!
//! # Performance Targets (Spec Section 7)
//! - Cold start: <100ms (M15 mitigation: lazy grammar loading)
//! - Parse time: <5ms per file
//! - Call graph: <5s for 10K LOC
//!
//! # Output Formats (Spec Section 3.2)
//! - `json`: Structured output with consistent field order (default)
//! - `text`: Human-readable formatted output
//! - `compact`: Minified JSON for piping
//!
//! # Mitigations Addressed
//! - M15: Cold start under 100ms via lazy grammar loading
//! - M19: JSON output differences via serde preserve_order
//! - M20: Better error messages with suggestions

use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};

use tldr_core::Language;

use tldr_cli::commands::remaining::{ApiCheckArgs, VulnArgs};
use tldr_cli::commands::{
    ApiSurfaceArgs, AvailableArgs, BodyArgs, BugbotCheckArgs, CacheClearArgs, CacheStatsArgs,
    CallsArgs,
    ChangeImpactArgs, ChopArgs, ChurnArgs, ClonesArgs, CognitiveArgs, ComplexityArgs, ContextArgs,
    ContractsArgs, CoverageArgs, DaemonListArgs, DaemonNotifyArgs, DaemonQueryArgs,
    DaemonStartArgs, DaemonStatusArgs, DaemonStopArgs, DeadArgs, DeadStoresArgs, DebtArgs,
    DefinitionArgs, DepsArgs,
    DiagnosticsArgs, DiceArgs, DiffArgs, DoctorArgs, ExplainArgs, ExtractArgs, FixArgs,
    HalsteadArgs, HealthArgs, HotspotsArgs, HubsArgs, ImpactArgs, ImportersArgs, ImportsArgs,
    InheritanceArgs, InvariantsArgs, LocArgs, PatternsArgs, ReachingDefsArgs, ReferencesArgs,
    SecureArgs, SliceArgs, SmartSearchArgs, SmellsArgs, SpecsArgs, StatsArgs, StructureArgs,
    TaintArgs, TodoArgs, TreeArgs, VerifyArgs, WarmArgs, WhatbreaksArgs,
};
// Pattern analysis commands
use tldr_cli::commands::patterns::{
    CohesionArgs, CouplingArgs, InterfaceArgs, ResourcesArgs, TemporalArgs,
};
#[cfg(feature = "semantic")]
use tldr_cli::commands::{EmbedArgs, SemanticArgs, SimilarArgs};
use tldr_cli::output::{validate_format_for_command, OutputFormat};

/// TLDR - Token-efficient code analysis for LLMs
#[derive(Debug, Parser)]
#[command(
    name = "tldr",
    version,
    about = "Token-efficient code analysis tool",
    long_about = "TLDR provides code analysis commands optimized for LLM consumption.\n\n\
                  Commands are organized by analysis layer:\n\
                  - L1 (AST): tree, structure\n\
                  - L2 (Call Graph): calls, impact, dead\n\
                  - L3 (CFG): reaching-defs, available\n\
                  - L4 (DFG): dead-stores\n\
                  - L5 (PDG): slice\n\
                  - Search: search\n\
                  - Context: context\n\
                  - Quality: smells\n\
                  - Security: taint, vuln, secure"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Output format
    ///
    /// Supported by every command: json, text, compact.
    ///
    /// Command-specific formats (rejected at runtime by other commands):
    ///   sarif  — only: vuln, clones
    ///   dot    — only: calls, impact, hubs, inheritance, clones, deps
    ///
    /// cli-error-clarity-v2 (P2.BUG-5): possible values are hidden on the
    /// global help to avoid promising sarif/dot for every subcommand. Run
    /// `tldr <cmd> --help` to confirm what a specific command emits, and
    /// see `validate_format_for_command` in `output.rs` for the source of
    /// truth.
    #[arg(
        long,
        short = 'f',
        global = true,
        default_value = "json",
        hide_possible_values = true,
        value_name = "FORMAT"
    )]
    pub format: OutputFormat,

    /// Programming language (auto-detect if not specified)
    #[arg(long, short = 'l', global = true)]
    pub lang: Option<Language>,

    /// Suppress progress output
    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,

    /// Enable verbose/debug output
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,
}

/// Available commands
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Show file tree structure
    #[command(visible_alias = "t")]
    Tree(TreeArgs),

    /// Extract code structure (functions, classes, imports)
    #[command(visible_alias = "s")]
    Structure(StructureArgs),

    /// Build cross-file call graph
    #[command(visible_alias = "c")]
    Calls(CallsArgs),

    /// Analyze impact of changing a function
    #[command(visible_alias = "i")]
    Impact(ImpactArgs),

    /// Find dead (unreachable) code
    #[command(visible_alias = "d")]
    Dead(DeadArgs),

    // Cfg, Dfg, Ssa: archived (T5 deep analysis)
    /// Analyze reaching definitions for a function
    #[command(name = "reaching-defs", visible_alias = "rd")]
    ReachingDefs(ReachingDefsArgs),

    // Dominators, LiveVars: archived (T5 deep analysis)
    /// Analyze taint flows to detect security vulnerabilities
    #[command(visible_alias = "ta")]
    Taint(TaintArgs),

    // Alias: archived (T5 deep analysis)
    /// Analyze available expressions for CSE detection
    #[command(visible_alias = "av")]
    Available(AvailableArgs),

    // AbstractInterp: archived (T5 deep analysis)
    /// Compute program slice
    Slice(SliceArgs),

    /// Enriched search with function-level context cards (BM25 + structure + call graph)
    #[command(name = "search")]
    SmartSearch(SmartSearchArgs),

    /// Build LLM-ready context from entry point
    Context(ContextArgs),

    /// Detect code smells
    Smells(SmellsArgs),

    /// Extract complete module info from a file
    #[command(visible_alias = "e")]
    Extract(ExtractArgs),

    /// Parse import statements from a file
    Imports(ImportsArgs),

    /// Find files that import a given module
    Importers(ImportersArgs),

    /// Calculate function complexity metrics
    Complexity(ComplexityArgs),

    /// Analyze git-based code churn
    Churn(ChurnArgs),

    /// Analyze technical debt using SQALE method
    Debt(DebtArgs),

    /// Comprehensive code health dashboard
    #[command(visible_alias = "h")]
    Health(HealthArgs),

    /// Detect hub functions using centrality analysis
    Hubs(HubsArgs),

    /// Analyze what breaks if a target is changed
    #[command(visible_alias = "wb")]
    Whatbreaks(WhatbreaksArgs),

    /// Detect design patterns and coding conventions
    #[command(visible_alias = "p")]
    Patterns(PatternsArgs),

    /// Extract class inheritance hierarchies
    #[command(visible_alias = "inh")]
    Inheritance(InheritanceArgs),

    /// Find tests affected by code changes
    #[command(visible_alias = "ci", name = "change-impact")]
    ChangeImpact(ChangeImpactArgs),

    /// Analyze module dependencies
    #[command(visible_alias = "dep")]
    Deps(DepsArgs),

    /// Run type checking and linting
    #[command(visible_alias = "diag")]
    Diagnostics(DiagnosticsArgs),

    /// Check and install diagnostic tools
    #[command(visible_alias = "doc")]
    Doctor(DoctorArgs),

    /// Find all references to a symbol
    #[command(visible_alias = "refs")]
    References(ReferencesArgs),

    /// Detect code clones in a codebase
    #[command(visible_alias = "cl")]
    Clones(ClonesArgs),

    /// Compare similarity between two code fragments
    Dice(DiceArgs),

    // -------------------------------------------------------------------------
    // Session 15: Metrics Commands
    // -------------------------------------------------------------------------
    /// Count lines of code with type breakdown (code, comments, blanks)
    Loc(LocArgs),

    /// Calculate cognitive complexity for functions (SonarQube algorithm)
    #[command(visible_alias = "cog")]
    Cognitive(CognitiveArgs),

    /// Calculate Halstead complexity metrics per function
    #[command(visible_alias = "hal")]
    Halstead(HalsteadArgs),

    /// Parse coverage reports (Cobertura XML, LCOV, coverage.py JSON)
    #[command(visible_alias = "cov")]
    Coverage(CoverageArgs),

    /// Identify churn x complexity hotspots
    #[command(visible_alias = "hot")]
    Hotspots(HotspotsArgs),

    // -------------------------------------------------------------------------
    // Session 16: Semantic Search Commands (requires "semantic" feature)
    // -------------------------------------------------------------------------
    #[cfg(feature = "semantic")]
    /// Generate embeddings for code chunks
    #[command(visible_alias = "emb")]
    Embed(EmbedArgs),

    #[cfg(feature = "semantic")]
    /// Semantic code search using natural language
    #[command(visible_alias = "sem")]
    Semantic(SemanticArgs),

    #[cfg(feature = "semantic")]
    /// Find similar code fragments
    #[command(visible_alias = "sim")]
    Similar(SimilarArgs),

    // -------------------------------------------------------------------------
    // Session 17: Daemon Subsystem
    // -------------------------------------------------------------------------
    /// Daemon management commands (start, stop, status)
    #[command(subcommand)]
    Daemon(DaemonCommand),

    /// Cache management commands (stats, clear)
    #[command(subcommand)]
    Cache(CacheCommand),

    // -------------------------------------------------------------------------
    // Phase 7-8: Warm and Stats Commands
    // -------------------------------------------------------------------------
    /// Pre-warm call graph cache for faster subsequent queries
    #[command(visible_alias = "w")]
    Warm(WarmArgs),

    /// Show TLDR usage statistics
    Stats(StatsArgs),

    // -------------------------------------------------------------------------
    // Session 18: Contracts & Flow Commands
    // -------------------------------------------------------------------------
    /// Extract machine-readable API surface for a library/package
    #[command(visible_alias = "surf")]
    Surface(ApiSurfaceArgs),

    /// Infer pre/postconditions from guard clauses, assertions, isinstance checks
    #[command(visible_alias = "con")]
    Contracts(ContractsArgs),

    // Bounds: archived (T5 deep analysis)
    /// Find dead stores using SSA-based analysis
    #[command(visible_alias = "ds")]
    DeadStores(DeadStoresArgs),

    /// Compute the dependency closure between two lines (forward slice of FROM ∩ backward slice of TO).
    ///
    /// NOT a line-range extractor: output is not bounded by FROM..TO and may include lines
    /// outside the window (or nothing when no dependency path exists). For contiguous source
    /// use `tldr body`.
    #[command(name = "chop", visible_alias = "deps-between", alias = "chp")]
    Chop(ChopArgs),

    /// Print the exact contiguous source of a function body or line range — byte-faithful (preserves CRLF/BOM/whitespace). Safe to read or reconstruct from, unlike slice/chop.
    #[command(name = "body")]
    Body(BodyArgs),

    /// Extract behavioral specifications from pytest test files
    #[command(visible_alias = "sp")]
    Specs(SpecsArgs),

    /// Infer invariants from test execution traces (Daikon-lite)
    #[command(visible_alias = "inv")]
    Invariants(InvariantsArgs),

    /// Aggregated verification dashboard combining multiple analyses
    #[command(visible_alias = "ver")]
    Verify(VerifyArgs),

    // -------------------------------------------------------------------------
    // Pattern Analysis Commands (patterns module)
    // -------------------------------------------------------------------------
    /// Analyze class cohesion using LCOM4 metric
    #[command(visible_alias = "coh")]
    Cohesion(CohesionArgs),

    /// Mine temporal constraints (method call sequences)
    #[command(visible_alias = "tem")]
    Temporal(TemporalArgs),

    // Behavioral: archived (T5 deep analysis)
    /// Analyze resource lifecycle (leaks, double-close, use-after-close)
    #[command(visible_alias = "res")]
    Resources(ResourcesArgs),

    /// Analyze coupling between modules/classes via cross-module call edges
    /// (afferent/efferent, instability). Measures function-call coupling, not
    /// import-level dependencies — use `tldr deps` or `tldr imports` for that
    /// (P12.AGG12-14).
    #[command(visible_alias = "coup")]
    Coupling(CouplingArgs),

    /// Extract interface contracts (public API signatures, contracts)
    #[command(visible_alias = "iface")]
    Interface(InterfaceArgs),

    // -------------------------------------------------------------------------
    // Remaining Commands (Phase 4+)
    // -------------------------------------------------------------------------
    /// Comprehensive function analysis (signature, purity, complexity, callers, callees)
    #[command(visible_alias = "exp")]
    Explain(ExplainArgs),

    /// Aggregate improvement suggestions (dead code, complexity, cohesion, similar)
    Todo(TodoArgs),

    /// Security analysis dashboard (taint, resources, bounds, contracts, behavioral, mutability)
    #[command(visible_alias = "sec")]
    Secure(SecureArgs),

    /// Go-to-definition - find where a symbol is defined
    #[command(visible_alias = "def")]
    Definition(DefinitionArgs),

    /// AST-aware structural diff between two files
    #[command(visible_alias = "df")]
    Diff(DiffArgs),

    // DiffImpact: archived (superseded by change-impact)
    // /// Analyze impact of code changes - identify affected functions and suggest tests
    // #[command(name = "diff-impact", visible_alias = "di")]
    // DiffImpact(DiffImpactArgs),
    /// Detect API misuse patterns (missing timeouts, bare except, weak crypto, unclosed files)
    #[command(name = "api-check", visible_alias = "ac")]
    ApiCheck(ApiCheckArgs),

    /// Vulnerability scanning via taint analysis (SQL injection, XSS, command injection)
    Vuln(VulnArgs),
    // Gvn (EquivalenceArgs): archived (T5 deep analysis)

    // -------------------------------------------------------------------------
    // Fix: error diagnosis and auto-fix system
    // -------------------------------------------------------------------------
    /// Diagnose and auto-fix errors from compiler/runtime output.
    ///
    /// Auto-detects and parses error text from any of:
    ///   - Rust:      cargo build / cargo check / rustc errors (E0xxx)
    ///   - C/C++:     gcc / clang diagnostics (file:line:col: error: ...)
    ///   - Python:    tracebacks (NameError, AttributeError, ImportError)
    ///   - JS/TS:     jest / mocha test output, tsc errors (TS2xxx)
    ///   - Linters:   eslint --format json, ruff, pylint
    ///
    /// Pass error text via --error "...", --error-file path, or --stdin.
    #[command(visible_alias = "fx")]
    Fix(FixArgs),

    // -------------------------------------------------------------------------
    // Bugbot: automated bug detection on code changes
    // -------------------------------------------------------------------------
    /// Automated bug detection on code changes
    #[command(subcommand)]
    Bugbot(BugbotCommand),
}

/// Daemon subcommands
#[derive(Debug, Subcommand)]
pub enum DaemonCommand {
    /// Start the TLDR daemon
    Start(DaemonStartArgs),

    /// Stop the TLDR daemon
    Stop(DaemonStopArgs),

    /// Show daemon status
    Status(DaemonStatusArgs),

    /// Send a raw query to the daemon
    Query(DaemonQueryArgs),

    /// Notify daemon of file changes
    Notify(DaemonNotifyArgs),

    /// List all running daemons (multi-daemon registry, v0.3.0)
    List(DaemonListArgs),
}

/// Cache subcommands
#[derive(Debug, Subcommand)]
pub enum CacheCommand {
    /// Show cache statistics
    Stats(CacheStatsArgs),

    /// Clear cache files
    Clear(CacheClearArgs),
}

/// Bugbot subcommands
#[derive(Debug, Subcommand)]
pub enum BugbotCommand {
    /// Run bugbot check on uncommitted changes
    Check(BugbotCheckArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Set up verbose logging if requested
    if cli.verbose {
        std::env::set_var("TLDR_LOG", "debug");
    }

    // Run the command
    let result = run_command(&cli);

    // Handle result
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Print error with helpful context (M20 mitigation)
            eprintln!("Error: {}", e);

            // Print chain of errors for debugging
            if cli.verbose {
                let mut source = e.source();
                while let Some(err) = source {
                    eprintln!("  Caused by: {}", err);
                    source = err.source();
                }
            }

            // Return appropriate exit code based on error type
            if let Some(bugbot_err) =
                e.downcast_ref::<tldr_cli::commands::bugbot::BugbotExitError>()
            {
                ExitCode::from(bugbot_err.exit_code())
            } else if let Some(tldr_err) = e.downcast_ref::<tldr_core::TldrError>() {
                ExitCode::from(tldr_err.exit_code() as u8)
            } else if let Some(remaining_err) =
                e.downcast_ref::<tldr_cli::commands::remaining::RemainingError>()
            {
                ExitCode::from(remaining_err.exit_code() as u8)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

/// Stable, user-facing name for a `Command` variant.
///
/// Used by `validate_format_for_command` (format-flag-strictness-v1) so that
/// error messages name the actual subcommand (`smells`, `vuln`, ...) rather
/// than the Rust enum variant. Names match what users type on the CLI.
fn command_name(cmd: &Command) -> &'static str {
    match cmd {
        Command::Tree(_) => "tree",
        Command::Structure(_) => "structure",
        Command::Calls(_) => "calls",
        Command::Impact(_) => "impact",
        Command::Dead(_) => "dead",
        Command::ReachingDefs(_) => "reaching-defs",
        Command::Taint(_) => "taint",
        Command::Available(_) => "available",
        Command::Slice(_) => "slice",
        Command::SmartSearch(_) => "search",
        Command::Context(_) => "context",
        Command::Smells(_) => "smells",
        Command::Extract(_) => "extract",
        Command::Imports(_) => "imports",
        Command::Importers(_) => "importers",
        Command::Complexity(_) => "complexity",
        Command::Churn(_) => "churn",
        Command::Debt(_) => "debt",
        Command::Health(_) => "health",
        Command::Hubs(_) => "hubs",
        Command::Whatbreaks(_) => "whatbreaks",
        Command::Patterns(_) => "patterns",
        Command::Inheritance(_) => "inheritance",
        Command::ChangeImpact(_) => "change-impact",
        Command::Deps(_) => "deps",
        Command::Diagnostics(_) => "diagnostics",
        Command::Doctor(_) => "doctor",
        Command::References(_) => "references",
        Command::Clones(_) => "clones",
        Command::Dice(_) => "dice",
        Command::Loc(_) => "loc",
        Command::Cognitive(_) => "cognitive",
        Command::Halstead(_) => "halstead",
        Command::Coverage(_) => "coverage",
        Command::Hotspots(_) => "hotspots",
        #[cfg(feature = "semantic")]
        Command::Embed(_) => "embed",
        #[cfg(feature = "semantic")]
        Command::Semantic(_) => "semantic",
        #[cfg(feature = "semantic")]
        Command::Similar(_) => "similar",
        Command::Daemon(sub) => match sub {
            DaemonCommand::Start(_) => "daemon start",
            DaemonCommand::Stop(_) => "daemon stop",
            DaemonCommand::Status(_) => "daemon status",
            DaemonCommand::Query(_) => "daemon query",
            DaemonCommand::Notify(_) => "daemon notify",
            DaemonCommand::List(_) => "daemon list",
        },
        Command::Cache(sub) => match sub {
            CacheCommand::Stats(_) => "cache stats",
            CacheCommand::Clear(_) => "cache clear",
        },
        Command::Warm(_) => "warm",
        Command::Stats(_) => "stats",
        Command::Surface(_) => "surface",
        Command::Contracts(_) => "contracts",
        Command::DeadStores(_) => "dead-stores",
        Command::Chop(_) => "chop",
        Command::Body(_) => "body",
        Command::Specs(_) => "specs",
        Command::Invariants(_) => "invariants",
        Command::Verify(_) => "verify",
        Command::Cohesion(_) => "cohesion",
        Command::Temporal(_) => "temporal",
        Command::Resources(_) => "resources",
        Command::Coupling(_) => "coupling",
        Command::Interface(_) => "interface",
        Command::Explain(_) => "explain",
        Command::Todo(_) => "todo",
        Command::Secure(_) => "secure",
        Command::Definition(_) => "definition",
        Command::Diff(_) => "diff",
        Command::ApiCheck(_) => "api-check",
        Command::Vuln(_) => "vuln",
        Command::Fix(_) => "fix",
        Command::Bugbot(sub) => match sub {
            BugbotCommand::Check(_) => "bugbot check",
        },
    }
}

fn run_command(cli: &Cli) -> Result<()> {
    // format-flag-strictness-v1: reject (cmd, format) pairs where the command
    // does not actually emit the requested format. Without this, callers
    // (especially CI wiring up SARIF for code-scanning) silently received
    // plain JSON and believed SARIF was being produced.
    if let Err(msg) = validate_format_for_command(command_name(&cli.command), cli.format) {
        anyhow::bail!(msg);
    }

    // low-cleanup-bundle-v1 (L8): propagate the global `--quiet`/`-q` flag
    // through `TLDR_QUIET=1` so library code outside the CLI's writer path
    // (notably `Embedder::new`'s model-load banner) can suppress its own
    // stderr output. Without this, `tldr semantic --quiet "query"` still
    // printed 3+ lines from the embedder bootstrap.
    //
    // high-bundle-progress-determinism-coverage-v1 (N1): also set the env
    // flag when the user picked a machine-readable format so that any
    // process-level banner (stderr-bound) shuts up too. Note the in-CLI
    // `OutputWriter::progress` already auto-suppresses for json/sarif/
    // compact (see crates/tldr-cli/src/output.rs); this env flag covers
    // the library-side banners that don't go through the writer.
    let auto_quiet_env = matches!(
        cli.format,
        OutputFormat::Json | OutputFormat::Compact | OutputFormat::Sarif
    );
    if cli.quiet || auto_quiet_env {
        std::env::set_var("TLDR_QUIET", "1");
    }
    // Keep `q == cli.quiet` for the dispatch table so that commands which
    // (legitimately or not) wrap their *actual* JSON emission in
    // `if !quiet` keep emitting on json. The N1 progress-suppression now
    // lives in `OutputWriter::progress` itself and triggers automatically
    // for machine-readable formats — no need to pierce the dispatch table.
    let q = cli.quiet;

    match &cli.command {
        Command::Tree(args) => args.run(cli.format, q),
        Command::Structure(args) => args.run(cli.format, q),
        Command::Calls(args) => args.run(cli.format, q),
        Command::Impact(args) => args.run(cli.format, q),
        Command::Dead(args) => args.run(cli.format, q),
        // Cfg, Dfg, Ssa, Dominators, LiveVars, Alias, AbstractInterp: archived
        Command::ReachingDefs(args) => args.run(cli.format, q),
        Command::Taint(args) => args.run(cli.format, q),
        Command::Available(args) => args.run(cli.format, q),
        Command::Slice(args) => args.run(cli.format, q),
        Command::SmartSearch(args) => args.run(cli.format, q),
        Command::Context(args) => args.run(cli.format, q),
        Command::Smells(args) => args.run(cli.format, q),
        Command::Extract(args) => args.run(cli.format, q),
        Command::Imports(args) => args.run(cli.format, q),
        Command::Importers(args) => args.run(cli.format, q),
        Command::Complexity(args) => args.run(cli.format, q),
        Command::Churn(args) => args.run(cli.format, q),
        Command::Debt(args) => args.run(cli.format, q, cli.lang),
        Command::Health(args) => args.run(cli.format, q, cli.lang),
        Command::Hubs(args) => args.run(cli.format, q),
        Command::Whatbreaks(args) => args.run(cli.format, q),
        Command::Patterns(args) => args.run(cli.format, q),
        Command::Inheritance(args) => args.run(cli.format, q),
        Command::ChangeImpact(args) => args.run(cli.format, q),
        Command::Deps(args) => args.run(cli.format, q),
        Command::Diagnostics(args) => args.run(cli.format, q),
        // Doctor respects --format like all other commands
        Command::Doctor(args) => args.run(cli.format, q),
        Command::References(args) => args.run(cli.format, q, cli.lang),
        Command::Clones(args) => args.run(cli.format, q, cli.lang),
        Command::Dice(args) => args.run(cli.format, q),
        // Session 15: Metrics commands
        Command::Loc(args) => args.run(cli.format, q),
        Command::Cognitive(args) => args.run(cli.format, q),
        Command::Halstead(args) => args.run(cli.format, q),
        Command::Coverage(args) => args.run(cli.format, q),
        Command::Hotspots(args) => args.run(cli.format, q),
        // Session 16: Semantic search commands
        #[cfg(feature = "semantic")]
        Command::Embed(args) => args.run(cli.format, q),
        #[cfg(feature = "semantic")]
        Command::Semantic(args) => args.run(cli.format, q),
        #[cfg(feature = "semantic")]
        Command::Similar(args) => args.run(cli.format, q),
        // Session 17: Daemon subsystem
        Command::Daemon(daemon_cmd) => match daemon_cmd {
            DaemonCommand::Start(args) => args.run(cli.format, q),
            DaemonCommand::Stop(args) => args.run(cli.format, q),
            DaemonCommand::Status(args) => args.run(cli.format, q),
            DaemonCommand::Query(args) => args.run(cli.format, q),
            DaemonCommand::Notify(args) => args.run(cli.format, q),
            DaemonCommand::List(args) => args.run(cli.format, q),
        },
        // Cache management commands
        Command::Cache(cache_cmd) => match cache_cmd {
            CacheCommand::Stats(args) => args.run(cli.format, q),
            CacheCommand::Clear(args) => args.run(cli.format, q),
        },
        // Phase 7-8: Warm and Stats commands
        Command::Warm(args) => args.run(cli.format, q),
        Command::Stats(args) => args.run(cli.format, q),
        // Session 18: API Surface
        Command::Surface(args) => args.run(cli.format, q, cli.lang),
        // Behavioral contracts (pre/postconditions)
        Command::Contracts(args) => args.run(cli.format, q),
        // Bounds: archived
        Command::DeadStores(args) => args.run(cli.format, q),
        Command::Chop(args) => args.run(cli.format, q),
        Command::Body(args) => args.run(cli.format, q, cli.lang),
        Command::Specs(args) => args.run(cli.format, q),
        Command::Invariants(args) => args.run(cli.format, q),
        Command::Verify(args) => args.run(cli.format, q),
        // Pattern analysis commands
        Command::Cohesion(args) => args.run(cli.format),
        Command::Temporal(args) => args.run(cli.format),
        // Behavioral: archived
        Command::Resources(args) => args.run(cli.format),
        Command::Coupling(args) => {
            tldr_cli::commands::patterns::coupling::run(args.clone(), cli.format)
        }
        Command::Interface(args) => {
            tldr_cli::commands::patterns::interface::run(args.clone(), cli.format)
        }
        // Remaining commands
        Command::Explain(args) => args.run(cli.format, q),
        Command::Todo(args) => args.run(cli.format, q, cli.lang),
        Command::Secure(args) => args.run(cli.format),
        Command::Definition(args) => args.run(cli.format, q, cli.lang),
        Command::Diff(args) => args.run(cli.format),
        // DiffImpact: archived (superseded by change-impact)
        Command::ApiCheck(args) => args.run(cli.format, q, cli.lang),
        Command::Vuln(args) => args.run(cli.format),
        // Gvn: archived
        // Fix: error diagnosis and auto-fix
        Command::Fix(args) => args.run(cli.format, q, cli.lang),
        // Bugbot
        Command::Bugbot(bugbot_cmd) => match bugbot_cmd {
            BugbotCommand::Check(args) => args.run(cli.format, q, cli.lang),
        },
    }
}
