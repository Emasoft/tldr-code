# TLDR Architecture

**Version:** 2.0
**Purpose:** Token-efficient code analysis engine with 5-layer analysis stack

---

## Overview

TLDR (Token-efficient Language-agnostic Data Representation) is a Rust-based code analysis engine designed for:

- **Token Efficiency**: 95% token savings vs raw source code
- **5-Layer Analysis Stack**: AST → Call Graph → CFG → DFG → PDG
- **Multi-language Support**: 31 languages — 27 via tree-sitter, 4 via native scanners (Log, Text, CSV, TSV have no usable grammar)
- **Fast Static Analysis**: No LSP required, syntactic analysis only

### Design Philosophy

```
Fast Static Analysis (Current)          Full Type Resolution (Not Done)
─────────────────────────              ─────────────────────────────
✓ Syntactic patterns                ✗ LSP integration
✓ Import resolution                  ✗ Type inference
✓ Call tracking                     ✗ Method resolution
✗ Method resolution (needs LSP)    ✗ Interface resolution
✗ Dynamic dispatch (needs LSP)     ✗ Complex type flows
```

TLDR intentionally avoids LSP integration to maintain speed and token efficiency.

---

## Crate Organization

```
tldr-code/
├── crates/
│   ├── tldr-core/        # Analysis engine
│   ├── tldr-cli/         # CLI application
│   ├── tldr-daemon/      # Background daemon
│   └── tldr-mcp/         # MCP server integration
├── vendor/
│   └── tree-sitter-yaml/ # Vendored, int32-row-patched YAML grammar
│                         # (workspace path-dep member; see its README.md)
├── docs/                 # Documentation
└── target/               # Build output
```

### tldr-core (`crates/tldr-core/`)

The core analysis engine. See individual modules below.

### tldr-cli (`crates/tldr-cli/`)

CLI interface built with `clap`. `src/main.rs` defines the subcommands; each is
implemented as a module in `src/commands/` (`mod.rs` is the wiring of record —
module list + `Args` re-exports). The real layout, grouped by analysis area:

```
commands/
├── mod.rs                    # module list + Args re-exports
├── AST:                      # tree, structure, extract, imports, importers,
│                             # body, context, order, logs
├── call graph / impact:      # calls, impact, dead, hubs, whatbreaks,
│                             # references, change-impact, dice
├── data flow / slicing:      # reaching-defs, available, slice
├── quality / metrics:        # churn, complexity, smells, debt, health,
│                             # hotspots, clones, cognitive, halstead,
│                             # coverage, loc, diagnostics, doctor
├── search:                   # search (BM25); embed/semantic/similar behind
│                             # the `semantic` feature
├── structure patterns:       # deps, inheritance, detect-patterns
├── contracts/                # contracts, specs, invariants, verify,
│                             # dead-stores, chop
├── patterns/                 # cohesion, coupling, interface, resources,
│                             # temporal
├── bugbot/                   # bugbot check runner
├── remaining/                # todo, explain, secure, definition, diff,
│                             # api-check (+ vuln, graph utils)
├── daemon/ + daemon_router.rs  # daemon IPC client (start/stop/status/list/
│                             # log/query/notify), cache clear/stats, warm/
│                             # stats, and the auto-routing through the cache
├── misc:                     # taint, fix, api-surface
└── archived/                 # retired deep-analysis commands kept for
                              # reference (cfg, dfg, ssa, dominators, bounds, …)
```

### tldr-daemon (`crates/tldr-daemon/`)

Background caching daemon using `axum` HTTP server:

- Unix socket on macOS/Linux
- TCP socket on Windows
- LRU cache for analysis results

### tldr-mcp (`crates/tldr-mcp/`)

MCP server exposing tools via JSON-RPC 2.0 over stdio:

```
tools/
├── ast.rs         # AST analysis tools
├── callgraph.rs   # Call graph tools
├── flow.rs        # Data flow tools
├── search.rs      # Search tools
├── quality.rs     # Quality tools
└── security.rs    # Security tools
```

---

## Analysis Layers

### Layer 1: AST (Abstract Syntax Tree)

**Purpose:** Parse source code, extract high-level structure

**Key files:**
- `tldr-core/src/ast/parser.rs` — Tree-sitter parser pool
- `tldr-core/src/ast/extract.rs` — Full module extraction
- `tldr-core/src/ast/imports.rs` — Import parsing

**Output types:**
```rust
pub struct ModuleInfo {
    pub file_path: PathBuf,
    pub language: Language,
    pub docstring: Option<String>,
    pub imports: Vec<ImportInfo>,
    pub functions: Vec<FunctionInfo>,
    pub classes: Vec<ClassInfo>,
    pub constants: Vec<FieldInfo>,
    pub call_graph: IntraFileCallGraph,
}
```

**CLI commands:** `tree`, `structure`, `extract`, `imports`

---

### Layer 2: Call Graph

**Purpose:** Build cross-file call relationships

**Key files:**
- `tldr-core/src/callgraph/builder.rs` — Main builder
- `tldr-core/src/callgraph/resolver.rs` — Module resolution
- `tldr-core/src/callgraph/languages/*.rs` — Per-language handlers

**Key types:**
```rust
pub struct ProjectCallGraph {
    pub edges: HashSet<CallEdge>,
    pub functions: HashMap<FunctionRef, FunctionMetadata>,
}

pub struct CallEdge {
    pub src_file: PathBuf,
    pub src_func: String,
    pub dst_file: PathBuf,
    pub dst_func: String,
    pub call_type: CallType,
    pub confidence: Confidence,
}
```

**CLI commands:** `calls`, `impact`, `dead`, `hubs`, `whatbreaks`, `refs`

---

### Layer 3: CFG (Control Flow Graph)

**Purpose:** Extract control flow within functions

**Key files:**
- `tldr-core/src/cfg/extractor.rs`

**Output types:**
```rust
pub struct CfgContext {
    pub entry: BlockId,
    pub blocks: HashMap<BlockId, CfgBlock>,
}

pub enum BlockType {
    Entry, Branch, LoopHeader, LoopBody, Return, Exit, Body,
}
```

---

### Layer 4: DFG (Data Flow Graph)

**Purpose:** Track variable definitions and uses

**Key files:**
- `tldr-core/src/dfg/extractor.rs`
- `tldr-core/src/dfg/reaching.rs`

**Output types:**
```rust
pub struct DfgContext {
    pub entry: BlockId,
    pub blocks: HashMap<BlockId, DfgBlock>,
}

pub enum RefType {
    Definition,  // x = value
    Update,      // x += value
    Use,         // f(x)
}
```

**CLI commands:** `reaching-defs`, `available`

---

### Layer 5: PDG (Program Dependence Graph)

**Purpose:** Combine control and data flow for slicing

**Key files:**
- `tldr-core/src/pdg/extractor.rs`
- `tldr-core/src/pdg/slice.rs`

**CLI commands:** `slice`, `chop`

---

### Element & Document-Reference Layers (formats and documents)

Formats have no functions/classes, so beyond the 5-layer code stack they flow
through their own layers:

- **Element extraction** — `tldr-core/src/ast/elements.rs` emits element-level
  definitions (JSON keys, TOML sections, YAML documents, XML/SVG/HTML elements,
  CSS selectors, LaTeX sections/environments, Markdown headings/code-blocks/tables)
  through the normal `DefinitionInfo` channel. The native no-grammar scanners are
  its counterparts: `tldr-core/src/ast/csvscan.rs` (CSV/TSV records + header
  cells), `tldr-core/src/ast/sqlscan.rs` (`.sql`/`.ddl` schema outline — DDL
  statements as elements, `REFERENCES` targets as reference edges),
  `tldr-core/src/ast/logs.rs` (log entries), and `tldr-core/src/ast/dotfiles.rs`
  (`.env`-family `KEY=value` lines and `.gitignore`-family glob patterns).
- **Document reference graph** — `tldr-core/src/ast/doclinks.rs` scans link/path/
  URL/import references out of markdown, HTML, XML, CSS, LaTeX, JSON, YAML, TOML,
  Bash, and text; `tldr-core/src/analysis/doc_impact.rs` resolves them to project
  files and computes transitive blast radius for `tldr imports` / `importers` /
  `impact`.
- **Plain text & containers** — `tldr-core/src/ast/toc.rs` surfaces plain-text
  headings/TOC; `tldr-core/src/ast/ooxml.rs` unzips `.docx`/`.xlsx`/`.pptx` and
  walks the main XML part; `tldr-core/src/fs/sniff.rs` makes extensionless text
  files first-class targets (binary sniff + shebang→XML→text ladder).
- **Virtual documents** — embedded code is a document, not decoration
  (virtual-documents-v1, `ast/elements.rs`): an inline `<script>` body re-parses
  with the JavaScript grammar, a `<style>` body with the CSS grammar, and SVG
  `foreignObject` content with the HTML grammar — each emitting the same rows a
  standalone file would. Rows and outbound references ride the host file's
  arrays with additive provenance fields: `DefinitionInfo::container` /
  `ImportInfo::via` name the virtual document (`page.html#script-1`,
  `page.html#style-2`), and nested documents compose hierarchically
  (`page.html#fo-1#script-1`). Recursion is bounded three ways — every re-parse
  operates on a strictly smaller same-file byte slice (no cross-file parsing:
  external `src`/`href` stay references), `MAX_EMBED_DEPTH` (8) caps nesting,
  and `MAX_VIRTUAL_DOCS_PER_FILE` (256) caps documents per file — so circular
  html→svg→foreignObject markup cannot hang or blow up the walk. Full-fidelity
  YAML element extraction rides the vendored `vendor/tree-sitter-yaml` workspace
  member (int32-row-patched grammar — upstream aborts into one root `ERROR` past
  row 32768), with no chunking or outline workaround.

---

## Data Flow Diagram

```
Source Code
    │
    ▼
┌─────────────────────────────────┐
│  Layer 1: AST                   │ → ModuleInfo
│  (ast/extract.rs)              │
└────────────┬────────────────────┘
             │
             ▼
┌─────────────────────────────────┐
│  Layer 2: Call Graph           │ → ProjectCallGraph
│  (callgraph/builder.rs)        │
└────────────┬────────────────────┘
             │
             ▼
┌─────────────────────────────────┐
│  Layer 3: CFG                   │ → CfgContext
│  (cfg/extractor.rs)             │
└────────────┬────────────────────┘
             │
             ▼
┌─────────────────────────────────┐
│  Layer 4: DFG                   │ → DfgContext
│  (dfg/extractor.rs)             │
└────────────┬────────────────────┘
             │
             ▼
┌─────────────────────────────────┐
│  Layer 5: PDG                   │ → PdgContext
│  (pdg/extractor.rs)             │
└────────────┬────────────────────┘
             │
             ▼
┌─────────────────────────────────┐
│  Program Slicing                │ → SliceResult
│  (pdg/slice.rs)                 │
└─────────────────────────────────┘
```

---

## Supported Languages

| Tier | Languages | Notes |
|------|-----------|-------|
| 1 | Python, Go, C, C++ | Most complete implementations |
| 2 | TypeScript, JavaScript, Rust, Ruby, Java | Full support (TS/JS ride the two TypeScript-grammar dialects) |
| 3 | C#, Kotlin, Swift | Full support |
| 4 | Scala, PHP, Lua, Luau, Elixir, OCaml | Full support |
| formats | JSON, YAML, TOML, XML/SVG, HTML, CSS, Bash | Parsed via tree-sitter; element-level extraction (keys, sections, documents, elements, selectors) instead of functions/classes; excluded from project-language detection |
| formats (documents) | LaTeX, Markdown | Parsed via tree-sitter; element extraction (LaTeX sections/environments, Markdown headings/code-blocks/tables) |
| formats (data) | CSV, TSV | No usable tree-sitter grammar — native streaming RFC 4180 scanner (`ast/csvscan.rs`); records and header cells as elements |
| native (no grammar) | Log, Text | No tree-sitter grammar exists — native scanners only (`ast/logs.rs` entry scanner, `ast/toc.rs` plain-text heading scanner) |
| native (path predicate) | .sql / .ddl | No `Language` variant and no usable grammar on crates.io (`tree-sitter-sql` 0.0.2 is source-only and dead; full vendoring evaluated and deferred — see the root `Cargo.toml`) — files resolve to `Language::Text` and the native schema-outline scanner (`ast/sqlscan.rs`) runs behind the `is_sql_path` path predicate; DDL statements become elements, `REFERENCES` targets become reference edges |
| containers | .docx / .xlsx / .pptx | OOXML containers, NOT languages — no `Language` variant; the main XML part is unzipped and walked by the XML element walker (`ast/ooxml.rs`) |

18 code languages + 11 formats + 2 native no-grammar languages = 31 `Language`
variants; `.sql`/`.ddl` and the OOXML containers carry no variant at all (they
are reached by path predicates, not by language dispatch).

---

## Performance Targets

From `crates/tldr-cli/src/main.rs`:

- **Cold start**: <100ms (via lazy grammar loading)
- **Parse time**: <5ms per file
- **Call graph**: <5s for 10K LOC

---

## Output Formats

All commands support multiple formats via `--format`:

| Format | Use case |
|--------|----------|
| `json` | Structured output, machine consumption |
| `text` | Human-readable, colored output |
| `compact` | Minified JSON for piping |
| `sarif` | GitHub/VS Code integration |
| `dot` | Graphviz visualization |

---

## Caching Architecture

```
┌─────────────────┐     ┌─────────────────┐
│   tldr-cli      │────▶│   tldr-daemon   │
│                 │ IPC │   (background) │
└─────────────────┘     └────────┬────────┘
                                 │
                                 ▼
                        ┌─────────────────┐
                        │  LRU Cache      │
                        │  (memory)      │
                        └─────────────────┘
```

Cache key: `hash(tool_name + arguments + file_mtimes)`
Invalidation: Via `daemon notify` command
