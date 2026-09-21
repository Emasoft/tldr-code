# tldr

Token-efficient code analysis for LLMs. 66 commands (63 in a default build, 3 behind the `semantic` feature) across AST, call graph, data flow, security, and quality — output optimized for machine consumption.

> **Install this fork** (precompiled, no Rust toolchain needed):
> ```sh
> curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Emasoft/tldr-code/releases/download/v0.4.1-fork.1/tldr-cli-installer.sh | sh
> ```
> Windows (PowerShell): the same URL with `tldr-cli-installer.ps1`. Build from source instead: `cargo install --path crates/tldr-cli`. Verify: `tldr --version` → `0.4.1-fork.1`.

## Why

LLMs waste context on raw source dumps. tldr extracts the signal: function signatures, call graphs, taint flows, complexity metrics, dead code — as structured JSON that fits in a fraction of the tokens.

**31 languages**: Python, TypeScript, JavaScript, Go, Rust, Java, C, C++, Ruby, Kotlin, Swift, C#, Scala, PHP, Lua, Luau, Elixir, OCaml — plus JSON, YAML, TOML, XML, HTML, CSS, Bash, LaTeX, Markdown, CSV, TSV as formats, and Log and Text as native no-grammar languages.

Formats and documents are first-class targets too:

- **Element extraction** — headings, code blocks, tables, XML/HTML elements, CSS selectors, LaTeX sections/environments, CSV records, and log entries, each with byte spans
- **Document reference graph** — `tldr imports` / `importers` / `impact` resolve links and transitive blast radius across markdown, HTML, XML, CSS, LaTeX, JSON, YAML, TOML, Bash, and text
- **`tldr logs`** — filter log entries by `--from`/`--to` timestamp window, `--level`, and `--grep`
- **OOXML containers** — `docx`, `xlsx`, `pptx` structure from their main XML part (a container, not a language)
- **Extensionless text targets** — `Makefile`, `LICENSE`, `.bashrc` join structure, imports, and the reference graph via content sniffing
- **Depth navigation** — `tldr structure --max-depth N` narrows the markup node tree to the first N nesting levels; text mode renders it tree-indented
- **Virtual documents** — inline `<script>`/`<style>` bodies and SVG `<foreignObject>` HTML are indexed as `#script-N`/`#style-N`/`#fo-N` containers whose outbound references join the host's blast radius
- **SQL schema scanner** — `.sql`/`.ddl` DDL structure (tables, views, functions, triggers) plus `REFERENCES` foreign-key edges in the reference graph
- **`.env` and ignore files** — `.env*`, `*.env`, `.gitignore` and friends report their own structure
- **`tldr daemon log`** — the daemon writes a persistent JSONL request log (`.tldr/cache/daemon.log`), readable with `--tail`/`--event`/`--command` filters

## Installation

### Standard install (recommended)

```bash
cargo install tldr-cli                    # crates.io release
cargo install --path crates/tldr-cli      # this checkout, from the repo root
```

This gives you 63 analysis commands — everything except natural-language semantic search.

### With semantic search

```bash
cargo install tldr-cli --features semantic
cargo install --path crates/tldr-cli --features semantic   # this checkout
```

Adds three commands:

- `tldr semantic '<query>' <path>` — natural-language code search
- `tldr embed <path>` — build embedding index
- `tldr similar <file>` — find similar fragments

This pulls in `fastembed` + ONNX Runtime. On first run it downloads the arctic-embed-m model (~110MB, cached). Builds reliably on Mac. Other platforms are unverified — if it doesn't compile for you, a PR with the fix is very welcome.

### The agent skill

This repo ships an agent skill under [`skills/tldr-code/`](skills/tldr-code/) — a command
catalog, argument shapes that surprise people, the performance envelope, and the recipes worth
reaching for. Install it from **this checkout** with the open skills CLI:

```bash
make install-skill                          # npx skills add -g --all ./skills/tldr-code
```

The local-path source is the point: it installs the skill matching the binary you just built, so
an agent never reads docs for a `tldr` you do not have. `skills add` writes to every supported
agent it finds (Claude Code, Codex, Cursor, OpenCode, and [73 more](https://github.com/vercel-labs/skills))
and is idempotent. `-g` puts it at user level, next to the binary — the default is project-level,
which would install it into this repo and nowhere you actually work.

`tldr doctor` tells you whether it took.

### With fastedit — the WRITE companion

`tldr` reads code. [`fastedit`](https://github.com/parcadei/fastedit) edits it, by symbol name,
so an agent never repeats old lines just to say where an edit goes. They pair naturally: `tldr
structure` locates the symbol, `fastedit --replace <symbol>` changes it.

```bash
make install-full     # tldr + fastedit + the skill
make install-fastedit # just the companion
```

Optional, and deliberately not a manifest dependency: `fastedit` is a Python package
(`uv tool install 'fastedits[mlx,mcp]'`), and `cargo install` has no post-install hook — a
`build.rs` that reached the network would fire during CI and docs.rs builds. The Make target
detects the platform, skips if `fastedit` is already present, and **does not** pull the ~3 GB
merge model; it prints that command for you to run.

Note the direction: fastedit lists `tldr` as *its* prerequisite, not the reverse. Nothing in
`tldr` requires fastedit.

## Quick start

```bash
# What's in this codebase?
tldr structure src/

# Who calls this function?
tldr impact parse_config src/

# Find dead code
tldr dead src/

# Security scan
tldr secure src/

# Full health dashboard
tldr health src/
```

## Commands

### AST Analysis (L1)
| Command | Description |
|---------|-------------|
| `tree` | File tree structure |
| `structure` | Code structure — functions, classes, imports |
| `extract` | Complete module info |
| `imports` | Parse import statements |
| `importers` | Find files importing a module |
| `logs` | Filter log entries by `--from`/`--to`, `--level`, `--grep` |

### Call Graph (L2)
| Command | Description |
|---------|-------------|
| `calls` | Cross-file call graph |
| `impact` | Reverse call graph — who calls this? |
| `dead` | Dead code detection |
| `hubs` | Hub functions (centrality analysis) |
| `whatbreaks` | What breaks if target changes? |
| `references` | All references to a symbol |
| `deps` | Module dependency analysis (import-level) |

### Data Flow (L3-L4)
| Command | Description |
|---------|-------------|
| `reaching-defs` | Reaching definitions |
| `available` | Available expressions (CSE detection) |
| `dead-stores` | Dead store detection (SSA-based) |

### Program Dependence (L5)
| Command | Description |
|---------|-------------|
| `slice` | Backward program slice |
| `chop` | Chop slice (forward + backward intersection) |
| `body` | Byte-faithful source of a function body or line range |
| `taint` | Taint flow analysis |

### Security
| Command | Description |
|---------|-------------|
| `secure` | Security dashboard |
| `taint` | Taint flows (injection, XSS) |
| `vuln` | Vulnerability scanning |
| `api-check` | API misuse patterns |
| `resources` | Resource leak detection |

### Quality & Metrics
| Command | Description |
|---------|-------------|
| `smells` | Code smells |
| `complexity` | Cyclomatic complexity |
| `cognitive` | Cognitive complexity |
| `halstead` | Halstead metrics |
| `loc` | Lines of code |
| `churn` | Git churn analysis |
| `debt` | Technical debt (SQALE) |
| `health` | Health dashboard |
| `hotspots` | Churn x complexity |
| `clones` | Code clone detection |
| `cohesion` | LCOM4 cohesion |
| `coupling` | Afferent/efferent coupling |
| `coverage` | Parse coverage reports (Cobertura XML, LCOV, coverage.py JSON) |

### Patterns & Architecture
| Command | Description |
|---------|-------------|
| `patterns` | Design pattern detection |
| `inheritance` | Class hierarchies |
| `surface` | API surface extraction |

### Contracts & Verification
| Command | Description |
|---------|-------------|
| `contracts` | Pre/postcondition inference |
| `specs` | Extract test specs |
| `invariants` | Infer invariants from tests |
| `verify` | Verification dashboard |
| `interface` | Interface contracts |
| `order` | Use-before-define / TDZ hazards (JS/TS/Python) |
| `temporal` | Mine temporal constraints (call sequences) |

### Diagnostics & tooling
| Command | Description |
|---------|-------------|
| `diagnostics` | Type checking + linting |
| `doctor` | Check / install diagnostic tools |

### Search & Context
| Command | Description |
|---------|-------------|
| `search` | BM25 search with structural context |
| `semantic` | Natural language code search * |
| `similar` | Find similar code fragments * |
| `embed` | Generate embeddings for code chunks * |
| `dice` | Similarity between two code fragments |
| `context` | LLM-ready context from entry point |
| `definition` | Go-to-definition |
| `explain` | Comprehensive function analysis |

\* Requires the `semantic` feature: `cargo install tldr-cli --features semantic` (or `--path crates/tldr-cli` from a checkout)

### Aggregated
| Command | Description |
|---------|-------------|
| `todo` | Improvement suggestions |
| `diff` | AST-aware structural diff |
| `fix` | Diagnose and auto-fix errors |
| `bugbot` | Automated bug detection on changes |
| `change-impact` | Find tests affected by code changes |

## Output formats

```bash
--format json      # Default — structured, machine-readable
--format text      # Human-readable
--format compact   # Minified JSON for piping
--format sarif     # GitHub/VS Code integration
--format dot       # Graphviz visualization
```

## Daemon mode

For repeated queries, the daemon caches results in memory:

```bash
tldr daemon start
tldr warm src/          # Pre-warm cache
tldr calls src/         # Fast — cache hit
tldr daemon stop
```

| Command | Description |
|---------|-------------|
| `daemon start` / `stop` / `status` | Manage the in-memory daemon |
| `daemon log` | Read the daemon's persistent JSONL request log |
| `cache stats` / `cache clear` | Cache statistics and clearing |
| `warm` | Pre-warm the caches |
| `stats` | Usage statistics |

## Documentation

For detailed documentation, see the [docs/](docs/) folder:
- [Installation Guide](docs/INSTALL.md)
- [Setup Guide](docs/SETUP.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [MCP Integration](docs/MCP.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Command Reference](docs/commands/)

## License

AGPL-3.0
