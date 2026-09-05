# tldr

Token-efficient code analysis for LLMs. 40+ commands across AST, call graph, data flow, security, and quality — output optimized for machine consumption.

## Why

LLMs waste context on raw source dumps. tldr extracts the signal: function signatures, call graphs, taint flows, complexity metrics, dead code — as structured JSON that fits in a fraction of the tokens.

**18 languages**: Python, TypeScript, JavaScript, Go, Rust, Java, C, C++, Ruby, Kotlin, Swift, C#, Scala, PHP, Lua, Luau, Elixir, OCaml.

## Installation

### Standard install (recommended)

```bash
cargo install tldr-cli                    # crates.io release
cargo install --path crates/tldr-cli      # this checkout, from the repo root
```

This gives you 60+ analysis commands — everything except natural-language semantic search.

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

### Call Graph (L2)
| Command | Description |
|---------|-------------|
| `calls` | Cross-file call graph |
| `impact` | Reverse call graph — who calls this? |
| `dead` | Dead code detection |
| `hubs` | Hub functions (centrality analysis) |
| `whatbreaks` | What breaks if target changes? |

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

### Search & Context
| Command | Description |
|---------|-------------|
| `search` | BM25 search with structural context |
| `semantic` | Natural language code search * |
| `similar` | Find similar code fragments * |
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
