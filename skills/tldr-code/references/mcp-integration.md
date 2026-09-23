# MCP Server Integration

TLDR includes a Model Context Protocol (MCP) server for integration with Claude Code and other MCP-compatible clients.

> Source of truth for everything on this page: `crates/tldr-mcp/src/` — the tool registry in
> `crates/tldr-mcp/src/tools/mod.rs` builds every tool definition and schema by hand.

## What is MCP?

The [Model Context Protocol](https://modelcontextprotocol.io/) is a standard interface for connecting AI assistants to external tools and data sources. TLDR's MCP server exposes code analysis capabilities to any MCP client.

## Architecture

```
┌─────────────────┐     JSON-RPC 2.0      ┌─────────────────┐
│   Claude Code   │ ◄──────────────────► │    tldr-mcp     │
│   (or other    │     stdio transport   │   (MCP server)  │
│   MCP client)   │                       │                 │
└─────────────────┘                       └────────┬────────┘
                                                    │
                                                    ▼
                                           ┌─────────────────┐
                                           │   tldr-core     │
                                           │  (analysis engine)│
                                           └─────────────────┘
```

The MCP server computes every result directly through `tldr-core`. It does not talk to `tldr-daemon`; the daemon's query cache is a separate mechanism used by the CLI (see [Caching](#caching)).

## Installation

### 1. Build the MCP Server

```bash
cargo build --release
```

The binary will be at: `target/release/tldr-mcp`

### 2. Configure Your MCP Client

#### Claude Code

Add to your Claude Code MCP configuration:

```json
{
  "mcpServers": {
    "tldr": {
      "command": "/path/to/tldr-mcp"
    }
  }
}
```

The server takes no command-line arguments and reads no environment variables. Every tool call carries its own `path` argument, so no project-root configuration exists at the server level.

#### Other MCP Clients

The server uses stdio transport and JSON-RPC 2.0 protocol, making it compatible with any MCP client.

## Available Tools

The registry exposes **30 tools**, registered in `crates/tldr-mcp/src/tools/mod.rs`
(methods `register_ast_tools`, `register_callgraph_tools`, `register_flow_tools`,
`register_search_tools`, `register_quality_tools`, `register_security_tools`,
`register_composite_tools`; the startup banner `TLDR MCP server ready (30 tools)`
prints the same count). Required arguments are listed first; `?` marks optional ones.

### AST / Navigation

| Tool | Description | Arguments |
|------|-------------|-----------|
| `tldr_tree` | File tree structure for a directory | `path`, `extensions?`, `exclude_hidden?` |
| `tldr_structure` | Code structure (functions, classes, imports) from files; codemap overview | `path`, `language`, `max_results?`, `max_depth?` |
| `tldr_extract` | Complete module info from a single file (functions, classes, docstrings, intra-file call graph) | `file`, `base_path?` |
| `tldr_imports` | Parse import statements from a source file | `file`, `language?` |

### Call Graph / Analysis

| Tool | Description | Arguments |
|------|-------------|-----------|
| `tldr_calls` | Cross-file call graph: which functions call which | `path`, `language` |
| `tldr_impact` | All callers of a function (reverse call-graph traversal) | `path`, `function`, `language`, `depth?`, `file?` |
| `tldr_dead` | Dead code: functions that are never called | `path`, `language`, `entry_points?` |
| `tldr_importers` | All files that import a given module | `path`, `module`, `language` |
| `tldr_arch` | Architecture layers (entry/service/utility) and circular dependencies | `path`, `language` |

### Data Flow

| Tool | Description | Arguments |
|------|-------------|-----------|
| `tldr_cfg` | Control flow graph for a function (basic blocks, control-flow edges) | `file`, `function`, `language?` |
| `tldr_complexity` | Cyclomatic and cognitive complexity for a function | `file`, `function`, `language?` |
| `tldr_dfg` | Data flow graph for a function (definitions, uses, def-use chains) | `file`, `function`, `language?` |
| `tldr_slice` | Program slice from a line: what affects it (backward) or what it affects (forward) | `file`, `function`, `line`, `direction?`, `variable?`, `language?` |
| `tldr_pdg` | Program dependence graph combining CFG and DFG | `file`, `function`, `language?` |

### Search

| Tool | Description | Arguments |
|------|-------------|-----------|
| `tldr_search` | Regex search over files | `pattern`, `path`, `extensions?`, `context_lines?`, `max_results?`, `max_files?` |
| `tldr_bm25` | BM25 keyword search ranked by relevance | `query`, `path`, `language?`, `top_k?` |
| `tldr_semantic` | Hybrid search combining BM25 and semantic embeddings via RRF* | `query`, `path`, `language?`, `top_k?` |

\* `tldr_semantic` is registered in every build. Embeddings live behind tldr-core's
`semantic` feature (`dep:fastembed`), which is not enabled by default; without it —
and in fact with the current MCP handler, which passes no embedding client
(`tools/search.rs`) — the tool degrades gracefully to BM25-only results and reports
`fallback_mode: "bm25_only"`.

### Quality

| Tool | Description | Arguments |
|------|-------------|-----------|
| `tldr_context` | Token-efficient LLM context from an entry point (~95% token savings vs reading full files) | `path`, `entry_point`, `language`, `depth?`, `include_docstrings?` |
| `tldr_change_impact` | Tests affected by changed files (selective test running) | `path`, `language`, `changed_files?` |
| `tldr_smells` | Code smell detection (God Class, Long Method, Long Parameter List, …) | `path`, `threshold?`, `smell_type?`, `suggest?` |
| `tldr_maintainability` | Maintainability Index (MI) score for files | `path`, `include_halstead?`, `language?` |
| `tldr_diagnostics` | Type checking and linting (pyright/ruff for Python) | `path`, `language?` |
| `tldr_diff` | Semantic diff between two versions of code | `old`, `new`, `language?` |
| `tldr_debt` | Technical debt estimate from complexity and smells | `path`, `language?` |

### Security

| Tool | Description | Arguments |
|------|-------------|-----------|
| `tldr_secrets` | Hardcoded secrets scan (API keys, passwords, private keys) | `path`, `entropy_threshold?`, `include_test?`, `severity_filter?` |
| `tldr_vuln` | Vulnerability detection via taint analysis (SQL injection, XSS, command injection, …) | `path`, `language?`, `vuln_type?` |
| `tldr_api_check` | Insecure API usage patterns | `path`, `language?` |

### Composite

| Tool | Description | Arguments |
|------|-------------|-----------|
| `tldr_health` | Health dashboard combining complexity, smells, maintainability | `path`, `language?` |
| `tldr_todo` | Action items from analysis (high complexity, dead code, security issues) | `path`, `language?` |
| `tldr_secure` | Security summary combining secrets scan and vulnerability detection | `path`, `language?` |

## Tool Definitions

Tool handlers and registrations live in [`crates/tldr-mcp/src/tools/`](https://github.com/parcadei/tldr-code/tree/main/crates/tldr-mcp/src/tools):

| File | Tools handled |
|------|---------------|
| `ast.rs` | `tldr_tree`, `tldr_structure`, `tldr_extract`, `tldr_imports` |
| `callgraph.rs` | `tldr_calls`, `tldr_impact`, `tldr_dead`, `tldr_importers`, `tldr_arch` |
| `flow.rs` | `tldr_cfg`, `tldr_complexity`, `tldr_dfg`, `tldr_slice`, `tldr_pdg` |
| `search.rs` | `tldr_search`, `tldr_bm25`, `tldr_semantic` |
| `quality.rs` | `tldr_context`, `tldr_change_impact`, `tldr_smells`, `tldr_maintainability`, `tldr_diagnostics`, `tldr_diff`, `tldr_debt` + composite `tldr_health`, `tldr_todo` |
| `security.rs` | `tldr_secrets`, `tldr_vuln`, `tldr_api_check` + composite `tldr_secure` |

## Usage Examples

### Claude Code

Once configured, use natural language:

```
What's the call graph for the auth module?
What functions call parse_config?
Find dead code in the utils directory.
Scan this project for vulnerabilities and hardcoded secrets.
```

### Direct JSON-RPC

The MCP server accepts standard JSON-RPC 2.0 requests:

```bash
# Initialize
echo '{"jsonrpc":"2.0","id":1,"method":"initialize"}' | tldr-mcp

# Post-handshake notification (namespaced form; notifications get no response)
echo '{"jsonrpc":"2.0","method":"notifications/initialized"}' | tldr-mcp

# List tools
echo '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | tldr-mcp

# Call a tool (arguments validated against the tool's inputSchema)
echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"tldr_structure","arguments":{"path":"src","language":"python"}}}' | tldr-mcp
```

## Configuration

The `tldr-mcp` binary itself has no configuration surface: it parses no CLI
arguments and reads no environment variables. All inputs — project root, file
paths, language — are arguments on each tool call.

Other `TLDR_*` variables do exist in the codebase, but the `tldr-mcp` binary
reads none of them: they belong to `tldr-daemon` and `tldr-cli` (daemon socket
and registry directories, the bugbot daemon client, the semantic embedding
cache, quiet mode) — `docs/commands/daemon.md` documents `TLDR_SOCKET_DIR`.
The daemon's log level, for instance, comes from:

| Variable | Consumed by | Where | Default |
|----------|-------------|-------|---------|
| `TLDR_LOG` | `tldr-daemon` | `crates/tldr-daemon/src/lib.rs` (tracing `EnvFilter`) and `crates/tldr-daemon/src/server.rs` (log level) | `info` |

There is no tool filtering: every build of the server exposes all 30 tools.

## Caching

The MCP server has a single in-process result cache (`crates/tldr-mcp/src/cache.rs`):

- **L1 in-process cache** — keyed `tool_name:sorted_args_json` (object keys are
  recursively sorted, so argument order never matters), TTL 15 s, bounded at 200
  entries with oldest-entry eviction.
- Only **successful** results are cached; errors are retryable and never cached.
- Six project-wide tools are excluded from caching entirely (large results,
  rarely repeated): `tldr_calls`, `tldr_dead`, `tldr_health`, `tldr_todo`,
  `tldr_secure`, `tldr_arch`.
- There is no disk cache and no file-mtime component in the MCP cache key. The
  15 s TTL is the freshness mechanism: a repeated identical call within the TTL
  window is served from memory, anything else recomputes.

Separately, the **daemon** (`tldr daemon start`) maintains its own query cache
for CLI commands, invalidated by file-change notifications (`tldr daemon notify`).
That cache is not consulted by the MCP server.

## Error Handling

Two distinct error surfaces:

1. **Tool-level failures** come back as a normal JSON-RPC *result* with
   `"isError": true` (missing arguments, paths that don't exist, analysis
   errors, panics caught at the tool boundary):

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [{ "type": "text", "text": "Missing required argument: function" }],
    "isError": true
  }
}
```

2. **Protocol-level errors** are JSON-RPC error responses (see `protocol.rs`):

| Code | Meaning |
|------|---------|
| `-32700` | Parse error (invalid JSON; response carries `id: null`) |
| `-32600` | Invalid request (wrong `jsonrpc` version) |
| `-32601` | Method not found |
| `-32602` | Invalid params (missing/malformed `tools/call` params) |
| `-32603` | Internal error (serialization failure, etc.) |

Notifications (frames without `id`) never receive a response, not even on error.

## Development

### Adding a New Tool

There is no `#[derive(Tool)]` macro — definitions are hand-built. To add a tool:

1. Write a handler in the matching category file (`crates/tldr-mcp/src/tools/ast.rs`,
   `callgraph.rs`, `flow.rs`, `search.rs`, `quality.rs`, or `security.rs`), using the
   argument helpers exported by `tools/mod.rs`:

```rust
pub fn handle_my_thing(args: Value) -> ToolsCallResult {
    let file = match get_required_string(&args, "file") {
        Ok(f) => f,
        Err(e) => return ToolsCallResult::error(e),
    };
    let depth = get_optional_int(&args, "depth");
    // Call tldr-core, serialize the result, return ToolsCallResult::text(...)
}
```

2. Register it in the matching `register_*_tools()` method in
   `crates/tldr-mcp/src/tools/mod.rs` with a hand-built `json!` input schema —
   required arguments must be listed in `"required"`:

```rust
self.register(
    ToolDefinition {
        name: "tldr_my_thing".to_string(),
        description: "One-line description shown to MCP clients.".to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "file": { "type": "string", "description": "Source file path" },
                "depth": { "type": "integer", "description": "Traversal depth" }
            },
            "required": ["file"]
        }),
    },
    ast::handle_my_thing,
);
```

3. Update the module doc comment at the top of `tools/mod.rs` (it states the tool
   count and categories).

4. Rebuild: `cargo build --release`

Tool dispatch is wrapped in `catch_unwind`, so a panicking handler becomes an
`isError` result instead of a crashed server.

### Testing MCP Server

```bash
# Run the crate's tests
timeout 600 cargo test -p tldr-mcp

# Manual test with echo
echo '{"jsonrpc":"2.0","id":0,"method":"initialize"}' | target/debug/tldr-mcp
```

## Troubleshooting

### Server won't start

1. Check binary exists and is executable:
```bash
ls -la target/release/tldr-mcp
./target/release/tldr-mcp
```
The startup banner on stderr (`TLDR MCP server ready (N tools)`) confirms the
server is up and shows the registered tool count.

2. Check logs:
```bash
TLDR_LOG=debug tldr daemon start --project <path> 2>&1   # daemon-side logging only
```
The MCP server itself emits only stderr diagnostics; it does not read `TLDR_LOG`.

### Tools not appearing

1. Verify JSON-RPC connection:
```bash
echo '{"jsonrpc":"2.0","id":0,"method":"initialize"}' | tldr-mcp
```

2. Check tool registry initialization logs

### Slow tool execution

Every MCP tool call recomputes through `tldr-core`; only an identical call within
the 15 s L1 TTL window is served from memory. The daemon's warmed cache speeds up
CLI commands, not MCP tool calls — for interactive MCP sessions there is no
persistent warm-up path.

## See Also

Link paths below are relative to the repository root (this document lives at
`docs/MCP.md` and is mirrored verbatim to
`skills/tldr-code/references/mcp-integration.md`):

- [TLDR Architecture](docs/ARCHITECTURE.md) — How the analysis engine works
- [Command Reference](docs/commands/) — Detailed command documentation
- [MCP Protocol Spec](https://modelcontextprotocol.io/spec) — Protocol specification
