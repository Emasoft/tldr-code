# AGENTS.md — working rules for AI agents in this repo

## Repo layout
- Cargo workspace:
  - `crates/tldr-core` — analysis engine (library)
  - `crates/tldr-cli` — binary `tldr` + wrappers `tldr-daemon`, `tldr-mcp`
  - `crates/tldr-daemon` — daemon crate
  - `crates/tldr-mcp` — MCP server crate

## Commands (blessed)
```bash
make build   # release build
make dev     # debug build
make lint    # clippy --workspace -- -D warnings
make fmt     # cargo fmt --check
make test    # lib-only tests — the DEFAULT and only sanctioned bulk verification
timeout 3600 cargo test -p tldr-core --test large_file_accuracy_v1 --release -- --ignored --test-threads=1   # 100MB byte-accuracy e2e (all languages)
```
- In the accuracy-suite command, `--test-threads=1` is load-bearing (multi-GB peak RAM per test).

## Test safety policy (MANDATORY)
- `make test` runs `cargo test -p tldr-core --lib` + `cargo test -p tldr-cli --lib` ONLY. Use it.
- For a single integration suite (explicit `--test <name>` works even for targets marked `test = false`):
  ```bash
  timeout 600 cargo test -p tldr-cli --test <name>
  timeout 600 cargo test -p tldr-core --test <name>
  ```
- NEVER run bare `cargo test`, `cargo test --workspace`, or any command that would run all integration tests. `tests/` holds ~200 binaries including benchmark suites (`bench_*`) and daemon lifecycle tests; a full run takes hours.
- Always wrap any cargo test invocation in `timeout` (900s for lib tests, 600s for a single suite).
- Daemon warning: some integration tests spawn a real `tldr-daemon` (30-minute idle timeout). If a test run is interrupted, clean up before re-running:
  ```bash
  tldr daemon stop --project <path>   # or kill lingering tldr-daemon processes
  ```
- Do not run two cargo commands concurrently; cargo holds a build lock and stacked invocations appear hung.
