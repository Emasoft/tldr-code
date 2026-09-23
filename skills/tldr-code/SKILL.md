---
name: tldr-code
description: >
  Token-efficient code analysis (READ, via `tldr`) AND AST-scoped editing (WRITE,
  via `fastedit` — edit/insert/rename/move/delete/refactor a symbol without
  repeating old code) for 31 languages (Python, TypeScript, JavaScript, Go, Rust,
  Java, C, C++, Ruby, Kotlin, Swift, C#, Scala, PHP, Lua, Luau, Elixir, OCaml,
  JSON, YAML, TOML, XML, HTML, CSS, Bash, LaTeX, Markdown, CSV, TSV, Log, Text).
  Reach for it BEFORE reading whole files or editing unfamiliar code: it extracts
  ONLY the lines that define a symbol, that it calls, or that call it — plus call
  graphs, reverse-impact, program slices, taint/security flows, complexity
  metrics, dead code, design patterns, and BM25 + natural-language semantic
  search. Use when you need to understand, navigate, locate, or assess impact in
  a codebase — where is X defined, who calls X, what breaks if I change X, what
  affects line N, is this input tainted, what's the structure of this module,
  find dead code, find the function that does Y.
---

# tldr — surgical, token-efficient code analysis

`tldr` (upstream: parcadei/tldr-code; this fork, which the behaviour documented
here matches: Emasoft/tldr-code; Rust, AGPL-3.0) parses code with tree-sitter
into a knowledge graph and answers **structural** questions as compact JSON/text.
It is the single best tool for **exploring a codebase and extracting the exact
slice of code that matters** — instead of reading entire files into context.

**The core idea — intentional & surgical.** Do NOT dump a whole file to "see how
it works." Ask `tldr` the precise question and it returns ONLY the relevant
lines: the symbol's definition, the lines it depends on, the lines that depend on
it, the callers, the slice. You decide the query; `tldr` returns the signal.

> `tldr` is invoked **deliberately by you**. It is NOT a passive interceptor.
> The generic output-compression layer is **distill** (`cmd | distill "<prompt>"`),
> which wraps command OUTPUT indiscriminately. `tldr` is the opposite: a precise
> instrument you reach for on purpose. The two coexist — `distill` makes a call's
> output cheaper; `tldr` makes you ask a better question in the first place.

## When to reach for tldr (instead of Read/Grep)

Trigger questions this skill answers: "where is X defined / who calls X / what
breaks if I change X / show me only the code that affects line N / is this input
tainted / what's the structure of this module / find dead code / find the
function that does Y" — the table below maps each to the command that answers it:

| You want to… | Don't | Do |
|---|---|---|
| Understand a module | Read the whole file | `tldr structure <path>` |
| Navigate a huge XML/HTML/SVG document without drowning | Read the whole file | `tldr structure <file> --max-depth 2` — depth-narrowed, tree-indented node tree; inline `<script>`/`<style>` bodies and SVG foreignObject HTML are navigable virtual documents (`page.html#script-1`, `page.html#fo-1#style-1`) |
| Find where X is defined | Grep + read | `tldr definition --symbol X --file <f>` (`--symbol` needs `--file`) |
| See every caller of X | Grep the name | `tldr references X <path>` / `tldr impact X <path>` |
| Know what breaks if you change X | Guess | `tldr whatbreaks X <path>` |
| Get only the code that affects line N | Read the file | `tldr slice <file> <fn> <N>` — default output is NOT contiguous source (banner-warned); add `--contiguous` for a gapless view, or `tldr body` for byte-faithful source |
| Understand one function fully | Read around it | `tldr structure <file>` + `tldr impact <fn> <path>` (fast) — or `tldr explain <file> <fn> --scope <dir>` (unscoped, it builds the FULL project call graph — see Performance) |
| Trace how data reaches a sink | Read everything | `tldr taint <file> <fn>` / `tldr vuln <path>` |
| Find the function that does Y | Grep keywords | `tldr semantic 'Y' <path>` |
| Assess a codebase's health | Skim files | `tldr health <path>` |
| Find dead code before deleting | Manual audit | `tldr dead <path>` |

**Default to `tldr` first when navigating or assessing code you don't already
have open.** Read the actual file only once `tldr` has pinned the exact lines.

## Killer intentional recipes

```bash
# BEFORE EDITING a symbol — get its definition, its callers, and blast radius:
tldr definition --symbol parse_config --file src/config.py --project .   # by NAME: --symbol REQUIRES --file
                                          # (positional form is `tldr definition <FILE> <LINE> <COLUMN>`)
tldr impact parse_config src/             # who calls it (reverse call graph; also non-call
                                          # reference sites, e.g. "reference (not a call) at line N")
tldr whatbreaks parse_config src/         # what breaks if its behavior changes
tldr explain src/config.py parse_config --scope src/   # signature + purity + complexity + callers/callees
                                          # (FILE then FUNCTION). ALWAYS pass --scope on anything but a
                                          # tiny repo — unscoped, explain builds the FULL project call
                                          # graph (see Performance). --no-callers skips caller discovery
                                          # entirely (sub-second); --depth N bounds the walk (default 2).

# EXTRACT ONLY the lines that affect a specific line (backward program slice):
tldr slice src/auth.py authenticate 142        # statements that influence L142 — ⚠ NOT contiguous
                                               # source (banner-warned): non-criterion lines are DROPPED.
                                               # Add --contiguous for a gapless view, or tldr body for
                                               # byte-faithful source you may reconstruct from.
tldr chop src/auth.py authenticate 142 150     # forward(from L142) ∩ backward(to L150) — needs TWO lines;
                                               # not a line-range extractor (output may fall outside the window)

# READ the exact source (byte-faithful — safe to reconstruct from):
tldr body src/auth.py authenticate             # the function's exact body lines
tldr body src/auth.py --from 142 --to 150      # or any contiguous line range

# UNDERSTAND a subsystem without reading it:
tldr structure src/payments/              # functions, classes, imports per file
tldr structure page.html --max-depth 2    # markup node TREE, narrowed to the top nesting levels
                                          # (text mode is tree-indented); inline <script>/<style>
                                          # bodies and SVG foreignObject HTML are navigable too:
                                          # page.html#script-1, page.html#fo-1#style-1
tldr context handle_request src/          # LLM-ready context graph from an entry point
tldr calls src/                           # cross-file call graph

# FIND code without an exact name — `tldr search` works in every build:
tldr search 'retry.*backoff' src/         # BM25 + structure + call-graph context cards
# (`tldr semantic` — natural-language search — requires the `semantic` build
#  feature, which the default build does NOT include; see the * footnote in the
#  command catalog before trying it)

# SECURITY / CORRECTNESS sweeps:
tldr taint src/auth.py authenticate       # injection/XSS taint flows (FILE + FUNCTION, not a dir)
tldr vuln src/                            # SQLi, XSS, command injection (path-wide)
tldr secure src/                          # security dashboard (taint+resources+bounds+contracts)
tldr resources src/                       # leaks, double-close, use-after-close
tldr api-check src/                       # missing timeouts, bare except, weak crypto, unclosed files

# QUALITY / REFACTOR triage:
tldr health src/                          # one-shot health dashboard
tldr smells src/ ; tldr hotspots src/ ; tldr cognitive src/     # path-wide
tldr dead src/ ; tldr clones src/ ; tldr todo src/              # cleanup targets
tldr complexity src/auth.py authenticate  # ⚠ per-FUNCTION, not per-path (unlike its siblings above)
```

## Argument shapes that surprise people

Most commands take `<PATH>`. These do NOT — getting them wrong yields a confusing
"required arguments were not provided", or silently misreads your symbol as a filename:

| Command | Real shape | Trap |
|---|---|---|
| `definition` | `--symbol X --file <f>` (or positional `<FILE> <LINE> <COLUMN>`) | `--symbol` **requires** `--file`; `tldr definition X src/` reads `X` as the FILE |
| `explain`, `taint`, `complexity`, `contracts`, `reaching-defs`, `available`, `dead-stores` | `<FILE> <FUNCTION>` | file FIRST, function second; not a directory |
| `slice` | `<FILE> <FUNCTION> <LINE>` | — |
| `chop` | `<FILE> <FUNCTION> <FROM> <TO>` | needs **two** line numbers |
| `resources` | `<FILE> [FUNCTION]` | function is OPTIONAL (all functions if omitted) |
| `specs` / `invariants` | `--from-tests <tests>` (+ `<FILE>` for invariants) | the test file is a FLAG, not a positional |

When unsure: `tldr <cmd> --help` — and note that `--help` does not surface the
`--symbol`⇒`--file` dependency, so prefer the forms above.

## Performance — scope `explain`; the daemon rarely pays

Nearly every command is fast; `explain` is the one exception, and its UNSCOPED
cost is governed by how big the surrounding project is, not by the function you
ask about. Times below are order-of-magnitude:

| Command | Typical time | Notes |
|---|---|---|
| `structure`, `references`, `slice`, `complexity`, `taint`, `semantic`, `search` | **< 3 s** | fast — reach for these freely |
| `impact` | **~3 s** | reverse call graph |
| **`explain` UNSCOPED** | **grows with the whole tree** | see the measured jump below |
| `explain --scope <dir>` / `--no-callers` | bounded / sub-second | the default posture on any real repo |

**Root cause (verified by controlled test, pre-scoping-flags):** unscoped
`explain` resolves the caller+callee call graph across the ENTIRE detected
project, so the *same function in the same file* took **0.1 s alone in a 1-file
dir vs 8.9 s inside a 395-file tree** — an ~90× jump from repo size, nothing
else changed. On a mid-size TypeScript repo a 3-line function took **~300 s**.

**Scoping flags (now built in — use them):** `--scope <dir>` bounds the
caller/callee graph traversal AND the reference search to that directory;
`--no-callers` skips caller discovery entirely (callers emitted empty, every
other field unchanged — sub-second); `--depth N` bounds the caller traversal
(default 2). `--project` / `--workspace` / `--no-workspace` remain rejected
(`rc=2`) for `explain` — the flag is `--scope`, not `--project`.

**So:** there is no reason to run `explain` unscoped on a large repo. Scoped,
it bundles signature + purity + complexity + callers + callees in one call;
unscoped on a big codebase it is still the trap the measurements above
describe. The equivalent facts are also available in seconds by composing the
individually-fast commands: `tldr structure <file>` (signature) →
`tldr impact <fn> <path>` (callers) → `tldr references <fn> <path>`.

**The daemon (`tldr daemon start` + `tldr warm`) gave NO measurable speedup** —
re-verified on this checkout (0.4.1-fork.1): `tldr structure` over the same
tree took ~10 s cold and 11–13 s with the daemon running and warmed, and the
daemon's request log showed the query never routed through it. Structural,
`search`, and `semantic` commands ran the same cold or warmed, and it did NOT
help `explain` either (the cost is the graph computation, not a cold cache). It
is an index-reuse optimization whose payoff depends on repo size and query
volume; **measure before assuming it helps** rather than starting it
reflexively. (It never *hurts* correctness — it just may not pay off.)

## Full command catalog (66 commands; `[aliases]` shown)

Per-command flags & detail: run `tldr <cmd> --help`, or read `references/`.
Flags below are the non-global ones; every command also accepts `-f/--format`,
`-l/--lang`, `-q/--quiet`, `-v/--verbose`, and several add `-o/--output <file>`
(write results to a file instead of stdout).

**AST / structure (L1)**
- `tree` `[t]` — file tree structure (`--ext` repeatable, `--include-hidden`)
- `structure` `[s]` — functions, classes, imports per file, **plus anonymous callbacks**
  (see *Anonymous callbacks* below) (`--max-results N` 0=unlimited; `--max-depth N`
  narrows the markup node tree only — code symbols are never filtered)
- `extract` `[e]` — complete module info for one file
- `imports` — parse import statements from a file (`--legacy-array` for the old bare-array JSON)
- `importers` — files that import a given module (`--limit`)
- `logs` — filter log entries from a log file by `--from`/`--to` timestamp window,
  `--level` (normalized severity), `--grep` (case-sensitive substring)

**Call graph (L2)**
- `calls` `[c]` — cross-file call graph (`--respect-ignore`, `--max-items N`)
- `impact` `[i]` — reverse call graph: who calls this function — including
  **non-call reference sites** (a "reference (not a call) at line N" caller row;
  impact-reference-sites-v1) (`--depth`, `--file`, `--type-aware`)
- `dead` `[d]` — dead / unreachable code (`--entry-points`, `--max-items`,
  `--call-graph`, `--no-default-ignore`)
- `hubs` — hub functions via centrality analysis (`--top`, `--algorithm`,
  `--threshold`)
- `whatbreaks` `[wb]` — what breaks if a target changes (`--type
  function\|file\|module`, `--depth`, `--quick`)
- `references` `[refs]` — all references to a symbol (`--include-definition`,
  `-t/--kinds call,read,write,import,type`, `-s/--scope local\|file\|workspace`,
  `-n/--limit`, `--min-confidence`; `-C/--context-lines` is advertised but not
  implemented yet)
- `deps` `[dep]` — module dependency analysis (import-level) (`--include-external`,
  `--collapse-packages`, `--depth`, `--show-cycles`, `--max-cycle-length`)

**Data flow (L3–L4)**
- `reaching-defs` `[rd]` — reaching definitions for a function (`--var`, `--line`,
  `--chains-only`, `--params`)
- `available` `[av]` — available expressions (CSE detection) (`--check`, `--at-line`,
  `--killed-by`, `--cse-only`)
- `dead-stores` `[ds]` — dead stores (SSA-based) (`--compare` vs live-variables)

**Program dependence / slicing (L5)**
- `slice` — backward (default) or forward (`-d/--direction`) program slice,
  optional `--variable` filter — only the lines that affect the target line.
  ⚠ **Default output is NOT contiguous source** — non-criterion lines are
  DROPPED — and every run banner-warns it. `--contiguous` emits the gapless
  view (elided lines become visible markers) — the safe basis for reading or
  reconstructing a region
- `chop` `[chp]` — chop slice (forward ∩ backward); needs two lines. NOT a
  line-range extractor: output is not bounded by FROM..TO (its `--help` says so)
- `body` — print the exact contiguous source of a function body or a
  `--from`/`--to` line range (byte-faithful, preserves CRLF/BOM/whitespace) —
  the safe read/reconstruct counterpart to slice/chop
- `taint` `[ta]` — taint flow analysis (also a security command)

**Security**
- `secure` `[sec]` — security dashboard (taint, resources, bounds, contracts,
  behavioral, mutability) (`--detail`, `--quick`, `--include-tests`,
  `--no-default-ignore`)
- `vuln` — vulnerability scan (SQL injection, XSS, command injection, SSRF,
  path traversal, …) (`--severity`, `--vuln-type`, `--include-informational`,
  `--include-smells`, `--include-tests`, `--no-default-ignore`; JS/TS
  test-file findings suppressed by default)
- `api-check` `[ac]` — API misuse (missing timeouts, bare except, weak crypto,
  unclosed files) (`--category`, `--severity`)
- `resources` `[res]` — resource lifecycle (leaks, double-close, use-after-close)
  (`--check-all`, per-check flags, `--summary`)

**Quality & metrics**
- `smells` — code smells (`--threshold strict\|default\|relaxed`, `--smell-type`,
  `--deep`, `--suggest`, `--files`, `--include-tests`, `--no-default-ignore`)
- `complexity` — cyclomatic complexity per function
- `cognitive` `[cog]` — cognitive complexity (SonarQube algorithm) (`--function`,
  `--threshold`, `--show-contributors`, `--top`)
- `halstead` `[hal]` — Halstead metrics per function (`--function`,
  `--show-operators`, `--show-operands`, `--top`)
- `loc` — lines of code (code/comments/blanks) (`--by-file`, `--by-dir`,
  `--exclude`, `--include-hidden`)
- `churn` — git-based code churn (`--days`, `--top`, `--exclude`, `--authors`)
- `debt` — technical debt (SQALE) (`--category`, `--top`, `--hourly-rate`)
- `health` `[h]` — comprehensive health dashboard (`--detail`, `--quick`,
  `--preset`, `--summary`)
- `hotspots` `[hot]` — churn × complexity hotspots (`--days`, `--top`,
  `--by-function`, `--since`, `--recency-halflife`)
- `clones` `[cl]` — code clone detection (`--threshold`, `--min-lines`,
  `--show-classes`, `--exclude-generated`, `--exclude-tests`, `-o json\|text\|sarif`)
- `cohesion` `[coh]` — class cohesion (LCOM4) (`--min-methods`, `--include-dunder`)
- `coupling` `[coup]` — afferent/efferent coupling + instability (call-edge based;
  use `deps`/`imports` for import-level) (`<PATH_A> [PATH_B]` pair mode or
  project-wide; `--top`, `--cycles-only`, `--include-tests`)
- `coverage` `[cov]` — parse coverage reports (Cobertura XML, LCOV, coverage.py
  JSON) (`-R/--report-format auto\|cobertura\|lcov\|coveragepy`, `--threshold`,
  `--uncovered`, `--by-file`, `--uncovered-only`)

**Patterns & architecture**
- `patterns` `[p]` — design pattern & convention detection (`--category`,
  `--min-confidence`, `--no-constraints`)
- `inheritance` `[inh]` — class inheritance hierarchies (`--class`, `--depth`,
  `--no-patterns`)
- `surface` `[surf]` — machine-readable API surface of a library/package
  (`--lookup`, `--include-private`, `--manifest-path`)

**Contracts & verification**
- `contracts` `[con]` — infer pre/postconditions from guards/assertions/isinstance
  (`--limit`)
- `specs` `[sp]` — extract behavioral specs from pytest test files
  (`--from-tests` required, `--function`, `--source`)
- `invariants` `[inv]` — infer invariants from test traces (Daikon-lite)
  (`--from-tests`, `--function`, `--min-obs`)
- `verify` `[ver]` — aggregated verification dashboard (`--detail`, `--quick`)
- `interface` `[iface]` — interface contracts (public API signatures)
- `order` — use-before-define / TDZ hazards from definition line ranges (JS/TS/Python)
- `temporal` `[tem]` — mine temporal constraints (method call sequences)
  (`--min-support`, `--min-confidence`, `--query`, `--include-trigrams`)

**Search & context**
- `search` — enriched BM25 search with function-level context cards
  (`-k/--top-k`, `--regex`, `--hybrid PAT`, `--no-callgraph`); flag-like queries
  such as `tldr search '--port' src/` are taken verbatim (no `--` escape needed)
- `semantic` `[sem]` * — natural-language code search
- `similar` `[sim]` * — find similar code fragments
- `dice` — similarity between two code fragments (targets: `file`, `file::function`,
  `file:start:end`; `--normalize`)
- `context` — LLM-ready context from an entry point (`--depth`, `--include-docstrings`,
  `--file` to disambiguate; positional PATH, `--project` deprecated)
- `definition` `[def]` — go-to-definition: where a symbol is defined (`--symbol`
  needs `--file`; `--project`, `--workspace=true\|false`)
- `explain` `[exp]` — full function analysis (signature, purity, complexity,
  callers, callees) (`--scope DIR`, `--no-callers`, `--depth N`; see Performance)

**Aggregated / change**
- `todo` — aggregate improvement suggestions (dead code, complexity, cohesion,
  similar) (`--detail`, `--quick`, `--max-items`)
- `diff` `[df]` — AST-aware structural diff between two files
  (`-g/--granularity token…architecture`, `--semantic-only`)
- `fix` `[fx]` — diagnose & auto-fix errors from compiler/runtime output
  (subcommands `diagnose` / `apply` / `check`; error text via `--error`,
  `--error-file`, or stdin)
- `bugbot` — automated bug detection on code changes (subcommand `check`)
- `change-impact` `[ci]` — find tests affected by code changes (`--files`,
  `--base`, `--staged`, `--uncommitted`, `--depth`, `--include-imports`,
  `--test-patterns`, `--runner pytest\|jest\|go-test\|…`)

**Diagnostics**
- `diagnostics` `[diag]` — type checking + linting (`--tools`, `--no-typecheck`,
  `--no-lint`, `--severity`, `--ignore`, `--strict`, `--baseline`,
  `--save-baseline`)
- `doctor` `[doc]` — check / install diagnostic tools (`tldr doctor --install python`)

**Daemon / cache / stats**
- `daemon` — daemon management (`start`, `stop`, `status`, `query`, `notify`;
  `log` reads the persistent JSONL request log, `list` shows running daemons)
- `cache` — cache management (`stats`, `clear` — clear stops the project's daemon)
- `warm` `[w]` — pre-warm the call-graph cache (see Performance — measure before relying on it; `--background`)
- `stats` — tldr usage statistics
- `embed` `[emb]` * — generate embeddings for code chunks

\* `semantic`, `similar`, `embed` require the `semantic` build feature — from the
repo root, `cargo install --path crates/tldr-cli --features semantic` (the crates.io
release may lag this checkout). The first semantic run downloads the arctic-embed-m
model (~110 MB, cached).

### Anonymous callbacks

`structure` also emits a definition with `kind: "call"` for a **multi-line anonymous
callable passed to a call** — the test block, the `spawn`/`forEach`/`HandleFunc`
closure, the `do` block. Without this, the bodies that hold most of a test suite's
and most async code's real logic are invisible to `structure`, so an agent reads the
whole file to find them.

Covered in all 17 of the 18 code languages that have such a form (C has none;
the formats and no-grammar languages have no callables):
arrow functions and function expressions, Python `lambda`, Ruby/Elixir `do` blocks,
Go `func` literals, Rust closures, Java/Scala/C++/C# lambdas, Kotlin/Swift trailing
lambdas, PHP anonymous + arrow functions, Lua/Luau function definitions, OCaml `fun`.

**The name is the call that receives it**, because an anonymous callable has none of
its own:

| Source | Emitted name |
|---|---|
| `suiteSetup(async function () { … })` | `suiteSetup` |
| `test('a title here', async () => { … })` | `test:a-title-here` |
| `it 'does a thing' do … end` | `it:does-a-thing` |
| `RSpec.describe "Widget" do … end` | `describe:widget` (the method, not the receiver) |
| `http.HandleFunc("/x", func(w, r) { … })` | `HandleFunc:x` |
| two `test(…)` blocks with the same title | `test:same`, `test:same#2` (first keeps the bare name) |

A first string-literal argument becomes a `:slug` (lowercased, hyphenated, capped at
40 chars) so sibling blocks are distinguishable — and stable when a sibling is
inserted above them, which a positional index would not be. Only genuine collisions
fall back to the `#N` suffix.

Why it matters for an agent: `tldr structure spec/api_spec.rb` now returns one line
per `it` block with its line range, so `tldr slice`, `fastedit edit --replace`, and a
plain ranged `Read` can all target a single test without touching the file around it.

## Global flags & output formats

```
--format json      # default — structured, machine-readable
--format text      # human-readable (best for quick reading)
--format compact   # minified JSON for piping
--format sarif      # GitHub / VS Code integration (only: vuln, clones)
--format dot       # Graphviz visualization (only: calls, impact, hubs, inheritance, clones, deps)
```

JSON is the default and is the most token-efficient for downstream parsing; use
`--format text` when you just want to read the answer. `sarif`/`dot` are
command-specific and rejected at runtime elsewhere.

## Daemon mode (measure first)

The daemon keeps state in memory so repeated queries *can* become cache hits:

```bash
tldr daemon start
tldr warm src/          # pre-warm the call-graph cache
tldr impact foo src/    # may be served from the daemon
tldr cache stats
tldr daemon stop
tldr daemon log --event error --tail 50   # what did the daemon actually do?
```

⚠ Measured on this checkout, warmed-daemon runs were NOT faster than cold runs
for the structural commands (see Performance) — start the daemon for many
repeated queries on the same tree only after measuring, not reflexively.

The daemon replaces the old file-cache model (`.claude/cache/tldr/*.json`); state
is in memory, queried automatically by the CLI when the daemon is running. Every
daemon session also writes a persistent JSONL request log at
`<project>/.tldr/cache/daemon.log` — `tldr daemon log` filters it by `--event`,
`--command` and `--tail`, which is where you look when a warmed query silently
fell back to local compute or a request failed after the fact.

## Editing code with fastedit (the WRITE companion)

`tldr` is READ-ONLY. To CHANGE code, use **`fastedit`** — an AST-aware editor (it
uses `tldr-code` internally, so tldr must be installed first). It finds the target
by SYMBOL NAME via tree-sitter, so you write ONLY the change (plus a line or two of
context) — never the old code repeated back. ~74% of edits resolve
deterministically (0 tokens, <1 ms); a local 1.7B model merges the rest (~40 tok).
Same discipline as tldr: invoke it INTENTIONALLY, by symbol.

Three edit modes (all through `edit`): `--after <symbol>` = verbatim text insert
below it (0 tok, instant) · `--replace <symbol>` deterministic = context anchors
splice new lines (0 tok) · `--replace <symbol>` model = the 1.7B SLM merges your
snippet into the ~35-line chunk around the symbol.

Full command surface (20 subcommands — there is no separate `insert`; insertion
is `edit --after`):

| Need | Command |
|---|---|
| File's symbols + line ranges (files ≤100 lines print in full) | `fastedit read <file>` |
| Replace a function/class body | `fastedit edit <file> --replace <symbol> --snippet '<body; #... keeps untouched lines>'` |
| Insert code after a symbol | `fastedit edit <file> --after <symbol> --snippet '<code>'` |
| Snippet from stdin | `fastedit edit <file> --replace <symbol> --snippet -` |
| Many edits to one file (ordered; each sees the previous result) | `fastedit batch-edit <file> --edits '[{"after":"x","snippet":"…"}]'` (`-` for stdin) |
| Edits across MANY files (all-or-nothing) | `fastedit multi-edit --file-edits '[{"file_path":"a.py","edits":[…]}]'` (`-` for stdin) |
| Find a symbol / its references | `fastedit search <query> [path]` (`--mode search\|regex\|hybrid\|references`, `--top-k N` default 10, `--regex-filter PAT` for hybrid) |
| Show the last edit as a unified diff (read-only) | `fastedit diff <file>` |
| Revert the last edit (repeat to step back) | `fastedit undo <file>` |
| Delete a symbol (caller-safe) | `fastedit delete <file> <symbol>` (`MyClass.method` works; refuses cross-file callers; `--force` skips that check — never parse validation) |
| Move a symbol within a file | `fastedit move <file> <symbol> --after <other>` |
| Rename in one file (AST-verified) | `fastedit rename <file> <old> <new>` (`--dry-run`; skips strings/comments) |
| Rename across a tree | `fastedit rename-all <dir> <old> <new>` (`--dry-run`, `--only class\|function\|method\|variable`) |
| Move a symbol to another file (+rewrite importers) | `fastedit move-to-file <symbol> <src> <dst>` (`--after <sym>`; `--dry-run`; dst must exist, same language) |
| New file | `fastedit create <file> --content '…'` (`--content-file PATH\|-`; stdin if neither; `--force`, `--parents`) |
| Byte-for-byte copy (binary-safe) | `fastedit duplicate <src> <dst>` (`--force`, `--parents`) |
| Split a file | `fastedit split <file> --out DIR` + exactly one of `--rows N` (csv/tsv, header repeated) · `--by heading --level N` (markdown) · `--by element` (json/xml/html) · `--lines N` |
| Join parts back (inverts `split`) | `fastedit join <parts-dir-or-parts…> -o FILE` (uses the manifest; XML/HTML element splits have no join) |
| Fetch the merge model (~3 GB, one-time) | `fastedit pull --model mlx-8bit` (Apple Silicon) / `--model bf16` (Linux/GPU) |
| Install the agent skill | `fastedit init` (`--skill-agent <agent>`, default claude-code) |
| Diagnose setup | `fastedit doctor` |
| Write the MCP entry | `fastedit mcp-install` (`--scope user\|project`, default user → `~/.claude.json`) |

Intentional read → check → edit loop:
```bash
fastedit read src/app.py                    # learn exact symbol names first
tldr impact handle_request src/             # blast radius before changing it
fastedit edit src/app.py --replace handle_request --snippet '
    validate(data)
    #...                                     # #... preserves the rest of the body
    logger.info("done")
'
fastedit diff src/app.py                     # confirm  ·  fastedit undo <file> to revert
```
`--replace` auto-preserves the signature; `#...` (C-family: `// ...`) means "keep
the untouched lines" — honored only where a snippet anchor line matches the
original body, and a marker with no matching anchor is refused, never guessed.
Prefer `fastedit rename`/`rename-all` over manual find-replace (AST-verified,
skips strings/comments). Languages: the offline tree-sitter pack — 173
e2e-proven (175 classified; 26 wired by extension by default); unsupported
extensions refuse symbol-targeted edits (plain-text files need anchor lines).
Backend: local MLX (Apple Silicon) / vLLM (GPU), or any OpenAI-compatible server:
`--backend {mlx,vllm}`, `--model-path DIR`, `--api-base URL`, `--api-model NAME`
(env `FASTEDIT_BACKEND` / `FASTEDIT_MODEL_PATH` / `FASTEDIT_VLLM_API_BASE` /
`FASTEDIT_VLLM_MODEL`). Every merged result is parse-checked against the original
and retried with the failure reason on rejection (`FASTEDIT_MAX_RETRIES`, default
8; on exhaustion the edit is refused and the file is unchanged); per-file writes
are flock-locked (a second fastedit exits 1 naming the holder; the lock
self-releases if it crashes). Backups (5 per file / 24 h under
`~/.fastedit/backups`) bound how far `undo` steps back. An optional MCP server
exists — `fastedit mcp-install` writes the Claude Code entry (12 `fast_*` tools;
`--scope user|project`) — but it is NOT enabled here: intentional-CLI use keeps
the per-turn token cost at zero, whereas an MCP/hook path that fires on every
tool call injects text into the transcript and re-bills the cached prefix.

## Coexistence with distill

- **distill** is a generic, non-discriminating output-compression pipe. `tldr` is
  a deliberate instrument — it does not duplicate or replace distill, and it is
  not a Read-interceptor.
- An MCP server (`tldr-mcp`) is available for tool-style access — see
  `references/mcp-integration.md`.

## Per-command reference

`references/` holds verbatim copies of this repo's docs (`command-overview.md` is
`README.md`) — read the one for the category you need:

- `references/command-overview.md` — the full README catalog
- `references/ast.md`, `callgraph.md`, `dataflow.md`, `metrics.md`,
  `patterns.md`, `quality.md`, `search.md`, `security.md`, `tools.md`,
  `daemon.md` — per-category command detail
- `references/mcp-integration.md` — using the `tldr-mcp` server

When the exact arguments of a command matter, prefer `tldr <cmd> --help` (ground
truth) over memory.
