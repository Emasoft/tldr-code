# Data Flow Commands (Layers 3-5)

Data flow commands track how values move through code.

## reaching-defs

**Alias:** `rd`

**Purpose:** Analyze reaching definitions for a function.

**Implementation:** `crates/tldr-cli/src/commands/reaching_defs.rs`

```rust
// Reaching definitions analysis
pub struct ReachingDefsArgs {
    pub file: PathBuf,
    pub function: String,
    pub var: Option<String>,
    pub line: Option<u32>,
    pub show_chains: bool,        // enabled by default
    pub show_uninitialized: bool, // enabled by default
    pub show_in_out: bool,
    pub chains_only: bool,
    pub params: Option<String>,
}
```

**How it works:**
1. Builds CFG for function
2. Computes IN/OUT sets per block using dataflow framework
3. Tracks where each variable definition reaches

Def-use chains (`--show-chains`) and uninitialized-use detection (`--show-uninitialized`) are both **enabled by default** — the flags re-affirm them, they don't opt you in.

**Example:**
```bash
tldr reaching-defs src/process.py process_data

# Filter by variable
tldr reaching-defs src/process.py process_data --var user_input

# Show at specific line
tldr reaching-defs src/process.py process_data --line 25

# Chains only — hide header, blocks, and statistics
tldr reaching-defs src/process.py process_data --chains-only

# Pass function parameters (comma-separated) for uninitialized-use detection
tldr reaching-defs src/process.py process_data --params user_input,limit
```

**Output:**
```json
{
  "function": "process_data",
  "blocks": [...],
  "def_use_chains": [
    {
      "variable": "result",
      "definition": {"line": 10, "block": 1},
      "uses": [{"line": 15}, {"line": 20}]
    }
  ]
}
```

---

## available

**Alias:** `av`

**Purpose:** Analyze available expressions for CSE (Common Subexpression Elimination).

**Implementation:** `crates/tldr-cli/src/commands/available.rs`

**How it works:**
1. Builds CFG for function
2. Computes available expressions per block
3. An expression is "available" if all paths to a point have computed it
4. Identifies CSE opportunities

**Example:**
```bash
tldr available src/process.py process_data

# Check specific expression
tldr available src/process.py process_data --check "a + b"

# At specific line
tldr available src/process.py process_data --at-line 50

# Show what kills an expression
tldr available src/process.py process_data --killed-by "x + y"

# Only CSE opportunities, skip per-block details
tldr available src/process.py process_data --cse-only
```

---

## dead-stores

**Alias:** `ds`

**Purpose:** Find dead stores using SSA-based analysis.

**Implementation:** `crates/tldr-cli/src/commands/contracts/dead_stores.rs`

**How it works:**
1. Converts function to SSA form
2. Identifies assignments that are never read
3. Returns lines where value is stored but never used

**Example:**
```bash
tldr dead-stores src/process.py process_data

# Compare with live-variables approach
tldr dead-stores src/process.py process_data --compare
```

---

## slice

**Purpose:** Compute program slice (backward or forward).

**Implementation:** `crates/tldr-cli/src/commands/slice.rs`

```rust
// Program slicing
pub struct SliceArgs {
    pub file: PathBuf,
    pub function: String,
    pub line: u32,
    pub direction: Direction,  // backward or forward
    pub variable: Option<String>,
    pub contiguous: bool,
}
```

**How it works:**
1. Builds PDG (Program Dependence Graph)
2. **Backward slice**: All statements affecting this line
3. **Forward slice**: All statements affected by this line
4. Optionally filter by variable

**Hazard — slice output is NOT contiguous source:** the default output contains only the slice's criterion lines and **drops every non-criterion line between them**. The binary banner-warns on every default-mode run (`dataflow slice — NOT contiguous source; do not reconstruct or edit from this output`), so never reconstruct or edit code from default slice output. To read or reconstruct a region safely:

- use `--contiguous` — it emits every line from the first to the last slice line, showing non-criterion lines as a visible `// ... elided` marker instead of dropping them; or
- use `tldr body` (below) for a byte-faithful, contiguous read of a function body or line range.

**Example:**
```bash
tldr slice src/process.py process_data 25

# Forward slice
tldr slice src/process.py process_data 25 -d forward

# Filter by variable
tldr slice src/process.py process_data 25 --variable result

# Gapless view: elided lines shown as markers instead of dropped
tldr slice src/process.py process_data 25 --contiguous
```

---

## chop

**Alias:** `deps-between` (legacy `chp` still works but is hidden from `--help`)

**Purpose:** Compute the dependency closure between two lines (forward slice of FROM ∩ backward slice of TO).

**Implementation:** `crates/tldr-cli/src/commands/contracts/chop.rs`

**How it works:**
1. Computes the **forward slice** of the source line (`source_line`) — all statements the source can affect
2. Computes the **backward slice** of the target line (`target_line`) — all statements that can affect the target
3. Returns the intersection: statements on a dependency path from source to target

**Hazard — chop is NOT a line-range extractor:** the output is not bounded by `FROM..TO` and may include lines outside that window (or nothing at all when no dependency path exists). Do not use it to extract contiguous source text — use `tldr body` (below).

**Example:**
```bash
# Find all lines on the dependency path from line 10 to line 50
tldr chop src/process.py process_data 10 50
```

---

## body

**Purpose:** Print the exact contiguous source of a function body or line range — byte-faithful (preserves CRLF/BOM/whitespace). Safe to read or reconstruct from, unlike slice/chop.

**Implementation:** `crates/tldr-cli/src/commands/body.rs`

**Usage:** `tldr body <file> [function] [--from N --to M]`

- With `[function]`: prints that function's exact body lines.
- With `--from N --to M`: prints the contiguous, 1-indexed, inclusive line range (the newline terminating line M is included). `--from` and `--to` require each other.

**Example:**
```bash
# Whole function body, byte-faithful
tldr body src/process.py process_data

# Exact contiguous line range
tldr body src/process.py --from 10 --to 25
```

JSON output reports `file`, `function`, `language`, `line_start`, `line_end`, `line_count`, and `byte_count` alongside the `body` text.
