# Quality Commands

Quality commands analyze code maintainability, complexity, and technical debt.

## smells

**Purpose:** Detect code smells.

**Implementation:** `crates/tldr-cli/src/commands/smells.rs`

```rust
pub struct SmellsArgs {
    pub path: PathBuf,
    pub threshold: ThresholdPreset,
    pub smell_type: Option<SmellType>,
    pub suggest: bool,
    pub deep: bool,
    pub no_default_ignore: bool,
    pub files: Vec<PathBuf>,
    pub include_tests: bool,
}
```

**How it works:**
1. Analyzes structure for known anti-patterns
2. Computes metrics per smell type
3. Compares against threshold presets
4. `--deep` runs additional cohesion/coupling/dead analysis

**Smell types:**
- `god-class` — >20 methods or >500 LOC
- `long-method` — >50 LOC or cyclomatic >10
- `long-parameter-list` — >5 parameters
- `feature-envy` — method accessing too much foreign data
- `data-clumps` — same parameters always grouped
- `high-cognitive-complexity` — >= 15
- `deep-nesting` — nesting depth >= 5
- `data-class` — many fields, few methods
- And more...

**Scope flags:**
- `--files <PATH>` — limit the scan to specific files (repeatable;
  **exact paths only**, no glob expansion; each entry must exist and be
  traversal-free). When set, the positional path becomes a project-root
  anchor for output ordering only and the directory walker is bypassed.
  Implies `--include-tests` (the caller picked the list)
- `--include-tests` — include findings from test files. Default: test-file
  findings are excluded (PR-review default); implicit `true` when
  `--files` is non-empty
- `--no-default-ignore` — walk vendored/build dirs (node_modules, target,
  dist, ...) that would normally be skipped

**Example:**
```bash
tldr smells src/

# Strict thresholds
tldr smells src/ -t strict

# Specific smell type
tldr smells src/ -s god-class

# With suggestions
tldr smells src/ --suggest

# Deep analysis
tldr smells src/ --deep

# Exact-file scan (walker bypassed; tests implicitly included)
tldr smells src/ --files src/a.py --files src/b.py
```

---

## complexity

**Purpose:** Calculate function complexity metrics.

**Implementation:** `crates/tldr-cli/src/commands/complexity.rs`

**How it works:**
1. Parses function and builds CFG
2. Counts decision points (if, while, for, &&, ||, ?, etc.)
3. Returns cyclomatic complexity = edges - nodes + 2

**Example:**
```bash
tldr complexity src/process.py process_data

# Text output
tldr complexity src/process.py process_data -f text
```

---

## cognitive

**Alias:** `cog`

**Purpose:** Calculate cognitive complexity (SonarQube algorithm).

**Implementation:** `crates/tldr-cli/src/commands/cognitive.rs`

**How it works:**
1. Increments complexity for nesting depth
2. Increments for control flow structures
3. Does NOT increment for structured breaks (early returns)
4. Higher = more difficult to understand

**Example:**
```bash
tldr cognitive src/

# Per function
tldr cognitive src/ --function process_data

# Threshold filtering
tldr cognitive src/ --threshold 15
```

---

## halstead

**Alias:** `hal`

**Purpose:** Calculate Halstead complexity metrics per function.

**Metrics:**
- **Volume**: Size of implementation
- **Difficulty**: Operator count / operand count ratio
- **Effort**: Cognitive work to understand

**Example:**
```bash
tldr halstead src/process.py

# Show operators/operands
tldr halstead src/process.py --show-operators --show-operands
```

---

## loc

**Purpose:** Count lines of code with type breakdown.

**How it works:**
1. Counts total lines per file
2. Categorizes as code, comment, or blank
3. Aggregates by file or directory

**Example:**
```bash
tldr loc src/

# Per file
tldr loc src/ --by-file

# By directory
tldr loc src/ --by-dir
```

---

## churn

**Purpose:** Analyze git-based code churn.

**How it works:**
1. Scans git history (default: 365 days)
2. Counts commits per file
3. Tracks modification frequency

**Example:**
```bash
tldr churn src/

# Last 30 days
tldr churn src/ --days 30

# Top 50
tldr churn src/ --top 50

# With author stats
tldr churn src/ --authors
```

---

## debt

**Purpose:** Analyze technical debt using SQALE method.

**SQALE categories:**
- `reliability` — Bugs, error handling
- `security` — Vulnerabilities
- `maintainability` — Code quality
- `efficiency` — Performance
- `changeability` — Dependencies
- `testability` — Test coverage

**Example:**
```bash
tldr debt src/

# Category filter
tldr debt src/ -c security

# With cost estimation
tldr debt src/ --hourly-rate 150
```

---

## health

**Alias:** `h`

**Purpose:** Comprehensive code health dashboard.

**Implementation:** `crates/tldr-cli/src/commands/health.rs`

**How it works:**
1. Runs multiple analyzers in parallel:
   - Complexity (cyclomatic + cognitive)
   - Cohesion (LCOM4)
   - Dead code
   - Similarity
   - Coupling
2. Aggregates into health score

**Example:**
```bash
tldr health src/

# Quick mode
tldr health src/ --quick

# Detailed sub-analyzer
tldr health src/ --detail complexity

# Summary only
tldr health src/ --summary

# Threshold preset + result caps
tldr health src/ --preset strict --max-items 100
```

**Flags:**
- `--preset <PRESET>` — threshold preset: `strict`, `default` (default),
  or `relaxed` (legacy code)
- `--max-items <N>` — maximum items returned for coupling and similarity
  analyses (default: 50)

---

## hotspots

**Alias:** `hot`

**Purpose:** Identify churn x complexity hotspots.

**How it works:**
1. Combines churn analysis with complexity metrics
2. Scores files/functions by risk (high churn + high complexity)
3. Applies recency weighting (recent changes count more)

**Example:**
```bash
tldr hotspots src/

# Function level
tldr hotspots src/ --by-function

# Include trends
tldr hotspots src/ --show-trend

# Different time window
tldr hotspots src/ --days 90 --recency-halflife 30
```

---

## clones

**Alias:** `cl`

**Purpose:** Detect code clones in a codebase.

**Clone types:**
- **Type 1**: Identical code (whitespace differences)
- **Type 2**: Same structure, different literals
- **Type 3**: Modified statements

**Flags:**
- `--type-filter <1|2|3|all>` — filter by clone type (default: all)
- `--normalize <none|identifiers|literals|all>` — normalization mode
  (default: all)
- `--show-classes` — show clone classes (transitive grouping)
- `--exclude-generated` — exclude generated files (`*.pb.go`,
  `*_generated.ts`, `vendor/`, ...)
- `--include-within-file` — include clones within the same file
- `-o, --output <json|text|sarif>` — output format (default json); use
  **sarif** for IDE/CI integration (GitHub, VS Code, ...)

**Example:**
```bash
tldr clones src/

# Minimum thresholds
tldr clones src/ --min-lines 10 --min-tokens 50

# Similarity threshold
tldr clones src/ -t 0.8

# Exclude tests
tldr clones src/ --exclude-tests

# Type-2 clones only, normalized, as SARIF for CI
tldr clones src/ --type-filter 2 --normalize all -o sarif

# Transitive clone classes, including intra-file clones
tldr clones src/ --show-classes --include-within-file --exclude-generated
```

---

## cohesion

**Alias:** `coh`

**Purpose:** Analyze class cohesion using LCOM4 metric.

**LCOM4:** Number of connected components in method-field graph. Higher = lower cohesion.

**Example:**
```bash
tldr cohesion src/

# Minimum methods filter
tldr cohesion src/ --min-methods 3
```

---

## coupling

**Alias:** `coup`

**Purpose:** Analyze coupling between modules/classes via cross-module
**call edges** (afferent/efferent, instability).

**Not import-level coupling:** the analysis measures function-call
coupling — it builds on the call graph, not on `import` statements. For
import-level dependencies use `tldr deps` or `tldr imports` instead
(P12.AGG12-14).

**Metrics:**
- **Afferent**: Incoming dependencies (what depends on this)
- **Efferent**: Outgoing dependencies (what this depends on)
- **Instability**: efferent / (afferent + efferent)

**Example:**
```bash
tldr coupling src/

# Pair mode
tldr coupling src/module_a.py src/module_b.py

# Cycles only
tldr coupling src/ --cycles-only
```
