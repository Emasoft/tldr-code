# Patterns Commands

Pattern commands detect design patterns, contracts, and behavioral specifications.

## patterns

**Alias:** `p`

**Purpose:** Detect design patterns and coding conventions.

**Implementation:** `crates/tldr-cli/src/commands/detect_patterns.rs`

**How it works:**
1. Single-pass signal extraction across codebase
2. Aggregates `PatternSignals` for each function/class
3. Detects known design patterns:
   - **Creational**: Singleton, Factory, Builder
   - **Structural**: Adapter, Decorator, Facade
   - **Behavioral**: Observer, Strategy, Command
   - **Architectural**: MVC, Repository, Service
   - **Anti-patterns**: God class, Spaghetti code

**Example:**
```bash
tldr patterns src/

# Category filter
tldr patterns src/ -c behavioral

# Confidence threshold
tldr patterns src/ --min-confidence 0.8
```

---

## inheritance

**Alias:** `inh`

**Purpose:** Extract class inheritance hierarchies.

**Implementation:** `crates/tldr-cli/src/commands/inheritance.rs`

**How it works:**
1. Parses class declarations
2. Resolves base classes (ABC, Protocol, mixins)
3. Builds inheritance graph
4. Detects diamond inheritance patterns

**Example:**
```bash
tldr inheritance src/

# Focus on specific class
tldr inheritance src/ -c DataProcessor

# Limit depth
tldr inheritance src/ -c BaseHandler -d 3
```

---

## contracts

**Alias:** `con`

**Purpose:** Infer pre/postconditions from guard clauses, assertions, isinstance checks.

**Implementation:** `crates/tldr-cli/src/commands/contracts/contracts.rs`

**How it works:**
1. Parses function body
2. Extracts guard clauses (if-raise patterns)
3. Finds isinstance/type checks
4. Builds precondition/postcondition model

**Example:**
```bash
tldr contracts src/process.py process_data

# Limit results
tldr contracts src/process.py process_data --limit 50
```

---

## specs

**Alias:** `sp`

**Purpose:** Extract behavioral specifications from pytest test files.

**Implementation:** `crates/tldr-cli/src/commands/contracts/specs.rs`

**How it works:**
1. Parses pytest test functions
2. Extracts test names, fixtures, assertions
3. Generates formal spec from tests

**Flags:**
- `-t, --from-tests <PATH>` — test file or directory to scan (required)
- `--function <FN>` — filter to specific function under test
- `--source <DIR>` — source directory for cross-referencing (optional)

**Example:**
```bash
tldr specs --from-tests tests/test_process.py

# Filter to specific function
tldr specs --from-tests tests/test_process.py --function process_data

# Cross-reference against the implementation tree
tldr specs --from-tests tests/test_process.py --source src/
```

---

## invariants

**Alias:** `inv`

**Purpose:** Infer invariants from test execution traces (Daikon-lite).

**Implementation:** `crates/tldr-cli/src/commands/contracts/invariants.rs`

**How it works:**
1. Runs tests to generate execution traces
2. Analyzes variable states at each point
3. Infers patterns (e.g., "x > 0", "len(list) < 100")

**Example:**
```bash
tldr invariants --from-tests tests/ src/process.py

# Specific function
tldr invariants --from-tests tests/ src/process.py --function process_data

# Minimum observations
tldr invariants --from-tests tests/ src/process.py --min-obs 3
```

---

## verify

**Alias:** `ver`

**Purpose:** Aggregated verification dashboard combining multiple analyses.

**Implementation:** `crates/tldr-cli/src/commands/contracts/verify.rs`

**How it works:**
1. Runs contracts analysis
2. Runs invariants analysis
3. Runs patterns analysis
4. Aggregates into verification score

**Example:**
```bash
tldr verify src/

# Quick mode
tldr verify src/ --quick

# Detail specific
tldr verify src/ --detail contracts
```

---

## temporal

**Alias:** `tem`

**Purpose:** Mine temporal constraints (method call sequences).

**Implementation:** `crates/tldr-cli/src/commands/patterns/temporal.rs`

**How it works:**
1. Analyzes method call sequences in classes
2. Mines frequent patterns (2-method, 3-method sequences)
3. Reports required/optional ordering

**Example:**
```bash
tldr temporal src/

# Filter to specific method
tldr temporal src/ --query connect

# Minimum support
tldr temporal src/ --min-support 5

# Stricter pattern acceptance, 3-method sequences, hard time bound
tldr temporal src/ --min-confidence 0.8 --include-trigrams --timeout 30
```

**Flags:**
- `--min-confidence <0.0-1.0>` — minimum confidence threshold
  (default: 0.5)
- `--include-trigrams` — mine 3-method sequences in addition to pairs
- `--timeout <SECONDS>` — analysis timeout (default: 60; E03 mitigation)
- `--max-files <N>` — maximum files to analyze (default: 1000)
- `--source-lang <LANG>` — legacy source-language hint (prefer the global
  `--lang/-l` flag); default `python`

---

## order

**Purpose:** Report use-before-define / TDZ hazards computed from
definition line ranges (JavaScript, TypeScript, Python).

**How it works:**
1. Parses the file and collects definition line ranges
2. Flags uses that occur before their definition
3. Reports temporal-dead-zone hazards (e.g. `const`/`let`/`class` used
   before initialization)

**Example:**
```bash
tldr order src/main.py
```

---

## interface

**Alias:** `iface`

**Purpose:** Extract interface contracts (public API signatures, contracts).

**Implementation:** `crates/tldr-cli/src/commands/patterns/interface.rs`

**How it works:**
1. Extracts public functions/classes
2. Builds API surface
3. Infers contracts from signatures and usage

**Flags:**
- `--project-root <DIR>` — project root for path validation

**Example:**
```bash
tldr interface src/

# Validate paths against an explicit project root
tldr interface src/ --project-root .
```
