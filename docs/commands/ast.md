# AST Analysis Commands (Layer 1)

<!-- m117-deferred-decisions-v1 (v0.4.2 M-118): D8/D10 flag documentation -->

## Cross-cutting flags

### `--qualified` (D8)

Available on the per-function analysis commands: `explain`,
`complexity`, `cognitive`, `slice`, `contracts`, `halstead`.

By default `tldr` accepts both bare names (`parse`) and qualified
names (`ParserPool::parse`) on per-function commands; the canonical
`find_function_node` resolver covers Rust / C / C++ `::`-qualified
forms via M-013. **The default behaviour is strict-qualified** — if
you typed `ParserPool::parse`, the lookup tries the qualified form
first.

Pass `--qualified` to opt INTO the bare-name fallback when you know
the input is qualified. The flag pre-canonicalizes the input to the
rightmost bare segment via
`tldr_core::ast::function_finder::qualified_name_fallback_bare` —
the same helper M-013 wired into `impact` / `whatbreaks`. This is
useful when you have a copy-pasted module-prefixed path
(`mod::Type::method`) and want to short-circuit any ambiguity in
the class-scope resolver.

```bash
# Default — strict-qualified lookup.
tldr complexity src/parser.rs ParserPool::parse

# Opt in to bare-name fallback (here: equivalent to `parse`).
tldr complexity src/parser.rs ParserPool::parse --qualified
```

The flag is a no-op for languages that don't use `::` for method
paths (Python, Java, JS/TS, Go, etc.) — the helper returns the
input unchanged.

### `--all-langs` / `-A` (D10)

Available on commands that take a project path. Currently wired
end-to-end on `structure`; other project-path commands accept the
flag for surface consistency.

By default, `tldr` scans a project in its **auto-detected dominant
language** only. This is fast and correct for monoglot repos but
silently drops files in secondary languages on polyglot
monorepos — a Python project with a `tools/` subtree of Rust
helpers will not see those `.rs` files unless you pass `--lang
rust` explicitly.

Pass `--all-langs` (short: `-A`) to scan every detected language
and merge the result:

```bash
# Default — dominant-language only (drops secondary-language files).
tldr structure path/to/polyglot/repo

# Scan every detected language and merge.
tldr structure path/to/polyglot/repo --all-langs

# Equivalent short form.
tldr structure path/to/polyglot/repo -A
```

The merged output adds a `--all-langs: scanned N language(s): …`
entry to the `warnings` array so you can see which languages were
covered. The flag is mutually exclusive with `--lang` (passing
`--lang` always wins and pins a single language).

---


Layer 1 commands extract structure from source code using tree-sitter AST parsing.

## tree

**Alias:** `t`

**Purpose:** Show file tree structure of a directory.

**Implementation:** `crates/tldr-cli/src/commands/tree.rs`

```rust
// Key code path (tree.rs:36-90)
pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
    let tree = get_file_tree(
        &self.path,
        extensions.as_ref(),
        !self.include_hidden,
        Some(&IgnoreSpec::default()),
    )?;
    // Output as JSON or formatted text
}
```

**How it works:**
1. Traverses directory with `WalkDir`
2. Respects `.gitignore` and `.tldrignore`
3. Filters by extension if `--ext` specified
4. Returns hierarchical `FileTree` structure

**Example:**
```bash
# Basic tree
tldr tree src/

# Python files only
tldr tree src/ -e .py

# Include hidden files
tldr tree src/ -H
```

**Output (text format):**
```
src/
├── main.py
├── utils/
│   ├── __init__.py
│   └── helpers.py
└── tests/
    └── test_main.py
```

---

## structure

**Alias:** `s`

**Purpose:** Extract code structure — functions, classes, imports.

**Implementation:** `crates/tldr-cli/src/commands/structure.rs`

```rust
// Key code path
pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
    let structure = get_code_structure(
        &self.path,
        self.language,
        self.max_results,
    )?;
}
```

**How it works:**
1. Walks directory finding files matching language extensions
2. Parses each file with tree-sitter
3. Extracts `ModuleInfo`: functions, classes, imports, constants
4. Returns per-file structure with caller/callee relationships

**Example:**
```bash
# Get structure
tldr structure src/

# Limit results
tldr structure src/ -m 50

# Text format for readability
tldr structure src/ -f text
```

**Output structure:**
```json
{
  "files": [
    {
      "path": "src/main.py",
      "functions": [
        {
          "name": "process_data",
          "params": ["input: str"],
          "line": 10,
          "is_async": false
        }
      ],
      "classes": [...],
      "imports": [...]
    }
  ]
}
```

---

## extract

**Alias:** `e`

**Purpose:** Extract complete module info from a single file.

**Implementation:** `crates/tldr-core/src/ast/extract.rs`

```rust
// Core extraction (tldr-core)
pub fn extract_file(path: &Path, base_path: Option<&Path>) -> TldrResult<ModuleInfo> {
    let tree = parser.parse_file(path)?;
    extract_from_tree(&tree, source, lang, path, base_path)
}
```

**How it works:**
1. Parses single file with tree-sitter
2. Extracts full `ModuleInfo` including docstrings
3. Resolves intra-file call graph
4. Returns detailed metadata per function/class

**Example:**
```bash
# Extract single file
tldr extract src/main.py

# Text output
tldr extract src/main.py -f text
```

---

## imports

**Purpose:** Parse import statements from a file.

**Implementation:** `crates/tldr-core/src/ast/imports.rs`

```rust
// Import parsing
pub fn get_imports(tree: &Tree, source: &str, language: Language) -> TldrResult<Vec<ImportInfo>>
```

**How it works:**
1. Parses file and extracts `import`/`from ... import` statements
2. Categorizes as standard library, third-party, or local
3. Returns source location for each import

**Example:**
```bash
tldr imports src/main.py
```

**Output:**
```json
{
  "imports": [
    {
      "module": "os",
      "names": ["path"],
      "line": 1,
      "is_from": true,
      "level": 0
    },
    {
      "module": "mymodule",
      "names": ["MyClass"],
      "line": 5,
      "is_from": true,
      "level": 1
    }
  ]
}
```

---

## importers

**Purpose:** Find files that import a given module.

**Implementation:** Uses call graph analysis to find importers.

**How it works:**
1. Scans all files for imports matching target module
2. Returns list of importing files

**Example:**
```bash
tldr importers os src/
tldr importers mymodule src/
```

---

## definition

**Alias:** `def`

**Purpose:** Go-to-definition — find where a symbol is defined.

**Implementation:** Uses AST analysis to resolve symbol definitions.

**How it works:**
1. Accepts file+line+column or --symbol flag
2. Traverses AST to find matching definition
3. Cross-file resolution via import graph

**Example:**
```bash
# By position
tldr definition src/main.py 10 5

# By symbol name
tldr definition --symbol process_data --file src/main.py
```

---

## references

**Alias:** `refs`

**Purpose:** Find all references to a symbol.

**How it works:**
1. Builds cross-file reference map
2. Searches for identifier matches
3. Filters by reference kind (call, read, write, type)

**Example:**
```bash
tldr references process_data src/

# Filter by kind
tldr references process_data src/ -t call,write
```
