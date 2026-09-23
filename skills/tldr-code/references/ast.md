# AST Analysis Commands (Layer 1)

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

**Markup depth filter:** `--max-depth N` keeps only markup element
definitions at nesting depth ≤ N (root-level elements are depth 0).
Markup-node-tree only (markup-node-tree-v1): it applies to formats that
carry element depths — XML/SVG/HTML/XHTML and OOXML parts. Definitions
without depth semantics (code symbols, inner-CSS/inner-JS rows,
json/yaml/toml keys, log/text/csv/sql rows) are never filtered. Unset =
no filtering (the full flat element list, JSON-complete).

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
pub fn get_imports(file_path: &Path, language: Language) -> TldrResult<Vec<ImportInfo>>
```

**How it works:**
1. Parses file and extracts `import`/`from ... import` statements
2. Categorizes as standard library, third-party, or local
3. Returns source location for each import

**Output shape:** by default a canonical envelope object
`{file, language, imports}`. `--legacy-array` emits the legacy bare-array
JSON shape (`[ImportInfo, ...]`) instead, for backward compatibility with
consumers that hard-coded `jq '.[]'` over the top level. New code should
consume the envelope shape.

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

**Result cap:** `-m/--limit <LIMIT>` — maximum number of importing files
to show (default **50**, `0` = unlimited).

**Example:**
```bash
tldr importers os src/
tldr importers mymodule src/

# Show all importers, not just the first 50
tldr importers mymodule src/ -m 0
```

---

## logs

**Purpose:** Filter and list log entries from a log file.

**Implementation:** native, streaming log-entry scanner (`ast::logs`) —
`.log` files never parse through tree-sitter (no grammar exists); entries
are heuristically delimited by timestamps / level tokens.

**How it works:**
1. Streams the file through the native log-entry scanner
2. Prints the entries matching **all** supplied filters
3. Entries whose timestamp is missing or year-less are excluded and
   counted as unfilterable

**Filters:**
- `--from <TS>` — inclusive lower bound on the entry timestamp
  (e.g. `2026-09-14`, `2026-09-14T08:00:00Z`, `2026-09-14 08:00:00`)
- `--to <TS>` — inclusive upper bound (same forms as `--from`)
- `--level <LEVEL>` — exact normalized level, case-insensitive
  (fatal/critical/emerg/alert/panic → error-family; warn/warning → warn;
  info/notice/information → info; debug/trace/fine/finer/finest → debug)
- `--grep <PAT>` — case-sensitive substring filter on the entry's raw
  source text

**Example:**
```bash
# All entries
tldr logs app.log

# Time window + level
tldr logs app.log --from 2026-09-14 --to 2026-09-15 --level error

# Substring filter
tldr logs app.log --grep "connection refused"
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
