# Decision: `loc` over-attributes C `.h` headers to C++ via the project-level fallback

Cluster: [11] misc-tail. Command: `loc`. File: `crates/tldr-core/src/metrics/loc.rs`
(`resolve_loc_language`, lines ~952-999; `project_has_cpp` computation ~636-681).
Classification in `reaudit-rootcause.json` analysis[11]: **design-fork**.

## Problem (reproduced LIVE)

`tldr loc /tmp/tldr_corpora_b/c-redis` reports:

```
c:   files=471  code=217678
cpp: files=319  code=35390   <-- WRONG
```

The 319 "cpp" files are `7 .cpp + 1 .hpp + 311 .h`. The 311 `.h` files are
Redis's own C headers (`server.h`, `dict.h`, …) — C, not C++. They are bucketed
as C++ purely because the tree contains a handful of `.cpp` files (vendored
deps / benchmarks).

## Root cause

`resolve_loc_language` (loc.rs:967-970):

```rust
// Project-level signal: any C++ TU anywhere → `.h` is a C++ header.
if project_has_cpp {
    return Some(Language::Cpp);
}
```

`project_has_cpp` is `true` if **any** `.cpp/.cc/.cxx/.hpp/...` file exists
**anywhere** in the tree (loc.rs:646-650). The unconditional early return then
overrides both the per-directory sibling check below it and
`Language::from_path` (which maps `.h` → C). So in a C-dominant project that
merely contains one C++ file, every `.h` flips to C++.

## Attribution

CAMPAIGN-CAUSED (regression). Verified via git: at baseline `5635a77`, `loc`
used `Language::from_path(entry_path)` directly (`.h` → C); `resolve_loc_language`
/ `project_has_cpp` / `CPP_SIBLING_EXTS` did not exist (grep count 0). The
project-level fallback was added by `cd220eb` + `82807cb` (`fix-C5-6-v1`) to fix
the opposite problem — pure-header C++ libraries like `cpp-fmt`
(`include/fmt/*.h` with TUs under `src/`) whose headers were under-attributed to
C. That fix over-corrected.

So this is a genuine PRECISION/RECALL trade between two real corpora:
- **c-redis**: C-dominant + a few `.cpp` → headers should stay **C** (current = wrong).
- **cpp-fmt**: header-only C++ public API + `.cc` TUs elsewhere → headers should be **C++** (the fix-C5-6 target).

A purely local (same-directory sibling) rule satisfies c-redis but regresses
cpp-fmt; the unconditional project-level rule satisfies cpp-fmt but regresses
c-redis. Hence design-fork.

## Options

### Option A — drop the project-level fallback (precision-first)
Delete loc.rs:968-970; keep only the same-directory sibling check. c-redis
headers become C (correct). cpp-fmt `include/fmt/*.h` regress to C (wrong) unless
an `include/` dir happens to have a cpp sibling. Under-attributes pure-header C++.

### Option B — gate the fallback on C++ DOMINANCE (recommended, IMPLEMENTED)
Apply the project-level `.h → C++` fallback only when C++ translation units
**outnumber** C translation units in the project (`cpp_tu_count > c_tu_count`).
- c-redis: 472 `.c` TUs ≫ 7 `.cpp` TUs → C++ NOT dominant → `.h` stays **C**. Fixed.
- cpp-fmt: TUs are `.cc` with no competing `.c` → C++ dominant → `.h` is **C++**. Preserved.
The same-directory sibling check (Option-A behavior) still runs first as a
positive local signal, so a `.h` next to a `.cpp` is C++ regardless of project
dominance (handles mixed dirs).

### Option C — per-header content sniff (class/namespace/template tokens)
Most accurate but adds a parse/scan per ambiguous header. Overkill for a LOC
counter and slower on large trees. Deferred.

## Decision

**Option B**, implemented in `fix-R7-cl11-misctail`:
- Compute `cpp_tu_count` and `c_tu_count` during the existing single detection
  walk (no extra traversal).
- `resolve_loc_language` takes a `cpp_is_dominant: bool` instead of the raw
  `project_has_cpp`; the project-level fallback fires only when dominant.
- Same-directory sibling check unchanged (still the primary signal).

Rationale: it is the minimal change that fixes the c-redis regression WITHOUT
re-regressing the cpp-fmt case the campaign fix targeted, it is AST/heuristic-
free (extension counting only), and it adds zero extra filesystem walks.

## Blast radius

`loc` per-language breakdown for mixed/headers-only C/C++ projects only
(c-redis, cpp-fmt, cpp-tinyxml2). `patterns`/`health` use a separate, correct
classifier and are unaffected. The fix-C5-6 unit tests
(`test_loc_h_header_in_headers_only_dir_attributed_to_cpp`,
`test_loc_h_header_stays_c_in_pure_c_project`,
`test_loc_h_header_attributed_to_cpp_when_cpp_siblings`) are updated to assert
the dominance-gated behavior; a new test pins the c-redis-shaped regression
(C-dominant project + stray `.cpp` → `.h` stays C).
