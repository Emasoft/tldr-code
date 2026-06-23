# RC2 — Kotlin parse-recovery failure on `suspend = { ... }` named-arg lambda (grammar-level)

**Cluster:** structure-extract (analysis[2]), root_cause #16
**Commands affected:** ALL Kotlin commands (`structure`, `extract`, `interface`, `complexity`, `slice`, `explain`, `context`) — identically
**Classification:** research-needed -> **NOT fixable in tldr extraction logic** (the parse tree itself is wrong). Documented; not implemented.

## Problem (#105)

`tree-sitter-kotlin-ng = "=1.1.0"` fails to parse an expression-body function whose call uses a named-argument lambda where the argument NAME is a soft keyword. In kotlinx-coroutines `Semaphore.kt` L192–196:

```kotlin
protected fun acquire(waiter: CancellableContinuation<Unit>) = acquire(
    waiter = waiter,
    suspend = { cont -> addAcquireToQueue(cont as Waiter) },   // <- `suspend` as arg name
    onAcquired = { cont -> cont.resume(Unit, onCancellationRelease) }
)
```

The parser drops into an `ERROR` state that consumes the REST of the file. Verified via `cargo run --example dump_ast -- kotlin Semaphore.kt`:

```
ERROR 'package kotlinx.coroutines.sync\n\nimport ...'      <- the whole file is inside ERROR
  function_body '= SemaphoreImpl(permits, acquiredPermits)'
  identifier 'SemaphoreAndMutexImpl'                         <- class name orphaned to a bare identifier
  property_declaration 'private val head: ...'
```

Consequences: `SemaphoreAndMutexImpl` / `SemaphoreImpl` / `SemaphoreSegment` + ~26 methods vanish, and 3 impl methods leak to top level. Bisected: `head -191` (before the construct) parses cleanly; `head -193` is broken. `Mutex.kt` (no such construct) parses perfectly. The failure is IDENTICAL across all commands — proof it is grammar-level, upstream of every tldr extractor.

## Why it is NOT fixable in my files

extract.rs / extractor.rs / interface.rs all consume the tree-sitter parse tree. When that tree is an `ERROR` node swallowing the file, there is no node-kind logic any of them can apply — the structure simply is not there. A fix must live at the parse layer (grammar or a re-scan pass), which is outside the three files this task may edit, and an ERROR-recovery rescan would be a broad new subsystem with high blast radius across every Kotlin file.

## Options (all outside this task's edit scope)

| Option | Scope | Risk | Notes |
|---|---|---|---|
| (a) Grammar bump | `Cargo.toml` dep (parse layer) | MED | Check whether a tree-sitter-kotlin release > 1.1.0 parses the L192–196 construct. Highest leverage if it works; needs FULL Kotlin corpus re-validation because a grammar change can shift other parses. NOT a closeout-pass change. |
| (b) AST ERROR-recovery rescan | new parse-layer pass | HIGH | When a `class_body` (or file) contains an `ERROR`, re-scan the remaining source for `class`/`object`/`fun` declarations. Broad, risky, and not in extract.rs/extractor.rs/interface.rs. |
| (c) File upstream | tree-sitter-kotlin-ng | — | Report the `suspend = { ... }` named-arg parse-recovery bug. Correct long-term home. |

## Recommendation

**File upstream (c)** and, in a dedicated (non-closeout) cycle, **evaluate a grammar bump (a)** with a full Kotlin corpus re-validation. Do NOT attempt the in-tree ERROR-recovery rescan (b) under the closeout constraints — it is broad, high-risk, and outside the three editable files. No tldr extraction-logic change can recover a corrupt parse tree, so there is nothing to implement here.

## Pointers
- Grammar: `tree-sitter-kotlin-ng = "=1.1.0"` (`Cargo.toml` L54).
- Repro: `/tmp/tldr_corpora_b/kotlin-coroutines/.../common/src/sync/Semaphore.kt` L192–196; `cargo run --example dump_ast -- kotlin <file>` shows the top-level `ERROR`.
- Consumers (all downstream of the bad parse): `extractor.rs::extract_kotlin_*`, `extract.rs` Kotlin detailed extractors, `interface.rs` Kotlin arms.
