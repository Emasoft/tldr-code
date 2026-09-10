---
trdd-id: Q7VXK3M2
title: Sub-analyses swallow per-file errors so a wholly failed run returns Ok(empty)
column: todo
created: 2026-09-10T14:20:12+0200
updated: 2026-09-10T18:55:29+0200
current-owner: session-claude
task-type: bugfix
scope: project
min-approval-requirement: none
labels: [silent-failure, json-output, error-handling]
---

# Sub-analyses swallow per-file errors so a wholly failed run returns Ok(empty)

## Symptom

`tldr todo -f json` cannot distinguish "this analysis ran and found nothing"
from "this analysis failed on every single file". Both produce an empty item
list and no warning, because the analyzers discard their per-file errors
individually and then return `Ok` with whatever survived — which, when nothing
survived, is an empty report.

Partial per-file failures are the common case and are dropped the same way
as a total failure — the all-failing run named in the title is only the
extreme end of the same defect, and the JSON carries no count of dropped
files either way.

This is the defect TRDD-RX6JWVVZ set out to find. That card fixed the `Err`
arm of `TodoCommand::run` (a failure message now lands in `TodoReport.warnings`,
which every format emits), and in doing so established that the arm is
UNREACHABLE today. **The fix is correct and the arm is the right place for a
failure to surface — but it only surfaces a future `Err`.** The actual
invisibility a user experiences right now happens one level down, before the
`Err` arm is ever reached. Hence this card.

## Evidence — read in the working tree 2026-09-10

**Complexity** — `crates/tldr-core/src/quality/complexity.rs:229-243`, inside
`analyze_complexity` (`:197-201`, returns `TldrResult<ComplexityReport>`):

```rust
.par_iter()
.filter_map(
    |file_path| match analyze_file_complexity(file_path, opts.include_cognitive) {
        Ok(functions) => Some(functions),
        Err(e) => {
            eprintln!("Warning: skipping {} due to parse error: {}", file_path.display(), e);
            None
        }
    },
)
```

Every per-file failure becomes `None` and is dropped from the collect. If all N
files fail, `all_functions` is empty and `analyze_complexity` returns `Ok` with
an empty report. The `eprintln!` is real and is the one thing a user watching
the terminal does see — but it is stderr, so it is absent from a redirected
`-f json` payload, from `-o <path>`, and from any pipe.

**Cohesion** — `crates/tldr-core/src/quality/cohesion.rs:312-316`, inside
`analyze_cohesion_with_options` (`:286-290`, returns
`TldrResult<CohesionReport>`):

```rust
for file_path in &file_paths {
    if let Ok(classes) = analyze_file_cohesion(file_path, &options) {
        all_classes.extend(classes);
    }
    // Skip files that fail to parse (graceful degradation)
}
```

Strictly worse than complexity's shape: the `Err` value is not even bound, so
there is no stderr line either. A total failure is indistinguishable from a
codebase with no classes, on every channel.

**Dead** — `crates/tldr-core/src/analysis/dead.rs:200-204`:
`pub fn dead_code_analysis_refcount(...) -> TldrResult<DeadCodeReport>`. It
returns a `Result` by signature, so the `Err` arm above is reachable **by
type**; whether any input drives it there was not established by this card and
must not be asserted from a grep. Read the body before claiming either way.

## What this card must decide, not assume

The graceful-degradation behaviour is probably right — one unparseable file
should not abort a whole-project analysis. **The defect is that the degradation
is not REPORTED in the payload**, not that it happens. So the likely fix is to
thread the per-file failures into the report the same way the dead-code
analysis already threads its skipped-file list (`TodoReport.warnings`, the lift
TRDD-K3XQ7M2V built), rather than to make the analyzers fail hard.

Whether a run in which EVERY file failed should additionally become an `Err` —
which would then reach the arm TRDD-RX6JWVVZ fixed and surface as a named
failed analysis — is a separate call and should be made explicitly, with the
reason recorded. Do not decide it by picking the smaller diff.

## Acceptance

- [ ] Both swallow sites are read in full and their behaviour on a
      whole-directory failure is recorded here from a RUN, not from reading —
      a fixture where every file fails to parse, `-f json`, output captured.
- [ ] `dead_code_analysis_refcount`'s body is read and the card states whether
      any input reaches its `Err` path. Type-level reachability is not an
      answer.
- [ ] The per-file failures reach the JSON payload (via `warnings` or a
      dedicated field), so a consumer can tell an empty result from a failed
      one. Asserted on the message PRESENT, never on absence.
- [ ] The "should a total failure become `Err`" question is answered here with
      its reason, whichever way it goes.
- [ ] Red-proofed: the new assertion is observed FAILING against today's code
      before it is accepted as passing.

## Relationships

- TRDD-RX6JWVVZ — the sibling that fixed the `Err` arm and proved it currently
  unreachable. This card owns the reason it is unreachable. Neither subsumes
  the other: RX6JWVVZ makes a future failure visible, this one makes today's
  failure visible.
- TRDD-K3XQ7M2V — built `TodoReport.warnings`, the field a fix here would most
  likely reuse.
- TRDD-O66FM8TN — the parent family (silent read failures made visible).

## Notes
