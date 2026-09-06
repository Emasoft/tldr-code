---
trdd-id: MWLIUB72
title: Decide whether the encoding module is wired into the read paths or retired
column: complete
created: 2026-09-06T04:14:07+0200
updated: 2026-09-06T04:24:00+0200
current-owner: unassigned
task-type: refactor
min-approval-requirement: user
labels: [scan-2026-09-05, encoding, api_change]
parent-trdd: 7X459MTO
---

# Decide whether the encoding module is wired into the read paths or retired

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-06

- This card exists because the decision had NO card. TRDD-7X459MTO's STATE block routed it to
  TRDD-V11BVG55, and a session handoff repeated that. Both were wrong — V11BVG55's 17 items were
  read in full and none mentions `encoding`. Corrected on both of those cards.
- **DECIDED 2026-09-06: LEAVE AS-IS, DOCUMENTED.** The first version of this card listed three
  options and picked none. That was deferral dressed as progress — the evidence already below it
  had eliminated two of the three, so the question was settled and the card presented it as open.
  The eliminations, each on evidence already gathered:
  - **RETIRE is eliminated.** There are no discoverable public library consumers, so the module
    costs nothing to keep; and deleting a public item buys nothing measurable while paying
    divergence cost against upstream forever. A deletion needs a benefit; this one has none.
  - **WIRE IN is eliminated *as a decision*.** 176 call sites plus every command's output schema
    is not a decision, it is a programme of work, and it is arguably upstream's architectural
    call rather than a fork's. It stays available as a future proposal, and TRDD-BKALIK1B may
    reopen it on evidence.
  - **LEAVE AS-IS is what remains**, and it is only honest because the read-path defect it would
    otherwise hide is now filed independently as **TRDD-BKALIK1B** (not as a checkbox here).
- **The standard used, stated so it can be argued with rather than merely invoked.** "Divergence
  cost" as first written ("every deletion is a merge conflict forever after") is a veto, not a
  cost — it opposes all divergence with no threshold and can therefore never lose an argument,
  which is the signature of a post-hoc rationalisation. The exchange rate: *a change is worth its
  divergence cost when it fixes a defect that reaches this fork's actual consumers — people
  running the `tldr` binary — and is not when it only tidies code nothing reaches.*
  Its falsifier is whether this fork intends to track upstream at all; if it never merges either
  direction, the cost is zero and the standard evaporates.
  **What is measured, stated at its true strength:** the `upstream` remote is configured AND
  fetched (`refs/remotes/upstream/*` present), `HEAD..upstream/main` is **0** (this branch
  already contains all of upstream/main), and 52 commits sit on the fork parent `7f50527`.
  That is an ANCESTRY fact and it is **consistent with tracking upstream — it does not establish
  a policy.** The same facts fit a fork that pulled once at creation and has ignored upstream
  since; the history sampled shows no merge commit FROM upstream. Evidence that would actually
  establish intent: an upstream merge in the history, a written rebase policy, or the owner
  saying so. None exists. Recording the weaker claim deliberately — an earlier version of this
  bullet asserted intent as measured, which is the same error class as the `d71f6f0` propagation
  corrected two hours earlier: a plausible inference written down as a fact.
  **The rate is so far UNFALSIFIED, not validated.** It has ratified every call made under it,
  and item 3 below shows why that is suspicious rather than reassuring: it condemned the UTF-16
  fix and was then given an escape clause ("latent defect, goes live if wired") sized exactly to
  that change. A standard that has never made anyone not do something they wanted to do has not
  yet constrained anything. It earns its keep the first time it does; if that moment never
  arrives, it is decoration and should be dropped rather than cited.
- **Applying that rate honestly costs me a claim I made earlier.** Under it, TRDD-7X459MTO's
  UTF-16 fix does NOT currently pass either — it corrects a real defect in a module no command
  routes through, so its benefit to binary users today is zero, exactly like the deletion it was
  contrasted with. The difference is direction, not consumer benefit. It remains justified as
  fixing a latent defect that becomes live if this module is ever wired in, and that is the
  honest defence; the earlier framing that it "passes a consumer-benefit test" was wrong.

## Why

`tldr-core` exposes `pub mod encoding` (`crates/tldr-core/src/lib.rs:45`) offering
`read_source_file`, `read_source_file_or_skip`, `FileReadResult` and `EncodingIssues` — a file
reader that classifies a source file as ok / lossy / binary / skipped and accumulates per-file
encoding problems for reporting.

**It has zero non-test callers anywhere in the workspace.** Verified across all four crates,
excluding the module's own file and its tests. Every command reads files directly instead.

TRDD-7X459MTO fixed a real defect inside this module (UTF-16 files were handed to callers as an
empty string, counted as analysed with zero symbols while the warning said "skipping"). That fix
is correct and shipped, but it corrects code nothing in this repo calls, and 7X459MTO's second
acceptance line — a `tldr structure` JSON run listing the file in an issues section — is
unsatisfiable until this card is decided, because no command consumes `EncodingIssues`.

## The measured facts that constrain the decision

**1. The status quo is worse than "the module is unused" suggests.** A survey of every non-test
`read_to_string` call site (176 real sites; report under `reports/encoding-survey/`) buckets them
by what happens when a file is not valid UTF-8:

| bucket | sites | effect on a non-UTF-8 file |
|---|---|---|
| PROPAGATED | 75 | the whole command aborts |
| SILENT | 73 | the file vanishes from the analysis, no message |
| PANIC | 25 | the process panics |
| WARNED | 3 | the user is actually told |

So today a single UTF-16 file in a tree can kill a command or silently shrink the result set,
and only 3 sites out of 176 report it. That is precisely the defect class this module was built
to fix. (Spot-checked first-hand: a one-line grep for `.unwrap()`/`.expect(` on a
`read_to_string(` line finds 24; the survey's 25 includes one multi-line form.)

**2. RETIRE is not the cheap cleanup it looks like, but not for the obvious reason.** The
tempting argument — "it is published public API, so it has callers you cannot grep" — is WRONG
here. Those callers belong to crates.io `tldr-core` ≤ `0.4.0`, a different artifact. This tree is
`0.4.1-fork.1` and is not in the index. Measured: GitHub code search for `"Emasoft/tldr-code"` in
a `Cargo.toml` returns **0**, the fork has **0** forks, upstream `"parcadei/tldr-code"` returns
**5** (the non-zero control proving the query works). Stated at its true strength: this fork has
no **discoverable public** library consumers. GitHub code search cannot see private repos,
unindexed files, path dependencies on a local clone, vendored copies, or `[patch]` entries — so
"0 results" is not "0 consumers". It is enough to decide this card and it is not a fact to quote
onward as established. Its consumers, so far as anything can show, run the `tldr` binary.
What actually argues against deletion is **divergence cost**: this fork's value depends on
tracking upstream, and every deletion is a merge conflict forever after. That standard is
recorded on TRDD-V11BVG55 and must be applied consistently, including against changes that have
already shipped.

**3. WIRE IN is large.** 176 call sites plus every command's output schema would have to carry an
issues section. It is also arguably upstream's architectural call, not a fork's to make
unilaterally.

## What

Pick ONE and record the reasoning:

- **WIRE IN** — route command file reads through `read_source_file_or_skip` and surface
  `EncodingIssues` in each command's output. Fixes the 73 SILENT and 25 PANIC sites. Large; needs
  its own staged plan and almost certainly an upstream conversation.
- **RETIRE** — delete `pub mod encoding`. Cheap in-tree, but pays divergence cost forever and
  discards the only code that addresses the table above.
- **LEAVE AS-IS, documented** — keep the module as an available public utility and add a doc note
  saying no in-repo command routes through it. Costs nothing, changes nothing, and leaves the 73
  SILENT / 25 PANIC sites unaddressed — so this option is only honest if the read-path robustness
  problem is split out into its own card rather than dropped.

## Acceptance

- [x] One of the three options is chosen, with the reasoning recorded in this card's STATE block.
      — LEAVE AS-IS, DOCUMENTED. Two eliminations recorded with their evidence.
- [x] A separate card exists for the 73 SILENT + 25 PANIC read sites — that defect is real
      whatever happens to this module. — **TRDD-BKALIK1B**, filed unconditionally rather than as
      a checkbox contingent on this card's branch.
- [x] `pub mod encoding` carries a doc note stating that no in-repo command routes file reads
      through it, so a reader does not mistake it for the sanctioned read path. — Placed in
      `encoding.rs`'s own `//!` block, NOT as a `//` comment beside the `pub mod` line in
      `lib.rs`: the audience is whoever reads the public API, and a `//` comment never reaches
      rustdoc. `lib.rs` keeps a one-line pointer so the export list is not silent about it.
- [x] TRDD-7X459MTO's acceptance line 2 is marked permanently unsatisfiable, citing this
      decision: no command consumes `EncodingIssues`, so there is no issues section for a
      `tldr structure` run to list a UTF-16 file in.

## Approval log

- 2026-09-06T04:14:07+0200 — Filed by the session Claude under the user's 2026-09-05 directive to
  decide from verified facts. Filing only; no option chosen and no code changed.
- 2026-09-06T04:52:00+0200 — COMPLETED. All four acceptance boxes met: the decision is recorded
  (LEAVE AS-IS, DOCUMENTED, with both eliminations and their evidence), the doc note is placed in
  `encoding.rs`'s `//!` block, TRDD-BKALIK1B carries the read-path defect independently, and
  TRDD-7X459MTO's acceptance line 2 is struck as permanently unsatisfiable.
  Closed the same session it was finished. It had been left at `column: todo` with every box
  ticked — a column that asserts "approved, designed, not started" over finished work, which is
  indistinguishable on the board from an abandoned card.
  **One conclusion of this card was later falsified and the correction belongs here**, since a
  terminal card must not leave a wrong premise standing: its "WIRE IN means 176 call sites" was
  wrong for the parse path. `parse_file_with_lang` is the single chokepoint every parse-based
  command goes through, so encoding-awareness there is ONE site, and TRDD-BKALIK1B shipped
  exactly that. The LEAVE-AS-IS verdict still stands — the fix reused the pre-existing
  `TldrError::EncodingError` rather than the `encoding` module, so the module's fate is unchanged
  — but a future reader must not inherit the 176 figure as a reason not to try.
