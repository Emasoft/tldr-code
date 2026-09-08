---
trdd-id: N1VHRIN6
title: A second intermittent tldr-cli lib failure at the default thread count was seen once and never named
column: backburner
created: 2026-09-08T23:14:51+0200
updated: 2026-09-08T23:14:51+0200
current-owner: main-session
task-type: spike
scope: project
min-approval-requirement: none
labels: [flaky-test, concurrency]
---

# A second intermittent tldr-cli lib failure at the default thread count was seen once and never named

## What is known

- TRDD-6CKB3RRH (archived 2026-09-08 under `design/archived/`) measured `cargo test -p tldr-cli --lib`
  at HEAD `afe7838`: `1438 passed; 0 failed` at `--test-threads=1`, two failures at the default
  thread count. One was `test_l2_all_engines_budget`, fixed in `228ad09` by deleting its wall-clock
  assert. The other's NAME was captured in only one of that card's three default-threads runs and
  is not recorded anywhere on the board.
- After `228ad09`, one default-threads `--lib` run on 2026-09-08 gave `1438 passed; 0 failed`,
  cargo exit 0. One clean run does not show the second failure is gone; it shows it is intermittent.
- Filed so that a known-but-unnamed defect does not vanish into an archived card.

## Next action

Run `cargo test -p tldr-cli --lib` at the default thread count, n>=5, after snapshotting the process
table to a file and confirming no other cargo run in this repo is live (a concurrent runner can
fabricate lib-target failures — see the archived card's STATE block). Capture every `^---- ` line.
If any test fails, name it here, move this card to `todo`, and file its fix as its own card. If all
five runs are clean, close this card as `complete` with the five `test result:` lines quoted.

## Acceptance

- [ ] Five default-threads `--lib` runs recorded with their `test result:` lines and any `^---- `
      failure names, each with its concurrency condition stated.
- [ ] Either the second failure is named here, or five clean runs are quoted and the card closes.
