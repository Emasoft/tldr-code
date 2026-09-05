export const meta = {
  name: 'tldr-scan-and-fix-wave',
  description: 'Scan one wave of line-budgeted batches with tldr-navigating workers, fix verified defects in place, evidence-gate every hunk, and consolidate the run',
  phases: [
    { title: 'Scan', detail: 'one worker per batch: read once, refute, fix safe defects, write <batch>.md + <batch>.jsonl' },
    { title: 'Verify', detail: 'one worker per edited batch: judge each hunk; a fix with no pasted tldr evidence is SKIPPED, not kept' },
    { title: 'Consolidate', detail: 'one agent reads every report of the run and writes SUMMARY.md (final wave only)' },
  ],
}

// ONE WAVE PER INVOCATION. The build/test gate that follows a wave is a shell
// command, and workflow scripts have no shell — so the script stops at the end
// of a wave and returns `edited` + `nextWaveStart`; the coordinator runs
// `cargo check` and the targeted tests, then relaunches for the next wave.
// That is lesson 1 of TRDD-PX8JOJY4: a systemic break is caught after one wave
// instead of after all 220 batches. See SKILL.md for the coordinator loop.
//
// Prompts are NOT in this file. The coordinator reads references/prompts.md,
// extracts the three fenced blocks and passes them as args.prompts — so the
// prompts stay reviewable prose with their rationale next to them.

const {
  root,                 // repo root, absolute; never hardcoded
  runStamp,             // "YYYYmmdd_HHMMSS+ZZZZ" from the coordinator (scripts cannot call Date)
  batchDir,             // where make_batches.py wrote <id>.txt + index.json
  batches,              // index.json contents: [{id, kind, lines, nfiles}, ...]
  nSrc, nTest,          // fallback when `batches` is not passed
  waveStart = 0,        // index into the batch list this wave begins at
  waveSize = 24,        // batches per wave; the gate runs between waves
  pilot,                // {batch, tokens, seconds, fixes} — absent ⇒ this run is the pilot
  done,                 // [{id, e: [repo-relative edited files], c: [fixed, skipped, false_positive]}]
  prompts,              // {scan, verify, consolidate} from references/prompts.md
  knownPatterns = '',   // FALSE_POSITIVE themes distilled from the previous run (the learning loop)
  project,              // one sentence describing the codebase, for the worker prompts
  consolidate = false,  // true on the final wave only
  agentType = 'lean-worker',
  effort = 'medium',
} = args

// Fail fast on the two args whose absence would otherwise be silent: a missing
// runStamp bakes the string "undefined" into the report path, and a run whose
// reports land in `undefined-scan` cannot be resumed from them.
if (!root) throw new Error('args.root is required')
if (!args.reportDir && !runStamp) throw new Error('pass args.reportDir or args.runStamp')

const reportDir = args.reportDir || `${root}/reports/workflows/${runStamp}-scan`
const doneById = new Map((done || []).map(d => [d.id, d]))

const all = batches && batches.length
  ? batches.map(b => ({ id: b.id, kind: b.kind }))
  : [
      ...Array.from({ length: nSrc || 0 }, (_, i) => ({ id: 'b' + String(i + 1).padStart(3, '0'), kind: 'src' })),
      ...Array.from({ length: nTest || 0 }, (_, i) => ({ id: 't' + String(i + 1).padStart(3, '0'), kind: 'test' })),
    ]

// PILOT-FIRST (lesson 9). With no pilot record, this run is one batch: it is
// both the cost measurement and the parse check of the script itself, since a
// script the Workflow loader rejects passes `node --check` happily.
// A resumed batch returns its cached record without spawning an agent, so a
// pilot that landed on one would "measure" a run that never happened. Skip to
// the first UNDONE batch instead.
let start = waveStart
if (!pilot) while (start < all.length && doneById.has(all[start].id)) start++
const wave = all.slice(start, start + (pilot ? waveSize : 1))
const nextWaveStart = start + wave.length

const SCAN_SCHEMA = {
  type: 'object',
  properties: {
    batch: { type: 'string' },
    report_path: { type: 'string' },
    files_edited: { type: 'array', items: { type: 'string' } },
    counts: {
      type: 'object',
      properties: { fixed: { type: 'integer' }, skipped: { type: 'integer' }, false_positive: { type: 'integer' } },
      required: ['fixed', 'skipped', 'false_positive'],
    },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          file: { type: 'string' }, line: { type: 'integer' }, severity: { type: 'string' },
          status: { type: 'string' }, summary: { type: 'string' }, evidence: { type: 'string' },
        },
        required: ['file', 'line', 'severity', 'status', 'summary', 'evidence'],
      },
    },
  },
  required: ['batch', 'report_path', 'files_edited', 'counts', 'findings'],
}

const VERIFY_SCHEMA = {
  type: 'object',
  properties: {
    batch: { type: 'string' },
    kept: { type: 'integer' },
    reverted: { type: 'integer' },
    unevidenced: { type: 'integer' },
    notes: {
      type: 'array',
      items: {
        type: 'object',
        properties: { file: { type: 'string' }, line: { type: 'integer' }, verdict: { type: 'string' }, reason: { type: 'string' } },
        required: ['file', 'line', 'verdict', 'reason'],
      },
    },
  },
  required: ['batch', 'kept', 'reverted', 'unevidenced', 'notes'],
}

function fill(tpl, vars) {
  return Object.keys(vars).reduce((s, k) => s.split('{{' + k + '}}').join(vars[k]), tpl)
}

const TEST_NOTE = `THESE ARE TEST FILES. Additionally flag: tests that assert nothing or assert a tautology; tests that mock the very code they claim to test; tests that cannot fail; \`#[ignore]\` without a reason; assertions that pass for the wrong reason. Fix assertions to test the real behaviour when that is safe and local; never delete a test; never add a mock. Do NOT remove an \`#[ignore]\` unless the report line pastes the command output proving the test now passes — this whole wave is gated on the suite, not on your reading.`

function scanPrompt(b) {
  return fill(prompts.scan, {
    PROJECT: project,
    BATCH_ID: b.id,
    BATCH_KIND: b.kind === 'test' ? 'test files' : 'source files',
    BATCH_FILE: `${batchDir}/${b.id}.txt`,
    REPORT_MD: `${reportDir}/${b.id}.md`,
    REPORT_JSONL: `${reportDir}/${b.id}.jsonl`,
    TEST_NOTE: b.kind === 'test' ? TEST_NOTE : '',
    KNOWN_PATTERNS: knownPatterns || 'none recorded yet — this is the first run.',
  })
}

function verifyPrompt(r, b) {
  return fill(prompts.verify, {
    PROJECT: project,
    BATCH_ID: b.id,
    EDITED_FILES: r.files_edited.map(f => '- ' + f).join('\n'),
    SCAN_REPORT: r.report_path,
  })
}

phase('Scan')
log(`wave ${start}..${nextWaveStart} of ${all.length} batches${pilot ? '' : ' (PILOT — one undone batch, no fan-out until its cost is recorded)'}; ${doneById.size} already done`)

const results = await pipeline(
  wave,
  b => {
    const d = doneById.get(b.id)
    if (d) {
      return {
        batch: b.id,
        report_path: `${reportDir}/${b.id}.md`,
        files_edited: (d.e || []).map(p => `${root}/${p}`),
        counts: { fixed: d.c[0], skipped: d.c[1], false_positive: d.c[2] },
        findings: [],
        resumed: true,
      }
    }
    return agent(scanPrompt(b), { label: `scan:${b.id}`, phase: 'Scan', schema: SCAN_SCHEMA, agentType, effort })
  },
  (r, b) => {
    if (!r) return null
    if (!r.files_edited || r.files_edited.length === 0) return { scan: r, verify: null }
    return agent(verifyPrompt(r, b), { label: `verify:${b.id}`, phase: 'Verify', schema: VERIFY_SCHEMA, agentType, effort })
      .then(v => ({ scan: r, verify: v }))
  },
)

const finished = results.filter(Boolean)
const dropped = wave.filter((b, i) => !results[i]).map(b => b.id)
if (dropped.length) log(`DROPPED (agent died or was skipped): ${dropped.join(', ')}`)

const totals = { batches: finished.length, fixed: 0, skipped: 0, false_positive: 0, kept: 0, reverted: 0, unevidenced: 0, edited_batches: 0 }
const edited = new Set()
for (const r of finished) {
  totals.fixed += r.scan.counts.fixed
  totals.skipped += r.scan.counts.skipped
  totals.false_positive += r.scan.counts.false_positive
  for (const f of r.scan.files_edited || []) edited.add(f)
  if (r.verify) {
    totals.edited_batches++
    totals.kept += r.verify.kept
    totals.reverted += r.verify.reverted
    totals.unevidenced += r.verify.unevidenced
  }
}
log(`wave done: ${JSON.stringify(totals)}; dropped=${dropped.length}`)

let summary = null
if (consolidate) {
  phase('Consolidate')
  summary = await agent(
    fill(prompts.consolidate, {
      PROJECT: project,
      REPORT_DIR: reportDir,
      TOTALS: JSON.stringify(totals),
      DROPPED: JSON.stringify(dropped),
    }),
    { label: 'consolidate', phase: 'Consolidate', agentType, effort },
  )
}

// `edited` is the gate's input: the coordinator runs `cargo check` plus the
// targeted tests of these files BEFORE launching the next wave.
return {
  wave: { start, end: nextWaveStart, ids: wave.map(b => b.id) },
  nextWaveStart: nextWaveStart < all.length ? nextWaveStart : null,
  totals,
  dropped,
  reportDir,
  edited: [...edited].map(f => f.startsWith(root + '/') ? f.slice(root.length + 1) : f),
  summary,
}
