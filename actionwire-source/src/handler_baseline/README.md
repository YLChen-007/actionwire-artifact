# Blind Claude Code Per-Handler Baseline

Run the complete blind experiment from the repository root:

```bash
python -m src.handler_baseline --all --workers 4 --timeout 3600
```

The deterministic universe is every row in the registered projects'
`handler-entry/debug/tool-handler-entries.csv` files. Each row receives an isolated
Claude Code session backed by `deepseek-v4-flash`. Bubblewrap mounts only the selected
project source at read-only `/workspace`; ground truth, ClawGap output, the manuscript,
other benchmark projects, Git metadata, and user Claude settings are absent. The only
tools are `Read`, `Grep`, and `Glob`.

Use `--inventory-only` to preview the universe and `--only HB-...` for a focused smoke
run. A full run stores resumable per-trial artifacts and publishes `inventory.jsonl`,
`trials.jsonl`, `findings.jsonl`, `manifest.json`, `blind-freeze.json`, and
`baseline-results.md` under `output/cross-project/claude-handler-baseline/`. The Markdown
report begins with its complete repository-root reproduction command. Partial `--only`
runs use the same output contracts but must not be interpreted as a full-corpus result.

For the ground-truth-conditioned handler-recall experiment, select only current handlers
referenced by curated reports:

```bash
python -m src.handler_baseline --all --ground-truth-handlers --inventory-only
python -m src.handler_baseline --all --ground-truth-handlers --workers 4 --timeout 3600
```

The current frozen selection contract is 46 curated reports, 48 report-handler bindings,
and 26 unique handler trials across 11 projects. Every binding must resolve as `exact`,
`source-confirmed-drift`, or the LettaBot `markdown-fallback`; ambiguous or unmapped
bindings fail closed before Claude starts. The controller records the ground-truth hashes
and exact `GT-*`/handler-to-`HB-*` mapping in `ground-truth-handler-scope.json`, but the
Bubblewrap-isolated discovery prompt still contains only the ordinary handler inventory
row. Outputs default to
`output/cross-project/claude-handler-baseline-ground-truth-handlers/`.

This selected experiment measures label-blind recall conditional on being given a curated
handler root. It cannot estimate whole-inventory precision or discovery performance.

For the precision-first comparison, keep the same blind handler selection but request only
the best zero, one, or two source-proven high-confidence vulnerabilities per handler:

```bash
python -m src.handler_baseline --all --ground-truth-handlers \
  --report-policy most-credible-vulnerabilities \
  --workers 4 --timeout 3600
```

This policy never fills the second slot with a medium/low candidate. Every vulnerability must
prove model control, handler-rooted reachability, realistic supported preconditions, a concrete
security boundary, an unauthorized capability delta beyond intended/equivalent behavior, the
complete gate defect, and a concrete sink effect. Trigger spellings of one invariant are merged.
The response contract enforces one or two contiguous credibility ranks and publishes
`vulnerabilities.jsonl` under
`output/cross-project/claude-handler-baseline-credible-vulnerabilities-ground-truth-handlers/`.
The legacy `all-findings` policy and output directory remain separate.

The top-two constraint has a graph-derived maximum coverage of 34 of the current 46 reports
(73.9%): several curated reports share a handler, and one vulnerability may still match at most
one report. This ceiling is reported separately from observed recall.

Only after a full blind freeze may ground truth be read:

```bash
python -m src.handler_baseline --all --ground-truth-handlers \
  --ground-truth-only --timeout 900
```

This compares frozen findings with the current `design/*/groundtruth/new-vuls` corpus.
Model-proposed matches remain `pending-manual-review`. Copy the generated review template
to `ground-truth-manual-reviews.jsonl`, replace every placeholder with independent
source-backed reasoning for all nine verification facets, and rerun the audit. Positive
matches require every facet and a one-finding-to-one-report assignment; only explicitly
confirmed same-invariant matches contribute to strict recall.

For the precision-first output, include its policy so the CLI selects the versioned directory:

```bash
python -m src.handler_baseline --all --ground-truth-handlers \
  --report-policy most-credible-vulnerabilities \
  --ground-truth-only --timeout 900
```

The audit also creates `vulnerability-manual-review-template.jsonl`. Copy completed rows to
`vulnerability-manual-reviews.jsonl`, classify each vulnerability as `tp`, `fp`, `duplicate`,
or `unknown`, provide source anchors, and rerun the audit. It then reports the conditioned
validity rate, pending reviews, prior false-positive recurrence annotations, and comparison with
the preserved legacy adjudication. This validity rate does not estimate full-inventory precision.

Provider usage is recorded per call as uncached input, cache creation input, cache-read
input, output, total input, and total tokens. Missing provider usage remains unavailable
rather than being zero-filled. Detection and post-hoc adjudication usage are reported
separately; the experiment never converts tokens to monetary cost.
