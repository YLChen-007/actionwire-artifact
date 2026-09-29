# QwenPaw v1.1.10 Pipeline Adaptation

QwenPaw is analyzed as a revision-pinned Python benchmark project:

- source: `benchmark/python/QwenPaw`
- revision: `6d1e936f1ba08ad2e0398367f8c27529e9d1d5df`
- CodeQL DB: `codeql-db/QwenPaw-db`
- output: `output/QwenPaw`
- GT inventory: `design/QwenPaw/groundtruth/summary-reported.md`
- curated GT bundles: `design/QwenPaw/groundtruth/new-vuls` (15 oracle-referenced report IDs; symlinks only)
- acceptance oracle: `design/QwenPaw/qwenpaw-v1.1.10-acceptance.json`

The four stages are:

```bash
python -m src.pipeline --project QwenPaw infer-gates
python -m src.pipeline --project QwenPaw infer-call-chains
python design/QwenPaw/call-chain/debug/script/count_detected_call_chains.py
python -m src.pipeline --project QwenPaw infer-gate-semantics
python -m src.pipeline --project QwenPaw infer-call-chain-semantics
```

## Handler, source, and runtime edges

The adapter roots functions actually referenced by the `tool_functions` dictionary inside
`QwenPawAgent._create_toolkit`, plus the concrete memory-manager methods returned by `list_memory_tools()` and passed
to `toolkit.register_tool_function`. At this revision both `ReMeLightMemoryManager` (the default backend) and optional
`ADBPGMemoryManager` expose `memory_search`; they are two profile-specific concrete handlers under one tool name.
Every parameter except `self`/`cls` is a model-controlled source. Other memory helpers, the universal agent loop, and
functions that are neither in `tool_functions` nor returned by `list_memory_tools()` are not roots.

The Windows shell branch passes `_execute_subprocess_sync` to `asyncio.to_thread`. The adapter supplies that exact
callback edge and maps arguments after the callback position to callback parameters. It does not connect unrelated
callbacks merely because they have a compatible name or signature.

`ToolGuardMixin._decide_guard_action` executes the policy engine before concrete dispatch. Its `guard(tool_name,
tool_input, ...)` call is therefore emitted with `[pre-handler]` provenance and attached to the concrete handler owner.
This preserves execution order without inventing a handler-to-guard call edge.

## Sink constraints and GT decisions

Current structural chains reach process, browser, file, and network capabilities. Every distinct sink callsite has one
capability constraint and no sink is inserted into `gates[]`. The pinned GT oracle represents all 15 unique
`summary-reported.md` entries exactly once:

- model-path dimensions: jq `$ENV` shell-rule gap, mixed-origin request-context bypass, and managed CDP local control;
- explicit missing controls: jq environment-object handling, trusted request-context provenance, and CDP peer auth;
- remaining configuration/HTTP reports are explicitly out of the handler-to-sink model instead of being matched to a
  similarly named tool.

## Independent handler-entry and sink inventories

The CowAgent-style inventory reports can be regenerated independently of the four-stage pipeline:

```bash
python design/QwenPaw/handler-entry/debug/scripts/generate_handler_entry_data.py
python design/QwenPaw/sink/debug/scripts/generate_sink_data.py
```

At the pinned revision, the handler query enumerates 23 entries, including both concrete `memory_search` backend
profiles, and covers all 6/6 handler-entry GT rows. Seven of
the 13 GT JSON files have no `d5_tool_handler_entry` section and are reported explicitly without contributing rows.
The sink query enumerates 379 callsites across 55 labels and 179 files. It covers 10/17 sink GT rows: five direct
method-name matches and five audited revision overrides that bind wrapper/argument rows to the current
`subprocess.Popen` terminal. The remaining seven rows describe `connect_over_cdp`, stored/returned CDP URLs, or URL
disclosure rather than a concrete API modeled by `is_sink_af`; they remain visible as uncovered.

These inventory ratios do not replace the project acceptance oracle. The latter continues to check current
handler-to-sink reachability, gate expectations, zero-gate paths, and one capability constraint per current sink point.

Canonical static acceptance currently proves 5/5 expected handler/sink flows, 3/3 existing gates, 3/3 structural
expectations, and both required `memory_search` handler identities against the pinned DB. Stage 1 now emits 153
candidates and 28 eligible gates: the two established filter UIDs remain, and `_collapse_embedded_newlines` adds one
approved transform UID while generic replacements stay review-only. Stage 2 still emits 15 chains and 10 constraints.
The static refresh is build-slices-only, so the earlier Stage 3/4 semantic snapshots no longer prove current-catalog
completeness; rerun both semantic stages before making that claim.

Regenerate and test from the repository root:

```bash
python scripts/test_qwenpaw_gt_coverage.py
python design/QwenPaw/call-chain/debug/script/render_gt_coverage.py
python design/QwenPaw/call-chain/debug/script/test_render_gt_coverage.py
```

The shared `python scripts/test_ql.py` gate also runs this oracle alongside the other adapters, including the shared
JavaScript/TypeScript pack's OpenClaw, NanoClaw, and LobsterAI project modules, in a deterministic sequential order. The
TypeScript fixture run explicitly uses `--threads=1` so queries never compete for one temporary database.

The generated `call-chain/debug/gt-coverage.md` begins with its complete reproduction command. Generated CSV/Markdown
must be regenerated, not edited by hand. LLM stages read credentials only from `DEEPSEEK_API_KEY`.
## Zero-gate audit update

`src/qwenpaw/agents/tools/shell.py::_collapse_embedded_newlines` is the sole newly approved
QwenPaw transform signature. Its result must reach the pinned synchronous or asynchronous
subprocess sink. Inner `replace` calls, conflict-name rewrites, and other generic `replace`/`re.sub`
operations remain `needs-review`; they do not become eligible by API name alone. The two existing
filter UIDs retain exact revision-pinned helper bridges for dynamic archive/search dispatch.
