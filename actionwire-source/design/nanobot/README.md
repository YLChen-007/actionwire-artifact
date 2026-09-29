# nanobot v0.1.4.post5 Pipeline Adaptation

nanobot is analyzed at an explicit snapshot:

- source: `benchmark/python/nanobot`
- revision: `337c4600f3d78797bb4ed845b5a02118c7ac2d00`
- CodeQL DB: `codeql-db/nanobot-db`
- output: `output/nanobot`
- GT inventory: `design/nanobot/groundtruth/summary-reported.md`
- curated GT bundles: `design/nanobot/groundtruth/new-vuls` (16 oracle-referenced report IDs; symlinks only)
- acceptance oracle: `design/nanobot/nanobot-v0.1.4.post5-acceptance.json`

```bash
python -m src.pipeline --project nanobot infer-gates
python -m src.pipeline --project nanobot infer-call-chains
python design/nanobot/call-chain/debug/script/count_detected_call_chains.py
python -m src.pipeline --project nanobot infer-gate-semantics
python -m src.pipeline --project nanobot infer-call-chain-semantics
```

## Handler, source, and sinks

Concrete `Tool` subclasses under `nanobot/agent/tools/` are rooted at `execute(...)`; the abstract `Tool.execute`, tool
registry, and universal dispatcher are excluded. Sources are concrete handler parameters other than `self`, `cls`, and
framework `kwargs`. Audited class names are recovered as registered names such as `ExecTool -> exec` and
`ReadFileTool -> read_file`; unknown concrete subclasses retain their class name for auditability.

The shared sink catalog covers file and HTTP operations. `asyncio.create_subprocess_exec` and
`asyncio.create_subprocess_shell` each map to a process-spawn capability card. Each current sink point has exactly one
terminal constraint, including the three structural chains that legitimately have no eligible gate.

Generic HTTP/SSRF sinks select only their destination URL. The revision-pinned `web_search` adapter is an exact
payload exception: `_search_brave`, `_search_searxng`, and `_search_jina` send the model-controlled search query in
`client.get(..., params=...)` while their URLs are fixed or configured. The mapping is constrained by project, file,
scope, receiver, method, and named argument; it does not make arbitrary HTTP `params` values sensitive.

## Revision-pinned ground truth

All 16 unique source reports are represented once. Shell-chain, comment-tail/workspace, and wrapper-prefix gaps are
rebased to the current `ExecTool` sink and retain the existing line-83 policy gate while keeping four missing semantic
controls explicit. Login-shell environment behavior and MCP resource/prompt wrappers are not present in the pinned
v0.1.4.post5 source; WebUI, provider-response image fetching, and WhatsApp bridge findings are classified outside the
model-facing handler source.

## Independent handler-entry and sink inventories

Run the project-owned launchers from the repository root:

```bash
python design/nanobot/handler-entry/debug/scripts/generate_handler_entry_data.py
python design/nanobot/sink/debug/scripts/generate_sink_data.py
```

The handler inventory contains 11 current entries and covers 6/14 raw handler-entry GT rows. The eight uncovered rows
are the revision-stale MCP resource/prompt wrapper entries, which are absent from the pinned source and are not
fabricated as handlers. The sink inventory contains 30 callsites, 13 labels, and 20 files. It covers 7/23 raw sink GT
rows: one direct `create_subprocess_shell` match plus six explicit revision overrides from historical
`create_subprocess_exec` branches to the current `ExecTool.execute` shell sink. The login-shell disclosure row and 15
MCP wrapper rows remain uncovered because those behaviors do not exist at this revision.

The independent reports measure the raw D5 sections only. The revision-pinned acceptance oracle remains authoritative
for current handler-to-sink flows, expected gates/missing controls, and terminal sink-constraint cardinality.

Canonical acceptance proves 4/4 expected handler/sink flows, 4/4 existing gates, and 7/7 structural expectations.
Stage 1 now emits 9 candidates and 6 eligible gates after adding `_resolve_path`; stage 2 emits 7 chains, 7 constraints,
and 3 zero-gate chains. The static refresh is build-slices-only, so the earlier 5/5 Stage 3 and assembled Stage 4
snapshots no longer prove current-catalog completeness; rerun both semantic stages before making that claim.

## Synthetic login-shell regression

`scripts/build_nanobot_login_shell_synthetic.py` deterministically copies pinned
`v0.1.4.post5` and minimally transplants the later reduced-environment login-shell shape:
the child environment preserves the real `HOME`, while the model-controlled command reaches
`asyncio.create_subprocess_exec(shell, "-l", "-c", command, ...)`. The derivative is labeled
`337c4600...+synthetic-login-shell-v1` and is never empirical-coverage eligible.

The production pipeline recovers the strict command-to-sink witness as chain
`C-5bf383cf67d0`; its controlled sink arguments include `command`. The dedicated CodeQL
fixture also requires `HOME`, `-l`, and `-c`, and rejects `--noprofile`/`--norc` controls.
This proves detector support for the transplanted source shape without changing the canonical
Nanobot revision or its `not-present-at-analysis-revision` classification.

```bash
python scripts/build_nanobot_login_shell_synthetic.py
bin/codeql test run --threads=1 --additional-packs=src/ql -- \
  src/ql/tests/nanobot_login_shell_synthetic
```

```bash
python scripts/test_nanobot_gt_coverage.py
python design/nanobot/call-chain/debug/script/render_gt_coverage.py
python design/nanobot/call-chain/debug/script/test_render_gt_coverage.py
```

The shared `python scripts/test_ql.py` gate also runs this oracle alongside the other adapters, including the shared
JavaScript/TypeScript pack's OpenClaw, NanoClaw, and LobsterAI project modules, without concurrent access to one database. Its
TypeScript fixture command explicitly uses `--threads=1` because queries share temporary test databases.

Generated coverage Markdown records the full repository-root command at its beginning. Regenerate generated reports;
do not hand-edit them. Semantic stages obtain the LLM credential only from `DEEPSEEK_API_KEY`.
## Zero-gate audit update

The transform detector now approves only the exact
`nanobot/agent/tools/filesystem.py::_resolve_path` signature. It requires handler-source input,
the return bridge through `_resolve`, and transformed output at the concrete filesystem receiver;
similar names and the same name in another file are fixture negatives. Other canonical Nanobot
paths remain valid audited filter/transform zeros rather than being inferred from an empty query.
