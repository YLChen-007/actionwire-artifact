# poco-agent v0.5.4 Pipeline Adaptation

poco-agent uses the following pinned analysis identity:

- source: `benchmark/python/poco-agent`
- revision: `7a61cb9f0e871f75f5623448f849f1e3d1958e35`
- CodeQL DB: `codeql-db/poco-agent-db`
- output: `output/poco-agent`
- GT inventory: `design/poco-agent/groundtruth/summary-reported.md`
- curated GT bundles: `design/poco-agent/groundtruth/new-vuls` (6 oracle-referenced report IDs; symlinks only)
- acceptance oracle: `design/poco-agent/poco-agent-v0.5.4-acceptance.json`

```bash
python -m src.pipeline --project poco-agent infer-gates
python -m src.pipeline --project poco-agent infer-call-chains
python design/poco-agent/call-chain/debug/script/count_detected_call_chains.py
python -m src.pipeline --project poco-agent infer-gate-semantics
python -m src.pipeline --project poco-agent infer-call-chain-semantics
```

## Handler, injected clients, and terminal capabilities

Roots are limited to functions decorated with `@tool("...")` inside `channel_runtime.py` and `memory.py`. The decorator
string is the tool name and only `args` is a model-controlled source. Factory functions, executor-manager HTTP routes,
and similarly named control-plane methods are not roots.

Nested tools invoke methods on `runtime_client` and `memory_client`, which are injected into their enclosing factories.
The adapter connects only those handles to `ChannelRuntimeClient`/`MemoryClient`. Positional arguments skip `self`;
named arguments use `getArgByName`, which is required for keyword-only methods such as
`search_memories(self, *, query)`. Dict/list/tuple value-to-container steps preserve model-controlled fields when tools
pack payloads into JSON.

`client.post` in channel runtime and `client.request` in memory are project-scoped network-egress sinks. Their three
concrete callsites map to the corresponding httpx capability cards: `ChannelRuntimeClient._request`,
`ChannelRuntimeClient.download_artifact`, and `MemoryClient._request`. Unlike generic HTTP/SSRF sinks, which track only
the positional/keyword URL, these exact internal-client callsites opt into the shared `rpc-payload` role for their
named `json` argument. The mapping is constrained by project, file, `_request` scope, receiver, method, and argument
name; it does not make arbitrary `post(json=...)` bodies sensitive. The project-model fixture requires both
`post:json` and `request:json` to flow through this shared role-aware predicate. The current static result contains 22
structural chains over 21 unique handler/sink pairs and exactly 3 constraints.

## Ground-truth scope

All six unique reports are represented by four deduplicated dimensions. Every report originates in an HTTP/control-plane
input rather than a model-facing `@tool` argument: executor-manager task impersonation, executor callback URL SSRF,
workspace user-ID trust, and cross-user capability resolution. The oracle records them explicitly as out-of-model and
does not fabricate a handler-to-sink flow. Separately, 21 genuine model-tool structural expectations must remain present,
so an all-out-of-model GT inventory cannot make a broken adapter pass vacuously.

## Independent handler-entry and sink inventories

Run the same project-owned inventory interface used by CowAgent:

```bash
python design/poco-agent/handler-entry/debug/scripts/generate_handler_entry_data.py
python design/poco-agent/sink/debug/scripts/generate_sink_data.py
```

The handler query enumerates 25 current entries. The sink query enumerates 88 callsites across 23 labels and 42 files.
All six raw GT files omit both `d5_tool_handler_entry` and `d5_sink_points`, so both reports show `0/0 (n/a)` and list
the missing sections explicitly; they do not claim vacuous 100% coverage or fabricate GT rows. This agrees with the
oracle classification that the six reports reduce to four HTTP/control-plane dimensions outside the model-facing
tool-source boundary. The separate 21-item structural oracle still protects the real `@tool` adapter from vacuous
success.

Stage 1 now emits 62 eligible gates, including the two `_extract_messages` filter UIDs; stage 2 emits 22 chains and
3 constraints. The acceptance layer additionally checks
every emitted chain's ordered gate representation and every structural sink's constraint capability/card metadata.
The static refresh is build-slices-only, so the earlier 60/60 Stage 3 and assembled Stage 4 snapshots no longer prove
current-catalog completeness; rerun both semantic stages before making that claim.

```bash
python scripts/test_poco_agent_gt_coverage.py
python design/poco-agent/call-chain/debug/script/render_gt_coverage.py
python design/poco-agent/call-chain/debug/script/test_render_gt_coverage.py
```

The shared `python scripts/test_ql.py` gate also runs this oracle alongside the other adapters, including the shared
JavaScript/TypeScript pack's OpenClaw, NanoClaw, and LobsterAI modules, and keeps all fixed-DB jobs sequential.

Generated coverage artifacts must be regenerated and begin with the complete root-relative command. Stage 3 reads the
LLM credential only from `DEEPSEEK_API_KEY`; no credential is stored in source, manifests, or reports.
## Zero-gate audit update

The shared filter detector now recognizes `_extract_messages`' reject-and-`continue` loop. The
`role` and `content` `isinstance` checks conditionally admit normalized fields into the
`messages` list, and that list is proven to reach `MemoryClient._request`'s JSON payload. An
unrelated formatting collection is a fixture negative. Generic whitespace trimming remains
outside the approved transform table.
