# Mercury Agent TypeScript four-stage adaptation summary

The shared order is gates → call chains → gate semantics → call-chain semantics. Every resolved handler
continues into semantic analysis; the adapter, sink, gate, and ground-truth facts below are revision-pinned.

## Project identity and handler model

The registry entry is `mercury-agent`, adapter `mercury-agent-ts`, source language `typescript`, CodeQL language
`javascript`, and query pack `src/ql-js`. Its source, database, output, and design roots are
`benchmark/typescript/mercury-agent`, `codeql-db/mercury-agent-db`, `output/mercury-agent`, and
`design/mercury-agent`.

The project model constrains handlers, sources, and bridges. Sink definitions are shared across every TypeScript
benchmark and depend on imported API/receiver/enclosing signatures rather than `isMercuryAgentProject()`; GT
acceptance selects Mercury's exact reachable witnesses from the broader sink audit.

The shared pack also contains a synthetic two-vulnerability sink/bridge fixture guarded by
`isOpenClawProject()` and exact OpenClaw paths. Mercury's identity and paths cannot match it, so this
adapter's results remain unchanged.

`MercuryAgentModel.qll` requires the pinned capability registry plus shell factory symbols. A handler exists only
when a literal `this.tools.<tool>` property is assigned a `create*Tool(...)` result inside `registerAll()` or
`registerSpotifyTools()`, and the factory definition returns the matched `execute(args)` body. This excludes
unregistered same-shape objects and generic `execute` functions.

## Sinks, bridges, and capability constraints

The GT-backed terminal families are:

- `child_process.spawn` in the signature-constrained `executeCommand(command, cwd, timeoutMs)` callback;
- `this.askHandler(\`Run command: ${trimmed}\`)` in `checkShellCommand(command)`, constrained by receiver,
  enclosing signature, and command-derived argument;
- imported Node filesystem read, write, and delete primitives inside registered filesystem handlers or the
  signature-constrained `saveSkill(name, content)` helper;
- `fetch` in registered web/skill handlers or `githubRequest(path, options)`;
- the `ai.generateText({tools: ...})` sub-agent capability-exposure boundary.

Controlled facets include command, URL, path, content, and tool-map. `MA-COMMAND-APPROVAL` uses the
`mercury.command-approval.md` user-consent card; `child_process.spawn` remains a distinct later effect for reports
that retain it as their terminal sink. The model adds narrow DI/lifecycle bridges
for `skillLoader.saveSkill`, `permissions.checkShellCommand`, `permissions.checkFsAccess`, GitHub request
construction, and the supervisor-to-sub-agent lifecycle. `parseYaml -> meta.name -> saveSkill(name, content)` is
modeled as a local taint step so both path and content facets reach the concrete skill write. There is no generic
`run`, `spawn`, `fetch`, or `execute` name closure.

## Gates and ordered assembly

Revision-pinned inline and policy-call rows now require an explicit handler-rooted flow to the
checked operand in addition to the existing source-to-sink proof. This prevents a helper result
or configuration value from being treated as protection for the model-controlled spawn/file
facet merely because it appears on the same structural chain. The learned GT-slice records
excluded and rebound rows separately instead of silently retaining them.

The JavaScript pack detects inline early-return gates, direct policy calls, and transforms in
`permissions.ts`. Helper-definition provenance is preserved for `checkShellCommand`, `matchPattern`,
`hasPathBeyondCwd`, `findScope`, `findTempScope`, and `splitShellSegments`. Filesystem-policy transforms at
`permissions.ts:394` are eligible on filesystem chains, while the read-file size limit remains a distinct
source-dependent gate. For `checkShellCommand`, an audited parameter-level admission reconnects the exact
`command` DI formal to `matchPattern(segment, ...)`, `hasPathBeyondCwd(segment)`, and
`allSegmentsSafeRead`; it does not generalize to arbitrary same-function conditions.

The shared sink query audits 179 production callsites, including all 13 pinned Mercury adapter witnesses; 5 GT
references map to two concrete GT locations. The static result contains 42 raw gate candidates, 17 stable catalog
gates, zero slice failures, 14 chains, 14 unique constraints, 35 eligible chain-gate rows, and seven zero-gate
chains. The additional shared-catalog chains do not alter 5/5 sink-reference or 27/27 gate acceptance. Gate order is
assembled per exact structural chain rather than by global symbol occurrence.

The prior 13-chain Stage 4/5 semantic baseline is superseded by the shared catalog. A new full `all` run is required
before semantic record counts, reuse, or normalized digests are cited as current.

## Revision-pinned ground truth

`inventory/mercury-agent-groundtruth-lock.json` locks all 5 current reports and the aggregate corpus digest. The generated
inventory accounts for all 5 handler, 5 sink, 27 gate, 5 cross-component, and 10 extraction records. The
oracle requires exact handler/sink locations, the controlled facet, one concrete constraint, and—where applicable—
the helper definition span in the TypeScript slice.

Current coverage is 5/5 sink references and 27/27 eligible gate records. Four report records terminate at the
approval callback and one at the process-spawn primitive; report-specific inventory mapping preserves both sink
families instead of assigning every `run_command` gate to one global endpoint.

## Validation and limits

```bash
python design/mercury-agent/inventory/debug/scripts/test_generate_inventory.py
python design/mercury-agent/call-chain/debug/scripts/test_render_gt_coverage.py
python scripts/test_mercury_agent_gt_coverage.py
python scripts/test_ql.py --unit-only
python scripts/test_ql.py
python scripts/check_doc_drift.py --report
git diff --check
```

Stage 3/4 reads only `DEEPSEEK_API_KEY`. The adapter performs no live exploitation and does not describe the
51-handler inventory as exhaustive sink coverage beyond the locked GT dimensions.
## Shared filter/transform detector contract

The TypeScript filter detector now evaluates every registered project model with the same
same-origin admission proof. Mercury Agent's zero filter result is valid only after all 14
canonical witnesses are audited. Transform eligibility remains exact: filesystem `resolve`
calls are bound to the registered capability files, the policy normalizer to
`permissions.ts:394`, and `splitShellSegments` to its pinned permission path. A generic
`path.resolve` or similarly named call is review-only.
The separately guarded OpenClaw-CN filter signatures do not participate in Mercury Agent's project
model, so its detector output remains unchanged.
