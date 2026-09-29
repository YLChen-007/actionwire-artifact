# LettaBot TypeScript adapter summary

The shared pipeline order is gates → call chains → gate semantics → call-chain semantics. Every resolved handler
continues into semantic analysis; the adapter's static handler, sink, chain, and boundary contracts below are unchanged.

The registry entry is `lettabot`, adapter `lettabot-ts`, source language `typescript`, CodeQL language
`javascript`, and query pack `src/ql-js`. The application revision is
`99c3b5dd73550fe0a4eac2ee31b1c3229ca9e550`; vendored dependency identities are Letta Code SDK v0.1.14 at
`ffa11df0a17e82e5ac45f6b9ad1dbf778af2ac48` and Letta Code v0.19.5 at
`627073228938862ddd072d07f4cd45b4190575e1`.

The shared pack also contains a synthetic two-vulnerability sink/bridge fixture guarded by
`isOpenClawProject()` and exact OpenClaw paths. LettaBot's identity and paths cannot match it, so this
adapter's results remain unchanged.

## Handler and source identity

`LettaBotModel.qll` keeps the literal local `manage_todo` object installed by `baseSessionOptions`. Its
`execute(_, args)` body is the handler and its second parameter is the source.

The same model now resolves the seven client-side default tools only when all of the following hold:

1. LettaBot's exact fallback list
   `Bash,Read,Edit,Write,Glob,Grep,Task,web_search,conversation_search` flows through `parseCsvList` and
   `ensureRequiredTools`;
2. `baseSessionOptions` forwards `this.config.allowedTools` beside the local tool registration;
3. the exact `vendor-source/letta-code-v0.19.5/src/tools/toolDefinitions.ts` object is exported as
   `TOOL_DEFINITIONS`;
4. the corresponding registry key's `impl` identifier names the exact one-parameter `args` function at the pinned
   implementation path.

This yields eight public source-bearing handlers: `manage_todo` plus `Bash`, `Read`, `Edit`, `Write`, `Glob`,
`Grep`, and `Task`. The nine allowlisted names remain independently visible through `projectToolBoundary`.
`projectToolInventoryEntry` excludes those boundary anchors, so the seven resolved implementations are counted
once and the server-side `web_search`/`conversation_search` boundaries never acquire synthetic sources.

## Sink and chain identity

Seven `LB-CODE-*` semantic sink definitions report the handler names and use exact effect-call witnesses:

- `Bash`: line 185 background `spawn` and line 252 foreground `spawnCommand`;
- `Read`: line 239 image `readImageFile` and line 251 text `fs.readFile`;
- `Edit`: line 210 `fs.writeFile`;
- `Write`: line 31 `fs.writeFile`;
- `Glob`: line 93 ripgrep `execFileAsync`;
- `Grep`: line 102 ripgrep `execFileAsync`;
- `Task`: line 484 background delegation and line 518 foreground `spawnSubagent`.

All paths are relative to `vendor-source/letta-code-v0.19.5/src/tools/impl/`. Each call must be directly owned by
the exact registered handler and must satisfy call-specific callee, receiver, argument-count, and argument-shape
constraints. The lower Node primitives in these files are excluded from generic shared labels, preventing a
semantic `Read`/`Write`/`Bash` witness from also becoming an unrelated OpenClaw-style primitive sink.

The controlled node is the registered handler's `args` parameter. Capability-specific facets record the effective
schema/handler fields, including both foreground/background selection and Task resumption identifiers. The ten
effect callsites are direct depth-1 semantic chains. `manage_todo` retains five depth-3 mutation chains through the
constrained `saveStore(path, store)` write. Expected static totals are therefore 15 canonical chains, 11 reachable
sink callsites/constraints, and seven handler-named semantic capability labels.

Capability cards are `lettabot.command-execution.md`, `lettabot.file-read.md`, `lettabot.file-edit.md`,
`lettabot.file-write.md`, `lettabot.file-enumeration.md`, `lettabot.content-search.md`, and
`lettabot.subagent-delegation.md`; the todo write continues to use `node.fs.write.md`.

## Acceptance and limits

The shared SameOrigin contract requires one model-facing handler source to reach both a retained
gate operand and the exact terminal sink facet. LettaBot's project predicates already bind the
source-bearing handler and checked value for their exact chains, so the common tightening does
not authorize generic helper-name matches or weaken the SDK-boundary negative fixtures.

`call/lettabot_gates.qll` adds an exact LettaBot gate catalogue rather than routing these handlers through the
OpenClaw-only generic predicate. It recovers 24 unique dominated checks: eight vendored required-parameter calls,
the Read binary guard, the Glob nonempty guard, five Edit value/precondition guards, four Task validation/allowlist
decisions, and seven todo action/ID/text/date checks. The gate query first binds the exact source-bearing handler and
semantic sink ID, then proves the selected call path; the independent call-chain query remains responsible for
facet-level taint. This avoids repeating the global taint closure for every gate while retaining handler, source,
sink, owner, and checked-value traceability.

The two `args.<old_string|new_string>.replace(/\r\n/g, "\n")` calls in Edit are deliberately excluded from the
transform-gate catalogue. They canonicalize line endings so matching and file output behave consistently, but do
not reject attacker-controlled content, constrain the writable path, or reduce the file-write capability. Merely
feeding a later correctness check or the write payload is insufficient to promote this generic rewrite to a
security gate.

Task's mode-specific required-parameter calls and allowlists are branch-confirmed. Snooze date parsing is likewise
branch-confirmed because it runs only for a non-null date. All other selected checks reject, throw, or dominate the
effect path directly. Dispatch/routing, unrelated normalization without a proven check/effect path, post-sink
handling, and SDK approval are excluded; `baseSessionOptions` selects `permissionMode: "bypassPermissions"`, for
which the pinned SDK auto-allows noninteractive tools.

The JavaScript fixture asserts eight handlers/sources, nine separate boundaries, ten semantic callsites, all 15
chains, representative gates from every handler family, and rejection of a same-named function under a different
vendored version. Real-database generators assert the exact handler/boundary sets and all 12 adapter sink inventory
witnesses (ten semantic branches plus todo read and write primitives). Adapter coverage requires the per-handler
chain cardinalities, 11 constraints, 24 unique dominance gates, zero transform gates, and zero slice failures;
the generated adapter report checks the resulting 34 exact chain-gate attachments and zero ungated chains.

No ground-truth JSON corpus exists for this snapshot. `groundtruth.status` remains `not-applicable`; no coverage
denominator is fabricated. `web_search` and `conversation_search` cannot become local chains until a revision-pinned
backend implementation is added.

Validation:

```bash
python scripts/test_lettabot_adapter.py
python scripts/test_ql.py --unit-only
bin/codeql query compile --additional-packs=src/ql-js src/ql-js/*.ql
python scripts/test_ql.py
python scripts/check_doc_drift.py --report
git diff --check
```
## Shared filter/transform detector contract

The TypeScript filter detector now evaluates LettaBot through the same registered-project entry
as every other adapter, including guarded `push/add/set`, reject-then-admit, and `Array.filter`
results. Each candidate must carry handler-source-to-check and admitted-collection-to-sink
evidence. The transform detector can surface generic review candidates, but `path.resolve`,
line-ending replacement, ordinary normalization, and output filtering are never confirmed by
name. Consequently the pinned LettaBot transform count remains a genuine audited zero.
The separately guarded OpenClaw-CN filter signatures cannot match LettaBot handlers or sources and
do not change its eligible filter output.
## Shared Mercury approval-sink isolation

The shared TypeScript catalog now recognizes Mercury's signature-constrained
`checkShellCommand(command) -> this.askHandler(...)` control-flow sink as `MA-COMMAND-APPROVAL`.
LettaBot's pinned handlers do not reach that receiver/enclosing signature, and the accompanying gate admission
is guarded by `isMercuryAgentProject()`, so LettaBot's semantic tool-sink contract remains unchanged.
