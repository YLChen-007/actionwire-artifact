# DroidClaw TypeScript four-stage adaptation summary

The shared order is gates → call chains → gate semantics → call-chain semantics. Every resolved handler
continues into semantic analysis under the adapter, capability, gate, and ground-truth contracts below.

## Identity, handler, and source

The project registry uses `droidclaw`, adapter `droidclaw-ts`, TypeScript source language, CodeQL `javascript`,
and query pack `src/ql-js`. `DroidClawModel.qll` requires the LLM decision and both audited action dispatchers from
the pinned snapshot. It first resolves literal cases from `executeAction`'s `switch (action.action)` and
`executeSkill`'s `switch (skill)`, where `skill` derives from `decision.skill ?? decision.action`, then exposes a
function only when the dispatcher passes its `action` or `decision` first parameter into a matching first formal
parameter. This yields exactly 20
source-bearing handlers and excludes ten parameterless or UI-elements-only cases. Unrelated switches, unresolved
callees, tests, and functions outside the two source files are not roots.

The shared pack also contains a synthetic two-vulnerability sink/bridge fixture guarded by
`isOpenClawProject()` and exact OpenClaw paths. DroidClaw's identity and paths cannot match it, so this
adapter's results remain unchanged.

## Sink and chain

The sink catalog defines 19 semantic actions named after their handlers rather than the generic ADB executor:
`executeTap`, `executeType`, `executeSwipe`, `executeLaunch`, `executePaste`, `executeScreenshot`,
`executeLongPress`, `executeClipboardSet`, `executeOpenUrl`, `executeSwitchApp`, `executeKeyevent`,
`executeOpenSettings`, `executeScroll`, `executePullFile`, `executePushFile`, `executeShell`, `copyVisibleText`,
`findAndTap`, and `composeEmail`. `executeDone` is retained as a source-bearing handler but has no external effect,
so it has no sink.

Each sink requires the exact enclosing handler signature and one primary-effect call selected by callee and, when
needed, a command discriminator. The controlled node is the handler's model-decision parameter; emitted facets
record the operation selector (`action.action` or `decision.action`) plus the action-specific target or payload.
Fifteen DroidClaw capability cards map the 19 labels to named device input, launch/navigation, clipboard,
capture, transfer, shell, and email capabilities. The generic `Bun.spawnSync` implementation is intentionally not
a sink.

The locked GT path remains:

```text
executeShell@actions.ts -> executeShell@actions.ts
```

The second `executeShell` label denotes the semantic sink attached to the physical
`runAdbCommand(["shell", ...cmd.split(" ")])` call at `src/actions.ts:703`. All 19 effectful handlers produce a
depth-1 handler-to-semantic-sink chain. Model-controlled operation or target selection is accepted even when a
particular field does not flow into the final ADB argv; this intentionally covers selection capabilities such as
paste, scroll, settings navigation, copy-visible-text, and find-and-tap.

## Gate detection and semantics

The shared TypeScript SameOrigin tightening does not change DroidClaw's direct gate identity:
`action.command` reaches both `!cmd` and the ADB shell command argument. The project predicate
already proves this exact handler-rooted flow, so unrelated action/config checks remain excluded
without changing the approved non-empty-command gate.

The revision-pinned detector emits 21 security-relevant gate candidates and attaches all 21 to their owning
semantic chains: 15 dominated rejecting conditions, 3 query-controlled collection filters, and 3
source-to-effect transforms. The dominated checks cover direct required-value rejection, coordinate validation,
the settings allowlist lookup, query-selected UI matching, and empty-selection rejection. The filter rows are the
two `copyVisibleText` query filters and `findMatch`'s query filter. The transforms are the complete
`executeType` shell-escaping chain (counted once), clipboard quote escaping, and pull-file basename extraction.

Functional rewrites are intentionally excluded: shell token splitting, query lowercasing, email extraction,
display normalization, and coordinate rounding do not by themselves constrain the advertised capability. Five
actions have no qualifying gate: swipe, launch, paste, screenshot, and scroll. Gate slicing resolves all 21
candidates without failure, and the chain assembler produces 21 ordered attachments.

## Ground truth

The revision-pinned vulnerability inventory accounts for all 1 GT handler reference, 1 sink, 2 gates, 0
cross-component edges, and 3 extraction records; it is intentionally separate from the public 20-handler/source
inventory. `if (!cmd)` is an existing inline early-return gate that checks only non-emptiness. The
approval or deny-by-default policy required before model-selected shell execution is absent and remains an
`expected-missing` record tied to the `command` facet.

The exact-chain oracle fails if the existing gate disappears, the sink constraint changes, or any detector claims
an approval gate at the defect anchor. Thus a structurally nearby input-validity condition cannot become false
security coverage.

The completed semantic stages contain 21 gate records (one reused and 20 regenerated) and 19 unique V3 chain
records, including 5 zero-gate records, with zero analysis or assembly failures.

## Validation and limits

```bash
python design/droidclaw/inventory/debug/scripts/test_generate_inventory.py
python design/droidclaw/call-chain/debug/scripts/test_render_gt_coverage.py
python scripts/test_droidclaw_gt_coverage.py
python scripts/test_ql.py --unit-only
python scripts/test_ql.py
python scripts/check_doc_drift.py --report
git diff --check
```

The handler fixture asserts 20 handlers, 20 sources, 19 named sinks and chains, exactly 15 dominated checks, 3
filters, and 3 transforms; it also asserts no `done` chain, no `Bun.spawnSync` sink, and absence of all ten
non-source handlers. Stage 3/4 reads credentials only from `DEEPSEEK_API_KEY`. The adapter performs no live
exploit or device command and does not claim coverage of excluded Android/server/web components.
## Shared filter/transform detector contract

The common TypeScript filter entry now covers all registered project models and supports guarded
admission, reject-then-admit, and `Array.filter` shapes. DroidClaw retains its three exact
query-controlled filter witnesses and three source-to-effect transforms through the existing
semantic-action bridges. Generic replacements, lowercasing, splitting, and basename-like
operations are not promoted outside those exact audited signatures.
OpenClaw-CN's new helper-owned signatures are dispatched only by its mutually exclusive project
identity; DroidClaw continues to use only `droidClawFilterRow` and the generic proven shapes.
## Shared Mercury approval-sink isolation

The shared TypeScript catalog now recognizes Mercury's signature-constrained
`checkShellCommand(command) -> this.askHandler(...)` control-flow sink as `MA-COMMAND-APPROVAL`.
DroidClaw's pinned handlers do not reach that receiver/enclosing signature, and the accompanying gate admission
is guarded by `isMercuryAgentProject()`, so DroidClaw's semantic action-sink contract remains unchanged.
