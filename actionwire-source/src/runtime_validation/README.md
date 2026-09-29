# Runtime trigger validation

`src.runtime_validation` runs one prompt through a real benchmark agent and decides whether a
revision-bound security issue reached its terminal runtime condition. Version 1 provides a generic
Python instrumentation core and a Hermes one-shot adapter. It does not execute the dangerous
effect: the matching sink call is recorded and intercepted immediately before process creation.

## CLI

Set the credential named by the project registry, then run from the repository root:

```bash
export DEEPSEEK_API_KEY='<credential>'
python -m src.runtime_validation \
  --project hermes-agent \
  --report CVE-2026-Device-Blocking-Expanduser-Bypass \
  --prompt 'Use read_file to read /dev/./zero.'
```

The prompt can instead be supplied with `--prompt-file` or standard input. `--attempts`,
`--timeout`, `--model`, `--base-url`, `--api-key-env`, and `--out-dir` override the default request
contract. Exit code 0 means `triggered`, 1 means `not-triggered`, and 2 means `inconclusive` or an
invalid request.

## Python API

```python
from src.runtime_validation import ValidationRequest, validate_prompt

run = validate_prompt(
    ValidationRequest(
        project_id="hermes-agent",
        report_name="CVE-2026-Device-Blocking-Expanduser-Bypass",
        prompt="Use read_file to read /dev/./zero.",
    )
)
print(run.verdict, run.artifact_dir)
```

`triggered` requires all declared events in order and under one invocation identity. A clean agent
run without that sequence is `not-triggered`. A timeout, source mismatch, malformed trace,
instrumentation failure, or transport error is `inconclusive`; these states never become negative
evidence.

## Oracle and evidence contract

Issue rules live under `design/<project>/runtime-validation/oracles/` and conform to
`schemas/runtime-trigger-oracle-v1.schema.json`. Each sidecar binds the registered analysis
revision, every relevant source file SHA-256, and the curated ground-truth SHA-256. Rules use a
closed vocabulary for handler arguments, gate returns, path normalization, sink payload relation,
and interception. Arbitrary expressions are not accepted.

For the initial Hermes issue, a successful trace proves that `_handle_read_file` received a
traversal spelling of a blocked device, `_is_blocked_device` returned false for the same raw path,
and `LocalEnvironment._run_bash` attempted the corresponding `subprocess.Popen`. The patched
`Popen` records `effect_intercepted` and raises before the shell process is created. The result is
runtime trigger evidence, not an observed denial of service.

Each run is published below
`output/<project>/runtime-validation/<report>/<run-id>/`. The bundle contains the prompt, request,
oracle snapshot, verified source binding, per-attempt JSONL events and redacted process output,
final result, and a manifest with a complete reproduction command and artifact hashes. Credential
values are never written; a final credential scan fails publication if a value remains.

## Tests

The deterministic suite uses a subprocess fixture and a local OpenAI-compatible fake model. The
integration case drives the real Hermes one-shot tool dispatcher and does not require network
access or a live credential:

```bash
python -m unittest src.runtime_validation.tests.test_runtime_validation -v
```

The normal CLI command above is the optional live `deepseek-v4-flash` smoke test.

## Canonical v15 training-regression campaign

The candidate-centric path is separate from the one-report prompt API above. Current intake reads
only source-confirmed `coverage-candidate/v7` rows from v15's explicit
`training-regression-candidates.jsonl` overlay and binds 61 unique
strict-matched candidate IDs (43 covered training reports, 76 report/candidate references). It generates
one declarative exploit/control replay case per candidate and accounts for every ID even when a
native project driver is unavailable. The previously published 100-candidate/37-report campaign
is historical runtime evidence and remains the input to its independent v3 upgrade; it is not a
held-out consumer. Generic and held-out consumers must continue to read `candidates.jsonl`, which is
byte-equivalent to `generic-candidates.jsonl`; the four fallback candidates are training-only.

Generate cases from the repository-bound canonical artifacts:

```bash
python -m src.runtime_validation generate-covered \
  --coverage-root output/cross-project/coverage-comparison \
  --out-dir output/cross-project/runtime-validation-covered-v2 \
  --model deepseek-v4-flash \
  --base-url https://api.deepseek.com/v1 \
  --api-key-env DEEPSEEK_API_KEY
```

Generation gives the model only candidate/GT/chain evidence and bounded source excerpts. Model
output is restricted to JSON tool arguments, a paired control, and a closed value relation. The
compiler supplies the project adapter, capability probe, fixture, ordered handler/gate/sink/effect
stages, effect policy, and all source/artifact hashes. Invalid or unsafe model output receives one
schema repair and then becomes an explicit `unsupported` case; executable expressions and unknown
adapter/probe/fixture names are rejected.

Run the generated native-dispatch replay campaign:

```bash
python -m src.runtime_validation run-campaign \
  --campaign output/cross-project/runtime-validation-covered-v2 \
  --attempts 3 \
  --jobs 4
```

This mode does not ask a live LLM to select a tool. A project adapter must submit the generated
tool call through that project's native registry/dispatcher. Each execution uses three paired
exploit/control attempts in a capability sandbox: process/approval/delegation effects are
intercepted, files are confined to a temporary root, HTTP/browser/messaging use local fixtures,
and DroidClaw uses a recording fake `adb`. Registered adapters without a source-bound native
driver fail closed as `unsupported`; they never fall back to a direct handler call or fabricated
trace.

The current source-bound native drivers cover AstrBot `astrbot_file_read_tool`, CowAgent `bash`,
`read`, `vision`, and `web_fetch`, Hermes Agent `read_file`, and nanobot `exec`. Other registered
project/tool pairs remain explicitly `unsupported` until their native dispatcher and terminal
effect can be isolated with the same evidence contract.

`--jobs` is recorded as requested campaign metadata. The current in-process native drivers execute
serially (`jobs_effective=1`) because their safe probes patch process-global Python runtime state;
parallel execution is not enabled until drivers move behind isolated subprocess boundaries.

Candidate dispositions are `runtime-confirmed`, `not-reproduced`, `inconclusive`, and
`unsupported`. The canonical output includes `cases.jsonl`, `execution-groups.jsonl`,
`candidate-results.jsonl`, per-execution attempt bundles, `campaign-summary.md`, and a hashed
manifest. Results describe deterministic tool replay only, remain post-hoc/ground-truth-informed,
and do not replace the blind 18/42 result.

## Universal all-candidate dynamic trigger

The all-candidate mode validates exactly the current generic artifact:
`output/cross-project/coverage-comparison/candidates.jsonl`. Intake freezes 78 unique IDs across
11 projects, with 41 wrong-check and 37 missing-check rows. It does not add the four
training-only overlay rows. Candidate, comparison, semantic IR, origin-audit, capability-card,
project revision, and source hashes must agree before provider synthesis starts.

Generation emits a `clawgap-dynamic-trigger-case/v1` case per candidate. The constrained model may
propose only tool arguments, a paired safe control, a reproduction prompt, a closed relation, and
an argument path. One deterministic repair is allowed. Native adapter, launch profile, fixture,
ordered observations, pre-effect interception, correlation identity, and verdict logic remain
compiler/reviewer-owned. The independent review command is deterministic and never asks the model
for a verdict.

Run the complete workflow from the repository root:

```bash
python -m src.runtime_validation generate-dynamic-trigger \
  --coverage-root output/cross-project/coverage-comparison \
  --candidates output/cross-project/coverage-comparison/candidates.jsonl \
  --out-dir output/cross-project/runtime-dynamic-trigger-all-candidates-v1 \
  --model deepseek-v4-flash \
  --base-url https://api.deepseek.com/v1 \
  --api-key-env DEEPSEEK_API_KEY
python -m src.runtime_validation review-dynamic-trigger \
  --campaign output/cross-project/runtime-dynamic-trigger-all-candidates-v1 \
  --model deepseek-v4-flash \
  --base-url https://api.deepseek.com/v1 \
  --api-key-env DEEPSEEK_API_KEY
python -m src.runtime_validation provision-drivers \
  --campaign output/cross-project/runtime-dynamic-trigger-all-candidates-v1
python -m src.runtime_validation run-dynamic-trigger \
  --campaign output/cross-project/runtime-dynamic-trigger-all-candidates-v1 \
  --attempts 3 \
  --jobs 4
```

This publication's canonical evidence is L1 native dispatch with three paired exploit/control attempts. Existing
subprocess drivers isolate Python and TypeScript runtimes, disposable homes/workspaces, loopback
fixtures, fake credentials, and pre-effect process/filesystem/browser/HTTP/messaging/ADB/subagent
interception. Forced-provider L2 evidence is not inferred from a native adapter name; a future L2 run
must register the real entrypoint/provider path and publish separate tier metadata. Live-model
selection is not part of this campaign.

The GT projection is a hard truth gate. The 46-row ledger is 43 eligible reports plus 3 boundary
`not-applicable` rows. Only 38 eligible reports have a strict candidate in this 78-row input; the
other 5 remain `candidate-missing`. The 43 eligible rows reference 61 unique strict candidate IDs,
only 57 of which are present. Consequently, 78/78 candidate processing and complete 46-row
accounting are possible, but a green 46/46 runtime-detection claim is impossible unless the
upstream candidate artifact is corrected first.

### L2 qualification

L2 launch-profile qualification is separate from the published L1 results. Ten non-Hermes profiles
declare the real entrypoint, provider boundary, input transport, disposable state, instrumentation
anchors, effect interceptors, and cleanup canary. A shared loopback provider serves exactly one
reviewed exploit/control tool call, and an entrypoint supervisor owns process-group isolation and
readiness.

```bash
python -m src.runtime_validation qualify-dynamic-trigger-l2 \
  --campaign output/cross-project/runtime-dynamic-trigger-all-candidates-v1 \
  --out-dir output/cross-project/runtime-dynamic-trigger-l2-qualification-v1
```

The current qualification accounts for all 78 candidates and all ten non-Hermes profiles, but every
row is explicitly `blocked`: the project-native config/input fixtures and full-entrypoint
instrumentation bridges have not yet passed launch qualification. Sixteen Hermes cases are retained
as `hermes-agent-l2-bridge-pending`; existing Hermes L1 or production-like evidence is not silently
promoted. Consequently, `run-dynamic-trigger-l2` exits with code 2 until every selected case has a
ready, same-invocation provider-to-pre-effect trace.

### Universal runtime L2 environment builder

The common builder is the project-self-test tier defined by
`design/common/runtime-validation-build-test-environment.md`. It covers exactly the twelve projects
in `src/projects/registry.py`, materializes each one in a disposable OverlayFS layer, starts the
loopback provider fixture inside the same network namespace as the real target, drives the
project-native input/provider boundary, verifies an interceptor event with `executed=false`, and
publishes the required per-project handoff bundle.

```bash
python -m src.runtime_validation build-runtime-l2-environment \
  --all \
  --out-dir output/cross-project/runtime-l2-environment-builder-v1 \
  --setup-timeout 1800 \
  --launch-timeout 240
```

The builder emits only `ready` or `environment-blocked`. Poco-Agent uses native backend, executor,
and executor-manager processes plus a disposable PostgreSQL socket fixture; its S3-compatible
fixture and Anthropic client also remain on loopback. A ready project self-test does not compile a
candidate-specific handler/gate/sink plan, execute the canonical 78-row campaign, or assign any
vulnerability verdict.

### Candidate-bound L2 validation

The candidate CLI consumes the frozen generic artifact directly:

```bash
python -m src.runtime_validation validate-candidate-l2 \
  --project mercury-agent \
  --candidate-id CAND-60dd4810687a0688 \
  --candidates output/cross-project/coverage-comparison/candidates.jsonl \
  --out-dir output/cross-project/runtime-auto-l2/CAND-60dd4810687a0688
```

Intake freezes all 78 rows, the comparison/semantic/origin/capability inputs, registry revisions,
and cited source hashes. It reuses the independently reviewed source case, compiles candidate
anchors, and owns deterministic dispositions. Mercury-Agent, DroidClaw, LettaBot,
ChatGPT-on-WeChat, NanoClaw, OpenClaw, OpenClaw-CN, AstrBot, QwenPaw, Hermes Agent,
and nanobot execute
through registered project-native real-entrypoint adapters for exactly three exploit/control pairs. Projects
without a registered candidate-specific instrumentation adapter publish `unsupported` and six blocked
trace bundles; a ready project self-test cannot turn that into `not-reproduced`.

The sequential wrapper is:

```bash
python scripts/run_candidate_l2_campaign.py \
  --candidates output/cross-project/coverage-comparison/candidates.jsonl \
  --out-dir output/cross-project/runtime-auto-l2
```

The 78-row wrapper stops on systemic environment/planning failures, records every candidate exit and
artifact hash, and preserves its truthful GT boundary: 38 eligible reports linked to current
candidates, 5 `candidate-missing`, and 3 non-applicable. It rejects any 43/43 identification claim.

An explicitly expanded 80-row boundary is also available. It preserves the frozen 78-row base and
adds only the two executable CowAgent historical IDs for WebFetch SSRF and Vision SSRF; the
source-contradicted Browser file-scheme candidate remains excluded:

```bash
python scripts/build_expanded_candidate_l2_inputs.py
python scripts/run_candidate_l2_campaign.py \
  --candidates output/cross-project/coverage-comparison-expanded-v1/candidates.jsonl \
  --out-dir output/cross-project/runtime-auto-l2-expanded-v2
```

The expanded boundary projects 41 eligible reports as current-candidate-linked, 2 as
candidate-missing, and 3 as non-applicable. It is not the unchanged generic artifact and cannot be
reported as a blind-discovery or 43/43 identification result.

Report-level confirmed/non-confirmed reasons for the active expanded 80-row boundary are rendered to
`output/cross-project/runtime-auto-l2-gt-analysis-v1`; the prior 78-row rendering is retained at
`output/cross-project/runtime-auto-l2-gt-analysis-78-v1`:

```bash
python scripts/render_candidate_l2_gt_analysis.py \
  --candidates output/cross-project/coverage-comparison-expanded-v1/candidates.jsonl \
  --campaign output/cross-project/runtime-auto-l2-expanded-v2 \
  --out-dir output/cross-project/runtime-auto-l2-gt-analysis-v1
```

### Post-hoc GT-regression L2 cohort

The generic 78 candidate set intentionally identifies only 38 of the 43 eligible GT reports. For an
explicitly post-hoc GT-regression run, select the exact 61 candidate IDs linked to the 43 reports from
the 82-row training overlay:

```bash
python -m src.runtime_validation validate-gt-linked-candidates-l2 \
  --candidates output/cross-project/coverage-comparison/training-regression-candidates.jsonl \
  --out-dir output/cross-project/runtime-auto-l2-gt-regression-v1
```

The generated manifest records four training-only fallback IDs and 76 report/candidate links. This
command does not make a generic or blind-discovery claim. A fallback without a reviewed source-bound
fragment remains `planning-blocked`; a linked unsupported result remains unfinished work, not a
negative reproduction result.

The current browser file-scheme fallback is deliberately planning-blocked: BrowserTool rewrites a
non-HTTP(S) URL to `https://` before invoking `page.goto`, so the claimed file-scheme relation needs
new source and runtime evidence before it can be tested as a confirmation.

### Hermes Agent targeted L2

The Hermes executor covers exactly the 15 candidate IDs linked to the nine eligible Hermes reports
in `generic-81-expanded-v3`:

```bash
python -m src.runtime_validation run-dynamic-trigger-hermes-agent-l2 \
  --campaign output/cross-project/runtime-dynamic-trigger-all-candidates-expanded-v3 \
  --out-dir output/cross-project/runtime-dynamic-trigger-hermes-agent-l2-v1 \
  --attempts 3
```

The runtime uses a locked no-E2EE Matrix profile derived from `uv.lock`, the real Hermes oneshot,
non-YOLO chat, and cron run/tick entrypoints, and one reviewed OpenAI Chat Completions SSE tool call
plus continuation. Source transforms bind native registry dispatch, family handlers, factual gates or
missing-check boundaries, and terminal process, browser-process, Matrix, Slack/Mattermost, or
skill-read sinks. Every dangerous effect is intercepted with `executed=false`; disposable role roots
use short `/tmp` paths and bounded shutdown-aware cleanup.

The explicit v3 input preserves the frozen 78-row and expanded-v2 80-row artifacts, adds only the
current-source Hermes skill-view candidate, and changes GT intake to 42 current-candidate-linked, 1
candidate-missing, and 3 non-applicable reports. The current canonical result is mixed: the plain
text Matrix candidate and the reviewed interactive shell command are healthy `not-reproduced`
results, while 13 Hermes candidates confirm eight of the nine reports. The skill-view candidate
confirms the ninth report through a fresh current-source L2 witness.

The benchmark source now also provides an explicitly labeled source-revised profile at
`04439ac77f08915b4886bc3c79165a9538af6219+legacy-command-bypass-source-v1`. It keeps the native
`terminal` tool and candidate interface unchanged, but `tools/approval.py` restores the historical
decision only for the exact reviewed `eval $(curl ...)` command before `detect_dangerous_command`.
Use the same native executor and a separate output directory:

```bash
python -m src.runtime_validation run-dynamic-trigger-hermes-agent-l2 \
  --campaign output/cross-project/runtime-dynamic-trigger-all-candidates-expanded-v3 \
  --out-dir output/cross-project/runtime-dynamic-trigger-hermes-agent-source-revised-l2-v1 \
  --attempts 3 \
  --candidate-id CAND-1ba6a7fa9223b90a
```

This source-revised profile must not overwrite or be reported as the frozen v3 canonical campaign.
The completed all-Hermes source-revised campaign is stored at
`output/cross-project/runtime-dynamic-trigger-hermes-agent-source-revised-all-v1`: 14 candidates are
runtime-confirmed, the plain-text Matrix candidate remains a healthy `not-reproduced`, and all
90/90 exploit/control traces are valid. Compared with frozen v3, only
`CAND-1ba6a7fa9223b90a` changes, from `not-reproduced` to `runtime-confirmed`.

### Nanobot targeted L2

The nanobot executor covers exactly the five candidate IDs linked to the five eligible allowlist
reports in `generic-81-expanded-v3`; the two unlinked nanobot candidates remain unsupported:

```bash
python -m src.runtime_validation run-dynamic-trigger-nanobot-l2 \
  --campaign output/cross-project/runtime-dynamic-trigger-all-candidates-expanded-v3 \
  --out-dir output/cross-project/runtime-dynamic-trigger-nanobot-l2-v1 \
  --attempts 3
```

Every role launches the real one-shot `nanobot agent` CLI and drives the project's direct
OpenAI-compatible custom provider with one reviewed `exec` call and one continuation. The
disposable build only plumbs the existing `ExecTool.allow_patterns` constructor surface through
real configuration; guard and sink logic remain source-bound. Payload repairs preserve the report
semantics while replacing independently blocked loopback-URL carriers with chain, comment-tail, and
wrapper forms. Events record provider parsing, registry dispatch, controlled arguments, the
allow/block or missing-check boundary, and pre-effect process interception. The workspace-boundary
candidate remains a healthy `not-reproduced` row when the real pinned guard blocks it.

### Unified source-revised native L2

The retired additive runners have been replaced by one unified campaign for four reports outside
the frozen canonical runtime boundary. The campaign uses only project-native tool interfaces:
Nanobot `exec`, OpenClaw `browser(action=act)` and `message(action=send)`, and CowAgent
`browser(action=navigate)`.

```bash
python -m src.runtime_validation run-dynamic-trigger-source-revised-native-l2 \
  --all \
  --out-dir output/cross-project/runtime-dynamic-trigger-source-revised-native-l2-v1 \
  --attempts 3
```

The completed campaign records **4/4 reports runtime-confirmed** and **24/24 valid traces**. It is
labelled `source-revised-native-tool`, keeps `canonical_accounting_affected=false`, and does not
change the canonical 81-candidate denominator, 43-report eligible boundary, or `41/43` result.

### QwenPaw targeted L2

The QwenPaw executor covers exactly the one generic candidate linked to the eligible jq
environment-disclosure report:

```bash
python -m src.runtime_validation run-dynamic-trigger-qwenpaw-l2 \
  --campaign output/cross-project/runtime-dynamic-trigger-all-candidates-expanded-v2 \
  --out-dir output/cross-project/runtime-dynamic-trigger-qwenpaw-l2-v1 \
  --attempts 3
```

Every role launches the real FastAPI app, drives `/api/console/chat`, and uses the repository's
OpenAI-compatible client in its native SSE mode. The loopback provider returns one reviewed
`execute_shell_command` tool call and one final continuation. A mount namespace confines the reviewed
`/tmp` working directory and hashed fake jq. Source transforms record native dispatch, QwenPaw's
pre-guard raw-input repair, the empty ToolGuard findings, the missing jq environment-object rule,
and terminal process interception before jq runs.

### AstrBot targeted L2

The AstrBot executor covers exactly the three generic candidates linked to the two eligible AstrBot
reports:

```bash
python -m src.runtime_validation run-dynamic-trigger-astrbot-l2 \
  --campaign output/cross-project/runtime-dynamic-trigger-all-candidates-expanded-v2 \
  --out-dir output/cross-project/runtime-dynamic-trigger-astrbot-l2-v1 \
  --attempts 3
```

Every role launches the real dashboard/OpenAPI chat boundary, configures a restricted member with the
local computer runtime, and drives the repository's OpenAI-compatible SSE client with one reviewed
tool call plus its normal continuation. Plugin-skill write/edit fixtures use manifest-recorded
workspace symlinks to preserve reviewed labels while resolving to AstrBot's configured roots. The
hardlink role uses a mount namespace and proves same-inode identity with an outside target. Source
transforms record native tool dispatch, handler arguments, pathname admission, the missing write-root
or inode-identity check, and terminal write interception.

### ChatGPT-on-WeChat targeted L2

The current-candidate executor covers exactly the six generic ChatGPT-on-WeChat candidates linked to
the three current-candidate-linked eligible reports:

```bash
python -m src.runtime_validation run-dynamic-trigger-chatgpt-on-wechat-l2 \
  --out-dir output/cross-project/runtime-dynamic-trigger-chatgpt-on-wechat-l2-v1 \
  --attempts 3
```

It starts the real `app.py` terminal channel, drives the repository's OpenAI-compatible HTTP client
through a loopback Chat Completions SSE fixture, records `AgentStreamExecutor` native dispatch, and
instruments Read, primary Bash, and Bash exit-126 retry paths. Read controls use a disposable `/tmp`
mount namespace; Bash effects and sensitive reads are intercepted before execution.

The separately labeled post-hoc historical mode admits only WebFetch SSRF and Vision SSRF:

```bash
python -m src.runtime_validation run-dynamic-trigger-chatgpt-on-wechat-l2 \
  --historical \
  --out-dir output/cross-project/runtime-dynamic-trigger-chatgpt-on-wechat-historical-l2-v1 \
  --attempts 3
```

These two overlay candidates do not change the canonical 78-row denominator. The Browser `file://`
historical candidate remains `planning-blocked` because current BrowserTool rewrites a non-http(s)
URL to `https://` before `page.goto`.

### OpenClaw targeted L2

The OpenClaw executor covers the five generic candidates linked to the four eligible OpenClaw reports:

```bash
python -m src.runtime_validation run-dynamic-trigger-openclaw-l2 \
  --out-dir output/cross-project/runtime-dynamic-trigger-openclaw-l2-v1 \
  --attempts 3
```

It builds a source-instrumented OpenClaw copy, drives the real `node dist/entry.js agent` CLI through
a loopback OpenAI-compatible tool call, observes the cited exec handler, exact command, allowlist
gate, and process spawn, and intercepts the effect before execution. Every role receives disposable
state and fake `pwsh`/`cmd`/`jq` executables; the benchmark source remains unchanged. A blocked
exploit with healthy controls is `not-reproduced`, while missing traces or cleanup failures remain
`inconclusive`.

### OpenClaw-CN targeted L2

The OpenClaw-CN executor covers the nine generic candidates linked to the six eligible OpenClaw-CN
reports:

```bash
python -m src.runtime_validation run-dynamic-trigger-openclaw-cn-l2 \
  --out-dir output/cross-project/runtime-dynamic-trigger-openclaw-cn-l2-v1 \
  --attempts 3
```

It builds a source-instrumented OpenClaw-CN copy and Feishu extension, starts the real browser control
service when needed, and drives the real `node dist/entry.js agent` CLI through a loopback
OpenAI-compatible tool call. The runner covers browser click/evaluate/open, durable BusyBox approval
reuse, dangling-symlink patch writes, and Feishu outbound media. Every role has disposable state and
workspace; PTY/process, browser navigation/interaction, filesystem writes, and outbound fetch effects
are intercepted before execution. The six unlinked OpenClaw-CN candidates remain unsupported.

### NanoClaw targeted L2

The NanoClaw executor covers the four generic candidates linked to the two eligible NanoClaw reports:

```bash
python -m src.runtime_validation run-dynamic-trigger-nanoclaw-l2 \
  --out-dir output/cross-project/runtime-dynamic-trigger-nanoclaw-l2-v1 \
  --attempts 3
```

It builds a source-instrumented NanoClaw host and container-runner copy, seeds real central/session
database state, starts the real Docker agent through the pinned Claude Agent SDK, and forces the
reviewed `send_file` call through an internal Anthropic-compatible loopback. Arbitrary-source roles
intercept the container-side copy; A2A roles pre-place a disposable target-inbox symlink and
intercept the host-side forwarding copy. The broader `add_mcp_server` report has no canonical linked
candidate and is intentionally outside this four-ID boundary.

### All-project launch-environment smoke

Launch-environment smoke is a separate pre-L2 gate. It provisions each of the 11 campaign projects in
a disposable OverlayFS setup layer, then launches the real entrypoint in a fresh mount/PID/network
namespace where only loopback is available. Provider credentials and proxy variables are removed,
homes and state are disposable, logs are redacted, and source hashes cannot drift.

```bash
python -m src.runtime_validation run-environment-smoke \
  --out-dir output/cross-project/runtime-environment-smoke-v1 \
  --setup-timeout 1200 \
  --launch-timeout 60
```

The current truthful outcome is 11 `launch-confirmed` projects: 10 use a source-native channel or
input surface, while LettaBot uses an explicit `mock-channel-bridge`. The bridge runs only in the
disposable project copy, preserves `channels.mock`, and connects the repository's existing
`MockChannelAdapter` to the real `dist/main.js` channel factory. LettaBot is therefore
`native_channel=false` and `instrumented_channel_bridge=true`; it is not treated as source-native,
and its launch result is not L2 evidence. A launch row is never promoted
to `l2-ready` or `runtime-confirmed`; those labels require the complete same-invocation
provider-to-pre-effect chain.

### LettaBot targeted L2

`run-dynamic-trigger-lettabot-l2` validates exactly the three LettaBot candidates in the canonical
dynamic-trigger campaign; `--campaign` is optional and defaults to that reviewed canonical artifact.
It starts the real `dist/main.js`, injects the repository mock channel in
a disposable run, serves a loopback Letta API/SSE fixture to the real Letta client, forces the
reviewed `Task` call, records native dispatch through the SDK subprocess, checks the resolved
subagent permission envelope, and intercepts the terminal child before `spawn()`. Three paired
exploit/control attempts are mandatory; malformed traces, unsupported provider endpoints, unsafe
controls, source drift, cleanup failure, or credential findings produce `inconclusive` or fail the
run.

```bash
python -m src.runtime_validation run-dynamic-trigger-lettabot-l2 \
  --out-dir output/cross-project/runtime-dynamic-trigger-lettabot-l2-v1 \
  --attempts 3
```

This command publishes targeted LettaBot L2 evidence only. It does not mark the ten-project launch
profiles ready, promote any L1 result, or change the all-candidate GT accounting.

### DroidClaw targeted L2

`run-dynamic-trigger-droidclaw-l2` validates exactly `CAND-02629879756e5c81`, the single canonical
DroidClaw shell candidate. As with LettaBot, `--campaign` is optional and defaults to the reviewed
canonical all-candidate artifact. The runner stages a disposable source copy, starts the real
`src/kernel.ts` entrypoint under Bun, uses the project's Ollama/OpenAI-compatible provider path with
a loopback Chat Completions SSE fixture, supplies deterministic fake screen XML and ADB responses,
and instruments the exact stdin, dispatch, handler, non-empty-command gate, and ADB shell sink
anchors. The terminal shell effect is replaced by a controlled response before execution.

```bash
cd benchmark/typescript/droidclaw
bun install --no-save --ignore-scripts
cd ../../..
python -m src.runtime_validation run-dynamic-trigger-droidclaw-l2 \
  --out-dir output/cross-project/runtime-dynamic-trigger-droidclaw-l2-v1 \
  --attempts 3
```

The exploit/control pair is healthy only when the reviewed non-empty command is admitted and reaches
the exact `["shell", "rm", "-rf", "/data/local/tmp"]` sink while the empty control is rejected before
the sink. Three paired attempts are mandatory. Source, dependency-manifest, trace, provider, control,
cleanup, or credential failures are `inconclusive`; the unsafe shell effect is never executed. This
is targeted one-candidate evidence and does not mark the shared ten-project qualification profiles
ready or promote the historical 78-row L1 publication.

### Mercury-Agent targeted L2

`run-dynamic-trigger-mercury-agent-l2` validates exactly the six canonical Mercury-Agent
`run_command` candidates. It copies the real built bundle to a disposable workspace, starts
`node dist/index.js start --foreground` through a PTY, chooses **Ask Me**, supplies a minimal real
Mercury configuration, and points the real OpenAI-compatible AI SDK client at a loopback SSE fixture.
The first provider response forces the reviewed tool call; the second completes the AI SDK tool loop.
Exact-marker build instrumentation observes prompt ingress, dispatch, the controlled command,
permission classification, the consent boundary, and terminal `spawn`; the shell child is replaced
before execution.

```bash
cd benchmark/typescript/mercury-agent
npm ci --ignore-scripts
npm run build
cd ../../..
python -m src.runtime_validation run-dynamic-trigger-mercury-agent-l2 \
  --out-dir output/cross-project/runtime-dynamic-trigger-mercury-agent-l2-v2 \
  --attempts 3
```

The run deliberately preserves the default `cwdOnly` ask-me policy and never grants a path scope. The
runner applies two reviewed deterministic repairs recorded in `payload-repairs.jsonl`: unbraced
`$HOME` expansion for the home-expansion candidate and relative in-CWD redirection for the
redirection candidate. The canonical input campaign is unchanged. The current repaired default-mode
result is five `runtime-confirmed` candidates, one healthy `not-reproduced` candidate, and five linked
Mercury GT reports. This is targeted L2 evidence only; it does not promote the historical L1 rows,
ready the shared launcher, or change all-project GT accounting.

## Corrected-v3 completed native campaign

Version 3 preserves the v2 directory and denominator, upgrades the frozen v2 cases without another
model call, and eliminates unsupported dispositions. The ten rejected generation exchanges are
repaired deterministically: valid nested argument paths and safe controls are used where arguments
differ, while browser-page and target-inbox properties use the v3 `fixture-state` matcher when the
native exploit and control arguments must be identical. Registered-name aliases are accepted only
when the case's D5 handler binding names the canonical tool.

Run the complete workflow from the repository root:

```bash
python -m src.runtime_validation upgrade-covered-v3 \
  --source-campaign output/cross-project/runtime-validation-covered-v2 \
  --out-dir output/cross-project/runtime-validation-covered-v3
python -m src.runtime_validation provision-drivers \
  --campaign output/cross-project/runtime-validation-covered-v3
python -m src.runtime_validation run-campaign \
  --campaign output/cross-project/runtime-validation-covered-v3 \
  --attempts 3 \
  --jobs 4
```

`provision-drivers` uses `npm ci --ignore-scripts` for LettaBot and Mercury Agent and
`pnpm install --frozen-lockfile --ignore-scripts` for NanoClaw, OpenClaw, and OpenClaw CN.
It writes runtime, package, and lockfile hashes to `driver-provisioning.json`; tracked lockfiles are
never changed. Use `--check-only` to repeat readiness checks without installation.

Every native attempt runs in its own subprocess, so effective concurrency is four without leaking
module, logger, environment, or monkeypatch state. Python dispatch covers QwenPaw's guarded
`execute_shell_command`, CowAgent browser, and Hermes Agent `browser_console`, `send_message`,
`skill_view`, and `terminal` in addition to the v2 tools. The shared Bun protocol covers DroidClaw
`shell`, LettaBot `Task`, Mercury Agent `run_command`, NanoClaw `send_file`, OpenClaw `exec`, and
OpenClaw CN `exec`, `browser`, `apply_patch`, and `message`. Candidate effects terminate at recording
process/ADB hooks, temporary filesystem roots, loopback browser/HTTP fixtures, captured messaging,
or captured subagent launchers.

The canonical v3 publication is blocked unless all 100 IDs are present and both `unsupported` and
infrastructure/trace `inconclusive` are zero. It includes `repair-ledger.jsonl`, transformed-source
manifests and source maps per TypeScript attempt, `ground-truth-projection.json`,
`v2-v3-delta.json`, dependency hashes, and effect-canary results. The current revision-bound run is
9 runtime-confirmed and 91 not-reproduced candidates; at report level it is 8 runtime-confirmed
and 29 not-reproduced across all 37 targeted reports. All 58 formerly unsupported candidates and
all 24 formerly unsupported-only reports now have conclusive evidence.

## Ground-truth-centric campaign

The report-centric path validates the runtime framework independently of candidate generation or
candidate matching. Its authoritative denominator is the 46-row workbook: 42 benchmark-eligible
reports are replayed, while one fixed, one not-present, and two out-of-model reports remain visible
as `not-applicable`. Candidate IDs, comparisons, group oracles, and candidate-result artifacts are
not inputs.

Run the complete workflow from the repository root:

```bash
python -m src.runtime_validation audit-ground-truth \
  --out-dir output/cross-project/runtime-validation-ground-truth-audit-v1
python -m src.runtime_validation generate-ground-truth \
  --audit output/cross-project/runtime-validation-ground-truth-audit-v1 \
  --out-dir output/cross-project/runtime-validation-ground-truth-v1 \
  --model deepseek-v4-flash \
  --base-url https://api.deepseek.com/v1 \
  --api-key-env DEEPSEEK_API_KEY
python -m src.runtime_validation provision-drivers \
  --campaign output/cross-project/runtime-validation-ground-truth-v1
python -m src.runtime_validation review-ground-truth \
  --campaign output/cross-project/runtime-validation-ground-truth-v1 \
  --model deepseek-v4-flash \
  --base-url https://api.deepseek.com/v1 \
  --api-key-env DEEPSEEK_API_KEY
python -m src.runtime_validation run-ground-truth \
  --campaign output/cross-project/runtime-validation-ground-truth-v1 \
  --attempts 3 \
  --jobs 4
```

`audit-ground-truth` resolves the current handler, gates, and sink from registered tool surfaces
and revision-bound call-chain semantic IR. It records stale D5 locations in an anchor-rebase ledger;
missing or ambiguous current anchors are validator-support failures and can never become
`not-reproduced`. The current corpus has stale original locations in 19 reports, all deterministically
rebound to current hashed source anchors.

Generation produces one `RVGT-*` exploit/control case per eligible report. A separate isolated
review pass checks source reachability, exploit semantics, control safety, native identity, fixtures,
ordered stages, and effect interception; one feedback regeneration is permitted. The reviewed
campaign contains 42/42 approved executable cases. Hermes `CVE-Project-Code-Execution-Mode-Bypass`
required a report-specific semantic correction from its inconsistent `terminal` D5 entry to the
current registered `execute_code(args.code)` path.

Validator support and runtime outcome are separate. The canonical run has 42 `ready` eligible
reports, four `not-applicable` reports, and no support gaps. Runtime outcomes are 15
`runtime-confirmed`, 27 `not-reproduced`, zero `inconclusive`, and four `not-applicable`. A negative
requires three healthy native pairs with the instrumented handler observed; setup, source,
transformation, correlation, or control failure is never negative evidence. This campaign measures
native replay semantics, not live-LLM prompt selection.

## Claude-designed production-like propagation smoke

The first production-like pilot uses Hermes
`CVE-2026-Device-Blocking-Expanduser-Bypass` at the frozen benchmark revision. Claude Code
2.1.220, backed by `deepseek-v4-pro`, receives read-only source/report access plus a strict
`clawgap_lab` MCP surface. It cannot use Bash, Edit, Docker, host writes, or arbitrary network
tools. Claude designs the declarative lab plan; a separate Claude session independently reviews
the complete plan and source anchors before replay.

Run the smoke from the repository root:

```bash
python -m src.runtime_validation run-production-like-smoke \
  --out-dir output/cross-project/runtime-validation-ground-truth-production-like-v1/smoke/hermes-device-blocking \
  --claude-model deepseek-v4-pro \
  --claude-base-url https://api.deepseek.com/anthropic \
  --claude-credential-env DEEPSEEK_API_KEY \
  --attempts 3 \
  --timeout 60
```

The target Hermes process uses its real one-shot entrypoint, file toolset, registry, handler,
device gate, shell-file implementation, environment dispatcher, and local `Popen` callsite. A
loopback OpenAI-compatible provider deterministically emits the reviewed `read_file` call, so the
experiment does not require or measure a jailbreak. Temporary Python instrumentation records one
value identity through prompt receipt, provider request/response, registry dispatch,
`_handle_read_file`, `read_file_tool`, `_is_blocked_device`, `ShellFileOperations.read_file`,
`_exec`, `BaseEnvironment.execute`, `_run_bash`, and the matching `Popen` arguments.
Every observation binds the campaign, case, attempt, correlation, and value IDs. Each target runs
inside a per-attempt Bubblewrap sandbox with the repository and Python runtime mounted read-only;
only its disposable workspace and attempt-artifact directory are writable. The target receives an
allowlisted environment with no inherited credentials, and its Python socket boundary permits only
the loopback provider. A separate active sandbox canary verifies all three properties before replay.

The case binds both prompts and expected provider tool calls. The published transcript ledger binds
the exact user prompt, forced `read_file` response, and SHA-256 of all six E2E transcripts. The
instrumentation manifest binds target-source hashes, the injected overlay files, and source maps;
the independent review echoes both the reviewed case hash and lab-plan hash.

The canonical smoke is `prompt-to-sink-confirmed`: three native and three mocked-provider E2E
exploit/control pairs pass. `/dev/./zero` reaches the intercepted `Popen` sink with the gate
returning false; `/dev/zero` returns true at the device gate and never reaches the sink. The
interceptor raises before matching process creation. No denial-of-service effect is executed or claimed,
and live-model tool selection remains `not-tested`. A fully observed exploit that instead returns
`true` at the device gate in all three pairs is `not-reproduced`; missing or mismatched provider,
source, identity, stage, transcript, control, or sink evidence is `inconclusive`.

## Agent-guided candidate runtime validation pilot

The candidate-centric agent path implements `design/hermes-agent/runtime-validation/plan2.md`
for one reviewed Hermes read-file family. A Controller LLM sees a bounded candidate bundle
and anchor catalog, proposes a declarative plan, and may inspect only source-root-confined
excerpts. It has no shell, repository write, arbitrary Python, credential access, or direct
target-command authority. Python compiles the plan, starts Hermes in Bubblewrap with a new
process group and disposable home/workspace, injects `agent_sitecustomize.py`, serves a
loopback mock OpenAI-compatible provider, and evaluates ordered exploit/control events. The
evaluator also rejects instrumentation startup errors, source-hash drift, and failed disposable
workspace/process-group cleanup canaries. The controller can finalize only with an
evaluator-produced `evaluation_id`.

The v1 adapter currently binds the `_handle_read_file` / `file_ops.read_file` family and the
reviewed `/dev/./zero` versus `/dev/zero` differential. Other Hermes candidates fail closed as
unsupported until an anchor/fixture family is added. A successful result means
`forced-tool-candidate-path-propagation` with the process effect intercepted before creation; it
does **not** test live-model prompt selection.

```bash
python -m src.runtime_validation run-agent-runtime-validation \
  --coverage-root output/cross-project/coverage-comparison \
  --candidate-id CAND-925c9d1319c3ccbd \
  --out-dir output/cross-project/runtime-agent-validation-v1/scripted \
  --controller scripted-pilot \
  --confirmation-attempts 1 \
  --timeout 60
```

Use `--controller openai-compatible --model deepseek-v4-flash --base-url
https://api.deepseek.com/v1 --api-key-env DEEPSEEK_API_KEY` and
`--out-dir output/cross-project/runtime-agent-validation-v1/live` to let the external controller
propose the same closed-plan schema. Controller errors are feedback only; malformed traces,
source drift, missing mandatory anchors, unsafe values, and failed controls remain
`inconclusive` and never become negative evidence.

## Containerized adapter qualification

`generate-adapter-qualification` selects one `ready`, independently reviewed ground-truth case per
`(project, native adapter, tool, probe)` family. The current corpus yields 23 qualification cases
across 11 benchmark projects. This is infrastructure qualification only: it never claims that a
report is exploitable and it does not evaluate `missing-check` or `wrong-check` semantics.

```bash
python -m src.runtime_validation generate-adapter-qualification \
  --source-campaign output/cross-project/runtime-validation-ground-truth-v1 \
  --out-dir output/cross-project/runtime-validation-adapter-qualification-v1
python -m src.runtime_validation prebuild-qualification-containers \
  --campaign output/cross-project/runtime-validation-adapter-qualification-v1 --engine auto
python -m src.runtime_validation run-hermes-qualification-smoke \
  --campaign output/cross-project/runtime-validation-adapter-qualification-v1 \
  --out-dir output/cross-project/runtime-validation-adapter-qualification-v1/hermes-smoke \
  --engine auto
python -m src.runtime_validation run-adapter-qualification \
  --campaign output/cross-project/runtime-validation-adapter-qualification-v1 \
  --engine auto --attempts 3
python -m src.runtime_validation expand-adapter-qualification \
  --source-campaign output/cross-project/runtime-validation-ground-truth-v1 \
  --qualification-campaign output/cross-project/runtime-validation-adapter-qualification-v1 \
  --out-dir output/cross-project/runtime-validation-adapter-qualification-v1/ground-truth-expansion
python -m src.runtime_validation prebuild-qualification-containers \
  --campaign output/cross-project/runtime-validation-adapter-qualification-v1/ground-truth-expansion \
  --engine auto
python -m src.runtime_validation run-adapter-qualification \
  --campaign output/cross-project/runtime-validation-adapter-qualification-v1/ground-truth-expansion \
  --engine auto --attempts 3
```

The first real target is the Hermes `read_file`/filesystem family. Its immutable image uses the
pinned Python base recorded in the image manifest and the reviewed Hermes source/dependency hashes.
Container definitions are checked in under `src/runtime_validation/containers/`; pre-analysis
copies the declared `benchmark/python/hermes-agent` project and bridge into a temporary context,
then applies and verifies the dynamic revision/source/lock/bridge labels. Generated Dockerfiles are
not written back into campaign output. Replay never builds an image: if the pre-analysis image is
missing, the smoke is `blocked` rather than repaired during execution.
The reusable non-root baseline starts once; each of the three exploit/control pairs receives a new
target process group and disposable `/tmp/qualification/<pair>` state. After the pair, the bridge
removes only that state and a fail-closed probe verifies source hashes, the baseline canary, image
identity, credential isolation, and that no target child remains. A reset failure destroys and
recreates the baseline before the next family; it never retries the failed pair.

The mock provider is an in-container OpenAI-compatible loopback service, not a live model. It makes
exactly one request per side, records the prompt and HTTP exchange, and returns only the reviewed
tool call. Extra calls, prompt drift, malformed JSON, hash drift, or a response that does not decode
to the reviewed arguments makes the pair `inconclusive`.

```text
qualification:      qualified | blocked | inconclusive
forced-path:        confirmed | inconclusive
live-triggerability: not-run for the mock-only campaign
```

Full expansion is intentionally gated: the expansion generator refuses to run unless the canonical
campaign first publishes 23/23 qualified families. After that gate, the same mock-provider,
container, reset, and evidence contracts cover all 42 eligible reviewed ground truths. The current
expansion result is 42/42 qualified; it still contains no vulnerability verdict and does not
evaluate `missing-check` or `wrong-check` semantics.

```bash
python -m src.runtime_validation expand-adapter-qualification \
  --source-campaign output/cross-project/runtime-validation-ground-truth-v1 \
  --qualification-campaign output/cross-project/runtime-validation-adapter-qualification-v1 \
  --out-dir output/cross-project/runtime-validation-adapter-qualification-v1/ground-truth-expansion
```

The canonical provider is a strict mock. It records the reproduction prompt and returns only the
schema-bound reviewed tool call; the in-container bridge then invokes the project’s real native
dispatcher. Each pair emits correlated JSONL events for prompt ingress, provider request and tool
call, native dispatch, source-bound stages, and intercepted effect. A container image is admitted
only when it is non-root, read-only at runtime, network-disabled, host-mount-free, and labelled with
the exact project revision, source digest, dependency digest, and bridge version. Missing images or
bridges are reported as `blocked`, never as a successful host-native replay.

`run-exploratory-triggerability` creates a separate noncanonical `not-run` ledger until a
project-specific live prompt adapter is provided. It cannot alter forced-path qualification.

## Ground-truth LLM tool-triggerability prerequisite

Before interpreting runtime candidate results, audit whether every targeted ground truth actually
has a current model-facing tool route:

```bash
python -m src.runtime_validation audit-gt-tool-triggerability \
  --campaign output/cross-project/runtime-validation-covered-v3 \
  --out-dir output/cross-project/ground-truth-tool-triggerability-v1 \
  --jobs 4
```

The audit binds each report JSON and checks current handler, registration, model-exposure, and
dispatcher source witnesses. It then submits one representative JSON call through the isolated
native adapter and requires an emitted handler-stage event. The current ledger contains all 37
reports: 36 are reachable through function/MCP tool calls, while DroidClaw is reachable through an
LLM-generated structured `ActionDecision` rather than a function-tools API. There are no
inconclusive or non-triggerable reports at this boundary.

This result proves tool-call/action reachability, not natural-language prompt selection. Individual
deployments may hide tools through toolsets, project configuration, approval mode, provider support,
browser/gateway availability, plan-only mode, or channel/account configuration. A live-prompt
campaign is a separate experiment.
