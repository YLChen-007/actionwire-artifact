# Runtime Validation L2 Build-Environment Schema

## 1. Purpose and Evidence Boundary

This document is the common design schema for building a forced-provider L2 test environment for the
twelve projects registered under `benchmark/`. The environment builder produces an isolated, ready
environment handle; it does **not** assign a vulnerability verdict. The validation process defined in
`design/common/runtime-validation-test-validation.md` consumes that handle and evaluates the candidate
oracle.

An L2 environment is valid only when one same-invocation chain remains real:

```text
real entrypoint/input boundary
→ real provider client and request
→ real native tool/action dispatch
→ real cited handler
→ cited gates
→ declared terminal sink
→ pre-effect interception
```

Only external boundaries may be controlled: the model provider, chat channel, device, browser,
filesystem, network peer, or terminal child effect. A launch smoke, provider request, handler call, or
sink event alone is not L2 evidence.

## 2. Benchmark Project Inventory

The common environment builder must account for exactly these twelve project IDs:

| Project | Language | Source root | Environment family |
|---|---|---|---|
| `AstrBot` | Python | `benchmark/python/AstrBot` | installed Python CLI/service with native test channel |
| `QwenPaw` | Python | `benchmark/python/QwenPaw` | Python HTTP app with provider shim |
| `chatgpt-on-wechat` | Python | `benchmark/python/chatgpt-on-wechat` | Python channel bot with local test channel |
| `hermes-agent` | Python | `benchmark/python/hermes-agent` | Python one-shot/gateway agent |
| `nanobot` | Python | `benchmark/python/nanobot` | Python one-shot agent CLI |
| `poco-agent` | Python | `benchmark/python/poco-agent` | multi-service backend/executor/manager platform |
| `droidclaw` | TypeScript/Bun | `benchmark/typescript/droidclaw` | Bun CLI with structured action JSON and fake ADB |
| `lettabot` | TypeScript/Node | `benchmark/typescript/lettabot` | built Node service with Letta API/SSE provider |
| `mercury-agent` | TypeScript/Node | `benchmark/typescript/mercury-agent` | built Node PTY/Ink CLI with AI SDK tools |
| `nanoclaw` | TypeScript/Node | `benchmark/typescript/nanoclaw` | built Node service with Unix-socket delivery |
| `openclaw` | TypeScript/Node | `benchmark/typescript/openclaw` | built Node PTY/TUI agent |
| `openclaw-cn` | TypeScript/Node | `benchmark/typescript/openclaw-cn` | built Node PTY/TUI agent |

The project ID, analysis revision, source root, query pack, and adapter ID must come from
`src/projects/registry.py`. A plan that names an unregistered project or a source-root mismatch fails
closed.

## 3. Build Pipeline

```text
project + candidate identity
→ freeze source/dependency/artifact identity
→ select or synthesize project environment profile
→ materialize disposable source/build copy
→ install or verify immutable dependencies
→ render provider/input/perception fixtures
→ render source-anchored instrumentation
→ install terminal-effect interceptor
→ launch real entrypoint in a new process group
→ prove readiness and fixture health
→ publish environment handle to validator
```

The build pipeline may use an LLM to propose a profile, instrumentation anchors, fixture values, or a
payload repair. Deterministic code must validate and compile that proposal. The LLM must not mutate the
host checkout, choose the final verdict, disable a security gate, or bypass the sandbox.

## 4. Environment Plan Schema

A project profile or automatically generated plan uses conceptual schema
`clawgap-runtime-l2-environment-plan/v1`.

```yaml
schema_version: clawgap-runtime-l2-environment-plan/v1
project:
  project_id: mercury-agent
  analysis_revision: 587fad1bf9449598d1b27833f8c7db55d164741a
  source_root: benchmark/typescript/mercury-agent
  adapter_id: mercury-native/v1

identity:
  candidate_id: CAND-...
  case_id: DTC-...
  environment_id: ENV-...
  source_campaign: output/cross-project/runtime-dynamic-trigger-all-candidates-v1

source:
  required_files: [...]
  sha256: {path: digest}
  semantic_bindings:
    handler: src/...:line
    gates: [src/...:line]
    sink: src/...:line
  transformed_copy: workspace/project
  original_to_transformed_hashes: [...]

dependency:
  lockfile: package-lock.json | pnpm-lock.yaml | uv.lock | null
  install_command: [...]
  installed_manifest_hashes: {path: digest}
  build_command: [...]
  build_outputs: [dist/index.js]

runtime:
  language: python | typescript | javascript
  implementation: cpython | node | bun
  cwd: workspace/project
  command: [node, dist/index.js, start, --foreground]
  process_group: true
  timeout_seconds: 45

provider:
  protocol: openai-chat-completions/v1 | letta-api/v1 | anthropic-messages/v1 | project-custom/v1
  mode: native-openai-compatible | project-provider-shim
  base_url: http://127.0.0.1:${CLAWGAP_L2_PROVIDER_PORT}/v1
  credential: clawgap-loopback-mock
  request_contract: {...}
  response_contract: {...}
  transcript_path: provider-transcript.jsonl

input:
  kind: stdin | pty | http-api | native-test-channel | mock-channel-bridge | unix-socket | cli-argument
  prompt_template: ${CLAWGAP_L2_PROMPT}
  readiness: {kind: stdio-line | tcp-port | unix-socket | process-exit, pattern: ..., timeout_seconds: 30}

perception:
  filesystem: {workspace: ..., allowed: ..., outside: ..., canary: ...}
  device: {kind: fake-adb, serial: clawgap-fake, screen_xml: ...}
  browser: {kind: isolated-browser, pages: [...]}
  messaging: {kind: loopback-channel, accounts: [...]}
  subagents: {kind: controlled-protocol-child}
  database: {kind: disposable-sqlite | temporary-schema}

instrumentation:
  language_adapter: python-ast | typescript-ast | node-import | bun-preload | source-renderer
  event_path: events.raw.jsonl
  points:
    - {kind: prompt, anchor: src/...:line}
    - {kind: provider-request, anchor: provider-client}
    - {kind: dispatch, anchor: src/...:line}
    - {kind: handler, anchor: src/...:line}
    - {kind: controlled-value, anchor: src/...:line}
    - {kind: gate, anchor: src/...:line}
    - {kind: sink, anchor: src/...:line}
    - {kind: pre-effect, anchor: sink-or-runtime-primitive}
  transformed_source_manifest: transformed-source-manifest.json

interception:
  terminal_effect: process | filesystem | network | browser | messaging | adb | subagent | database
  primitive: child_process.spawn | subprocess.Popen | fetch | ...
  before_execution: true
  controlled_response: ...
  executed: false

isolation:
  home: runs/<...>/home
  workspace: runs/<...>/workspace
  data: runs/<...>/data
  temporary: runs/<...>/temporary
  environment_allowlist: [PATH, LANG, ...]
  inherited_credentials: false
  network_policy: loopback-only
  host_write_policy: forbidden
  cleanup_canary: host-effect-canary.txt
  process_cleanup: terminate-process-group

handoff:
  environment_status: ready | environment-blocked
  endpoints: {provider: ..., app: ..., socket: ...}
  process_identity: {pid: ..., start_time: ..., command_hash: ...}
  event_paths: [...]
  fixture_manifests: [...]
  launch_log: launch.log
```

### 4.1 Required Invariants

Every field above is normative. In addition:

- revision and all required source hashes must match the project registry and candidate binding;
- the only permitted source-hash exceptions are exact `(project, path, base-hash, revised-hash,
  marker)` tuples registered in `source_revision_compatibility.py` for the Hermes command guard,
  Nanobot native login profile, OpenClaw native message media profile, and CowAgent native
  file-scheme profile; all other drift remains blocked;
- dependency identity must use a lockfile when present and installed package manifests otherwise;
- the built entrypoint must be launched from the disposable copy, not the host benchmark checkout;
- provider credentials must be fake and redacted in every artifact;
- only `PATH`, locale, runtime home, and explicit fixture variables may be inherited or set;
- all HTTP(S) requests other than declared loopback fixtures must fail;
- every terminal child/effect must be intercepted before execution;
- instrumentation markers must bind to the cited handler, gate, and sink identities;
- a missing source anchor, duplicate marker, failed build, readiness timeout, or fixture failure must
  produce `environment-blocked`, not a runtime verdict.

## 5. Project Environment Matrix

This matrix is the high-level default design for all twelve projects. A project-specific pilot may
replace a default cell only by a reviewed profile with the same required invariants.

| Project | Materialization and launch | Input boundary | Provider boundary | Controlled external effects |
|---|---|---|---|---|
| `AstrBot` | disposable Python environment; `astrbot run --port <app-port>` | native test channel; config `data/cmd_config.json` | OpenAI-compatible loopback | filesystem, process, network, plugin APIs |
| `QwenPaw` | disposable source copy; run `qwenpaw.cli.main app` on loopback app port | HTTP `/agents/chat` | project provider shim on loopback | filesystem, process, network, plugin tools |
| `chatgpt-on-wechat` | disposable Python environment; `python app.py` | local native test channel; disposable `config.json` | OpenAI-compatible loopback | messaging, filesystem, process, network |
| `hermes-agent` | disposable Python environment; one-shot `hermes`/`hermes-agent` entrypoint | one-shot prompt/gateway boundary | project-native loopback provider | process, filesystem, browser, messaging |
| `nanobot` | disposable Python environment; `nanobot.cli.commands agent --message ...` | CLI argument and disposable config | provider shim | process, filesystem, network |
| `poco-agent` | disposable backend, executor, and executor-manager services with independent ports and databases | backend HTTP/channel API | Anthropic-compatible or project provider shim | process, browser, database, object storage, network |
| `droidclaw` | disposable source copy; `bun src/kernel.ts` | stdin after `Enter your goal` | Ollama/OpenAI-compatible Chat Completions/SSE | fake ADB startup and pre-effect ADB shell interception |
| `lettabot` | `npm run build`; disposable `dist/main.js` | explicit mock-channel bridge, labelled non-source-native | real Letta client against loopback Letta API/SSE | subagent child-process interception |
| `mercury-agent` | `npm ci`/build; disposable `dist/index.js`; Node PTY `start --foreground` | real Ink PTY; choose Ask Me | real AI SDK/OpenAI-compatible loopback | terminal `child_process.spawn` interception |
| `nanoclaw` | `pnpm build`; disposable service and session DB | Unix socket `data/cli.sock` | provider shim | process, messaging, database, filesystem |
| `openclaw` | `pnpm build`; disposable TUI | PTY | provider shim | process, browser, messaging, filesystem |
| `openclaw-cn` | `pnpm build`; disposable TUI | PTY | provider shim | process, browser, messaging, filesystem |

### 5.1 Current Readiness Boundary

The concrete builder is implemented by `src/runtime_validation/environment_builder.py` and the
checked-in `clawgap-runtime-l2-environment-plan/v1` profiles. Its project-self-test tier covers the
exact twelve registry projects:

```bash
python -m src.runtime_validation build-runtime-l2-environment \
  --all \
  --out-dir output/cross-project/runtime-l2-environment-builder-v1 \
  --setup-timeout 1800 \
  --launch-timeout 240
```

The current all-project result is **12/12 ready, 0/12 environment-blocked**. QwenPaw uses the
reviewed MCP compatibility fixture in its disposable venv. Poco-Agent runs native backend, executor,
and executor-manager processes against a migrated disposable PostgreSQL socket plus loopback S3 and
Anthropic fixtures. These are project-environment readiness claims only; they do not compile
candidate-specific handler/gate/sink plans or execute vulnerability verdicts.

The older shared launch-profile qualification remains separate and deliberately fail-closed for the
canonical 78-candidate campaign. Targeted DroidClaw, LettaBot, and Mercury-Agent verdict runners also
remain separate evidence and are not promoted by this builder.

### 5.2 Candidate-Validation Support Contract

The builder supports candidate validation through two explicit identity modes. They must not be
collapsed into one claim.

| Mode | Identity | Purpose | Current boundary |
|---|---|---|---|
| `project-self-test` | deterministic `probe_id` | prove that the project's real entrypoint, provider client, input boundary, instrumentation loader, interceptor, cleanup, and fixture contracts work together | Implemented for all twelve registry projects; current result is 12/12 ready |
| `candidate` | unique candidate row plus registry revision | compile and launch one candidate/attempt/role identity with the reviewed provider tool call and source anchors | Implemented for the handoff contract: uniqueness, project/revision, role identity, provider response, source anchors, trace loader, and terminal interceptor are compiled; verdict ownership remains in the validator |

A candidate validator uses this builder as its environment provider, not as its verdict engine:

1. Candidate intake resolves one row from `candidates.jsonl`, verifies project and analysis revision,
   and selects the same registry-bound profile family proven by the project self-test.
2. The candidate plan compiler converts the candidate's cited handler, gates, controlled value, sink,
   input transport, and provider contract into instrumentation for that profile. Generic project
   readiness cannot substitute for these candidate-specific anchors.
3. For every exploit/control role and each of three attempts, the validator requests a fresh
   disposable environment. It must not reuse a published project-self-test directory as a live
   candidate environment.
4. The validator submits the reviewed prompt or structured decision through the profile's native
   input boundary and uses the loopback provider only to force the reviewed provider response.
5. The validator correlates the candidate row, reviewed case, environment identity, provider
   transcript, normalized events, transformed-source manifest, interceptor event, and cleanup result.
6. Only the validator assigns `runtime-confirmed`, `not-reproduced`, or `inconclusive`. Builder
   failures remain `environment-blocked` and can never become healthy negative evidence.

The per-project artifacts produced by `build-runtime-l2-environment` are therefore both a readiness
audit and the implementation pattern for candidate execution. A candidate run must publish the same
artifact set under a candidate/attempt/role identity and must add candidate-bound source anchors and
case oracle hashes. The all-project manifest deliberately keeps
`canonical_candidate_execution_ready=false` until every project consumes the candidate contract in a
three-pair validator; a ready self-test or a compiled single-role handoff is not itself a verdict.

## 6. Fixture Families

### 6.1 Provider Fixtures

The fixture must use the project's real provider client. Supported contracts include:

- OpenAI Chat Completions JSON and SSE;
- Letta API/SSE;
- Anthropic-compatible Messages API;
- project-specific provider shim anchored to source.

The fixture records request method, path, body, response identity, and a redacted authorization header.
Undeclared endpoints, extra requests, non-loopback URLs, or malformed tool-call payloads make the
environment unhealthy.

### 6.2 Input Transports

| Kind | Contract |
|---|---|
| `stdin` | wait for readiness line, send reviewed prompt, preserve process group |
| `pty` | allocate PTY, drive real TUI key/input boundary, record normalized output |
| `http-api` | call only the reviewed app endpoint with disposable auth |
| `native-test-channel` | use project's local/test channel adapter, never a public chat network |
| `mock-channel-bridge` | explicitly label `native_channel=false` and `instrumented_channel_bridge=true` |
| `unix-socket` | wait for socket, send framed project-native request |
| `cli-argument` | one-shot command with reviewed prompt/config |

### 6.3 Perception and Effect Fixtures

| Family | Startup/perception fixture | Terminal-effect contract |
|---|---|---|
| process | no real external process needed | replace `spawn`/`Popen` with controlled child |
| filesystem | disposable allowed/outside trees and canary | permit only workspace writes or intercept write |
| network | loopback pages/services | block non-loopback and return controlled responses |
| browser | isolated profile and local pages | intercept browser launch/navigation before effect |
| messaging | loopback account/channel | capture send API and return controlled delivery |
| ADB | fake serial, screen XML, wm size, dump/pull | intercept reviewed ADB shell child |
| subagent | controlled configurations | intercept child delegation and return protocol response |
| database | disposable SQLite/schema | intercept migration/write or confine to disposable DB |

## 7. Build Acceptance Gates

Before handing an environment to validation, the builder must prove:

1. source, dependency, build, harness, and fixture hashes;
2. dependency installation completed without changing tracked benchmark files;
3. disposable copy is used and original checkout remains unchanged;
4. provider fixture health endpoint/request contract passes;
5. input readiness boundary is observed;
6. instrumentation emits a synthetic identity-consistent event;
7. terminal interceptor emits `executed=false` under a smoke payload;
8. process group and cleanup canary are live;
9. credential scan and non-loopback network probes pass;
10. environment manifest contains the exact reproduction command.

The output status is limited to:

```text
ready
environment-blocked
```

The builder does not emit `runtime-confirmed`, `not-reproduced`, or `inconclusive`.

## 8. Environment Handoff Artifacts

For each exploit/control role and attempt, publish:

```text
environment.json
fixture-manifest.json
transformed-source-manifest.json
provider-fixture.json
launch.log
events.raw.jsonl
host-effect-canary.txt
disposable-root-inventory.json
```

The validator may be given live process/endpoint handles during execution, but the published artifacts
must be sufficient to reconstruct and audit the environment after disposable roots are removed.

## 9. Mandatory Failure Modes

Fail environment construction for:

- unknown project/candidate;
- revision, source, dependency, build, or harness drift;
- missing lockfile-manifest identity;
- host checkout mutation;
- unavailable real entrypoint/provider client;
- unimplemented input/provider/perception adapter;
- missing or ambiguous handler/gate/sink anchors;
- non-loopback network;
- inherited real credential;
- unbuildable project or stale build output;
- readiness timeout;
- process-group creation failure;
- cleanup canary failure;
- residual disposable root;
- instrumentation marker mismatch;
- terminal interceptor cannot precede the cited effect.

Failure details belong in the environment ledger. They must not be converted into candidate
`not-reproduced` evidence.
