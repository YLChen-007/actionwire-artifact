# Canonical CR Coverage Comparison v15

Coverage v15 exposes one pipeline and one active output root:

```bash
python -m src.coverage_comparison --all
```

An isolated live experiment can run the two single-oracle Coverage Decision
configurations on only the 43 eligible training reports:

```bash
python -m src.coverage_comparison.scoped_ablation \
  --source-dir output/cross-project/coverage-comparison-v15-restaging7 \
  --out-dir output/cross-project/single-oracle-43-20260923-v1 --jobs 4
```

This uses a new input/prompt/implementation freeze rather than the replay-only
canonical CLI. The 43 reports map to 56 unique member chains; no other chains
receive inference. Group-only consumes admitted group-origin CRs plus the four
training fallbacks with their exact member scope. It excludes source-derived and
learned CRs; card execution facts can establish applicability but card policy
contracts are masked in that mode. Capability-only receives the same target IR
and the frozen cards, including their explicit contracts, with no group rules or
training fallbacks. It uses the existing bounded capability-gap response contract
(at most four proposals per chain). These are two different requirement sources,
not a rerun of the full mixed v15 detector.

The scope is selected using the GT chain mapping, but report invariants, old
candidates, and prior match verdicts never enter detection prompts. Fresh GT
matching begins only after candidate output is frozen. Results concern Coverage
Decision candidates matched to report invariants; they are not dynamic exploit
validation or a replacement for canonical source-validation admission. Prompts,
responses, provider usage, and errors are retained under `requests/`. `--prepare-only`
validates/freezes without API calls. `--resume` reuses only successful jobs from
this same experiment; acceptance is rebound whenever detection output changes.
No source result directory or canonical publication is overwritten.
When correcting the capability response contract, `--reuse-group-from PATH`
can retain this experiment's already completed Group-only calls. It requires
identical cohort, chains, group requirements, model settings, Group/GT prompts,
and revalidates the original response JSON. The new output links each reused
record and reports inherited versus newly executed model calls separately;
capability inference is still fresh. Implementations are archived in each run.

The active detector compares all 485 eligible security chains from the fail-closed
603-chain structural partition. Group requirements, concrete Capability Card guards,
source-derived rules, and the learned invariant catalog are normalized before assessment
into `canonical-requirement/v7` records. Their only active key is `CR-*`; source kind and
legacy `R-*`, `CAPR-*`, `SR-*`, or `LIR-*` identities survive only under
`provenance.sources[]` and in `identity-migration.jsonl`.

## Canonical requirement and candidate identity

A CR contains the normalized rule, applicability, controlled facet, enforcement stage,
state lifetime, policy basis, protected asset, security effect, source evidence, and
`refines_cr_ids`. Its fingerprint binds HSG scope plus the normalized semantic identity.
Equivalent proposals from multiple sources collapse into one CR while retaining every
source payload digest and evidence record.

`coverage-candidate/v7` binds only a CR:

```text
hash(coverage-candidate/v7, HSG, project, revision, chain, CR,
     failure mode, sorted gate IDs)
```

v15 retains the `canonical-requirement/v7` and `coverage-candidate/v7` wire contracts.
Existing `CR-*` and `CAND-*` identities remain stable; new requirements and candidates use
the same fingerprints and are added to the migration ledger.

## Approval capability-policy contracts

An approval/consent Capability Card may carry a source-owned, digest-bound
`approval-policy-contract/v1`. Ordinary capability facts remain non-normative. Each policy
entry becomes independent `capability-policy` evidence and a Group Oracle requirement only
when its exact rule, applicability, security effect, card digest, HC, and ST are bound.

The approval HSG keeps its existing type/destructive requirements and four separate
effective-command obligations: indirect option operands, shell expansion, redirection
effects, and action flags. `prompt_dangerous_approval` and
`PermissionManager.askHandler` share `ST-9ba88b26bf31d99b`; alignment remains a model
decision under the approval-equivalence prompt, with no API-to-ST override. A safe-read
matcher that omits one exact semantic delta is `wrong-check`, not `covered`.

## SameOrigin and canonical source analysis

Targeted Group Oracle repair runs may select whole HSGs with repeatable `--group-id` and
publish to a separate output root. Their `selection_scope` distinguishes selected counts
from the full upstream corpus; such partial artifacts are not a replacement for the canonical
129-group input. The reviewed URL-gate registry preserves model-origin URL policies and
conditional member applicability without promoting ordinary capability cards to normative
authority. `--observed-gates-only` keeps requirement origins attached to supplied gates;
it does not replace the field-sensitive SameOrigin checks below. The G06/G25 regression also
checks that adding website-blocklist coverage does not remove existing remote-URL admission
coverage or confuse policy-load errors with DNS-validation failures.
Observed-gate runs consolidate accepted policies across dimensions before publication,
so overlapping upstream rules must not silently remove a documented applicability or
private-address exception. Downstream SameOrigin and member applicability remain required.
Reviewed gate-qualification views may restrict upstream proposal origins using exact IR
hashes and field-origin evidence quotes. Their manifest retains the original inputs and
excluded IDs; this curated gate admission does not replace downstream field-flow evidence.

Strict SameOrigin is applied to all eligible chains. A gate can cover or partially cover a
CR only when one model-controlled handler source reaches both the checked value and the
concrete sink argument, and the gate executes on the relevant pre-effect path. Helper-only,
post-sink, unrelated-parameter, and mutually exclusive branch checks remain auditable in
`same-origin-exclusions.jsonl` but cannot protect the sink-bound value.

### v15 field-sensitive flow exchange

The v15 overlay refines the source leg from a whole handler object to a constant field read and
an exact sink role. Python uses `src/ql/get_field_flow.ql`; TypeScript/JavaScript uses
`src/ql-js/get_field_flow.ql`. Exclusion companions remain fixture/diagnostic queries for
prohibited propagation. Production records every missing exact witness as `absence-not-proof`,
which keeps the member `unknown` rather than treating analysis absence as a refutation. Ordinary
data flow may cross assignments, arguments, parameters, returns, and transforms. RPC/IPC flow
requires an explicit project bridge.

`value_authority` is one of `model-arbitrary`, `model-component`, `model-basename`, `model-enum`,
`internal-derived`, `operator-config`, `provider-response`, or `fixed`. A map key never implies its value;
whole-object, same-name, sibling-argument, selector-to-selected-content, configuration/provider,
and unbridged cross-component propagation are negative controls.

QL rows are admitted only through a revision-bound `field-flow-chain-binding/v1` index keyed by
`(project, handler name/file/line, sink file/line/column/role)`. Alternate structural chains for
the same concrete handler/sink endpoint receive separate, auditable bindings; unbound rows remain
in `unbound-query-rows.jsonl` and cannot enter member applicability.
Convert decoded witness and exclusion CSVs without changing the canonical entrypoint:

```bash
python -m src.coverage_comparison.field_flow_conversion \
  --witness-csv /tmp/field-flow-witnesses.csv \
  --exclusion-csv /tmp/field-flow-exclusions.csv \
  --chain-index /tmp/field-flow-chain-index.jsonl \
  --source-root benchmark/python/PROJECT \
  --witness-out /tmp/field-flow-witnesses.jsonl \
  --exclusion-out /tmp/field-flow-exclusions.jsonl
```

The resulting `field-flow-witness/v1` and `field-flow-exclusion/v1` records bind chain, handler,
sink, field, property read, exact sink role, authority, transforms, proof kind, typed path nodes,
and SHA-256 for every referenced source file. Missing/ambiguous chain joins, source-root escape,
invalid enums, or an `explicit-bridge` proof without a bridge path node fail closed.

Canonical source analysis is not a separate detection track. The routed mode selects at
most 64 chains. Its fixed scores are:

- `+100`: SameOrigin excluded a gate cited by the primary assessment.
- `+80`: no primary candidate.
- `+60`: at least one learned rule routes to the chain.
- `+40`: partial semantic IR.
- `+30`: partial Group Oracle.
- `+20`: high-risk process, file, navigation, messaging, approval, or delegation capability.

The frozen training-regression chains are selected first without changing their scores;
each project then receives up to three highest-scored chains and the global ordering fills
the remaining budget. Ties use `(project, chain_id)`. The manifest records the complete
weights, frozen set, selected rows, and excluded rows. `--canonical-source-scope all`
defines an explicit 485-chain detector run and therefore requires a new freeze publication.

Packet source validation may apply to every CR provenance. v15 reuses only digest- and
source-hash-bound validations whose handler, controlled field, sink, and research-completeness
contracts remain valid. The original validator builds a digest-bound
`source-validation-evidence-packet/v1` containing exact handler/value/hop/gate/sink spans,
SameOrigin evidence, per-file SHA-256, and bounded value/guard searches. One no-tool model call
must either return a source-supported verdict or request deep research. Deep fallback is limited
to the packet's source files, eight turns, and sixteen tool calls; broad `Glob` and workspace
symbol search are unavailable. Only a source-confirmed uncovered assessment may survive into
canonical `candidates.jsonl`; unvalidated rows remain in the provisional/filter ledgers and are
not silently discarded. Source/IR disagreement, missing evidence, unknown ordering, malformed
output, and operational failure fail closed.

Before promotion, deterministic precision filters reject non-normative `Recommended`
requirements, facet bindings that do not reach the requirement's exact sink role, and duplicate
effective invariants on the same chain. A confirmed impact must be reachable from the model-facing
flow without requiring a second independent compromise, and every conjunctive rule clause must
have source support. `candidate-filter-dispositions.jsonl` records every decision and any duplicate
replacement identity. v15 additionally binds direct content/environment/working-directory roles
to handler-controlled sink roles, requires concrete policy evidence for generic hardening rules,
and records semantic subsumption when a stronger same-chain CR covers a narrower symlink rule.
Unresolved wrong-checks are prioritized into lossless batches of at most four candidates sharing
one chain-scoped source packet. Partial Group Oracles fail closed as `upstream-incomplete` rather
than producing actionable candidates. Complete-oracle missing-checks are selected by whole-chain
density until the total unresolved population is below 150; packet/schema failures remain explicit
`source-unknown` or `operational-failure` rows and never enter canonical output.

Upstream normativity admission is evidence-authoritative. Ordinary `capability-card` rows may
describe sink behavior and applicability but cannot independently authorize a Group requirement.
Only capability-policy, fixed-delta, explicit source policy, standard/documentation policy, or a
learned-catalog entry can establish generic normativity. Four old member-scoped repairs are loaded
only after `generic-freeze-lock.json` is written; they recover five training reports in the
explicit training overlay and never enter generic candidates or held-out inputs. The validator's
original policy-basis label is non-authoritative when it conflicts with this evidence.

## Active artifacts

`output/cross-project/coverage-comparison/` contains:

- `canonical-requirements.jsonl`, `capability-hypotheses.jsonl`,
  `normative-evidence-resolutions.jsonl`, and executable requirement contracts
- `requirement-assessments.jsonl`, `comparisons.jsonl`, effective-capability views,
  field-flow ledgers, member facts, and `member-applicability.jsonl`
- `generic-candidates.jsonl`, its byte-identical `candidates.jsonl` alias, and the separate
  `training-regression-candidates.jsonl`
- `provisional-candidates.jsonl`, validation/disposition ledgers, and
  `vulnerability-clusters.jsonl`
- `same-origin-witnesses.jsonl`, `same-origin-exclusions.jsonl`, and
  `candidate-origin-audit.jsonl`
- `canonical-router-selected.jsonl` and `canonical-router-excluded.jsonl`
- v7 plus v15 identity-migration ledgers and the 114-card migration ledger
- `source-validation-evidence-packets.jsonl`, the learned catalog/assessment snapshots,
  `ground-truth-reuse.jsonl`, and their redacted chat sidecars
- `generic-freeze-lock.json`, `artifact-inventory.json`, `manifest.json`, and
  `coverage-index.md`
- generic and training-overlay ground-truth audits plus the training fallback snapshot

The validator checks schemas, CR and candidate fingerprints, survivor relationships,
router partitioning, artifact counts, inventory hashes, detector-freeze source hashes,
and exact migration coverage of every archived requirement and candidate ID.

Useful read-only commands are:

```bash
python -m src.coverage_comparison --all --replay-only
python -m src.coverage_comparison --all --analysis-plan
```

Replay performs no provider or source-agent call. Fresh canonical source or learned
analysis changes the frozen detector execution and must be published under a new detector
freeze; the current frozen artifact fails closed instead of silently issuing live calls.

## Evaluation and version history

The current 43-report corpus was used to derive the learned catalog, approval policy
contracts, chain-binding registry, and source regression set. Its strict result is therefore
**43/43 training-regression recall**, not blind recall. Generic artifacts alone cover 38/43;
the remaining five reports are present only through four explicit fallbacks. A blind
number may be reported only for vulnerabilities or projects added after the v15 detector
freeze, with generation completed before the held-out ground truth is opened.

A separate source-transplant diagnostic reports **46/46 synthetic-inclusive
detectability**. It combines the 43 revision-bound strict candidate matches with three
production-query witnesses obtained from explicitly labeled, empirical-ineligible source
derivatives: one Nanobot login-shell path and two OpenClaw later-only paths. This number is
not canonical recall and does not assert that the three transplanted defects exist in the
pinned sources. Regenerate it with
`python scripts/render_synthetic_inclusive_coverage.py`; the report is published under
`output/cross-project/coverage-comparison-synthetic-inclusive/`.

The current snapshot has 603 structural chains, 485 eligible comparisons, 120 admitted normative
CRs, 461 capability hypotheses, and 358 admitted CR/member pairs. Member applicability partitions
them as 95 applicable, 180 unknown, and 83 upstream-incomplete. The generic output contains 78
source-confirmed candidates and 74 root-cause clusters; the training overlay adds four fallbacks
for 82 total. There are 150 field-flow witnesses, 283 exclusion/absence records, and eight
evidence-bound removals of legacy candidates that lack complete member applicability. Ordinary
capability-card-only final requirements and unvalidated generic candidates are both zero. All previous
refuted, partial, unknown, and operational-failure rows remain auditable. A later
`--replay-only` validation reads frozen artifacts and makes zero provider/source-agent calls.

Coverage v14, v13, v12, v11, v10, and v9 are immutable under their corresponding
`output/cross-project/archive/coverage-comparison-v*/` directories; v8 and v7 remain under their
corresponding archive directories.
Coverage v6 remains under `output/cross-project/archive/coverage-v6/` and the annotated
tag `coverage-v7-pre-migration-20260822`. Corrected-v2 is historical post-hoc evidence only;
it contributes identity mappings but cannot contribute active v7 CRs, assessments, or
candidates. The migration tool is retained under
`archive/coverage-comparison-v7-migration/` for provenance and rollback, and is never
imported by the active pipeline.
