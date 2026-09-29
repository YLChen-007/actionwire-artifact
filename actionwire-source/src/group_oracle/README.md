# HC-Conditioned Group Oracles

Run from the repository root:

```bash
python -m src.group_oracle --all
```

The stage consumes the validated handler and sink catalogs, the exact downstream-eligible
`handler-sink-group/v1` records, and each member's complete `call-chain-semantic-ir/v3`.
The public oracle key is `(HC, ST)` and its stable input identity is the existing `HSG-*`.
Leaf `HT-*` identities remain upstream trace metadata and never scope an oracle.

Every security group receives one deterministic seed. A NanoBot-seeded ST uses its first
complete NanoBot chain when available; otherwise the first complete project/chain identity is
selected, with partial IR as a final fallback. The seed prompt emits ordered policy atoms and
gate-derived candidate requirements but is explicitly not treated as secure or complete.
Every seed or peer candidate must cite at least one gate from that exact chain. A zero-gate
chain emits no gate-derived candidates; it cannot turn the sink's general capability into a
normative obligation. Every peer is then compared against that same frozen seed profile in
batches of at most eight. Full semantic IR is never truncated; a request exceeding the default
96,000 estimated input-token limit fails before transport.

The checked subject of a gate-derived candidate must have an explicit model-origin
binding in the supplied IR. Whole-object `args` bindings and helper parameter names
are insufficient. A trusted configuration may define the comparison policy without
being a model input. Ordinary functional checks do not automatically become security
requirements. These are semantic prompt constraints, not a replacement for a complete
field-flow graph when the input does not establish provenance.

After seed profiling, a separate evidence-extension prompt runs only for groups with applicable
normative evidence. It can propose a zero-gate requirement directly from exact
repository-pinned documentation, standards, fixed deltas, or a versioned
`capability-policy`, which prevents an empty observed-gate set from silencing an independently
supported obligation. Every such proposal must cite exact allowed `EV-*` identifiers, is
attributed to the deterministic seed with no invented gate IDs, and is still subject to the
normal evidence validation and consolidation stages. Ordinary `capability-card` rows are
excluded from this proposal pass because they describe execution capability rather than
inventing normative requirements.

All proposals are assessed against the shared sink type and repository-pinned evidence. The
central `group-oracle-evidence-authority/v1` policy classifies documentation, standards,
fixed deltas, and `capability-policy` rows as normative; ordinary capability cards are
capability-only. Every `add`, component commit, continuity carry-forward, reused oracle, and
final requirement must cite at least one normative evidence ID. Capability-only evidence may
supplement that citation but can never authorize a requirement by itself. Additional
documentation, standards, and fixed-delta evidence must be added to
`oracle-evidence-registry.json` with an exact quote and SHA-256. The generator performs no live
research. Observed gates alone cannot justify an oracle requirement. Duplicate decisions form
a graph and each connected component is jointly adjudicated before stable `R-*` identifiers
are assigned. Recursive summary audit subjects include the component ordinal, so multiple
oversized components in one group cannot collide.

Project-neutral requirements may have conditional member applicability: a documented
blocklist policy need not be enabled or implemented by the seed or every peer. Preserve
that condition, model-origin subject, defaults and failure limits rather than rejecting
the policy solely as project-specific or imposing it on every HTTP client. The normative
evidence requirement still applies; a capability card alone cannot authorize the rule.

The canonical output directory contains `oracles.jsonl`, `seed-profiles.jsonl`,
`proposals.jsonl`, `proposal-assessments.jsonl`, `excluded-groups.jsonl`,
`evidence-index.json`, `manifest.json`, `oracle-index.md`, and prompt/response audit
sidecars. No-security-impact groups are recorded as exclusions and never sent to the LLM.
One schema-repair request is permitted per interaction. Normal reruns replay only
byte-identical audited prompts; an interrupted run also resumes from a redacted noncanonical
checkpoint journal, which is removed after successful publication. Use `--fresh` to bypass
canonical replay. Publication is atomic, and credentials are read only from
`DEEPSEEK_API_KEY`. `--fresh` also disables whole-group snapshot and requirement-continuity
reuse. Whole-group reuse otherwise requires an equal `construction_policy_sha256`, so
changed inference/repair instructions cannot be skipped by the content cache.
When a fresh candidate and a retained requirement share a proposal ID, continuity merging
retains normative origin evidence as well as chain/gate provenance and uses the evidence
origin contract. Losing that authority aborts publication rather than silently rejecting a
proposal while reporting that it was preserved.

## Isolated URL-group regression

The reviewed G06/G25 inputs have two model-origin URL objectives (secret-pattern blocking
and address prefiltering) and one conditional website-blocklist objective. The existing
G25 remote-image scheme/address admission objective must also survive the repair. Their separate
documentation registry preserves the exact exceptions and error behavior without changing
the baseline or ground-truth-correction registry. Run only these two complete groups:

```bash
python -m src.group_oracle --all \
  --group-id HSG-2a9409f6633c1b6a \
  --group-id HSG-3209832c56152666 \
  --evidence-registry src/group_oracle/oracle-evidence-registry-url-gates.json \
  --gate-qualification src/group_oracle/evidence/url-gate-qualification.json \
  --out-dir output/cross-project/group-oracles-url-gates-test-v7 \
  --fresh --observed-gates-only --timeout 120 --max-output-tokens 12000
```

Repeated `--group-id` retains every member of each selected group and excludes unrelated
groups from inference. A selected run cannot publish over canonical `group-oracles` or an
existing directory containing unselected rows. `selection_scope` records both the selected
identities and the full upstream denominators; ordinary counts describe only this run.
The output is a reviewed targeted repair, not a new blind full-corpus result.

`--observed-gates-only` requires every final requirement to retain at least one observed
origin gate. It disables the zero-gate evidence-extension pass and excludes zero-gate
continuity rows, while normative documentation still supports assessment. This prevents
authoring notes about error/default preservation from becoming standalone requirements.
It cannot be combined with correction-ledger injection. The mode is part of whole-group
reuse identity; it does not claim to mechanically reconstruct missing model-field flows.
Before publication, this mode also consolidates accepted policies across dimensions,
checking their combined conditions against the full member IR and normative contracts.
The review must partition the exact accepted proposal IDs, retain normative support and
respect the input token limit. This catches contradictions hidden by per-dimension
assessment, such as a duplicate rule overriding the intended private-address exception.

`--gate-qualification` applies a reviewed model-origin qualification to this inference
view. It validates exact group/member/revision scope, the complete original semantic-IR
digest, gate IDs and quoted JSON-pointer values. Only admitted gates (and their value
bindings) are exposed as proposal origins; all four members remain, including the peer
with no qualified gates. This enforces the reviewed decision and prevents the model from
citing unqualified helper gates; it is not an automatic field-flow proof. Original upstream
IR is unchanged and its hashes plus excluded IDs remain in the manifest audit.

Capability-card evidence is bound to the complete source by path and SHA-256. Any
credential-shaped examples are redacted before evidence IDs, prompts, resumable checkpoints,
chat sidecars, or canonical artifacts are constructed. Manual exact quotes containing such
data are rejected.

The manifest records provider-reported usage and its covered live-call count separately from
deterministic full-run token estimates computed over every audited exchange. This distinction
is necessary when an interrupted run resumes through exact replay.

## Post-hoc source correction v2

The corrected-v2 ledger is rebound in place to the rollback-adjusted 23/43 baseline. It covers
the exact 20 missed reports with a `9 add / 8 refine / 3 reassess` partition and records
`astrbot-write-policy-rollback-v1` as a post-hoc benchmark overlay. Ground-truth-informed,
source-backed corrections use the separately bound v2 registry and ledger:

```bash
python -m src.group_oracle --all \
  --evidence-registry src/group_oracle/oracle-evidence-registry-corrected-v2.json \
  --correction-ledger src/group_oracle/corrections/missed-reports-v2.json \
  --out-dir output/cross-project/group-oracles-corrected-v2 \
  --input-token-limit 80000 \
  --max-output-tokens 32000
```

The ledger must exactly cover the 20 baseline misses with the fixed `9 add / 8 refine /
3 reassess` partition and revalidates every baseline manifest, overlay source digest, report
digest, chain, HSG, HC/ST, and existing requirement. Its correction-only evidence locator set
must exactly equal the ledger-required set. Correction evidence contains only project-neutral claims and source
anchors; report text and report identifiers never enter oracle prompts. Reviewed correction
proposals are committed deterministically, while ordinary seed/peer proposals retain normal
model adjudication. The v2 manifest is marked `post_hoc_ground_truth_informed` and must never be
reported as the blind result. The rebound pipeline produces a 34/43 corrected audit over the
23/43 rollback-adjusted baseline, with 14 corrected matches and 6 evidence-insufficient rows.
