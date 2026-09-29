# Cross-Project Handler-Type Alignment

This package implements the manuscript's NanoBot-seeded handler-type alignment:

```bash
python -m src.handler_type_alignment --all
```

The CLI reserves a large output budget for project batches, bounded proposal matching,
component adjudication, and singleton challenges so validated JSON is not truncated.

It consumes every fresh, resolved handler specification and never reads or filters on
handler-impact decisions. NanoBot handlers seed immutable intent leaves. External handlers
are canonicalized in deterministic project batches. A normalized intent assigned conflicting
parent axes is resolved once from its observed tuples; an unrepaired conflict fails the run.
Handlers are then reconciled only inside an exact operation/resource/effect parent block.
An unanchored parent first forms proposals deterministically by exact validated intent key;
the later sibling stage still judges semantic aliases. Unmatched groups receive temporary
member-derived `HP-...` proposal IDs.

`handler-type-catalog/v4` is hierarchical:

- `HC-...` hashes `operation_family + resource_family + effect` and identifies a shared
  handler criterion.
- `HT-...` retains the existing
  `intent_family + operation_family + resource_family + effect` hash and identifies a precise
  user-visible action leaf.

Required and optional role shapes are aggregated as `role_signatures`; labels, roles, and
compatibility prose do not split handlers that perform the same primary user-visible action.
Browser click, typing, scrolling, and navigation can share an `HC-...` while remaining
separate `HT-...` leaves. The same applies to the required repository and device action
boundaries.

Batches of at most eight proposals compare against the complete sibling index under one
parent. Proposed-match components are jointly adjudicated with a cross-parent merge guard.
A one-member leaf is challenged only against sibling leaves. If its parent has no other leaf,
`singleton-audit.jsonl` records a deterministic `no-sibling-candidate` boundary without an
LLM call. Unresolved runtime definitions remain explicit exclusions.

Before hashing, a small audited normalization table collapses interface-packaging aliases
such as message payload/destination variants, file/document reads, single/batch browser
command execution, scheduled-task state controls, and skill lifecycle modes. The table also
normalizes their operation/effect axes. It does not alias the protected browser action
boundaries, repository issue/commit/pull-request creation, or device app/service/key/playback
boundaries.

Alignment prompts contain only declared handler intent and parameter roles. Sink identities,
capability classes, gate semantics, and impact verdicts are excluded so the tool-type axis
remains distinct from the later sink-type axis. After alignment, reachable sink IDs and
capability classes are joined deterministically into `capability-observations.jsonl` as a
cluster-consistency audit; they never affect type membership. `singleton-audit.jsonl`
records complete sibling coverage and the distinguishing reason for every final singleton.
`criterion-support.jsonl` reports handler, project, and leaf support per parent, while
`handler-oracle-inheritance.jsonl` projects `[HC, HT]` shared-parent then additive-leaf scope.
It is metadata only: this experiment does not call a group-oracle LLM stage. Canonical outputs
are written under `output/cross-project/handler-types/`.
