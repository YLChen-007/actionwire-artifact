# Cross-Project Sink-Type Alignment

Run the HC-conditioned global sink-type stage from the repository root:

```bash
python -m src.sink_type_alignment --all
```

The stage consumes the revision-bound `handler-type-catalog/v4` and
`handler-type-mapping/v2` artifacts plus every project's structural call chains,
assembled semantic IR, sink constraints, and capability cards. `HC-*` is the public
handler axis. `HT-*` remains trace metadata and never scopes an oracle group.

Every structural chain is accounted for exactly once. Retained chains with complete or
partial `call-chain-semantic-ir/v3` enter alignment. The semantic assembler accepts up to
64,000 estimated tokens, which covers the current retained corpus. Confirmed no-impact
chains remain excluded from ST inference but are grouped under the terminal key
`(HC, no-security-impact)` in `handler-sink-groups.jsonl`; these groups are marked
`downstream_oracle_eligible: false`. Semantic assembly failures and chains whose
model-facing handler has no resolved HC mapping remain in `excluded-chains.jsonl`.

Before any LLM call, the loader validates project revisions, manifest paths and schemas,
handler specifications and mappings, structural/semantic chain identities, sink
constraints, and capability-card SHA-256 values. It joins by exact model-facing
`(project, tool_name)` first and then by concrete handler function/file/line. Conflicting,
ambiguous, or unexplained joins fail the run. Repeated chains with the same
`(project, HC, sink_id)` share one assessment only when all sink semantics agree.
Targets for the same revision-bound concrete `(project, sink_id)` reached from different
HCs are deterministically forced into one global ST; conflicting raw semantics for that
identity fail the run.

NanoBot targets seed frozen global `ST-*` anchors. External reconciliation initially sees
only anchors already associated with its HC; an unseeded HC starts with an empty candidate
catalog. Unmatched proposals are subsequently compared with the complete global catalog,
and connected proposed-match components are jointly adjudicated. This makes ST identity
global while keeping initial candidate availability HC-conditioned.

The content-derived `ST-*` identity hashes capability family/facets, controlled semantic
roles, implicit-default facets, and project-neutral call-shape family. API/library names,
projects, languages, HC/HT IDs, labels, and compatibility prose are excluded. Prompts treat
all embedded handler and sink text as untrusted data and expose no tools. One schema-repair
request is permitted; an unrepaired response fails without replacing the previous output.
Credential-shaped substrings in untrusted source/card text and model responses are redacted
before transport or audit persistence.

Canonical output is written atomically to `output/cross-project/sink-types/`:

- `catalog.json` (`sink-type-catalog/v1`)
- `mappings.jsonl` (`sink-type-mapping/v1`, one row per eligible chain)
- `assessments.jsonl` (one row per unique project/HC/sink target)
- `excluded-chains.jsonl`
- `handler-sink-groups.jsonl` (security `(HC, ST)` groups plus terminal no-impact groups)
- `manifest.json`, `alignment.md`, and prompt/response audit sidecars

Use `--stdout` to run the full inference and preview the generated Markdown without
replacing the canonical output directory. Credentials are read only from
`DEEPSEEK_API_KEY`.

Normal reruns reuse a prior audited response only when both the complete system prompt
and complete user payload are byte-identical. This makes unchanged semantic artifacts
reproducible while any input, identifier, criterion snapshot, or prompt-contract change
causes a live request. Use `--fresh` to intentionally bypass all exact prompt replays.
