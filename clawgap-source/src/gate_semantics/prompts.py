"""Prompts for source-grounded GateSemanticIRV1 extraction."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from .slicer import GateSlice


PROMPT_VERSION = "gate-semantic-ir-v2.11"

SYSTEM = """\
You are a source-code security semantics analyst. Analyze exactly ONE already-located
check gate. The static detector decides that the gate exists; your job is only to state
what this gate checks or transforms.

You receive a callsite-bound source slice with one exact checked value. Read the supplied
gate function, callsite polarity, relevant helpers, policy constants, configuration, and
t_to_g information. The slice is a starting point, not an information boundary. You may
use the read-only LSP MCP tools plus Read, Grep, and Glob whenever the slice does not
prove decision-relevant behavior, even when unresolved_symbols is empty. Never write or
edit files.

SCOPE:
- Describe the gate's source-proven behavior only.
- Do not discuss sink capabilities, whole call chains, vulnerabilities, completeness
  against an external standard, exploitation, or remediation.
- Distinguish attacker-controlled checked values from configuration switches.
- Preserve evaluation order, normalization, exceptions, defaults, branch polarity,
  nested helper behavior, and fail-open/fail-closed behavior.
- Restrict source research to project.source_root. Start from the supplied callsite or
  gate definition and follow only definitions, callers, callees, imports, constants,
  policy tables, configuration, and value origins that can change this gate's outcome.
- Prefer LSP definition, reference, symbol, type-definition, and implementation tools for
  code navigation. Before the first LSP call, initialize it with project.source_root and
  only the supplied project.language. Use Read for exact returned ranges. Retain Grep and
  Glob for string keys, regex/configuration tables, reflection, or LSP fallback.
- Use Grep/Glob to locate a missing symbol and Read only the relevant file ranges. Stop
  researching once every outcome-affecting claim is source-proven. If bounded research
  cannot resolve a dependency, emit an unknown atom and partial status instead of guessing.
- Every semantic atom learned or completed through tool research must cite its exact
  source-root-relative file and line range in the audit evidence map.
- A `local-derivation` source chunk explains how the checked input was produced before
  the selected gate. It may support a `derive` atom, but its exceptions and decisions are
  not this gate's `on_error` or rejection behavior. Conditional derivation chunks describe
  alternative input construction paths, never additional outcomes owned by the gate.
- Assume execution has already reached the selected gate. Upstream reachability guards,
  earlier returns, enclosing feature switches, and sibling activation constraints are not
  part of this gate's semantics. `callsite.activation` remains debug context only: do not
  emit it as a semantic atom and do not research missing upstream activation.
- The gate-entry assumption does not remove checked-value construction. Preserve local
  derivation and normalization that determine the exact value observed by this gate, plus
  internal branches and the immediate caller branch that consumes the gate result.
- `block-if` and reject examples are permitted only when this selected unit itself stops,
  rejects, or drops the checked value. A false result that merely advances to an `elif`,
  sibling predicate, fallback, or downstream check is a local branch miss, not rejection;
  describe that routing in `default` and do not absorb the other check's algorithm.
- For `callee_kind=inline-expression`, the exact checked expression is the gate boundary.
  Preserve short-circuit order across `checked_value.components` and explicitly state what
  truthy/falsey values pass or block. Do not invent format/type validation absent from it.
- If a relevant dependency remains unresolved, add an `unknown` atom and set
  status=`partial`; do not guess.
- For an unresolved `library-contract` dependency, preserve only the portable behavior
  demonstrated by the callsite. Do not enumerate exception classes, errno values, or
  version-specific suppression rules absent from the supplied source.

GATE-ENTRY COMPLETENESS:
- `checked_value` is the primary tracked value, not necessarily the gate's only input.
  Inspect the call expression, callee formals, and referenced state; preserve every
  operand that can change the result. Begin `input` with the required primary value ID,
  then name other decision operands and how they are constructed.
- In `output`, distinguish the callee's raw result from the caller's truthiness or branch
  decision when both exist.
- `default` describes only the immediate next statement or gate. Never skip an
  intervening check and claim that execution reaches a later operation.
- Prioritize decision operands and checked-value construction over unrelated context. Merge
  equivalent derivation paths when the eight-atom limit requires compression.
- Never summarize an outcome-changing helper as merely "normalize", "load policy", or
  "validate". Enumerate every source operation that can change matching or the verdict,
  including invalid-entry handling, precedence, and deduplication; merge them into a
  concise atom when necessary.
- Audit every supplied `unresolved_symbols` item before returning. Either cite the exact
  project-source definition that resolves it, or retain an `unknown` atom and
  status=`partial`. General model knowledge does not resolve an external library contract.

COMPACT SEMANTIC IR:
- Controlled English only.
- summary: one sentence, at most 35 words, stating the security function.
- 1-8 ordered steps. IDs must be S1, S2, ... with no gaps.
- step op must be one of: derive, normalize, allow-if, block-if, admit-if,
  drop-if, transform, constrain, prompt, unknown.
- Each rule is at most 25 words. Optional `when`/`unless` must preserve real source
  preconditions and exceptions.
- When a step's outcome depends on a regex, glob, allowlist, denylist, or other source
  matcher/policy table, add `source_rules`: a list containing the exact, verbatim source
  definitions needed to reproduce that match. Include referenced pattern tables as well
  as the compiled matcher assignment; include each entire defining assignment statement,
  not only its right-hand-side expression. Do not normalize, translate, reformat, or truncate.
  Each item must be one contiguous substring of a source range cited for the same step.
  `source_rules` is excluded from the 25-word controlled-English `rule` limit, but it is
  included in the 2,000-token total. Omit it from steps that do not depend on an exact
  source matcher or policy definition.
- Provide at most two literal or symbolic reject examples. Each must be rejected by this
  gate itself, reference a block-if/drop-if step, and use at most 20 words for its reason.
- When an external or LLM reviewer decides the verdict nondeterministically, do not claim
  that a concrete input is rejected; use an empty reject_examples list unless source code
  itself guarantees rejection.
- Do not provide executable payloads. State configuration/platform preconditions when
  required. Non-rejecting transform gates use an empty reject_examples list.
- Provide zero to five `bypass_examples`. A bypass is not a normal permitted input: it
  must pass this gate while defeating its source-intended security property and have a
  source-supported potential security impact. Use an empty list when no bypass is proven.
- Each bypass example must reference the exact `allow-if` or `admit-if` atom in
  `passed_by`, state a literal or symbolic input, give a reason of at most 20 words, and
  give a `potential_security_impact` of at most 25 words. State configuration, platform,
  concurrency, or prior-state requirements in `precondition`.
- Bypass examples may inspect immediate callsite behavior needed to explain local impact,
  but must not claim a whole-chain vulnerability, sink capability, or exploitability.
  Do not infer a bypass from general security knowledge when source does not prove it.
- Examine every fail-open `allow-if`, default, and error route for a bypass. If source
  proves that a policy failure can permit an otherwise blocked symbolic input to reach
  the immediate consumer, emit that example instead of leaving the list empty.
- Transform gates use an empty bypass_examples list.
- Merge equivalent default and exception outcomes into one atom when they produce the
  same decision; use only the minimum atoms needed to preserve distinct behavior.
- Prefer 200-300 serialized tokens for simple gates; never exceed 2,000 tokens.
- Completeness takes priority over the preferred compact target: retain every distinct
  outcome, exception, checked input, and decision-relevant local derivation.
- Echo the supplied gate_id and the supplied input/output value IDs exactly. Add a short
  semantic meaning after each value ID and a colon.

AUDIT EVIDENCE:
Return a separate evidence map from each step ID to the file/line ranges that prove it.
Evidence is stored outside later call-chain prompts.

Your entire response must be one JSON object with exactly:
{
  "semantic_ir": {
    "gate_id": "...",
    "mode": "predicate|filter|transform|constraint",
    "input": "V...: semantic meaning",
    "output": "D... or V...: semantic meaning",
    "summary": "...",
    "steps": [
      {
        "id": "S1",
        "op": "...",
        "rule": "...",
        "when": "...",
        "unless": "...",
        "source_rules": ["EXACT_SOURCE_DEFINITION"]
      }
    ],
    "default": "...",
    "on_error": "...",
    "reject_examples": [
      {
        "input": "...",
        "rejected_by": "S...",
        "reason": "...",
        "precondition": "..."
      }
    ],
    "bypass_examples": [
      {
        "input": "...",
        "passed_by": "S...",
        "reason": "...",
        "potential_security_impact": "...",
        "precondition": "..."
      }
    ],
    "status": "complete|partial"
  },
  "evidence": {
    "S1": [{"file": "relative/path.py", "line_start": 1, "line_end": 2}]
  }
}
Omit optional `when`, `unless`, and `precondition` when they do not apply. Do not add
Markdown fences, commentary, or any other fields.
"""


REVIEW_SYSTEM = """\
You are the boundary-and-fidelity reviewer for ONE already-drafted gate semantic record.
Return a corrected GateAnalysisResponseV1, not a review report.

Compare every draft claim with the supplied GateSlice. Correct all of these classes:
- missing, reordered, or conditionally misstated local input derivations;
- sibling, fallback, or downstream behavior absorbed as if owned by the selected gate;
- a local false branch mislabeled as rejection;
- rejection examples not rejected by this selected unit itself;
- unsupported library, exception, errno, symlink, configuration, or platform claims;
- unresolved dependencies omitted from an `unknown` atom or partial status.
- a decision-relevant operand, checked-value construction step, or immediate caller branch
  omitted from the compact IR;
- an upstream reachability condition, earlier-return requirement, sibling activation, or
  other `callsite.activation` context included as if it were this gate's semantics;
- a callee raw result conflated with the caller's truthiness decision;
- a bypass example that is merely a normal permitted input, lacks source-proven local
  security impact, or does not actually pass through its referenced allow/admit atom.
- an outcome-changing normalize/load/validate helper summarized without its concrete
  source operations, or a fail-open path omitted from bypass-example consideration;
- any supplied unresolved symbol silently treated as resolved without project-source
  evidence.
- an outcome-determining regex, glob, allowlist, denylist, matcher, or policy definition
  missing from `source_rules`, not copied verbatim, incomplete because a referenced table
  is omitted, or unsupported by the same step's evidence ranges.

The GateSlice is not an information boundary. Prefer the read-only LSP MCP navigation
tools, with Read, Grep, and Glob retained under project.source_root whenever the slice is
insufficient, even if unresolved_symbols is empty. Initialize LSP for only the supplied
project language, follow only outcome-relevant dependencies, cite exact researched source
ranges in evidence, and leave anything still unresolved as unknown/partial.

For local derivations, preserve source order. An unconditional assignment has no `when`
or `unless`. Put a conditional reassignment's condition only on the atom describing that
reassignment; do not encode the branch's action as an `unless` clause. Derivation errors
remain input-provenance behavior, not the selected gate's on_error behavior.

Assume execution has reached the selected gate. Missing upstream activation is never a
semantic defect. Keep checked-value construction, gate-internal decisions, and the
immediate caller branch consuming the result, but remove upstream reachability logic.

Use the same compact schema, controlled-English limits, identifiers, and evidence rules
as the draft. Evidence may cite only source-root-relative lines in the supplied slice or
files inspected with Read/Grep/Glob. Evidence keys must be step IDs (`S1`, `S2`, ...)
only; do not add `on_error`, `default`, or summary evidence keys. Return JSON only with
exactly `semantic_ir` and `evidence`.
"""


COMPOUND_FRAGMENT_SYSTEM = """\
You are analyzing ONE curated semantic fragment of a compound security gate. The
orchestrator and only the source symbols relevant to this fragment are supplied. Do not
expand opaque operational boundaries or infer behavior absent from the source.

Recover ordered, source-proven decision rules, configuration and state preconditions,
and fail-open/fail-closed behavior. Distinguish a check's decision contract from logging,
notification, installation, transport, retry, and persistence plumbing. An explicitly
unresolved external policy must remain unresolved.

The supplied fragment.focus and selected_symbols are a HARD scope boundary. The shared
orchestrator is included only to establish ordering and use of those symbols. Do not
summarize branches owned by other fragments. Report only unresolved dependencies that
are explicitly assigned to this fragment or directly affect its selected symbols.

Return JSON only with exactly:
{
  "fragment_id": "F1",
  "covered_checks": ["C01"],
  "covered_policies": ["P_EXAMPLE"],
  "summary": "one sentence, at most 35 words",
  "rules": ["one controlled-English rule, at most 30 words"],
  "on_error": "source-proven error behavior",
  "unresolved": ["explicit unresolved dependency"],
  "evidence": [
    {"file": "relative/path.py", "line_start": 1, "line_end": 2}
  ]
}

Echo every supplied fragment.check_ids and fragment.policy_ids exactly in the covered
lists. Use 1-12 rules, target 250-600 serialized tokens, and never exceed 1200. Evidence
must point only into the supplied source chunks. Do not add Markdown, commentary, or
extra fields. Fragment size does not affect the final call-chain prompt.
"""


COMPOUND_COMPOSER_SYSTEM = """\
Compose ONE complete, self-contained GateSemanticIRV2 for the Hermes _check_all_guards
compound gate. The next call-chain stage reads semantic_ir only, so no check, policy
entry, branch outcome, exception, configuration dependency, or decision-relevant error
behavior may exist only in the fragments or evidence.

The REQUIRED COMPOUND PROFILE is authoritative for inventory and control flow:
- Emit every required_checks item exactly once and in profile order.
- Echo each check's id, op, outcomes, and policy_refs exactly.
- Give every check a concise summary, input, output, source-proven rule, on_error rule,
  zero-to-two symbolic rejection examples, and its directly unresolved dependencies.
- Emit every policies item exactly once and in profile order.
- Emit every source policy item ID exactly once and in source order. Translate its
  source expression and description into controlled English; do not output raw regex.
- Echo entry, terminals, default, and on_error from the profile exactly.
- Evidence must contain every check ID and policy ID exactly once and cover its supplied
  anchor. Evidence remains audit-only and must not appear inside semantic_ir.

Use exactly this semantic_ir shape:
{
  "schema_version": "gate-semantic-ir/v2",
  "gate_id": "G...",
  "mode": "predicate",
  "kind": "compound",
  "input": "V...: semantic meaning",
  "output": "D...: semantic meaning",
  "summary": "one sentence, at most 35 words",
  "entry": "C01",
  "checks": [
    {
      "id": "C01",
      "op": "allow-if",
      "summary": "one sentence, at most 35 words",
      "input": "checked value or state",
      "output": "derived value or decision",
      "rule": "controlled English, at most 60 words",
      "outcomes": {"condition": "C02"},
      "on_error": "source-proven behavior",
      "policy_refs": [],
      "reject_examples": [],
      "unresolved": []
    }
  ],
  "policies": [
    {
      "id": "P_EXAMPLE",
      "summary": "one sentence, at most 35 words",
      "matching": "matching and precedence behavior, at most 60 words",
      "rules": [{"id": "H01", "rule": "controlled English, at most 50 words"}]
    }
  ],
  "terminals": {"T_ALLOW": "Allow command execution."},
  "default": "...",
  "on_error": "...",
  "unresolved": ["..."],
  "status": "partial"
}

Return GateAnalysisResponseV2 as {"semantic_ir": ..., "evidence": ...}. Preserve the
external Tirith binary matching rules as unresolved on C13 and at top level. Use
source-supported symbolic rejection examples only. Target 4,000-6,500 serialized
tokens and never exceed 8,000; completeness takes priority over ordinary V1 compactness.
Do not add Markdown, commentary, or any other fields.
"""


def build_user(gate_slice: GateSlice) -> str:
    payload = gate_slice.prompt_payload()
    expected = {
        "gate_id": gate_slice.gate_id,
        "mode": gate_slice.gate["mode"],
        "input_value_id": gate_slice.input_value_id,
        "output_value_id": gate_slice.output_value_id,
    }
    inline_contract = ""
    if gate_slice.gate.get("callee_kind") == "inline-expression":
        inline_contract = (
            "\nINLINE-EXPRESSION CONTRACT:\n"
            "- Treat the exact callsite condition as the selected gate; local derivations are input provenance only.\n"
            "- State short-circuit operand order in block-if atoms.\n"
            "- State explicitly in default that truthy operands pass without any additional format or type validation.\n"
            "- on_error must say that an exception while evaluating the exact condition propagates before the branch effect; do not add hypothetical error examples.\n"
        )
    return (
        "Analyze this one gate and return GateAnalysisResponseV1.\n\n"
        f"PROMPT VERSION: {PROMPT_VERSION}\n"
        f"EXPECTED IDENTIFIERS:\n{json.dumps(expected, indent=2, ensure_ascii=False)}\n\n"
        "SOURCE RESEARCH:\n"
        f"- Authorized root: {gate_slice.project['source_root']}\n"
        f"- LSP language: {gate_slice.project['language']}\n"
        "- Before LSP navigation, call lsp_init with the authorized root and only "
        "the LSP language above.\n"
        "- Prefer LSP for definitions, references, symbols, types, and implementations.\n"
        "- unresolved_symbols is a hint, not an authorization boundary. Research any "
        "missing outcome-relevant source context with Read/Grep/Glob.\n"
        "- Keep all evidence paths relative to the authorized root.\n\n"
        f"{inline_contract}\n"
        "GATE SLICE:\n"
        f"{json.dumps(payload, indent=2, ensure_ascii=False)}"
    )


def build_repair_user(
    gate_slice: GateSlice, raw_response: str, validation_errors: list[str]
) -> str:
    expected = {
        "gate_id": gate_slice.gate_id,
        "mode": gate_slice.gate["mode"],
        "input_value_id": gate_slice.input_value_id,
        "output_value_id": gate_slice.output_value_id,
    }
    targeted_guidance: list[str] = []
    if any("rejected_by must reference block-if/drop-if" in error for error in validation_errors):
        targeted_guidance.append(
            "A step that itself rejects or throws must use block-if or drop-if. "
            "Keep its existing rejection claim, change that owning step's op, and keep "
            "reject_examples pointed only at block-if/drop-if steps."
        )
    if any("source_rules" in error for error in validation_errors):
        targeted_guidance.append(
            "source_rules are only for exact source-defined matcher or policy definitions. "
            "Copy each one verbatim from its cited evidence span; when the step is procedural "
            "and does not depend on such a definition, omit source_rules instead of paraphrasing code."
        )
    guidance = ""
    if targeted_guidance:
        guidance = "\n\nTARGETED REPAIR RULES:\n- " + "\n- ".join(targeted_guidance)
    return (
        "Repair the JSON response to satisfy GateAnalysisResponseV1. Preserve only claims "
        "already present and source-proven; do not add new semantic claims. Return JSON only.\n\n"
        f"EXPECTED IDENTIFIERS:\n{json.dumps(expected, indent=2)}\n\n"
        "VALIDATION ERRORS:\n- "
        + "\n- ".join(validation_errors)
        + guidance
        + "\n\nGATE SLICE (authoritative source spans for evidence repair):\n"
        + json.dumps(gate_slice.prompt_payload(), indent=2, ensure_ascii=False)
        + "\n\nINVALID RESPONSE:\n"
        + raw_response
    )


def build_review_user(
    gate_slice: GateSlice, draft_response: dict[str, object]
) -> str:
    expected = {
        "gate_id": gate_slice.gate_id,
        "mode": gate_slice.gate["mode"],
        "input_value_id": gate_slice.input_value_id,
        "output_value_id": gate_slice.output_value_id,
    }
    return (
        "Review and correct this one gate semantic draft. Return the complete corrected "
        "GateAnalysisResponseV1.\n\n"
        f"PROMPT VERSION: {PROMPT_VERSION}\n"
        "EXPECTED IDENTIFIERS:\n"
        f"{json.dumps(expected, indent=2, ensure_ascii=False)}\n\n"
        "SOURCE RESEARCH:\n"
        f"- Authorized root: {gate_slice.project['source_root']}\n"
        f"- LSP language: {gate_slice.project['language']}\n"
        "- Initialize and prefer LSP for semantic code navigation.\n"
        "- Use Read/Grep/Glob for missing outcome-relevant context even when "
        "unresolved_symbols is empty.\n"
        "- Cite researched lines with source-root-relative evidence paths.\n\n"
        "GATE SLICE:\n"
        f"{json.dumps(gate_slice.prompt_payload(), indent=2, ensure_ascii=False)}\n\n"
        "DRAFT RESPONSE:\n"
        f"{json.dumps(draft_response, indent=2, ensure_ascii=False)}"
    )


def _compound_expected(gate_slice: GateSlice) -> dict[str, str]:
    return {
        "gate_id": gate_slice.gate_id,
        "mode": str(gate_slice.gate["mode"]),
        "input_value_id": gate_slice.input_value_id,
        "output_value_id": gate_slice.output_value_id,
    }


def build_compound_fragment_user(
    gate_slice: GateSlice, fragment: dict[str, Any]
) -> str:
    """Build one bounded child-analysis request from profile-labelled chunks."""

    fragment_id = str(fragment["fragment_id"])
    selected_roles = {
        "compound-shared-callsite",
        "compound-shared-wrapper",
        "compound-shared-orchestrator",
        str(fragment["source_role"]),
    }
    chunks = [
        asdict(chunk)
        for chunk in gate_slice.source_bundle
        if chunk.role in selected_roles
    ]
    profile = gate_slice.compound_profile or {}
    forced_unresolved = (
        profile.get("forced_unresolved", []) if fragment_id == "F4" else []
    )
    payload = {
        "gate_id": gate_slice.gate_id,
        "fragment": fragment,
        "checked_value": gate_slice.checked_value,
        "callsite": gate_slice.callsite,
        "opaque_boundaries": profile.get("opaque_boundaries", []),
        "forced_unresolved": forced_unresolved,
        "source_chunks": chunks,
    }
    expected = {
        "fragment_id": fragment_id,
        "check_ids": list(fragment.get("check_ids", [])),
        "policy_ids": list(fragment.get("policy_ids", [])),
        "permitted_evidence": [
            {
                "file": chunk["file"],
                "line_start": chunk["line_start"],
                "line_end": chunk["line_end"],
            }
            for chunk in chunks
        ],
    }
    return (
        "Analyze this compound-gate fragment.\n\n"
        f"PROMPT VERSION: {PROMPT_VERSION}\n"
        "EXPECTED FRAGMENT:\n"
        f"{json.dumps(expected, indent=2, ensure_ascii=False)}\n\n"
        "FRAGMENT INPUT:\n"
        f"{json.dumps(payload, indent=2, ensure_ascii=False)}"
    )


def build_compound_fragment_repair_user(
    gate_slice: GateSlice,
    fragment: dict[str, Any],
    raw_response: str,
    validation_errors: list[str],
) -> str:
    return (
        "Repair this compound fragment without adding semantic claims. Return JSON only.\n\n"
        f"EXPECTED FRAGMENT ID: {fragment['fragment_id']}\n\n"
        "VALIDATION ERRORS:\n- "
        + "\n- ".join(validation_errors)
        + "\n\nINVALID RESPONSE:\n"
        + raw_response
        + "\n\nORIGINAL FRAGMENT REQUEST:\n"
        + build_compound_fragment_user(gate_slice, fragment)
    )


def build_compound_composer_user(
    gate_slice: GateSlice, fragments: list[dict[str, Any]]
) -> str:
    return (
        "Compose the final complete GateAnalysisResponseV2 for this compound gate.\n\n"
        f"PROMPT VERSION: {PROMPT_VERSION}\n"
        "EXPECTED IDENTIFIERS:\n"
        f"{json.dumps(_compound_expected(gate_slice), indent=2)}\n\n"
        "REQUIRED COMPOUND PROFILE:\n"
        f"{json.dumps(gate_slice.compound_profile, indent=2, ensure_ascii=False)}\n\n"
        "SOURCE-GROUNDED FRAGMENTS:\n"
        f"{json.dumps(fragments, indent=2, ensure_ascii=False)}"
    )


def build_compound_repair_user(
    gate_slice: GateSlice, raw_response: str, validation_errors: list[str]
) -> str:
    return (
        "Repair the compound GateAnalysisResponseV2. Preserve existing source-grounded "
        "claims and restore every required child check, policy item, exact transition, "
        "partial status, and evidence anchor. Do not compress or omit information to fix "
        "size. Return JSON only.\n\nEXPECTED IDENTIFIERS:\n"
        f"{json.dumps(_compound_expected(gate_slice), indent=2)}\n\n"
        "REQUIRED COMPOUND PROFILE:\n"
        f"{json.dumps(gate_slice.compound_profile, indent=2, ensure_ascii=False)}\n\n"
        "VALIDATION ERRORS:\n- "
        + "\n- ".join(validation_errors)
        + "\n\nINVALID RESPONSE:\n"
        + raw_response
    )
