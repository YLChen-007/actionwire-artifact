"""GT-informed learned-invariant component of canonical CR v7."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from src.gate_semantics.contracts import estimate_tokens

from .contracts import (
    CoverageComparisonError,
    canonical_json,
    digest,
    normalize_text,
    parse_json_response,
    sha256_file,
)
from .inputs import CoverageChain
from .prompts import contains_credentials, redact_credentials
from .same_origin import SameOriginRun
from .versions import (
    CANDIDATE_SCHEMA_VERSION,
    LEARNED_ASSESSMENT_SCHEMA_VERSION,
    LEARNED_PROMPT_VERSION,
    LEARNED_REQUIREMENT_SCHEMA_VERSION,
)


LEARNED_CATALOG_SCHEMA_VERSION = "learned-invariant-catalog/v9"
LEARNED_MAX_PATTERNS_PER_BATCH = 4
DEFAULT_CATALOG_PATH = Path(__file__).with_name("learned-invariants.json")


LEARNED_COMPARE_SYSTEM = r"""
Compare routed learned security invariants with one concrete, SameOrigin-qualified call chain.
The learned invariant catalog is a normative policy source derived from historical defects.  A
tool declaring a dangerous capability does not refute an applicable learned rule.  The exact
handler input, controlled sink facet, and concrete effect must nevertheless be realizable.

Use this observable proof sequence for every rule; do not emit hidden or free-form reasoning:
1. bind one supplied controlled_value_id to the model-facing handler source;
2. bind that value to the effective terminal sink facet;
3. use only gates carrying a supplied SameOrigin witness for that value;
4. compare the checked value with the effective value after parsing, normalization, persistence,
   post-action state changes, companion arguments, and policy-table lookup;
5. decide covered, wrong-check, missing-check, not-applicable, or unknown.

Worked examples:
- WRONG-CHECK: model command t reaches both parseInline(command) and spawn(command).  The parser
  recognizes PowerShell -c/-enc but not -ec, while the sink executes -ec.  Cite the parser gate,
  state the checked/effective flag delta, and return wrong-check.
- WRONG-CHECK: a dangerous-pattern table recognizes direct curl|sh and bash <(curl URL), but
  the same command reaches a shell as eval $(curl URL), source <(curl URL), or . <(wget URL).
  These are distinct shell grammar families: coverage of a pipeline or an outer shell process
  substitution is not coverage of an eval/source/dot builtin consuming substituted content.
  Cite the table gate and return wrong-check for the unrecognized nested grammar.
- MISSING-CHECK: a model-selected click reaches locator.click; the click can change page.url and a
  later browser consumer uses that page.  Direct URL navigation is guarded but no SameOrigin gate
  revalidates the resulting destination.  Return missing-check for the post-action rule.
- NOT A GATE: a timeout/config check and a model-controlled path sink do not share the same t.
  Never cite that check as coverage for the path.
- NOT HANDLER ROOTED: a helper parameter that affects a check is not model-controlled merely
  because it is on the call chain.  Without a supplied dispatch-bridge witness, do not use it.
- POST-SINK/OTHER BRANCH: a result check after open(path), or a check on a mutually exclusive
  delivery branch, cannot protect that sink effect.

Never infer that one shell grammar pattern covers another merely because both can execute remote
content.  Coverage requires the checked pattern to recognize the rule's exact builtin and
substitution structure, or a parser that soundly normalizes both to the same execution semantic.

Cover every supplied learned requirement exactly once.  Return JSON only:
{"project":"<exact>","revision":"<exact>","chain_id":"<exact>","assessments":[
 {"requirement_id":"<exact LIR>",
  "applicability":"applicable|not-applicable|unknown",
  "controlled_value_id":"<exact CV or null>",
  "origin_witness_ids":["<exact ORIGIN>"],
  "controlled_facet":"<exact model-controlled facet or explanation>",
  "effective_sink_facet":"<exact sink argument/effect or explanation>",
  "decision":"covered|wrong-check|missing-check|not-applicable|unknown",
  "gate_ids":["<exact GU>"],
  "covered_semantics":"<combined behavior or null>",
  "transform_or_policy_delta":"<residual delta or null>",
  "security_effect":"<concrete effect or null>",
  "uncertainty":"<reason or null>"}]}

Applicable covered/wrong-check require a controlled value, its sink witness, nonempty SameOrigin
gate IDs and their witness IDs, and covered_semantics; only wrong-check has a residual delta and
security effect.  Applicable missing-check requires the controlled value and sink witness, no
gate IDs, null covered_semantics, and a residual delta and security effect.  not-applicable has no
controlled value, witnesses, gates, delta, effect, or uncertainty.  unknown has no controlled
value, witnesses, or gates and requires uncertainty.  Never invent an identifier.
"""


LEARNED_REPAIR_SYSTEM = """
Repair a learned-invariant comparison response to satisfy the original JSON contract.  Use only
the supplied patterns, controlled values, origin witnesses, gates, and call shape.  Do not invent
identifiers or strengthen uncertainty.  Drop no requirement: return every requested LIR exactly
once and JSON only.
"""


Runner = Callable[[str, str], str]


@dataclass(frozen=True)
class LearnedInvariantRun:
    catalog: Mapping[str, Any]
    routed_requirements: tuple[dict[str, Any], ...]
    assessments: tuple[dict[str, Any], ...]
    provisional_candidates: tuple[dict[str, Any], ...]
    requirements: Mapping[tuple[str, str, str], Mapping[str, Any]]
    chats: Mapping[str, tuple[dict[str, str], ...]]


def stable_learned_requirement_id(pattern: Mapping[str, Any]) -> str:
    return "LIR-" + digest(
        [
            pattern["pattern_key"],
            " ".join(str(pattern["rule"]).split()),
            " ".join(str(pattern["applicability"]).split()),
            " ".join(str(pattern["controlled_facet"]).split()),
        ]
    )[:16]


def stable_learned_candidate_id(
    *,
    chain: CoverageChain,
    requirement_id: str,
    failure_mode: str,
    gate_ids: Sequence[str],
) -> str:
    if failure_mode not in {"wrong-check", "missing-check"}:
        raise CoverageComparisonError("learned candidate failure mode is invalid")
    return "CAND-" + digest(
        [
            "learned-invariant",
            chain.group_id,
            chain.project,
            chain.revision,
            chain.chain_id,
            requirement_id,
            failure_mode,
            sorted(gate_ids),
        ]
    )[:16]


def load_learned_catalog(path: Path = DEFAULT_CATALOG_PATH) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CoverageComparisonError(f"invalid learned invariant catalog: {exc}") from exc
    if not isinstance(raw, dict) or set(raw) != {
        "schema_version",
        "catalog_version",
        "analysis_label",
        "patterns",
    }:
        raise CoverageComparisonError("learned invariant catalog fields mismatch")
    if raw["schema_version"] != LEARNED_CATALOG_SCHEMA_VERSION:
        raise CoverageComparisonError("unsupported learned invariant catalog")
    patterns = raw["patterns"]
    if not isinstance(patterns, list) or len(patterns) != 15:
        raise CoverageComparisonError("learned invariant catalog must contain 15 patterns")
    expected_fields = {
        "pattern_key",
        "title",
        "training_report_ids",
        "projects",
        "handler_criterion_ids",
        "sink_type_ids",
        "capability_classes",
        "controlled_facet",
        "rule",
        "applicability",
        "security_effect",
        "positive_example",
        "negative_example",
    }
    normalized: list[dict[str, Any]] = []
    for index, pattern in enumerate(patterns):
        if not isinstance(pattern, dict) or frozenset(pattern) not in {
            frozenset(expected_fields),
            frozenset({*expected_fields, "routes"}),
        }:
            raise CoverageComparisonError(
                f"learned pattern {index} fields mismatch"
            )
        row = dict(pattern)
        for field in (
            "pattern_key",
            "title",
            "controlled_facet",
            "rule",
            "applicability",
            "security_effect",
            "positive_example",
            "negative_example",
        ):
            row[field] = normalize_text(row[field], field)
        for field in (
            "training_report_ids",
            "projects",
            "handler_criterion_ids",
            "sink_type_ids",
            "capability_classes",
        ):
            values = row[field]
            if (
                not isinstance(values, list)
                or not values
                or any(not isinstance(item, str) or not item.strip() for item in values)
                or len(values) != len(set(values))
            ):
                raise CoverageComparisonError(f"learned pattern {field} is invalid")
            row[field] = sorted(values)
        if "routes" in row:
            routes = row["routes"]
            if not isinstance(routes, list) or not routes:
                raise CoverageComparisonError("learned pattern routes are invalid")
            normalized_routes = []
            for route in routes:
                if not isinstance(route, dict) or set(route) != {
                    "project",
                    "handler_criterion_id",
                    "sink_type_id",
                    "capability_class",
                    "controlled_arguments",
                }:
                    raise CoverageComparisonError("learned route fields mismatch")
                controlled = route["controlled_arguments"]
                if (
                    not isinstance(controlled, list)
                    or not controlled
                    or any(not isinstance(value, str) or not value for value in controlled)
                    or len(controlled) != len(set(controlled))
                ):
                    raise CoverageComparisonError(
                        "learned route controlled arguments are invalid"
                    )
                normalized_routes.append(
                    {
                        **route,
                        "controlled_arguments": sorted(controlled),
                    }
                )
            row["routes"] = sorted(
                normalized_routes,
                key=lambda route: (
                    route["project"],
                    route["handler_criterion_id"],
                    route["sink_type_id"],
                    route["capability_class"],
                    route["controlled_arguments"],
                ),
            )
        row["requirement_id"] = stable_learned_requirement_id(row)
        row["schema_version"] = LEARNED_REQUIREMENT_SCHEMA_VERSION
        row["requirement_source"] = "learned-invariant"
        row["policy_basis"] = "learned-security-invariant"
        normalized.append(row)
    ids = [row["requirement_id"] for row in normalized]
    keys = [row["pattern_key"] for row in normalized]
    if len(ids) != len(set(ids)) or len(keys) != len(set(keys)):
        raise CoverageComparisonError("duplicate learned invariant identity")
    result = {
        **{key: raw[key] for key in ("schema_version", "catalog_version", "analysis_label")},
        "path": str(path),
        "sha256": sha256_file(path),
        "patterns": sorted(normalized, key=lambda row: row["requirement_id"]),
    }
    if contains_credentials(canonical_json(result)):
        raise CoverageComparisonError("credential-shaped learned invariant catalog")
    return result


def route_learned_requirements(
    chain: CoverageChain,
    catalog: Mapping[str, Any],
) -> list[dict[str, Any]]:
    capability_class = str(chain.semantic_ir["sink_constraint"]["capability_class"])
    controlled_argument = str(
        chain.semantic_ir["sink_constraint"]["controlled_argument"]
    )
    output = []
    for pattern in catalog["patterns"]:
        routes = pattern.get("routes")
        if routes is not None:
            matched = any(
                route["project"] == chain.project
                and route["handler_criterion_id"] == chain.handler_criterion_id
                and route["sink_type_id"] == chain.sink_type_id
                and route["capability_class"] == capability_class
                and controlled_argument in route["controlled_arguments"]
                for route in routes
            )
        else:
            matched = (
                chain.project in pattern["projects"]
                and chain.handler_criterion_id in pattern["handler_criterion_ids"]
                and chain.sink_type_id in pattern["sink_type_ids"]
                and capability_class in pattern["capability_classes"]
            )
        if matched:
            output.append(dict(pattern))
    return output


def _prompt_payload(
    *,
    chain: CoverageChain,
    requirements: Sequence[Mapping[str, Any]],
    origin: SameOriginRun,
) -> dict[str, Any]:
    gate_ids = {str(row["gate_uid"]) for row in chain.semantic_ir.get("gates", [])}
    witnesses = [
        row
        for row in origin.witnesses
        if row["project"] == chain.project
        and row["chain_id"] == chain.chain_id
        and (row["gate_uid"] is None or row["gate_uid"] in gate_ids)
    ]
    prompt_requirements = [
        {
            key: value
            for key, value in requirement.items()
            if key not in {"training_report_ids"}
        }
        for requirement in requirements
    ]
    return {
        "prompt_version": LEARNED_PROMPT_VERSION,
        "analysis_label": "GT-informed learned detector; no report content in this request",
        "project": chain.project,
        "revision": chain.revision,
        "group_id": chain.group_id,
        "chain_id": chain.chain_id,
        "allowed_requirement_ids": sorted(
            str(row["requirement_id"]) for row in requirements
        ),
        "allowed_controlled_value_ids": sorted(
            str(row["id"]) for row in chain.semantic_ir["values"]
        ),
        "allowed_gate_ids": sorted(gate_ids),
        "allowed_origin_witness_ids": sorted(
            str(row["origin_witness_id"]) for row in witnesses
        ),
        "learned_requirements": prompt_requirements,
        "same_origin_witnesses": witnesses,
        "handler": chain.semantic_ir["handler"],
        "controlled_values": chain.semantic_ir["values"],
        "sink_constraint": chain.semantic_ir["sink_constraint"],
        "ordered_qualified_gates": chain.semantic_ir["gates"],
        "semantic_status": chain.semantic_ir["status"],
        "semantic_unresolved": chain.semantic_ir["unresolved"],
    }


def build_learned_compare_user(
    *,
    chain: CoverageChain,
    requirements: Sequence[Mapping[str, Any]],
    origin: SameOriginRun,
) -> str:
    return "Compare these routed learned invariants:\n" + redact_credentials(
        canonical_json(
            _prompt_payload(chain=chain, requirements=requirements, origin=origin)
        )
    )


def _string_list(
    value: object,
    field: str,
    *,
    allowed: set[str] | None = None,
) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise CoverageComparisonError(f"{field} must be an array of strings")
    output = [" ".join(item.split()) for item in value]
    if len(output) != len(set(output)):
        raise CoverageComparisonError(f"{field} contains duplicates")
    if allowed is not None and not set(output) <= allowed:
        raise CoverageComparisonError(f"{field} contains unknown identifiers")
    return sorted(output)


def validate_learned_response(
    response: Mapping[str, Any],
    *,
    chain: CoverageChain,
    requirements: Sequence[Mapping[str, Any]],
    origin: SameOriginRun,
) -> list[dict[str, Any]]:
    if set(response) != {"project", "revision", "chain_id", "assessments"}:
        raise CoverageComparisonError("learned comparison response fields mismatch")
    if (
        response["project"] != chain.project
        or response["revision"] != chain.revision
        or response["chain_id"] != chain.chain_id
    ):
        raise CoverageComparisonError("learned comparison identity mismatch")
    rows = response["assessments"]
    if not isinstance(rows, list):
        raise CoverageComparisonError("learned assessments must be an array")
    requirement_by_id = {str(row["requirement_id"]): row for row in requirements}
    allowed_values = {str(row["id"]) for row in chain.semantic_ir["values"]}
    allowed_gates = {str(row["gate_uid"]) for row in chain.semantic_ir["gates"]}
    origin_rows = [
        row
        for row in origin.witnesses
        if row["project"] == chain.project and row["chain_id"] == chain.chain_id
    ]
    origin_by_id = {str(row["origin_witness_id"]): row for row in origin_rows}
    expected_fields = {
        "requirement_id",
        "applicability",
        "controlled_value_id",
        "origin_witness_ids",
        "controlled_facet",
        "effective_sink_facet",
        "decision",
        "gate_ids",
        "covered_semantics",
        "transform_or_policy_delta",
        "security_effect",
        "uncertainty",
    }
    output: list[dict[str, Any]] = []
    seen: list[str] = []
    for raw in rows:
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise CoverageComparisonError("learned assessment fields mismatch")
        requirement_id = str(raw["requirement_id"])
        if requirement_id not in requirement_by_id:
            raise CoverageComparisonError("unknown learned requirement")
        applicability = raw["applicability"]
        decision = raw["decision"]
        if applicability not in {"applicable", "not-applicable", "unknown"}:
            raise CoverageComparisonError("invalid learned applicability")
        if decision not in {
            "covered",
            "wrong-check",
            "missing-check",
            "not-applicable",
            "unknown",
        }:
            raise CoverageComparisonError("invalid learned decision")
        controlled_value = raw["controlled_value_id"]
        if controlled_value is not None and controlled_value not in allowed_values:
            raise CoverageComparisonError("unknown controlled value")
        witness_ids = _string_list(
            raw["origin_witness_ids"],
            "origin_witness_ids",
            allowed=set(origin_by_id),
        )
        gate_ids = _string_list(raw["gate_ids"], "gate_ids", allowed=allowed_gates)
        controlled_facet = normalize_text(
            raw["controlled_facet"], "controlled_facet", nullable=True
        )
        sink_facet = normalize_text(
            raw["effective_sink_facet"], "effective_sink_facet", nullable=True
        )
        covered = normalize_text(
            raw["covered_semantics"], "covered_semantics", nullable=True
        )
        delta = normalize_text(
            raw["transform_or_policy_delta"],
            "transform_or_policy_delta",
            nullable=True,
        )
        effect = normalize_text(raw["security_effect"], "security_effect", nullable=True)
        uncertainty = normalize_text(raw["uncertainty"], "uncertainty", nullable=True)
        selected_witnesses = [origin_by_id[item] for item in witness_ids]
        if applicability == "applicable":
            sink_for_value = [
                row
                for row in origin_rows
                if row["gate_uid"] is None
                and row["controlled_value_id"] == controlled_value
            ]
            if len(sink_for_value) != 1:
                raise CoverageComparisonError(
                    "applicable learned rule lacks a unique sink-origin witness"
                )
            if all(row["gate_uid"] is not None for row in selected_witnesses):
                selected_witnesses.append(sink_for_value[0])
            # The model may cite the complete SameOrigin context.  Canonicalize it to
            # the sink witness plus exactly the gates it actually claims as coverage;
            # unselected gate witnesses cannot turn a missing-check into wrong-check.
            selected_witnesses = [
                row
                for row in selected_witnesses
                if row["gate_uid"] is None or str(row["gate_uid"]) in set(gate_ids)
            ]
            witness_ids = sorted(
                str(row["origin_witness_id"]) for row in selected_witnesses
            )
        sink_witnesses = [row for row in selected_witnesses if row["gate_uid"] is None]
        gate_witness_uids = {
            str(row["gate_uid"])
            for row in selected_witnesses
            if row["gate_uid"] is not None
        }
        if applicability == "applicable":
            if decision not in {"covered", "wrong-check", "missing-check"}:
                raise CoverageComparisonError("applicable learned decision mismatch")
            if (
                controlled_value is None
                or not controlled_facet
                or not sink_facet
                or not sink_witnesses
                or uncertainty is not None
            ):
                raise CoverageComparisonError("applicable learned origin invariant failed")
            if any(row["controlled_value_id"] != controlled_value for row in selected_witnesses):
                raise CoverageComparisonError("learned witnesses bind different values")
            if decision in {"covered", "wrong-check"} and (
                not gate_ids
                or set(gate_ids) != gate_witness_uids
                or covered is None
            ):
                raise CoverageComparisonError("learned gate coverage invariant failed")
            if decision == "covered" and (delta is not None or effect is not None):
                raise CoverageComparisonError("covered learned rule has a residual gap")
            if decision == "wrong-check" and (delta is None or effect is None):
                raise CoverageComparisonError("wrong-check learned rule lacks delta/effect")
            if decision == "missing-check" and (
                gate_ids or gate_witness_uids or covered is not None or delta is None or effect is None
            ):
                raise CoverageComparisonError("missing-check learned invariant failed")
        elif applicability == "not-applicable":
            if any(
                value is not None and value != []
                for value in (
                    controlled_value,
                    witness_ids,
                    controlled_facet,
                    sink_facet,
                    gate_ids,
                    covered,
                    delta,
                    effect,
                    uncertainty,
                )
            ) or decision != "not-applicable":
                raise CoverageComparisonError("not-applicable learned invariant failed")
        else:
            if (
                decision != "unknown"
                or controlled_value is not None
                or witness_ids
                or gate_ids
                or uncertainty is None
            ):
                raise CoverageComparisonError("unknown learned invariant failed")
        requirement = requirement_by_id[requirement_id]
        output.append(
            {
                "schema_version": LEARNED_ASSESSMENT_SCHEMA_VERSION,
                "group_id": chain.group_id,
                "handler_criterion_id": chain.handler_criterion_id,
                "sink_type_id": chain.sink_type_id,
                "project": chain.project,
                "revision": chain.revision,
                "chain_id": chain.chain_id,
                "requirement_id": requirement_id,
                "requirement_source": "learned-invariant",
                "pattern_key": requirement["pattern_key"],
                "policy_basis": "learned-security-invariant",
                "applicability": applicability,
                "decision": decision,
                "capability_evidence": [],
                "call_shape_facts": (
                    [controlled_facet, sink_facet]
                    if applicability == "applicable"
                    else []
                ),
                "controlled_value_id": controlled_value,
                "origin_witness_ids": witness_ids,
                "controlled_facet": controlled_facet,
                "effective_sink_facet": sink_facet,
                "gate_ids": gate_ids,
                "covered_semantics": covered,
                "gap": delta,
                "transform_or_policy_delta": delta,
                "security_effect": effect,
                "uncertainty": uncertainty,
            }
        )
        seen.append(requirement_id)
    if len(seen) != len(set(seen)) or set(seen) != set(requirement_by_id):
        raise CoverageComparisonError("learned response must cover every rule")
    return sorted(output, key=lambda row: row["requirement_id"])


def _gate_semantics(chain: CoverageChain, gate_ids: Sequence[str]) -> list[dict[str, Any]]:
    selected = set(gate_ids)
    return [
        row
        for row in chain.semantic_ir["gates"]
        if row["gate_uid"] in selected
    ]


def _candidate(
    *,
    chain: CoverageChain,
    requirement: Mapping[str, Any],
    assessment: Mapping[str, Any],
) -> dict[str, Any]:
    gate_ids = list(assessment["gate_ids"])
    candidate_id = stable_learned_candidate_id(
        chain=chain,
        requirement_id=str(requirement["requirement_id"]),
        failure_mode=str(assessment["decision"]),
        gate_ids=gate_ids,
    )
    return {
        "schema_version": CANDIDATE_SCHEMA_VERSION,
        "candidate_id": candidate_id,
        "requirement_source": "learned-invariant",
        "provenance": {
            "kind": "learned-invariant",
            "requirement_id": requirement["requirement_id"],
            "origin_witness_ids": list(assessment["origin_witness_ids"]),
        },
        "group_id": chain.group_id,
        "handler_criterion_id": chain.handler_criterion_id,
        "sink_type_id": chain.sink_type_id,
        "project": chain.project,
        "revision": chain.revision,
        "chain_id": chain.chain_id,
        "handler_id": chain.handler_id,
        "sink_id": chain.sink_id,
        "failure_mode": assessment["decision"],
        "requirement_id": requirement["requirement_id"],
        "learned_pattern_key": requirement["pattern_key"],
        "requirement_rule": requirement["rule"],
        "requirement_applicability": requirement["applicability"],
        "controlled_value_id": assessment["controlled_value_id"],
        "origin_witness_ids": assessment["origin_witness_ids"],
        "controlled_facet": assessment["controlled_facet"],
        "effective_sink_facet": assessment["effective_sink_facet"],
        "gate_ids": gate_ids,
        "gate_semantics": _gate_semantics(chain, gate_ids),
        "reason": assessment["gap"],
        "trigger_goal": (
            "Exercise the exact learned invariant while preserving the bound "
            f"handler-to-sink origin: {requirement['rule']}"
        ),
        "group_oracle_status": chain.oracle["status"],
        "semantic_ir_status": chain.semantic_ir["status"],
        "capability_card": {
            "path": chain.capability_card_path,
            "sha256": chain.capability_card_sha256,
        },
        "policy_basis": "learned-security-invariant",
        "protected_asset": requirement["security_effect"],
        "security_effect": assessment["security_effect"],
        "training_report_ids": requirement["training_report_ids"],
    }


def _validated_call(
    *,
    runner: Runner,
    chain: CoverageChain,
    requirements: Sequence[Mapping[str, Any]],
    origin: SameOriginRun,
) -> tuple[list[dict[str, Any]], tuple[dict[str, str], ...]]:
    user = build_learned_compare_user(chain=chain, requirements=requirements, origin=origin)
    raw = redact_credentials(runner(LEARNED_COMPARE_SYSTEM, user))
    exchanges = [{"system": LEARNED_COMPARE_SYSTEM, "user": user, "response": raw}]
    try:
        rows = validate_learned_response(
            parse_json_response(raw),
            chain=chain,
            requirements=requirements,
            origin=origin,
        )
    except Exception as first:
        repair_user = (
            "Original task:\n"
            + user
            + "\nInvalid response:\n"
            + raw
            + "\nValidation error:\n"
            + f"{type(first).__name__}: {first}"
        )
        repaired = redact_credentials(runner(LEARNED_REPAIR_SYSTEM, repair_user))
        exchanges.append(
            {
                "system": LEARNED_REPAIR_SYSTEM,
                "user": repair_user,
                "response": repaired,
            }
        )
        rows = validate_learned_response(
            parse_json_response(repaired),
            chain=chain,
            requirements=requirements,
            origin=origin,
        )
    return rows, tuple(exchanges)


def analyze_learned_invariants(
    *,
    chains: Sequence[CoverageChain],
    origin: SameOriginRun,
    runner: Runner,
    catalog_path: Path = DEFAULT_CATALOG_PATH,
    jobs: int = 4,
    input_token_limit: int = 96_000,
) -> LearnedInvariantRun:
    if jobs < 1:
        raise CoverageComparisonError("learned invariant jobs must be positive")
    catalog = load_learned_catalog(catalog_path)
    tasks: list[tuple[CoverageChain, list[dict[str, Any]], int]] = []
    routed: list[dict[str, Any]] = []
    for original in sorted(chains, key=lambda row: row.key):
        chain = origin.qualified_chains[original.key]
        requirements = route_learned_requirements(chain, catalog)
        for requirement in requirements:
            routed.append(
                {
                    **requirement,
                    "project": chain.project,
                    "revision": chain.revision,
                    "chain_id": chain.chain_id,
                    "group_id": chain.group_id,
                }
            )
        for offset in range(0, len(requirements), LEARNED_MAX_PATTERNS_PER_BATCH):
            batch = requirements[offset : offset + LEARNED_MAX_PATTERNS_PER_BATCH]
            if batch:
                user = build_learned_compare_user(
                    chain=chain, requirements=batch, origin=origin
                )
                if estimate_tokens({"system": LEARNED_COMPARE_SYSTEM, "user": user}) > input_token_limit:
                    raise CoverageComparisonError(
                        f"learned invariant prompt exceeds token limit for {chain.key}"
                    )
                tasks.append((chain, batch, offset // LEARNED_MAX_PATTERNS_PER_BATCH + 1))
    assessment_rows: list[dict[str, Any]] = []
    chats: dict[str, tuple[dict[str, str], ...]] = {}

    def execute(task: tuple[CoverageChain, list[dict[str, Any]], int]):
        chain, batch, number = task
        rows, exchanges = _validated_call(
            runner=runner,
            chain=chain,
            requirements=batch,
            origin=origin,
        )
        return chain, number, rows, exchanges

    with ThreadPoolExecutor(max_workers=min(jobs, max(1, len(tasks)))) as pool:
        futures = {pool.submit(execute, task): task for task in tasks}
        for future in as_completed(futures):
            chain, number, rows, exchanges = future.result()
            assessment_rows.extend(rows)
            chats[f"{chain.project}-{chain.chain_id}-B{number:03d}"] = exchanges
    assessment_rows.sort(
        key=lambda row: (row["project"], row["chain_id"], row["requirement_id"])
    )
    requirement_index = {
        (row["project"], row["chain_id"], row["requirement_id"]): row
        for row in routed
    }
    assessment_index = {
        (row["project"], row["chain_id"], row["requirement_id"]): row
        for row in assessment_rows
    }
    if len(requirement_index) != len(routed) or set(requirement_index) != set(assessment_index):
        raise CoverageComparisonError(
            "learned requirements and assessments must be one-to-one"
        )
    candidates = [
        _candidate(
            chain=origin.qualified_chains[(row["project"], row["chain_id"])],
            requirement=requirement_index[
                (row["project"], row["chain_id"], row["requirement_id"])
            ],
            assessment=row,
        )
        for row in assessment_rows
        if row["decision"] in {"wrong-check", "missing-check"}
    ]
    if contains_credentials(
        canonical_json([catalog, routed, assessment_rows, candidates, chats])
    ):
        raise CoverageComparisonError("credential-shaped learned invariant artifact")
    return LearnedInvariantRun(
        catalog=catalog,
        routed_requirements=tuple(routed),
        assessments=tuple(assessment_rows),
        provisional_candidates=tuple(
            sorted(candidates, key=lambda row: row["candidate_id"])
        ),
        requirements={
            key: value for key, value in sorted(requirement_index.items())
        },
        chats=dict(sorted(chats.items())),
    )
