"""Compact rendering for a later call-chain semantics prompt."""

from __future__ import annotations

from typing import Any, Iterable


def _render_compound_gate(ir: dict[str, Any]) -> str:
    lines = [
        f"{ir['gate_id']} [{ir['mode']}/compound] {ir['input']} -> {ir['output']}",
        f"summary: {ir['summary']}",
        f"entry: {ir['entry']}",
    ]
    for check in ir["checks"]:
        lines.append(
            f"{check['id']} {check['op']}: {check['summary']} "
            f"({check['input']} -> {check['output']})"
        )
        lines.append(f"  rule: {check['rule']}")
        lines.append(
            "  outcomes: "
            + ", ".join(
                f"{outcome}=>{target}" for outcome, target in check["outcomes"].items()
            )
        )
        lines.append(f"  on_error: {check['on_error']}")
        if check["policy_refs"]:
            lines.append("  policies: " + ", ".join(check["policy_refs"]))
        if check["unresolved"]:
            lines.append("  unresolved: " + "; ".join(check["unresolved"]))
        for example in check["reject_examples"]:
            precondition = (
                f" if {example['precondition']}" if example.get("precondition") else ""
            )
            lines.append(
                f"  reject example: {example['input']}{precondition} because "
                f"{example['reason']}"
            )
    for policy in ir["policies"]:
        lines.append(f"{policy['id']}: {policy['summary']}")
        lines.append(f"  matching: {policy['matching']}")
        for rule in policy["rules"]:
            lines.append(f"  {rule['id']}: {rule['rule']}")
    lines.append(
        "terminals: "
        + ", ".join(f"{key}={value}" for key, value in ir["terminals"].items())
    )
    lines.append(f"default: {ir['default']}; on_error: {ir['on_error']}")
    if ir["unresolved"]:
        lines.append("unresolved: " + "; ".join(ir["unresolved"]))
    lines.append(f"status: {ir['status']}")
    return "\n".join(lines)


def _render_behavior_gate(ir: dict[str, Any]) -> str:
    lines = [
        f"{ir['gate_id']} [{ir['mode']}/behavior-complete]",
        f"summary: {ir['summary']}",
        "inputs: "
        + ", ".join(f"{item['id']}={item['meaning']}" for item in ir["inputs"]),
        f"entry: {ir['entry']}",
    ]
    for activation in ir["activation"]:
        lines.append(
            f"{activation['id']} activate-if: {activation['condition']} "
            f"(true=>{activation['when_true']}, false=>{activation['when_false']})"
        )
    for value in ir["derived_values"]:
        lines.append(
            f"{value['id']} derive from {','.join(value['sources'])}: "
            + "; ".join(value["operations"])
            + " used-by "
            + ",".join(value["used_by"])
        )
    for check in ir["checks"]:
        lines.append(
            f"{check['id']} {check['op']} reads {','.join(check['reads'])}: "
            f"{check['rule']}"
        )
        lines.append(
            "  outcomes: "
            + ", ".join(
                f"{label}=>{target}" for label, target in check["outcomes"].items()
            )
        )
    for policy in ir["policies"]:
        lines.append(
            f"{policy['id']} [{policy['kind']}]: {policy['summary']} "
            f"({policy['match']})"
        )
        for rule in policy["rules"]:
            lines.append(
                f"  {rule['id']}: {rule['matcher']} => {rule['outcome']} "
                f"({rule['meaning']})"
            )
    for outcome_id, outcome in ir["outcomes"].items():
        lines.append(
            f"{outcome_id} [{outcome['decision']}]: {outcome['effect']}"
        )
    if ir["unresolved"]:
        lines.append("unresolved: " + "; ".join(ir["unresolved"]))
    lines.append(f"status: {ir['status']}")
    return "\n".join(lines)


def render_gate(ir: dict[str, Any]) -> str:
    if ir.get("schema_version") == "gate-semantic-ir/v2":
        return _render_compound_gate(ir)
    if ir.get("schema_version") == "gate-semantic-ir/v3":
        return _render_behavior_gate(ir)
    lines = [
        f"{ir['gate_id']} [{ir['mode']}] {ir['input']} -> {ir['output']}",
        f"summary: {ir['summary']}",
    ]
    for step in ir["steps"]:
        suffix = ""
        if step.get("when"):
            suffix += f" when {step['when']}"
        if step.get("unless"):
            suffix += f" unless {step['unless']}"
        lines.append(f"{step['id']} {step['op']}: {step['rule']}{suffix}")
    lines.append(f"default: {ir['default']}; on_error: {ir['on_error']}")
    for example in ir["reject_examples"]:
        precondition = (
            f" if {example['precondition']}" if example.get("precondition") else ""
        )
        lines.append(
            f"reject example ({example['rejected_by']}): {example['input']}{precondition} "
            f"because {example['reason']}"
        )
    for example in ir["bypass_examples"]:
        precondition = (
            f" if {example['precondition']}" if example.get("precondition") else ""
        )
        lines.append(
            f"bypass example ({example['passed_by']}): {example['input']}{precondition} "
            f"because {example['reason']}; potential impact: "
            f"{example['potential_security_impact']}"
        )
    return "\n".join(lines)


def render_chain_semantics(records: Iterable[dict[str, Any]]) -> str:
    return "\n\n".join(render_gate(record) for record in records)
