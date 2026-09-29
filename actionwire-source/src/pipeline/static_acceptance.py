"""Revision-pinned static acceptance rendering for benchmark adapters."""

from __future__ import annotations

import argparse
import csv
import json
import re
import shlex
from collections import Counter
from pathlib import Path
from typing import Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATTERN = re.compile(r"`([^`]+)-ISSUE-REPORT\.md`")
ROW_FIELDS = (
    "row_kind",
    "dimension_id",
    "flow_id",
    "current_status",
    "model_scope",
    "handler",
    "anchor",
    "expected",
    "detected",
    "status",
    "detail",
)


class StaticAcceptanceError(RuntimeError):
    """Raised when acceptance inputs are malformed or unavailable."""


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        raise StaticAcceptanceError(f"required pipeline artifact is missing: {path}")
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=ROW_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _anchor(value: str) -> tuple[str, int]:
    file_name, line = value.rsplit(":", 1)
    return file_name, int(line)


def _command_path(path: Path) -> str:
    absolute = path.absolute()
    return (
        str(absolute.relative_to(REPO_ROOT))
        if absolute.is_relative_to(REPO_ROOT)
        else str(absolute)
    )


def _report_inventory(summary: Path) -> list[str]:
    if not summary.is_file():
        raise StaticAcceptanceError(f"report inventory is missing: {summary}")
    return REPORT_PATTERN.findall(summary.read_text(encoding="utf-8"))


def _source_line(source_root: Path, anchor: str) -> str:
    file_name, line = _anchor(anchor)
    path = source_root / file_name
    try:
        return path.read_text(encoding="utf-8").splitlines()[line - 1]
    except (FileNotFoundError, IndexError) as exc:
        raise StaticAcceptanceError(f"invalid source anchor: {anchor}") from exc


def _row(
    *,
    row_kind: str,
    status: str,
    dimension_id: str = "",
    flow_id: str = "",
    current_status: str = "",
    model_scope: str = "",
    handler: str = "",
    anchor: str = "",
    expected: object = "",
    detected: object = "",
    detail: object = "",
) -> dict[str, object]:
    return {
        "row_kind": row_kind,
        "dimension_id": dimension_id,
        "flow_id": flow_id,
        "current_status": current_status,
        "model_scope": model_scope,
        "handler": handler,
        "anchor": anchor,
        "expected": expected,
        "detected": detected,
        "status": status,
        "detail": detail,
    }


def render_acceptance(
    *,
    title: str,
    generation_script: str,
    oracle_path: Path,
    ground_truth_root: Path,
    source_root: Path,
    pipeline_output: Path,
    out_dir: Path,
) -> dict[str, object]:
    oracle_path = oracle_path.absolute()
    ground_truth_root = ground_truth_root.absolute()
    source_root = source_root.resolve()
    pipeline_output = pipeline_output.resolve()
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
    summary = ground_truth_root / str(oracle.get("report_inventory", "summary-reported.md"))
    inventory = _report_inventory(summary)
    inventory_counts = Counter(inventory)
    inventory_names = set(inventory_counts)

    static = pipeline_output / "static/call-chains"
    chains = _read_csv(static / "handler-sink-chains.csv")
    gates = _read_csv(static / "chain-gates.csv")
    constraints = _read_csv(static / "sink-constraints.csv")

    chains_by_sink: dict[tuple[str, int], list[dict[str, str]]] = {}
    chains_by_handler_sink: dict[tuple[str, str, int], list[dict[str, str]]] = {}
    for chain in chains:
        key = (chain["sink_file"], int(chain["sink_line"]))
        chains_by_sink.setdefault(key, []).append(chain)
        chains_by_handler_sink.setdefault((chain["tool_name"], *key), []).append(chain)

    gates_by_chain: dict[str, list[dict[str, str]]] = {}
    for gate in gates:
        if gate.get("gate_uid"):
            gates_by_chain.setdefault(gate["chain_id"], []).append(gate)
    for attached in gates_by_chain.values():
        attached.sort(key=lambda row: int(row["gate_seq"]))

    constraints_by_sink: dict[tuple[str, int], list[dict[str, str]]] = {}
    for constraint in constraints:
        key = (constraint["sink_file"], int(constraint["sink_line"]))
        constraints_by_sink.setdefault(key, []).append(constraint)

    dimensions = list(oracle.get("dimensions", []))
    oracle_reports = [
        report
        for dimension in dimensions
        for report in dimension.get("source_reports", [])
    ]
    oracle_counts = Counter(oracle_reports)
    rows: list[dict[str, object]] = []
    failures = 0

    for report in sorted(inventory_names | set(oracle_counts)):
        present = report in inventory_names
        represented = oracle_counts[report] == 1
        passed = present and represented
        failures += int(not passed)
        rows.append(
            _row(
                row_kind="source-report",
                anchor=report,
                expected="unique summary-reported entry represented exactly once",
                detected=(
                    f"summary_occurrences={inventory_counts[report]};"
                    f"oracle_dimensions={oracle_counts[report]}"
                ),
                status="pass" if passed else "fail",
            )
        )

    expected_capabilities: dict[str, str] = oracle.get(
        "expected_sink_capabilities", {}
    )
    expected_capabilities_by_sink = {
        _anchor(anchor): capability
        for anchor, capability in expected_capabilities.items()
    }

    # Validate the complete static envelope before evaluating selected GT flows.
    # Structural-only projects must still fail if a genuine chain loses or
    # misclassifies its terminal capability constraint.
    all_sink_keys = (
        set(chains_by_sink)
        | set(constraints_by_sink)
        | set(expected_capabilities_by_sink)
    )
    for sink_file, sink_line in sorted(all_sink_keys):
        sink_anchor = f"{sink_file}:{sink_line}"
        sink_chains = chains_by_sink.get((sink_file, sink_line), [])
        sink_constraints = constraints_by_sink.get((sink_file, sink_line), [])
        expected_capability = expected_capabilities_by_sink.get(
            (sink_file, sink_line)
        )
        constraint = sink_constraints[0] if len(sink_constraints) == 1 else {}
        metadata_complete = bool(constraint) and all(
            constraint.get(field)
            for field in (
                "constraint_id",
                "sink_id",
                "sink_api",
                "controlled_argument",
                "capability_class",
                "call_shape",
                "capability_card",
            )
        ) and bool(
            re.fullmatch(
                r"[0-9a-f]{64}",
                constraint.get("capability_card_sha256", ""),
            )
        )
        capability_matches = (
            not expected_capability
            or constraint.get("capability_class") == expected_capability
        )
        passed = (
            bool(sink_chains)
            and len(sink_constraints) == 1
            and metadata_complete
            and capability_matches
        )
        failures += int(not passed)
        rows.append(
            _row(
                row_kind="pipeline-sink-constraint",
                anchor=sink_anchor,
                expected=(
                    "one complete terminal constraint for a structural sink"
                    + (
                        f" with capability {expected_capability}"
                        if expected_capability
                        else ""
                    )
                ),
                detected=(
                    f"chains={len(sink_chains)};constraints={len(sink_constraints)};"
                    f"capability={constraint.get('capability_class', '')};"
                    f"metadata_complete={str(metadata_complete).lower()}"
                ),
                status="pass" if passed else "fail",
                detail=constraint.get("constraint_id", ""),
            )
        )

    known_chain_ids = {chain["chain_id"] for chain in chains}
    raw_gates_by_chain: dict[str, list[dict[str, str]]] = {}
    for gate in gates:
        raw_gates_by_chain.setdefault(gate.get("chain_id", ""), []).append(gate)
    for chain in chains:
        chain_id = chain["chain_id"]
        attached_rows = raw_gates_by_chain.get(chain_id, [])
        eligible = [row for row in attached_rows if row.get("gate_uid")]
        placeholders = [row for row in attached_rows if not row.get("gate_uid")]
        sequence_text = [row.get("gate_seq", "") for row in eligible]
        sequences = [int(value) for value in sequence_text if value.isdigit()]
        ordered = (
            len(sequences) == len(eligible)
            and sequences == list(range(1, len(eligible) + 1))
        )
        eligible_only = all(
            row.get("static_verdict") in {"confirmed", "branch-confirmed"}
            for row in eligible
        )
        unique_gates = len({row["gate_uid"] for row in eligible}) == len(eligible)
        representation_valid = (
            bool(eligible) and not placeholders
            or not eligible and len(placeholders) == 1
        )
        passed = ordered and eligible_only and unique_gates and representation_valid
        failures += int(not passed)
        rows.append(
            _row(
                row_kind="pipeline-chain-gates",
                handler=chain["tool_name"],
                anchor=chain_id,
                expected=(
                    "one zero-gate placeholder or consecutive eligible gates "
                    "in execution order"
                ),
                detected=(
                    f"eligible={len(eligible)};placeholders={len(placeholders)};"
                    f"sequence={','.join(str(value) for value in sequences)}"
                ),
                status="pass" if passed else "fail",
                detail=chain["call_chain"],
            )
        )

    for orphan_chain_id in sorted(set(raw_gates_by_chain) - known_chain_ids):
        failures += 1
        rows.append(
            _row(
                row_kind="pipeline-chain-gates",
                anchor=orphan_chain_id,
                expected="no chain-gate rows for unknown structural chains",
                detected=len(raw_gates_by_chain[orphan_chain_id]),
                status="fail",
            )
        )

    expected_flows = 0
    found_flows = 0
    expected_gates = 0
    found_gates = 0
    expected_missing = 0
    out_of_model = 0
    not_present = 0
    duplicates = 0
    stale = 0

    for dimension in dimensions:
        dimension_id = str(dimension["id"])
        current_status = str(dimension["current_status"])
        model_scope = str(dimension["model_scope"])
        reason = str(dimension.get("reason", ""))
        scope_passed = bool(reason) and (
            model_scope in {"handler-to-sink", "mixed-origin"}
            or not dimension.get("flows")
        )
        failures += int(not scope_passed)
        out_of_model += int(model_scope == "out-of-model")
        not_present += int(current_status == "not-present-at-analysis-revision")
        rows.append(
            _row(
                row_kind="scope-classification",
                dimension_id=dimension_id,
                current_status=current_status,
                model_scope=model_scope,
                anchor=dimension_id,
                expected="explicit model/source scope and revision status",
                detected=reason,
                status="pass" if scope_passed else "fail",
            )
        )

        for report in dimension.get("duplicate_reports", []):
            duplicates += 1
            is_source = report in dimension.get("source_reports", [])
            failures += int(not is_source)
            rows.append(
                _row(
                    row_kind="duplicate-report",
                    dimension_id=dimension_id,
                    current_status=current_status,
                    model_scope=model_scope,
                    anchor=report,
                    expected="deduplicated source report for this vulnerability dimension",
                    detected="deduplicated" if is_source else "not listed as source report",
                    status="note" if is_source else "fail",
                )
            )

        for flow_index, flow in enumerate(dimension.get("flows", []), 1):
            handler = str(flow["handler"])
            flow_id = f"{dimension_id}:{flow_index}:{handler}"
            flow_chains: list[dict[str, str]] = []
            for sink_anchor in flow.get("sink_points", []):
                expected_flows += 1
                sink_file, sink_line = _anchor(sink_anchor)
                matches = chains_by_handler_sink.get(
                    (handler, sink_file, sink_line), []
                )
                flow_chains.extend(matches)
                sink_constraints = constraints_by_sink.get((sink_file, sink_line), [])
                expected_capability = expected_capabilities.get(sink_anchor)
                capability_matches = [
                    value
                    for value in sink_constraints
                    if not expected_capability
                    or value.get("capability_class") == expected_capability
                ]
                passed = (
                    bool(matches)
                    and len(sink_constraints) == 1
                    and len(capability_matches) == 1
                )
                found_flows += int(bool(matches))
                failures += int(not passed)
                rows.append(
                    _row(
                        row_kind="sink-chain",
                        dimension_id=dimension_id,
                        flow_id=flow_id,
                        current_status=current_status,
                        model_scope=model_scope,
                        handler=handler,
                        anchor=sink_anchor,
                        expected=(
                            "taint-valid chain and exactly one sink constraint"
                            + (
                                f" with capability {expected_capability}"
                                if expected_capability
                                else ""
                            )
                        ),
                        detected=(
                            f"chains={len(matches)};constraints={len(sink_constraints)};"
                            f"capability_matches={len(capability_matches)}"
                        ),
                        status="pass" if passed else "fail",
                        detail=";".join(sorted(row["chain_id"] for row in matches)),
                    )
                )

            attached = [
                gate
                for chain in flow_chains
                for gate in gates_by_chain.get(chain["chain_id"], [])
            ]
            for gate_anchor in dimension.get("expected_existing_gates", []):
                expected_gates += 1
                gate_file, gate_line = _anchor(gate_anchor)
                matches = [
                    gate
                    for gate in attached
                    if gate["gate_file"] == gate_file
                    and int(gate["gate_line"]) == gate_line
                ]
                found_gates += int(bool(matches))
                failures += int(not matches)
                rows.append(
                    _row(
                        row_kind="detected-gate",
                        dimension_id=dimension_id,
                        flow_id=flow_id,
                        current_status=current_status,
                        model_scope=model_scope,
                        handler=handler,
                        anchor=gate_anchor,
                        expected="eligible callsite-bound gate attached in execution order",
                        detected=len(matches),
                        status="pass" if matches else "fail",
                        detail=";".join(
                            sorted({gate["gate_uid"] for gate in matches})
                        ),
                    )
                )

            for missing in dimension.get("expected_missing", []):
                expected_missing += 1
                forbidden = [
                    term.lower()
                    for term in dimension.get("forbidden_fabricated_gate_terms", [])
                ]
                fabricated = [
                    gate
                    for gate in attached
                    if any(term in gate["gate_name"].lower() for term in forbidden)
                ]
                passed = not fabricated
                failures += int(not passed)
                rows.append(
                    _row(
                        row_kind="expected-missing",
                        dimension_id=dimension_id,
                        flow_id=flow_id,
                        current_status=current_status,
                        model_scope=model_scope,
                        handler=handler,
                        anchor=missing,
                        expected="missing control remains explicit",
                        detected="no fabricated gate" if passed else len(fabricated),
                        status="pass" if passed else "fail",
                        detail=";".join(gate["gate_name"] for gate in fabricated),
                    )
                )

        for policy in dimension.get("current_policy_anchors", []):
            source_line = _source_line(source_root, policy["location"])
            passed = str(policy["contains"]) in source_line
            failures += int(not passed)
            rows.append(
                _row(
                    row_kind="current-policy",
                    dimension_id=dimension_id,
                    current_status=current_status,
                    model_scope=model_scope,
                    anchor=policy["location"],
                    expected=policy["contains"],
                    detected=source_line.strip(),
                    status="pass" if passed else "fail",
                    detail="revision-pinned current source",
                )
            )

        for absent in dimension.get("absent_source_terms", []):
            path = source_root / absent["file"]
            content = path.read_text(encoding="utf-8")
            present_terms = [term for term in absent["terms"] if term in content]
            passed = not present_terms
            failures += int(not passed)
            rows.append(
                _row(
                    row_kind="absent-source",
                    dimension_id=dimension_id,
                    current_status=current_status,
                    model_scope=model_scope,
                    anchor=absent["file"],
                    expected="report-only implementation terms absent at pinned revision",
                    detected="absent" if passed else ";".join(present_terms),
                    status="pass" if passed else "fail",
                )
            )

        for stale_anchor in dimension.get("stale_report_anchors", []):
            stale += 1
            rows.append(
                _row(
                    row_kind="stale-source-anchor",
                    dimension_id=dimension_id,
                    current_status=current_status,
                    model_scope=model_scope,
                    anchor=stale_anchor,
                    expected="historical or newer report anchor",
                    detected="rebased by revision-pinned oracle",
                    status="note",
                )
            )

    structural_expected = 0
    structural_found = 0
    for expectation in oracle.get("structural_expectations", []):
        handler = expectation["handler"]
        for sink_anchor in expectation.get("sink_points", []):
            structural_expected += 1
            sink_file, sink_line = _anchor(sink_anchor)
            matches = chains_by_handler_sink.get((handler, sink_file, sink_line), [])
            sink_constraints = constraints_by_sink.get((sink_file, sink_line), [])
            passed = bool(matches) and len(sink_constraints) == 1
            structural_found += int(bool(matches))
            failures += int(not passed)
            rows.append(
                _row(
                    row_kind="structural-chain",
                    handler=handler,
                    anchor=sink_anchor,
                    expected="genuine adapter chain and exactly one terminal constraint",
                    detected=f"chains={len(matches)};constraints={len(sink_constraints)}",
                    status="pass" if passed else "fail",
                    detail=";".join(sorted(row["chain_id"] for row in matches)),
                )
            )

    zero_gate_chains = [
        chain for chain in chains if not gates_by_chain.get(chain["chain_id"])
    ]
    for chain in zero_gate_chains:
        rows.append(
            _row(
                row_kind="zero-gate-chain",
                handler=chain["tool_name"],
                anchor=f"{chain['sink_file']}:{chain['sink_line']}",
                expected="preserved structural chain",
                detected=chain["chain_id"],
                status="note",
                detail=chain["call_chain"],
            )
        )

    _write_csv(out_dir / "gt-coverage.csv", rows)
    command = shlex.join(
        [
            "python",
            generation_script,
            "--oracle",
            _command_path(oracle_path),
            "--ground-truth",
            _command_path(ground_truth_root),
            "--source-root",
            _command_path(source_root),
            "--pipeline-output",
            _command_path(pipeline_output),
            "--out-dir",
            _command_path(out_dir),
        ]
    )
    flow_recall = found_flows / expected_flows if expected_flows else 1.0
    gate_recall = found_gates / expected_gates if expected_gates else 1.0
    structural_recall = (
        structural_found / structural_expected if structural_expected else 1.0
    )
    report_represented = sum(oracle_counts[name] == 1 for name in inventory_names)
    lines = [
        f"# {title} Ground-Truth Coverage",
        "",
        f"> Generation command: `{command}`",
        "",
        f"Revision: `{oracle['analysis_revision']}`.",
        "",
        f"- Unique source reports represented: **{report_represented}/{len(inventory_names)}**.",
        f"- Expected handler/sink flows: **{found_flows}/{expected_flows}**; recall: **{flow_recall:.1%}**.",
        f"- Expected existing gates: **{found_gates}/{expected_gates}**; recall: **{gate_recall:.1%}**.",
        f"- Explicit expected-missing controls: **{expected_missing}**.",
        f"- Structural adapter expectations: **{structural_found}/{structural_expected}**; recall: **{structural_recall:.1%}**.",
        f"- Out-of-model dimensions: **{out_of_model}**; not present at revision: **{not_present}**.",
        f"- Duplicate reports: **{duplicates}**; stale anchors: **{stale}**.",
        f"- Zero-gate structural chains: **{len(zero_gate_chains)}**.",
        f"- Acceptance failures: **{failures}**.",
        "",
        "The CSV distinguishes source inventory, scope classification, GT flows, "
        "eligible gates, expected-missing controls, structural chains, terminal "
        "capability constraints, revision anchors, duplicates, and zero-gate chains.",
    ]
    (out_dir / "gt-coverage.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    return {
        "project": oracle["project_id"],
        "revision": oracle["analysis_revision"],
        "rows": len(rows),
        "failures": failures,
        "statuses": dict(sorted(Counter(row["status"] for row in rows).items())),
    }


def main_for_project(
    *,
    title: str,
    generation_script: str,
    default_oracle: Path,
    default_ground_truth: Path,
    default_source_root: Path,
    default_pipeline_output: Path,
    default_out_dir: Path,
    argv: Sequence[str] | None = None,
) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--oracle", type=Path, default=default_oracle)
    parser.add_argument("--ground-truth", type=Path, default=default_ground_truth)
    parser.add_argument("--source-root", type=Path, default=default_source_root)
    parser.add_argument("--pipeline-output", type=Path, default=default_pipeline_output)
    parser.add_argument("--out-dir", type=Path, default=default_out_dir)
    args = parser.parse_args(argv)
    result = render_acceptance(
        title=title,
        generation_script=generation_script,
        oracle_path=args.oracle,
        ground_truth_root=args.ground_truth,
        source_root=args.source_root,
        pipeline_output=args.pipeline_output,
        out_dir=args.out_dir,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 1 if result["failures"] else 0
