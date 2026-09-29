"""Read-only intake for coverage candidates and candidate-bound anchors.

The agent campaign never mutates ``src/coverage_comparison``.  This loader binds
a candidate to its comparison artifact, semantic IR, exact benchmark source, and
the small read-file runtime adapter used by the Hermes pilot.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from src.projects import get_project
from src.sink_capacity.card_migration import validates_digest_transition
from src.coverage_comparison.versions import (
    CANDIDATE_SCHEMA_VERSION,
    COMPARISON_SCHEMA_VERSION,
    MANIFEST_SCHEMA_VERSION,
)

from .contracts import ValidationError, sha256_file


REPO_ROOT = Path(__file__).resolve().parents[2]


READ_FILE_TOOL = "read_file"
READ_FILE_PARAMETERS = {
    "type": "object",
    "properties": {
        "path": {"type": "string"},
        "offset": {"type": "integer", "minimum": 1},
        "limit": {"type": "integer", "minimum": 1},
    },
    "required": ["path"],
    "additionalProperties": False,
}


@dataclass(frozen=True)
class CandidateBundle:
    candidate: dict[str, Any]
    semantic: dict[str, Any]
    comparison: dict[str, Any]
    anchors: list[dict[str, Any]]
    source_bindings: list[dict[str, Any]]
    source_root: Path
    coverage_root: Path
    artifacts: dict[str, str]


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise ValidationError(f"required artifact does not exist: {path}")
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValidationError(f"{path}:{number}: JSONL row is not an object")
        rows.append(value)
    return rows


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValidationError(f"required artifact does not exist: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValidationError(f"{path}: root is not an object")
    return value


def _location(value: object, label: str) -> tuple[str, int]:
    if not isinstance(value, str) or ":" not in value:
        raise ValidationError(f"{label} has no file:line location")
    filename, line_text, *_ = value.split(":", 2)
    try:
        line = int(line_text)
    except ValueError as exc:
        raise ValidationError(f"{label} has a non-integer line") from exc
    return filename, line


def _safe_suffix(name: object) -> str:
    value = re.sub(r"[^a-zA-Z0-9]+", "-", str(name or "")).strip("-").lower()
    return value[:48] or "anchor"


def _anchor(
    anchor_id: str,
    *,
    kind: str,
    stage: str,
    file: str | None,
    function: str | None,
    line: int | None = None,
    argument_path: list[str] | None = None,
    relation: str = "equals",
    mandatory: bool = False,
    diagnostic_only: bool = False,
    source: str = "fixed-hermes",
) -> dict[str, Any]:
    return {
        "anchor_id": anchor_id,
        "kind": kind,
        "stage": stage,
        "file": file,
        "function": function,
        "line": line,
        "argument_path": argument_path,
        "relation": relation,
        "mandatory": mandatory,
        "diagnostic_only": diagnostic_only,
        "source": source,
    }


def _source_excerpt(
    source_root: Path, relative: str, line: int, radius: int = 18
) -> dict[str, Any]:
    path = source_root / relative
    lines = path.read_text(encoding="utf-8").splitlines()
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    selected = [
        {"line": number, "text": lines[number - 1]} for number in range(start, end + 1)
    ]
    return {"file": relative, "line": line, "lines": selected}


def _build_anchor_catalog(
    candidate: Mapping[str, Any], semantic: Mapping[str, Any]
) -> list[dict[str, Any]]:
    handler = semantic["handler"]
    handler_file, handler_line = _location(handler["location"], "semantic handler")
    sink_file, sink_line = _location(
        semantic["sink_constraint"]["location"], "semantic sink constraint"
    )
    anchors = [
        _anchor(
            "A-prompt-received",
            kind="prompt",
            stage="prompt_received",
            file="hermes_cli/oneshot.py",
            function="run_oneshot",
            line=124,
            argument_path=["prompt"],
            relation="contains",
            mandatory=True,
        ),
        _anchor(
            "A-provider-request",
            kind="provider-request",
            stage="provider_request",
            file=None,
            function=None,
            argument_path=["messages"],
            mandatory=True,
            source="mock-provider-transcript",
        ),
        _anchor(
            "A-provider-tool-call",
            kind="provider-tool-call",
            stage="provider_tool_call",
            file=None,
            function=None,
            argument_path=["tool_call"],
            mandatory=True,
            source="mock-provider-transcript",
        ),
        _anchor(
            "A-registry-dispatch",
            kind="registry-dispatch",
            stage="registry_dispatch",
            file="tools/registry.py",
            function="dispatch",
            line=347,
            argument_path=["args", "path"],
            mandatory=True,
        ),
        _anchor(
            f"A-handler-{_safe_suffix(handler['qualified_name'])}",
            kind="handler-argument",
            stage="handler_argument",
            file=handler_file,
            function=handler["qualified_name"],
            line=handler_line,
            argument_path=["args", "path"],
            mandatory=True,
            source="candidate-semantic-ir",
        ),
        _anchor(
            "P-read-file-tool",
            kind="propagation",
            stage="read_file_argument",
            file="tools/file_tools.py",
            function="read_file_tool",
            line=447,
            argument_path=["path"],
            mandatory=True,
            source="reviewed-call-chain",
        ),
        _anchor(
            "P-file-operations-read",
            kind="propagation",
            stage="shell_read_argument",
            file="tools/file_operations.py",
            function="read_file",
            line=618,
            argument_path=["path"],
            mandatory=True,
            source="reviewed-call-chain",
        ),
        _anchor(
            "P-shell-exec",
            kind="propagation",
            stage="shell_exec_command",
            file="tools/file_operations.py",
            function="_exec",
            line=486,
            argument_path=["command"],
            relation="contains-shell-quoted-value",
            mandatory=True,
            source="reviewed-call-chain",
        ),
        _anchor(
            "P-environment-execute",
            kind="propagation",
            stage="environment_execute_command",
            file="tools/environments/base.py",
            function="execute",
            line=739,
            argument_path=["command"],
            relation="contains-shell-quoted-value",
            mandatory=True,
            source="reviewed-call-chain",
        ),
        _anchor(
            "P-local-run-bash",
            kind="propagation",
            stage="local_run_bash_command",
            file="tools/environments/local.py",
            function="_run_bash",
            line=375,
            argument_path=["cmd_string"],
            relation="contains-shell-quoted-value",
            mandatory=True,
            source="reviewed-call-chain",
        ),
        _anchor(
            "S-popen-effect",
            kind="process-sink",
            stage="popen_sink_argument",
            file=sink_file
            if sink_file == "tools/environments/local.py"
            else "tools/environments/local.py",
            function="_run_bash",
            line=413,
            argument_path=["args"],
            relation="contains-shell-quoted-value",
            mandatory=True,
            source="terminal-effect-boundary",
        ),
    ]
    candidate_gate_ids = set(candidate.get("gate_ids") or [])
    semantic_gate_by_id = {
        row.get("semantic", {}).get("gate_id"): row for row in semantic.get("gates", [])
    }
    semantic_gate_by_uid = {
        row.get("gate_uid"): row for row in semantic.get("gates", [])
    }
    for gate_id in sorted(candidate_gate_ids):
        gate = semantic_gate_by_uid.get(gate_id) or semantic_gate_by_id.get(gate_id)
        if gate is None:
            raise ValidationError(
                f"candidate gate {gate_id} is absent from semantic IR"
            )
        gate_file, gate_line = _location(gate["callsite"], f"candidate gate {gate_id}")
        anchors.append(
            _anchor(
                f"G-candidate-{_safe_suffix(gate_id)}",
                kind="gate-input-return",
                stage="gate_input",
                file=gate_file,
                function=gate["gate_name"],
                line=gate_line,
                argument_path=["filepath"],
                mandatory=True,
                source="candidate-cited-gate",
            )
        )
        anchors.append(
            _anchor(
                f"GR-candidate-{_safe_suffix(gate_id)}",
                kind="gate-return",
                stage="gate_return",
                file=gate_file,
                function=gate["gate_name"],
                line=gate_line,
                argument_path=["filepath"],
                relation="gate-return",
                mandatory=True,
                source="candidate-cited-gate",
            )
        )
    seen_uids: set[str] = set()
    for gate in semantic.get("gates", []):
        uid = gate.get("gate_uid")
        if uid in candidate_gate_ids or uid in seen_uids:
            continue
        seen_uids.add(uid)
        gate_file, gate_line = _location(gate["callsite"], f"semantic gate {uid}")
        anchors.extend(
            (
                _anchor(
                    f"G-diagnostic-{_safe_suffix(uid)}",
                    kind="gate-input-return",
                    stage="gate_input",
                    file=gate_file,
                    function=gate["gate_name"],
                    line=gate_line,
                    argument_path=["filepath"],
                    mandatory=False,
                    diagnostic_only=True,
                    source="semantic-ir-diagnostic",
                ),
                _anchor(
                    f"GR-diagnostic-{_safe_suffix(uid)}",
                    kind="gate-return",
                    stage="gate_return",
                    file=gate_file,
                    function=gate["gate_name"],
                    line=gate_line,
                    argument_path=["filepath"],
                    relation="gate-return",
                    mandatory=False,
                    diagnostic_only=True,
                    source="semantic-ir-diagnostic",
                ),
            )
        )
    ids = [row["anchor_id"] for row in anchors]
    if len(ids) != len(set(ids)):
        raise ValidationError("anchor catalog contains duplicate IDs")
    return anchors


def load_candidate_bundle(
    coverage_root: Path, candidate_id: str, project: str
) -> CandidateBundle:
    coverage_root = coverage_root.resolve()
    candidates_path = coverage_root / "candidates.jsonl"
    candidates = _read_jsonl(candidates_path)
    matches = [row for row in candidates if row.get("candidate_id") == candidate_id]
    if len(matches) != 1:
        raise ValidationError(
            f"candidate {candidate_id} is not uniquely bound in {coverage_root}"
        )
    candidate = matches[0]
    provenance = candidate.get("provenance")
    if (
        candidate.get("schema_version") != CANDIDATE_SCHEMA_VERSION
        or not isinstance(provenance, Mapping)
        or not isinstance(provenance.get("sources"), list)
        or not provenance["sources"]
        or not str(candidate.get("requirement_id", "")).startswith("CR-")
    ):
        raise ValidationError("candidate is not a canonical coverage-candidate/v7 row")
    if candidate.get("project") != project:
        raise ValidationError("candidate project does not match the requested project")

    spec = get_project(project)
    semantic_path = (
        spec.output_root / "call-chain-semantics" / "call-chain-semantics.jsonl"
    )
    semantics = _read_jsonl(semantic_path)
    semantic_matches = [
        row for row in semantics if row.get("chain_id") == candidate.get("chain_id")
    ]
    if len(semantic_matches) != 1:
        raise ValidationError("candidate chain is not uniquely bound by semantic IR")
    semantic = semantic_matches[0]
    comparisons = _read_jsonl(coverage_root / "comparisons.jsonl")
    comparison_matches = [
        row
        for row in comparisons
        if row.get("chain_id") == candidate.get("chain_id")
        and row.get("project") == project
    ]
    if len(comparison_matches) != 1:
        raise ValidationError(
            "candidate chain is not uniquely bound by comparison output"
        )
    comparison = comparison_matches[0]
    manifest = _read_json(coverage_root / "manifest.json")
    if comparison.get("schema_version") != COMPARISON_SCHEMA_VERSION:
        raise ValidationError("comparison is not coverage-comparison/v7")
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ValidationError("manifest is not coverage-comparison-manifest/v7")

    expected_revision = spec.analysis_revision
    for label, value in (
        ("candidate", candidate.get("revision")),
        ("semantic IR", semantic.get("project", {}).get("revision")),
        ("comparison", comparison.get("revision")),
    ):
        if value != expected_revision:
            raise ValidationError(f"{label} revision drifted from {expected_revision}")
    if semantic.get("sink", {}).get("sink_id") != candidate.get("sink_id"):
        raise ValidationError("candidate and semantic sink IDs differ")
    if semantic.get("sink_constraint", {}).get("sink_id") != candidate.get("sink_id"):
        raise ValidationError("candidate and sink-constraint IDs differ")
    if semantic.get("handler", {}).get("qualified_name") != "_handle_read_file":
        raise ValidationError("Hermes adapter supports only the read_file handler")
    if semantic.get("sink_constraint", {}).get("sink_api") not in {
        "file_ops.read_file",
        "subprocess.Popen",
    }:
        raise ValidationError(
            "Hermes adapter supports only the reviewed read_file-to-Popen family"
        )

    anchors = _build_anchor_catalog(candidate, semantic)
    source_files = sorted({row["file"] for row in anchors if row["file"]})
    source_root = spec.source_root.resolve()
    source_bindings: list[dict[str, Any]] = []
    for relative in source_files:
        path = source_root / relative
        if not path.is_file():
            raise ValidationError(f"anchor source is missing: {relative}")
        current_sha = sha256_file(path)
        source_bindings.append(
            {
                "file": relative,
                "path": str(path),
                "sha256": current_sha,
                "analysis_revision": expected_revision,
            }
        )
    for label, binding in (
        ("candidate capability card", candidate.get("capability_card")),
        (
            "semantic sink capability card",
            semantic.get("sink_constraint", {}).get("capability_card"),
        ),
    ):
        if not isinstance(binding, Mapping):
            raise ValidationError(f"{label} binding is missing")
        card_path = REPO_ROOT / str(binding.get("path"))
        if not card_path.is_file():
            raise ValidationError(f"{label} is missing")
        actual_digest = sha256_file(card_path)
        if not validates_digest_transition(
            card_path=str(binding.get("path")),
            expected_sha256=str(binding.get("sha256")),
            actual_sha256=actual_digest,
            ledger_path=(
                REPO_ROOT
                / "src/sink_capacity/sink-capability-cards/identity-migration.jsonl"
            ),
        ):
            raise ValidationError(f"{label} hash drifted")

    excerpts = []
    for anchor in anchors:
        if (
            anchor["file"]
            and anchor["line"]
            and anchor["kind"]
            not in {
                "provider-request",
                "provider-tool-call",
            }
        ):
            excerpts.append(
                _source_excerpt(source_root, anchor["file"], anchor["line"])
            )

    bundle_candidate = {
        **candidate,
        "tool_schema": {
            "tool_name": READ_FILE_TOOL,
            "parameters": READ_FILE_PARAMETERS,
        },
        "bounded_source_excerpts": excerpts,
    }
    artifacts = {
        "manifest": sha256_file(coverage_root / "manifest.json"),
        "comparisons": sha256_file(coverage_root / "comparisons.jsonl"),
        "candidates": sha256_file(candidates_path),
        "semantic_ir": sha256_file(semantic_path),
        "manifest_schema_version": manifest.get("schema_version"),
    }
    return CandidateBundle(
        candidate=bundle_candidate,
        semantic=semantic,
        comparison=comparison,
        anchors=anchors,
        source_bindings=source_bindings,
        source_root=source_root,
        coverage_root=coverage_root,
        artifacts=artifacts,
    )


def candidate_digest(bundle: CandidateBundle) -> str:
    value = {
        "candidate_id": bundle.candidate["candidate_id"],
        "coverage_artifacts": bundle.artifacts,
        "semantic": {
            "chain_id": bundle.semantic.get("chain_id"),
            "sink_id": bundle.semantic.get("sink", {}).get("sink_id"),
        },
        "source_bindings": bundle.source_bindings,
    }
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
