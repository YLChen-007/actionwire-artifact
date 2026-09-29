"""Orchestrate detector CSVs -> GateSliceV1 -> Claude agent -> GateSemanticIRV1."""

from __future__ import annotations

import ast
import copy
import csv
import difflib
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable

from .behavior_checker import (
    check_and_upgrade_semantic,
    validate_behavior_semantic_ir,
)
from .agent_sdk import (
    ALL_RESEARCH_TOOLS,
    BUILTIN_RESEARCH_TOOLS,
    ClaudeCLIRunner,
    aggregate_token_usage,
    build_sdk_runner,
    normalize_token_usage,
)
from .catalog import build_catalog, write_catalog
from .candidates import CandidateSeed, load_candidates
from .contracts import (
    ContractError,
    estimate_tokens,
    parse_json_response,
    validate_analysis_response,
    validate_compound_analysis_response,
    validate_compound_semantic_ir,
    validate_semantic_ir,
    word_count,
)
from .prompts import (
    COMPOUND_COMPOSER_SYSTEM,
    COMPOUND_FRAGMENT_SYSTEM,
    PROMPT_VERSION,
    REVIEW_SYSTEM,
    SYSTEM,
    build_compound_composer_user,
    build_compound_fragment_repair_user,
    build_compound_fragment_user,
    build_compound_repair_user,
    build_repair_user,
    build_review_user,
    build_user,
)
from .slicer import (
    GateSlice,
    PythonGateSlicer,
    content_digest_from_payload,
)
from .typescript_slicer import TypeScriptGateSlicer


Runner = Callable[[str, str], str]
GATE_RESEARCH_TOOLS = BUILTIN_RESEARCH_TOOLS
SOURCE_RESEARCH_POLICY_VERSION = "adaptive-read-only-lsp/v2"
REGULAR_MAX_VALIDATION_ATTEMPTS = 3
EXACT_MATCHER_CALL_RE = re.compile(
    r"(?:^|\.)(?:search|match|fullmatch)\s*\(", re.IGNORECASE
)
MATCHER_RECEIVER_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\.(?:search|match|fullmatch)\s*\(",
    re.IGNORECASE,
)


class GateSelectionError(ValueError):
    """Raised when a requested catalog ordinal is invalid."""


class _ConversationRunner:
    """Capture exact runner inputs/outputs while preserving runner capabilities."""

    def __init__(self, runner: Runner) -> None:
        self.runner = runner
        self.exchanges: list[dict[str, Any]] = []

    def __call__(self, system: str, user: str) -> str:
        exchange: dict[str, Any] = {
            "call": len(self.exchanges) + 1,
            "system": system,
            "user": user,
        }
        self.exchanges.append(exchange)
        try:
            response = self.runner(system, user)
        except Exception as exc:
            exchange["error"] = f"{type(exc).__name__}: {exc}"
            raise
        exchange["assistant"] = response
        return response

    def audit_payload(self) -> dict[str, Any] | None:
        audit_payload = getattr(self.runner, "audit_payload", None)
        if not callable(audit_payload):
            return None
        value = audit_payload()
        return value if isinstance(value, dict) else None

    def chat_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": "gate-llm-chat/v1",
            "exchanges": list(self.exchanges),
        }
        chat_payload = getattr(self.runner, "chat_payload", None)
        if callable(chat_payload):
            trace = chat_payload()
            if isinstance(trace, dict):
                payload["agent_trace"] = trace
        return payload

    def close(self) -> None:
        _close_runner(self.runner)


def _json_line(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _write_jsonl(path: Path, values: Iterable[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "".join(_json_line(value) + "\n" for value in values)
    path.write_text(content, encoding="utf-8")


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object at {path}")
    return value


def _read_catalog_if_present(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _repository_gate_dir(repository_root: Path, gate_slice: GateSlice) -> Path:
    return repository_root / gate_slice.gate_uid


def _archive_repository_result(
    repository_dir: Path,
    *,
    current_content_digest: str,
    force: bool = False,
) -> bool:
    """Move a non-current result aside so downstream never reads stale semantics."""

    audit_path = repository_dir / "audit.json"
    if not audit_path.is_file() and not (repository_dir / "semantic.json").is_file():
        return False
    stored_digest = "unknown"
    if audit_path.is_file():
        try:
            stored_digest = str(_read_json(audit_path).get("content_digest") or "unknown")
        except (OSError, ValueError, json.JSONDecodeError):
            stored_digest = "unknown"
    if not force and stored_digest == current_content_digest:
        return False

    stale_dir = repository_dir / "stale" / stored_digest[:16]
    stale_dir.mkdir(parents=True, exist_ok=True)
    for filename in ("semantic.json", "audit.json", "chat.json"):
        source = repository_dir / filename
        if source.is_file():
            source.replace(stale_dir / filename)
    return True


def _backfill_unrecorded_usage(repository_dir: Path) -> None:
    """Mark legacy audit/chat artifacts whose provider token usage is unavailable."""

    for filename in ("audit.json", "chat.json"):
        path = repository_dir / filename
        if not path.is_file():
            continue
        try:
            payload = _read_json(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if "llm_usage" not in payload:
            payload["llm_usage"] = normalize_token_usage(None)
            _write_json(path, payload)


def _migrate_legacy_selected_artifacts(
    *,
    out_dir: Path,
    old_catalog: list[dict[str, str]],
    numbered_slices: list[tuple[int, GateSlice]],
    repository_root: Path,
) -> int:
    """Import compatible ordinal-named artifacts into the UID repository once."""

    old_by_gate_id = {
        row.get("gate_id", ""): row for row in old_catalog if row.get("gate_id")
    }
    migrated = 0
    for gate_number, gate_slice in numbered_slices:
        repository_dir = _repository_gate_dir(repository_root, gate_slice)
        if (repository_dir / "semantic.json").is_file():
            continue
        old_row = old_by_gate_id.get(gate_slice.gate_id)
        if old_row is None:
            continue
        raw_number = old_row.get("gate_number", "")
        if not raw_number.isdigit():
            continue
        legacy_dir = (
            out_dir
            / "selected"
            / f"{int(raw_number):04d}-{gate_slice.gate_id}"
        )
        required = {
            "slice": legacy_dir / "slice.json",
            "semantic": legacy_dir / "semantic.json",
            "audit": legacy_dir / "audit.json",
        }
        if not all(path.is_file() for path in required.values()):
            continue
        try:
            old_slice = _read_json(required["slice"])
            semantic = _read_json(required["semantic"])
            audit = _read_json(required["audit"])
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if content_digest_from_payload(old_slice) != gate_slice.content_digest:
            continue
        if semantic.get("gate_id") != gate_slice.gate_id:
            continue

        audit.update(
            {
                "gate_number": gate_number,
                "gate_uid": gate_slice.gate_uid,
                "content_digest": gate_slice.content_digest,
                "llm_usage": audit.get("llm_usage", normalize_token_usage(None)),
            }
        )
        _write_json(repository_dir / "slice.json", _slice_output(gate_number, gate_slice))
        _write_json(repository_dir / "semantic.json", semantic)
        _write_json(repository_dir / "audit.json", audit)

        chat_candidates = [
            legacy_dir / "chat.json",
            out_dir
            / "llm-chat"
            / f"{int(raw_number):04d}-{gate_slice.gate_id}.json",
        ]
        for chat_path in chat_candidates:
            if not chat_path.is_file():
                continue
            try:
                chat = _read_json(chat_path)
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            chat.update(
                {
                    "gate_number": gate_number,
                    "gate_uid": gate_slice.gate_uid,
                    "content_digest": gate_slice.content_digest,
                    "llm_usage": chat.get(
                        "llm_usage", normalize_token_usage(None)
                    ),
                }
            )
            _write_json(repository_dir / "chat.json", chat)
            break
        migrated += 1
    return migrated


def _slice_output(gate_number: int, gate_slice: GateSlice) -> dict[str, object]:
    return {
        "gate_number": gate_number,
        **gate_slice.prompt_payload(),
        "content_digest": gate_slice.content_digest,
    }


def _merge_slice(target: GateSlice, incoming: GateSlice) -> None:
    seen = {_json_line(ref) for ref in target.chain_refs}
    for ref in incoming.chain_refs:
        serialized = _json_line(ref)
        if serialized not in seen:
            target.chain_refs.append(ref)
            seen.add(serialized)


def _source_chunk_audit(gate_slice: GateSlice) -> list[dict[str, object]]:
    return [
        {
            "role": chunk.role,
            "symbol": chunk.symbol,
            "file": chunk.file,
            "line_start": chunk.line_start,
            "line_end": chunk.line_end,
            "sha256": chunk.sha256,
        }
        for chunk in gate_slice.source_bundle
    ]


def _effective_model(model: str | None, runner: Runner | None) -> str:
    if model:
        return model
    if runner is not None:
        return "injected-runner"
    from src.sink_capacity.agent import DEFAULT_MODEL

    return DEFAULT_MODEL


def build_slices_resilient(
    slicer: PythonGateSlicer | TypeScriptGateSlicer, seeds: Iterable[CandidateSeed]
) -> tuple[list[GateSlice], list[dict[str, object]]]:
    slices: dict[str, GateSlice] = {}
    failures: list[dict[str, object]] = []
    for seed in seeds:
        try:
            gate_slice = slicer.build_slice(seed)
        except Exception as exc:
            failures.append(
                {
                    "mode": seed.mode,
                    "gate_name": seed.gate_name,
                    "file": seed.call_file,
                    "line": seed.call_line,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            continue
        if gate_slice.gate_uid in slices:
            _merge_slice(slices[gate_slice.gate_uid], gate_slice)
        else:
            slices[gate_slice.gate_uid] = gate_slice
    return sorted(slices.values(), key=lambda item: item.gate_id), failures


def _validate_evidence(
    evidence: dict[str, list[dict[str, Any]]], source_root: Path
) -> list[str]:
    errors: list[str] = []
    root = source_root.resolve()
    for step_id, spans in evidence.items():
        for index, span in enumerate(spans):
            label = f"evidence.{step_id}[{index}]"
            raw_file = span.get("file", "")
            if not isinstance(raw_file, str):
                errors.append(f"{label} has an invalid source file")
                continue
            rel = raw_file.replace("\\", "/")
            rel_path = PurePosixPath(rel)
            if (
                not rel
                or rel_path.is_absolute()
                or ".." in rel_path.parts
                or rel_path.parts[0:1] == (".",)
            ):
                errors.append(f"{label} must use a normalized source-relative file")
                continue
            candidate = (root / Path(*rel_path.parts)).resolve()
            try:
                candidate.relative_to(root)
            except ValueError:
                errors.append(f"{label} escapes the source root")
                continue
            if not candidate.is_file():
                errors.append(f"{label} references missing source file {rel!r}")
                continue
            line_start = span.get("line_start")
            line_end = span.get("line_end")
            if (
                not isinstance(line_start, int)
                or isinstance(line_start, bool)
                or not isinstance(line_end, int)
                or isinstance(line_end, bool)
                or line_start < 1
                or line_end < line_start
            ):
                errors.append(f"{label} has an invalid line range")
                continue
            try:
                line_count = len(candidate.read_text(encoding="utf-8").splitlines())
            except (OSError, UnicodeDecodeError) as exc:
                errors.append(f"{label} cannot read source file: {exc}")
                continue
            if line_end > line_count:
                errors.append(
                    f"{label} ends at line {line_end}, beyond {rel!r} line {line_count}"
                )
    return errors


def _requires_exact_matcher_rules(gate_slice: GateSlice) -> bool:
    """Return whether the selected call is a source-defined matcher invocation."""

    expression = str(gate_slice.gate.get("call_expression", ""))
    return bool(EXACT_MATCHER_CALL_RE.search(expression))


def _validate_source_rules(
    ir: dict[str, Any],
    evidence: dict[str, list[dict[str, Any]]],
    source_root: Path,
    *,
    require_matcher_rules: bool = False,
) -> list[str]:
    """Prove every verbatim source rule against the same atom's evidence spans."""

    errors: list[str] = []
    root = source_root.resolve()
    source_rule_count = 0
    steps = ir.get("steps", [])
    if not isinstance(steps, list):
        return errors

    for step_index, step in enumerate(steps):
        if not isinstance(step, dict) or "source_rules" not in step:
            continue
        step_id = step.get("id")
        source_rules = step.get("source_rules")
        if not isinstance(step_id, str) or not isinstance(source_rules, list):
            continue
        spans = evidence.get(step_id, [])
        span_sources: list[str] = []
        for span in spans:
            if not isinstance(span, dict):
                continue
            raw_file = span.get("file")
            line_start = span.get("line_start")
            line_end = span.get("line_end")
            if (
                not isinstance(raw_file, str)
                or not isinstance(line_start, int)
                or isinstance(line_start, bool)
                or not isinstance(line_end, int)
                or isinstance(line_end, bool)
                or line_start < 1
                or line_end < line_start
            ):
                continue
            rel_path = PurePosixPath(raw_file.replace("\\", "/"))
            if rel_path.is_absolute() or ".." in rel_path.parts or not rel_path.parts:
                continue
            candidate = (root / Path(*rel_path.parts)).resolve()
            try:
                candidate.relative_to(root)
                lines = candidate.read_text(encoding="utf-8").splitlines()
            except (ValueError, OSError, UnicodeDecodeError):
                continue
            if line_end <= len(lines):
                span_sources.append("\n".join(lines[line_start - 1 : line_end]))

        for rule_index, source_rule in enumerate(source_rules):
            if not isinstance(source_rule, str) or not source_rule.strip():
                continue
            source_rule_count += 1
            exact_rule = source_rule.strip()
            if not any(exact_rule in span_source for span_source in span_sources):
                errors.append(
                    "semantic_ir.steps"
                    f"[{step_index}].source_rules[{rule_index}] is not an exact "
                    f"contiguous substring of evidence.{step_id}"
                )

    if require_matcher_rules and source_rule_count == 0:
        errors.append(
            "matcher gate must preserve its exact source matcher and referenced policy "
            "definitions in step.source_rules"
        )
    return errors


def _canonicalize_near_verbatim_source_rules(
    ir: dict[str, Any],
    evidence: dict[str, list[dict[str, Any]]],
    source_root: Path,
) -> None:
    """Correct only near-exact LLM transcription drift from a cited whole span."""

    root = source_root.resolve()
    steps = ir.get("steps", [])
    if not isinstance(steps, list):
        return
    for step in steps:
        if not isinstance(step, dict):
            continue
        step_id = step.get("id")
        source_rules = step.get("source_rules")
        if not isinstance(step_id, str) or not isinstance(source_rules, list):
            continue
        span_sources: list[str] = []
        for span in evidence.get(step_id, []):
            if not isinstance(span, dict):
                continue
            raw_file = span.get("file")
            line_start = span.get("line_start")
            line_end = span.get("line_end")
            if (
                not isinstance(raw_file, str)
                or not isinstance(line_start, int)
                or isinstance(line_start, bool)
                or not isinstance(line_end, int)
                or isinstance(line_end, bool)
                or line_start < 1
                or line_end < line_start
            ):
                continue
            rel_path = PurePosixPath(raw_file.replace("\\", "/"))
            if rel_path.is_absolute() or ".." in rel_path.parts or not rel_path.parts:
                continue
            candidate = (root / Path(*rel_path.parts)).resolve()
            try:
                candidate.relative_to(root)
                lines = candidate.read_text(encoding="utf-8").splitlines()
            except (ValueError, OSError, UnicodeDecodeError):
                continue
            if line_end <= len(lines):
                span_sources.append(
                    "\n".join(lines[line_start - 1 : line_end]).strip()
                )

        for index, source_rule in enumerate(source_rules):
            if not isinstance(source_rule, str) or not source_rule.strip():
                continue
            stripped = source_rule.strip()
            if any(stripped in span_source for span_source in span_sources):
                continue
            candidates = [
                (
                    difflib.SequenceMatcher(None, stripped, span_source).ratio(),
                    span_source,
                )
                for span_source in span_sources
            ]
            if not candidates:
                continue
            ratio, exact_span = max(candidates, key=lambda item: item[0])
            if ratio >= 0.98:
                source_rules[index] = exact_span


def _drop_unverifiable_source_rules(
    ir: dict[str, Any],
    evidence: dict[str, list[dict[str, Any]]],
    source_root: Path,
) -> None:
    """Discard model-quoted rules that cannot be proven by their cited spans.

    Removing an unverifiable optional quote is claim-preserving: the controlled-English
    atom and its evidence remain intact. Source-defined matcher closure is attached
    separately before this cleanup and therefore remains mandatory where required.
    """

    root = source_root.resolve()
    steps = ir.get("steps", [])
    if not isinstance(steps, list):
        return
    for step in steps:
        if not isinstance(step, dict):
            continue
        step_id = step.get("id")
        source_rules = step.get("source_rules")
        if not isinstance(step_id, str) or not isinstance(source_rules, list):
            continue
        span_sources: list[str] = []
        for span in evidence.get(step_id, []):
            if not isinstance(span, dict):
                continue
            raw_file = span.get("file")
            line_start = span.get("line_start")
            line_end = span.get("line_end")
            if (
                not isinstance(raw_file, str)
                or not isinstance(line_start, int)
                or isinstance(line_start, bool)
                or not isinstance(line_end, int)
                or isinstance(line_end, bool)
                or line_start < 1
                or line_end < line_start
            ):
                continue
            rel_path = PurePosixPath(raw_file.replace("\\", "/"))
            if rel_path.is_absolute() or ".." in rel_path.parts or not rel_path.parts:
                continue
            candidate = (root / Path(*rel_path.parts)).resolve()
            try:
                candidate.relative_to(root)
                lines = candidate.read_text(encoding="utf-8").splitlines()
            except (ValueError, OSError, UnicodeDecodeError):
                continue
            if line_end <= len(lines):
                span_sources.append("\n".join(lines[line_start - 1 : line_end]))

        retained: list[str] = []
        for source_rule in source_rules:
            if not isinstance(source_rule, str) or not source_rule.strip():
                continue
            exact_rule = source_rule.strip()
            if any(exact_rule in span_source for span_source in span_sources):
                if exact_rule not in retained:
                    retained.append(exact_rule)
        if retained:
            step["source_rules"] = retained
        else:
            step.pop("source_rules", None)


def _relocate_exact_source_rule_evidence(
    gate_slice: GateSlice,
    ir: dict[str, Any],
    evidence: dict[str, list[dict[str, Any]]],
    source_root: Path,
) -> None:
    """Relocate an exact model-quoted rule within the authoritative slice files."""

    root = source_root.resolve()
    allowed_files = sorted({chunk.file for chunk in gate_slice.source_bundle})
    steps = ir.get("steps", [])
    if not isinstance(steps, list):
        return
    for step in steps:
        if not isinstance(step, dict) or not isinstance(step.get("id"), str):
            continue
        step_id = str(step["id"])
        source_rules = step.get("source_rules")
        if not isinstance(source_rules, list):
            continue
        spans = evidence.setdefault(step_id, [])
        for source_rule in source_rules:
            if not isinstance(source_rule, str) or not source_rule.strip():
                continue
            rule = source_rule.strip()
            matches: list[dict[str, object]] = []
            for rel in allowed_files:
                candidate = (root / rel).resolve()
                try:
                    candidate.relative_to(root)
                    lines = candidate.read_text(encoding="utf-8").splitlines()
                except (ValueError, OSError, UnicodeDecodeError):
                    continue
                source = "\n".join(lines)
                offset = source.find(rule)
                if offset < 0 or source.find(rule, offset + 1) >= 0:
                    continue
                start = source.count("\n", 0, offset) + 1
                end = start + rule.count("\n")
                matches.append({"file": rel, "line_start": start, "line_end": end})
            if len(matches) == 1 and matches[0] not in spans:
                spans.append(matches[0])


def _attach_exact_matcher_definition_closure(
    gate_slice: GateSlice,
    ir: dict[str, Any],
    evidence: dict[str, list[dict[str, Any]]],
    source_root: Path,
) -> None:
    """Attach exact cited assignments for a named compiled matcher and its tables."""

    expression = str(gate_slice.gate.get("call_expression", ""))
    receiver_match = MATCHER_RECEIVER_RE.search(expression)
    if receiver_match is None:
        return
    receiver = receiver_match.group(1)
    root = source_root.resolve()
    steps = ir.get("steps", [])
    if not isinstance(steps, list):
        return
    callsite_span = gate_slice.callsite.get("span", {})
    callsite_file = str(callsite_span.get("file", ""))
    callsite_line = int(callsite_span.get("start_line", 0) or 0)

    for step in steps:
        if not isinstance(step, dict) or not isinstance(step.get("id"), str):
            continue
        step_id = str(step["id"])
        spans_by_file: dict[str, list[tuple[int, int]]] = {}
        for span in evidence.get(step_id, []):
            if not isinstance(span, dict):
                continue
            raw_file = span.get("file")
            line_start = span.get("line_start")
            line_end = span.get("line_end")
            if (
                isinstance(raw_file, str)
                and isinstance(line_start, int)
                and not isinstance(line_start, bool)
                and isinstance(line_end, int)
                and not isinstance(line_end, bool)
                and line_start >= 1
                and line_end >= line_start
            ):
                spans_by_file.setdefault(raw_file, []).append((line_start, line_end))

        for raw_file, spans in spans_by_file.items():
            if raw_file != callsite_file or not any(
                start <= callsite_line <= end for start, end in spans
            ):
                continue
            rel_path = PurePosixPath(raw_file.replace("\\", "/"))
            if rel_path.is_absolute() or ".." in rel_path.parts or not rel_path.parts:
                continue
            candidate = (root / Path(*rel_path.parts)).resolve()
            try:
                candidate.relative_to(root)
                source = candidate.read_text(encoding="utf-8")
                module = ast.parse(source, filename=raw_file)
            except (ValueError, OSError, UnicodeDecodeError, SyntaxError):
                continue
            source_lines = source.splitlines()
            assignments: dict[str, ast.Assign | ast.AnnAssign] = {}
            for statement in module.body:
                names: list[str] = []
                if isinstance(statement, ast.Assign):
                    names = [
                        target.id
                        for target in statement.targets
                        if isinstance(target, ast.Name)
                    ]
                elif isinstance(statement, ast.AnnAssign) and isinstance(
                    statement.target, ast.Name
                ):
                    names = [statement.target.id]
                if not names or not hasattr(statement, "end_lineno"):
                    continue
                for name in names:
                    assignments[name] = statement
            if receiver not in assignments:
                continue

            ordered_rules: list[str] = []
            ordered_spans: list[dict[str, Any]] = []
            visited: set[str] = set()

            def visit(name: str) -> None:
                if name in visited or name not in assignments:
                    return
                visited.add(name)
                statement = assignments[name]
                value = statement.value
                for dependency in sorted(
                    {
                        node.id
                        for node in (ast.walk(value) if value is not None else ())
                        if isinstance(node, ast.Name) and node.id in assignments
                    }
                ):
                    visit(dependency)
                start = int(statement.lineno)
                end = int(statement.end_lineno or statement.lineno)
                ordered_rules.append("\n".join(source_lines[start - 1 : end]).strip())
                ordered_spans.append(
                    {"file": raw_file, "line_start": start, "line_end": end}
                )

            visit(receiver)
            if not ordered_rules:
                continue
            existing = step.get("source_rules", [])
            retained: list[str] = []
            if isinstance(existing, list):
                for item in existing:
                    if not isinstance(item, str) or not item.strip():
                        continue
                    stripped = item.strip()
                    if any(stripped in exact_rule for exact_rule in ordered_rules):
                        continue
                    if stripped not in retained:
                        retained.append(stripped)
            step["source_rules"] = retained + ordered_rules
            existing_spans = evidence.setdefault(step_id, [])
            for assignment_span in ordered_spans:
                if assignment_span not in existing_spans:
                    existing_spans.append(assignment_span)
            return


def _source_research_audit(
    gate_slice: GateSlice,
    evidence: dict[str, list[dict[str, Any]]],
    *,
    max_turns: int,
    allowed_tools: tuple[str, ...] = ALL_RESEARCH_TOOLS,
) -> dict[str, Any]:
    """Identify evidence outside the deterministic slice without claiming a tool trace."""

    supplied = [
        (chunk.file, chunk.line_start, chunk.line_end)
        for chunk in gate_slice.source_bundle
    ]
    additional: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int, int]] = set()
    for step_id, spans in evidence.items():
        for span in spans:
            file = str(span["file"])
            line_start = int(span["line_start"])
            line_end = int(span["line_end"])
            covered = any(
                file == supplied_file
                and supplied_start <= line_start
                and line_end <= supplied_end
                for supplied_file, supplied_start, supplied_end in supplied
            )
            key = (step_id, file, line_start, line_end)
            if not covered and key not in seen:
                additional.append(
                    {
                        "step_id": step_id,
                        "file": file,
                        "line_start": line_start,
                        "line_end": line_end,
                    }
                )
                seen.add(key)
    return {
        "policy_version": SOURCE_RESEARCH_POLICY_VERSION,
        "allowed_tools": list(allowed_tools),
        "max_turns": max_turns,
        "additional_evidence": additional,
    }


def _validate_compound_fragment(
    response: dict[str, Any],
    *,
    expected_fragment_id: str,
    expected_check_ids: list[str],
    expected_policy_ids: list[str],
    permitted_chunks: list[dict[str, object]],
    required_unresolved: list[str],
    source_root: Path,
) -> dict[str, Any]:
    """Validate one audit-only compound fragment and its evidence boundary."""

    errors: list[str] = []
    allowed = {
        "fragment_id",
        "covered_checks",
        "covered_policies",
        "summary",
        "rules",
        "on_error",
        "unresolved",
        "evidence",
    }
    if not isinstance(response, dict):
        raise ContractError(["compound fragment must be a JSON object"])
    extras = sorted(set(response) - allowed)
    missing = sorted(allowed - set(response))
    if extras:
        errors.append(
            f"compound fragment contains unsupported fields: {', '.join(extras)}"
        )
    if missing:
        errors.append(f"compound fragment is missing fields: {', '.join(missing)}")

    fragment_id = response.get("fragment_id")
    if fragment_id != expected_fragment_id:
        errors.append(
            f"compound fragment_id must equal {expected_fragment_id!r}, "
            f"got {fragment_id!r}"
        )
    if response.get("covered_checks") != expected_check_ids:
        errors.append("compound fragment covered_checks must match its profile exactly")
    if response.get("covered_policies") != expected_policy_ids:
        errors.append(
            "compound fragment covered_policies must match its profile exactly"
        )
    summary = response.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        errors.append("compound fragment summary must be a non-empty string")
    elif word_count(summary) > 35:
        errors.append("compound fragment summary exceeds 35 words")
    on_error = response.get("on_error")
    if not isinstance(on_error, str) or not on_error.strip():
        errors.append("compound fragment on_error must be a non-empty string")

    rules = response.get("rules")
    if not isinstance(rules, list) or not 1 <= len(rules) <= 12:
        errors.append("compound fragment rules must contain between 1 and 12 strings")
        rules = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, str) or not rule.strip():
            errors.append(f"compound fragment rules[{index}] must be non-empty")
        elif word_count(rule) > 30:
            errors.append(f"compound fragment rules[{index}] exceeds 30 words")

    unresolved = response.get("unresolved")
    if not isinstance(unresolved, list) or any(
        not isinstance(item, str) or not item.strip() for item in unresolved
    ):
        errors.append("compound fragment unresolved must be a list of strings")
    elif not set(required_unresolved).issubset(unresolved):
        errors.append(
            "compound fragment must preserve required unresolved dependencies: "
            + ", ".join(required_unresolved)
        )

    evidence = response.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        errors.append("compound fragment evidence must be a non-empty list")
        evidence = []
    else:
        errors.extend(_validate_evidence({expected_fragment_id: evidence}, source_root))
        for index, span in enumerate(evidence):
            if not isinstance(span, dict):
                continue
            if not {"file", "line_start", "line_end"}.issubset(span):
                continue
            contained = any(
                span["file"] == chunk["file"]
                and isinstance(span["line_start"], int)
                and isinstance(span["line_end"], int)
                and span["line_start"] >= chunk["line_start"]
                and span["line_end"] <= chunk["line_end"]
                for chunk in permitted_chunks
            )
            if not contained:
                errors.append(
                    f"compound fragment evidence[{index}] is outside its supplied chunks"
                )

    if estimate_tokens(response) > 1200:
        errors.append("compound fragment exceeds 1200 serialized tokens")
    if errors:
        raise ContractError(errors)
    return response


def _validate_compound_coverage(
    gate_slice: GateSlice,
    ir: dict[str, Any],
    evidence: dict[str, list[dict[str, Any]]],
) -> list[str]:
    """Require evidence for every child check and complete policy table."""

    profile = gate_slice.compound_profile or {}
    errors: list[str] = []
    if ir.get("status") != "partial":
        errors.append(
            "compound semantic status must be partial for external Tirith rules"
        )

    required_units = [
        (item.get("id"), item.get("anchor", {}))
        for item in profile.get("required_checks", [])
    ] + [
        (item.get("id"), item.get("anchor", {})) for item in profile.get("policies", [])
    ]
    for unit_id, required in required_units:
        spans = evidence.get(unit_id, []) if isinstance(unit_id, str) else []
        covered = any(
            span.get("file") == required.get("file")
            and span.get("line_start", 0) <= required.get("line_start", -1)
            and span.get("line_end", -1) >= required.get("line_end", 0)
            for span in spans
            if isinstance(span, dict)
        )
        if not covered:
            errors.append(
                "compound evidence for "
                f"{unit_id} does not cover {required.get('file')}:"
                f"{required.get('line_start')}-{required.get('line_end')}"
            )
    return errors


def _normalize_compound_response(
    response: dict[str, Any], profile: dict[str, Any]
) -> dict[str, Any]:
    """Overlay source-resolved structure without changing LLM semantic prose.

    The LLM owns summaries, rules, inputs, outputs, and child error descriptions.
    Inventory, transitions, policy references, safe examples, and evidence anchors are
    deterministic products of the curated source profile and should not consume a model
    repair merely because they were serialized in a different shape.
    """

    normalized = copy.deepcopy(response)
    ir = normalized.get("semantic_ir")
    if not isinstance(ir, dict):
        return normalized
    ir["schema_version"] = "gate-semantic-ir/v2"
    ir["kind"] = "compound"
    ir["summary"] = profile.get("summary")
    ir["entry"] = profile.get("entry_check")
    ir["terminals"] = copy.deepcopy(profile.get("terminals"))
    ir["default"] = profile.get("default")
    ir["on_error"] = profile.get("on_error")
    ir["unresolved"] = copy.deepcopy(profile.get("forced_unresolved", []))
    ir["status"] = "partial"

    checks = ir.get("checks")
    if isinstance(checks, list):
        by_id = {
            check.get("id"): check
            for check in checks
            if isinstance(check, dict) and isinstance(check.get("id"), str)
        }
        ordered_checks: list[dict[str, Any]] = []
        for required in profile.get("required_checks", []):
            check = by_id.get(required.get("id"))
            if not isinstance(check, dict):
                continue
            check["op"] = required.get("op")
            check["outcomes"] = copy.deepcopy(required.get("outcomes"))
            check["policy_refs"] = copy.deepcopy(required.get("policy_refs", []))
            check["unresolved"] = copy.deepcopy(required.get("required_unresolved", []))
            check["reject_examples"] = copy.deepcopy(
                required.get("reject_examples", [])
            )
            ordered_checks.append(check)
        ir["checks"] = ordered_checks

    policies = ir.get("policies")
    if isinstance(policies, list):
        policies_by_id = {
            policy.get("id"): policy
            for policy in policies
            if isinstance(policy, dict) and isinstance(policy.get("id"), str)
        }
        ir["policies"] = [
            policies_by_id[required["id"]]
            for required in profile.get("policies", [])
            if required.get("id") in policies_by_id
        ]

    evidence: dict[str, list[dict[str, Any]]] = {}
    for required in profile.get("required_checks", []):
        if isinstance(required.get("id"), str) and isinstance(
            required.get("anchor"), dict
        ):
            evidence[required["id"]] = [copy.deepcopy(required["anchor"])]
    for required in profile.get("policies", []):
        if isinstance(required.get("id"), str) and isinstance(
            required.get("anchor"), dict
        ):
            evidence[required["id"]] = [copy.deepcopy(required["anchor"])]
    normalized["evidence"] = evidence
    return normalized


def _analyze_regular_gate(
    gate_slice: GateSlice,
    *,
    runner: Runner,
    source_root: Path,
    repair_runner: Runner | None = None,
    debug_fidelity_review: bool = False,
) -> tuple[
    dict[str, Any],
    dict[str, list[dict[str, Any]]],
    list[str],
    list[str],
]:
    user_prompt = build_user(gate_slice)
    raw = runner(SYSTEM, user_prompt)
    raw_responses = [raw]
    errors_seen: list[str] = []
    requires_matcher_rules = _requires_exact_matcher_rules(gate_slice)

    def normalize_regular_response(response: dict[str, Any]) -> dict[str, Any]:
        """Apply claim-preserving cleanup before structural validation."""
        normalized = copy.deepcopy(response)
        ir = normalized.get("semantic_ir")
        evidence = normalized.get("evidence")
        if isinstance(ir, dict) and isinstance(evidence, dict):
            step_ops = {
                step.get("id"): step.get("op")
                for step in ir.get("steps", [])
                if isinstance(step, dict)
                and isinstance(step.get("id"), str)
                and isinstance(step.get("op"), str)
            }
            reject_examples = ir.get("reject_examples")
            if isinstance(reject_examples, list):
                ir["reject_examples"] = [
                    example
                    for example in reject_examples
                    if isinstance(example, dict)
                    and step_ops.get(example.get("rejected_by"))
                    in {"block-if", "drop-if"}
                ]
            bypass_examples = ir.get("bypass_examples")
            if isinstance(bypass_examples, list):
                ir["bypass_examples"] = [
                    example
                    for example in bypass_examples
                    if isinstance(example, dict)
                    and step_ops.get(example.get("passed_by"))
                    in {"allow-if", "admit-if"}
                ]
            step_ids = {
                step.get("id")
                for step in ir.get("steps", [])
                if isinstance(step, dict) and isinstance(step.get("id"), str)
            }
            normalized["evidence"] = {
                step_id: spans
                for step_id, spans in evidence.items()
                if step_id in step_ids
            }
        return normalized

    def validate_raw(
        response: str,
        *,
        require_matcher_rules: bool = False,
    ) -> tuple[
        dict[str, Any],
        dict[str, Any],
        dict[str, list[dict[str, Any]]],
    ]:
        parsed_response = normalize_regular_response(parse_json_response(response))
        semantic_ir, semantic_evidence = validate_analysis_response(
            parsed_response,
            expected_gate_id=gate_slice.gate_id,
            expected_mode=str(gate_slice.gate["mode"]),
            expected_input_id=gate_slice.input_value_id,
            expected_output_id=gate_slice.output_value_id,
        )
        _canonicalize_near_verbatim_source_rules(
            semantic_ir,
            semantic_evidence,
            source_root,
        )
        _relocate_exact_source_rule_evidence(
            gate_slice,
            semantic_ir,
            semantic_evidence,
            source_root,
        )
        if requires_matcher_rules:
            _attach_exact_matcher_definition_closure(
                gate_slice,
                semantic_ir,
                semantic_evidence,
                source_root,
            )
        if not requires_matcher_rules:
            _drop_unverifiable_source_rules(
                semantic_ir,
                semantic_evidence,
                source_root,
            )
        normalized_ir_errors = validate_semantic_ir(
            semantic_ir,
            expected_gate_id=gate_slice.gate_id,
            expected_mode=str(gate_slice.gate["mode"]),
            expected_input_id=gate_slice.input_value_id,
            expected_output_id=gate_slice.output_value_id,
        )
        evidence_errors = _validate_evidence(semantic_evidence, source_root)
        source_rule_errors = _validate_source_rules(
            semantic_ir,
            semantic_evidence,
            source_root,
            require_matcher_rules=require_matcher_rules,
        )
        if normalized_ir_errors or evidence_errors or source_rule_errors:
            raise ContractError(
                normalized_ir_errors + evidence_errors + source_rule_errors
            )
        return parsed_response, semantic_ir, semantic_evidence

    for attempt in range(REGULAR_MAX_VALIDATION_ATTEMPTS):
        try:
            parsed, ir, evidence = validate_raw(
                raw,
                require_matcher_rules=requires_matcher_rules,
            )
            break
        except ContractError as exc:
            errors_seen.extend(exc.errors)
            if attempt == REGULAR_MAX_VALIDATION_ATTEMPTS - 1 or repair_runner is None:
                raise ContractError(errors_seen, raw_responses=raw_responses) from exc
            raw = repair_runner(
                SYSTEM,
                build_repair_user(gate_slice, raw, exc.errors),
            )
            raw_responses.append(raw)
    else:
        raise AssertionError("unreachable")

    if not debug_fidelity_review:
        return ir, evidence, raw_responses, errors_seen

    review_raw = runner(REVIEW_SYSTEM, build_review_user(gate_slice, parsed))
    raw_responses.append(review_raw)
    for attempt in range(REGULAR_MAX_VALIDATION_ATTEMPTS):
        try:
            _reviewed, reviewed_ir, reviewed_evidence = validate_raw(
                review_raw,
                require_matcher_rules=requires_matcher_rules,
            )
            return reviewed_ir, reviewed_evidence, raw_responses, errors_seen
        except ContractError as exc:
            errors_seen.extend(exc.errors)
            if attempt == REGULAR_MAX_VALIDATION_ATTEMPTS - 1 or repair_runner is None:
                raise ContractError(errors_seen, raw_responses=raw_responses) from exc
            review_raw = repair_runner(
                REVIEW_SYSTEM,
                build_repair_user(gate_slice, review_raw, exc.errors),
            )
            raw_responses.append(review_raw)
    raise AssertionError("unreachable")


def _analyze_compound_fragment(
    gate_slice: GateSlice,
    fragment: dict[str, Any],
    *,
    runner: Runner,
    source_root: Path,
    repair_runner: Runner | None,
) -> tuple[dict[str, Any], list[str], list[str]]:
    fragment_id = str(fragment["fragment_id"])
    selected_roles = {
        "compound-shared-callsite",
        "compound-shared-wrapper",
        "compound-shared-orchestrator",
        str(fragment["source_role"]),
    }
    permitted_chunks = [
        {
            "file": chunk.file,
            "line_start": chunk.line_start,
            "line_end": chunk.line_end,
        }
        for chunk in gate_slice.source_bundle
        if chunk.role in selected_roles
    ]
    raw = runner(
        COMPOUND_FRAGMENT_SYSTEM,
        build_compound_fragment_user(gate_slice, fragment),
    )
    raw_responses = [raw]
    errors_seen: list[str] = []
    for attempt in range(2):
        try:
            parsed = parse_json_response(raw)
            validated = _validate_compound_fragment(
                parsed,
                expected_fragment_id=fragment_id,
                expected_check_ids=list(fragment.get("check_ids", [])),
                expected_policy_ids=list(fragment.get("policy_ids", [])),
                permitted_chunks=permitted_chunks,
                required_unresolved=(
                    list(
                        (gate_slice.compound_profile or {}).get("forced_unresolved", [])
                    )
                    if fragment_id == "F4"
                    else []
                ),
                source_root=source_root,
            )
            return validated, raw_responses, errors_seen
        except ContractError as exc:
            errors_seen.extend(exc.errors)
            if attempt or repair_runner is None:
                raise ContractError(errors_seen, raw_responses=raw_responses) from exc
            raw = repair_runner(
                COMPOUND_FRAGMENT_SYSTEM,
                build_compound_fragment_repair_user(
                    gate_slice, fragment, raw, exc.errors
                ),
            )
            raw_responses.append(raw)
    raise AssertionError("unreachable")


def _analyze_compound_gate(
    gate_slice: GateSlice,
    *,
    runner: Runner,
    source_root: Path,
    repair_runner: Runner | None,
) -> tuple[
    dict[str, Any],
    dict[str, list[dict[str, Any]]],
    list[str],
    list[str],
    dict[str, Any],
]:
    profile = gate_slice.compound_profile or {}
    fragments: list[dict[str, Any]] = []
    fragment_audit: list[dict[str, Any]] = []
    all_raw_responses: list[str] = []
    all_errors: list[str] = []

    for fragment in profile.get("fragments", []):
        try:
            result, raw_responses, prior_errors = _analyze_compound_fragment(
                gate_slice,
                fragment,
                runner=runner,
                source_root=source_root,
                repair_runner=repair_runner,
            )
        except ContractError as exc:
            all_raw_responses.extend(exc.raw_responses)
            all_errors.extend(exc.errors)
            raise ContractError(all_errors, raw_responses=all_raw_responses) from exc
        fragments.append(result)
        all_raw_responses.extend(raw_responses)
        all_errors.extend(prior_errors)
        fragment_audit.append(
            {
                "fragment_id": fragment["fragment_id"],
                "result": result,
                "raw_responses": raw_responses,
                "repair_validation_errors": prior_errors,
            }
        )

    raw = runner(
        COMPOUND_COMPOSER_SYSTEM,
        build_compound_composer_user(gate_slice, fragments),
    )
    composer_raw_responses = [raw]
    all_raw_responses.append(raw)
    composer_errors: list[str] = []
    for attempt in range(2):
        try:
            parsed = _normalize_compound_response(parse_json_response(raw), profile)
            ir, evidence = validate_compound_analysis_response(
                parsed,
                profile=profile,
                expected_gate_id=gate_slice.gate_id,
                expected_mode=str(gate_slice.gate["mode"]),
                expected_input_id=gate_slice.input_value_id,
                expected_output_id=gate_slice.output_value_id,
            )
            evidence_errors = _validate_evidence(evidence, source_root)
            coverage_errors = _validate_compound_coverage(gate_slice, ir, evidence)
            if evidence_errors or coverage_errors:
                raise ContractError(evidence_errors + coverage_errors)
            compound_audit = {
                "profile_id": profile.get("profile_id"),
                "fragments": fragment_audit,
                "required_checks": profile.get("required_checks", []),
                "policies": profile.get("policies", []),
                "opaque_boundaries": profile.get("opaque_boundaries", []),
                "forced_unresolved": profile.get("forced_unresolved", []),
                "composer_raw_responses": composer_raw_responses,
                "composer_repair_validation_errors": composer_errors,
                "composer_structural_normalization": (
                    "profile-derived inventory, transitions, policy references, "
                    "symbolic rejection examples, and evidence anchors"
                ),
            }
            return (
                ir,
                evidence,
                all_raw_responses,
                all_errors + composer_errors,
                compound_audit,
            )
        except ContractError as exc:
            composer_errors.extend(exc.errors)
            if attempt or repair_runner is None:
                raise ContractError(
                    all_errors + composer_errors,
                    raw_responses=all_raw_responses,
                ) from exc
            raw = repair_runner(
                COMPOUND_COMPOSER_SYSTEM,
                build_compound_repair_user(gate_slice, raw, exc.errors),
            )
            composer_raw_responses.append(raw)
            all_raw_responses.append(raw)
    raise AssertionError("unreachable")


def analyze_gate_detailed(
    gate_slice: GateSlice,
    *,
    runner: Runner,
    source_root: Path,
    repair_runner: Runner | None = None,
    debug_fidelity_review: bool = False,
) -> tuple[
    dict[str, Any],
    dict[str, list[dict[str, Any]]],
    list[str],
    list[str],
    dict[str, Any] | None,
]:
    """Analyze one normal or explicitly profiled compound gate."""

    if gate_slice.compound_profile is not None:
        return _analyze_compound_gate(
            gate_slice,
            runner=runner,
            source_root=source_root,
            repair_runner=repair_runner,
        )
    ir, evidence, raw_responses, errors = _analyze_regular_gate(
        gate_slice,
        runner=runner,
        source_root=source_root,
        repair_runner=repair_runner,
        debug_fidelity_review=debug_fidelity_review,
    )
    ir, evidence, semantic_check = check_and_upgrade_semantic(
        slice_payload=gate_slice.prompt_payload(),
        semantic_ir=ir,
        evidence=evidence,
        source_root=source_root,
    )
    return ir, evidence, raw_responses, errors, semantic_check


def analyze_gate(
    gate_slice: GateSlice,
    *,
    runner: Runner,
    source_root: Path,
    repair_runner: Runner | None = None,
    debug_fidelity_review: bool = False,
) -> tuple[
    dict[str, Any],
    dict[str, list[dict[str, Any]]],
    list[str],
    list[str],
]:
    """Compatibility wrapper returning the established four analysis values."""

    ir, evidence, raw_responses, errors, _compound_audit = analyze_gate_detailed(
        gate_slice,
        runner=runner,
        source_root=source_root,
        repair_runner=repair_runner,
        debug_fidelity_review=debug_fidelity_review,
    )
    return ir, evidence, raw_responses, errors


def _default_runner(
    *,
    source_root: Path,
    model: str | None,
    timeout: int,
    max_turns: int,
    agent_transport: str,
    enable_lsp: bool,
) -> Runner:
    if agent_transport == "sdk":
        return build_sdk_runner(
            source_root=source_root,
            model=model,
            timeout=timeout,
            max_turns=max_turns,
            enable_lsp=enable_lsp,
        )
    if agent_transport != "cli":
        raise ValueError(f"unsupported agent transport: {agent_transport!r}")

    return ClaudeCLIRunner(
        source_root=source_root,
        model=model,
        timeout=timeout,
        max_turns=max_turns,
    )


def _runner_audit(runner: Runner) -> dict[str, Any] | None:
    audit_payload = getattr(runner, "audit_payload", None)
    if callable(audit_payload):
        value = audit_payload()
        return value if isinstance(value, dict) else None
    return None


def _runner_chat(runner: Runner) -> dict[str, Any] | None:
    chat_payload = getattr(runner, "chat_payload", None)
    if callable(chat_payload):
        value = chat_payload()
        return value if isinstance(value, dict) else None
    return None


def _runner_token_usage(runner: Runner) -> dict[str, int | bool]:
    audit = _runner_audit(runner)
    return normalize_token_usage(audit.get("token_usage") if audit else None)


def _write_llm_chat(
    path: Path,
    *,
    gate_number: int,
    gate_slice: GateSlice,
    runner: Runner,
    model: str,
    debug_fidelity_review: bool,
) -> None:
    payload = _runner_chat(runner) or {
        "schema_version": "gate-llm-chat/v1",
        "exchanges": [],
        "capture_error": "runner did not expose a chat payload",
    }
    payload = {
        **payload,
        "gate_number": gate_number,
        "gate_id": gate_slice.gate_id,
        "gate_uid": gate_slice.gate_uid,
        "content_digest": gate_slice.content_digest,
        "gate_name": gate_slice.gate["name"],
        "prompt_version": PROMPT_VERSION,
        "project_revision": gate_slice.project["revision"],
        "model": model,
        "debug_fidelity_review": debug_fidelity_review,
        "llm_usage": _runner_token_usage(runner),
    }
    _write_json(path, payload)


def _research_tools_for_runner(
    runner: Runner | None,
    *,
    agent_transport: str,
    enable_lsp: bool,
) -> tuple[str, ...]:
    if runner is not None:
        payload = _runner_audit(runner)
        available = payload.get("available_tools") if payload else None
        if isinstance(available, list) and all(
            isinstance(tool, str) for tool in available
        ):
            return tuple(available)
        return GATE_RESEARCH_TOOLS
    if agent_transport == "sdk" and enable_lsp:
        return ALL_RESEARCH_TOOLS
    return GATE_RESEARCH_TOOLS


def _close_runner(runner: Runner) -> None:
    close = getattr(runner, "close", None)
    if callable(close):
        close()


def _load_reusable_semantic(
    *,
    gate_slice: GateSlice,
    repository_dir: Path,
    source_root: Path,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Load a current, contract-valid repository entry without invoking the LLM."""

    paths = {
        "slice": repository_dir / "slice.json",
        "semantic": repository_dir / "semantic.json",
        "audit": repository_dir / "audit.json",
    }
    if not all(path.is_file() for path in paths.values()):
        return None
    try:
        _read_json(paths["slice"])
        semantic = _read_json(paths["semantic"])
        audit = _read_json(paths["audit"])
    except (OSError, ValueError, json.JSONDecodeError):
        return None

    stored_digest = audit.get("content_digest")
    if stored_digest != gate_slice.content_digest:
        return None
    if semantic.get("gate_id") != gate_slice.gate_id:
        return None

    evidence = audit.get("evidence", {})
    if not isinstance(evidence, dict):
        return None
    errors: list[str] = []
    semantic_check: dict[str, Any] | None = None
    try:
        if gate_slice.compound_profile is not None:
            errors.extend(
                validate_compound_semantic_ir(
                    semantic,
                    profile=gate_slice.compound_profile,
                    expected_gate_id=gate_slice.gate_id,
                    expected_mode=str(gate_slice.gate["mode"]),
                    expected_input_id=gate_slice.input_value_id,
                    expected_output_id=gate_slice.output_value_id,
                )
            )
        else:
            semantic, evidence, semantic_check = check_and_upgrade_semantic(
                slice_payload=gate_slice.prompt_payload(),
                semantic_ir=semantic,
                evidence=evidence,
                source_root=source_root,
            )
            if semantic.get("schema_version") == "gate-semantic-ir/v3":
                errors.extend(validate_behavior_semantic_ir(semantic))
            else:
                errors.extend(
                    validate_semantic_ir(
                        semantic,
                        expected_gate_id=gate_slice.gate_id,
                        expected_mode=str(gate_slice.gate["mode"]),
                        expected_input_id=gate_slice.input_value_id,
                        expected_output_id=gate_slice.output_value_id,
                    )
                )
    except Exception:
        return None

    errors.extend(_validate_evidence(evidence, source_root))
    errors.extend(
        _validate_source_rules(
            semantic,
            evidence,
            source_root,
            require_matcher_rules=_requires_exact_matcher_rules(gate_slice),
        )
    )
    if errors:
        return None

    audit.update(
        {
            "gate_uid": gate_slice.gate_uid,
            "content_digest": gate_slice.content_digest,
            "source_digest": gate_slice.source_digest,
            "source_chunks": _source_chunk_audit(gate_slice),
            "evidence": evidence,
            "llm_usage": audit.get("llm_usage", normalize_token_usage(None)),
        }
    )
    if semantic_check is not None:
        audit["reuse_validation"] = semantic_check
    return semantic, audit


def run_pipeline(
    *,
    source_root: Path,
    dominance_candidates: Path,
    filter_candidates: Path,
    transform_candidates: Path,
    out_dir: Path,
    generation_command: str,
    build_slices_only: bool = False,
    model: str | None = None,
    timeout: int = 900,
    max_turns: int = 20,
    agent_transport: str = "sdk",
    enable_lsp: bool = True,
    debug_fidelity_review: bool = False,
    max_gates: int | None = None,
    only: set[str] | None = None,
    gate_numbers: list[int] | None = None,
    independent_example_command: str = "python -m src.gate_semantics.main --gate-number 4",
    runner: Runner | None = None,
    project_name: str = "hermes-agent",
    project_revision: str | None = None,
    source_language: str = "python",
) -> dict[str, Any]:
    seeds = load_candidates(
        dominance_candidates, filter_candidates, transform_candidates
    )
    if source_language == "python":
        slicer: PythonGateSlicer | TypeScriptGateSlicer = PythonGateSlicer(
            source_root,
            project_name=project_name,
            revision=project_revision,
        )
    elif source_language == "typescript":
        slicer = TypeScriptGateSlicer(
            source_root,
            project_name=project_name,
            revision=project_revision,
        )
    else:
        raise ValueError(f"unsupported gate slicer language: {source_language!r}")
    all_slices, slice_failures = build_slices_resilient(slicer, seeds)
    numbered_slices = list(enumerate(all_slices, start=1))

    requested_numbers = list(gate_numbers or [])
    if len(requested_numbers) != len(set(requested_numbers)):
        raise GateSelectionError("--gate-number values must be unique")
    invalid_numbers = sorted(
        number
        for number in requested_numbers
        if number < 1 or number > len(numbered_slices)
    )
    if invalid_numbers:
        formatted = ", ".join(str(number) for number in invalid_numbers)
        raise GateSelectionError(
            f"--gate-number out of range: {formatted}; catalog contains "
            f"{len(numbered_slices)} gates numbered 1..{len(numbered_slices)}"
        )

    selected = numbered_slices
    if requested_numbers:
        requested = set(requested_numbers)
        selected = [item for item in selected if item[0] in requested]
    if only:
        selected = [
            (gate_number, gate_slice)
            for gate_number, gate_slice in selected
            if gate_slice.gate_id in only
            or gate_slice.gate_uid in only
            or str(gate_slice.gate["name"]) in only
        ]
    if max_gates is not None:
        selected = selected[:max_gates]

    out_dir.mkdir(parents=True, exist_ok=True)
    catalog_csv_path = out_dir / "gate-index.csv"
    catalog_markdown_path = out_dir / "gate-index.md"
    slice_path = out_dir / "gate-slices.jsonl"
    semantics_path = out_dir / "gate-semantics.jsonl"
    audit_path = out_dir / "gate-semantics-audit.jsonl"
    manifest_path = out_dir / "manifest.json"
    repository_root = out_dir / "repository"
    old_catalog = _read_catalog_if_present(catalog_csv_path)
    migrated_semantics = _migrate_legacy_selected_artifacts(
        out_dir=out_dir,
        old_catalog=old_catalog,
        numbered_slices=numbered_slices,
        repository_root=repository_root,
    )
    write_catalog(
        csv_path=catalog_csv_path,
        markdown_path=catalog_markdown_path,
        rows=build_catalog(numbered_slices),
        generation_command=generation_command,
        independent_example_command=independent_example_command,
    )
    _write_jsonl(
        slice_path,
        (_slice_output(number, gate_slice) for number, gate_slice in selected),
    )
    selected_dirs: dict[str, str] = {}
    invalidated_semantics = 0
    for gate_number, gate_slice in selected:
        gate_dir = _repository_gate_dir(repository_root, gate_slice)
        selected_dirs[str(gate_number)] = str(gate_dir)
        invalidated_semantics += int(
            _archive_repository_result(
                gate_dir, current_content_digest=gate_slice.content_digest
            )
        )
        _backfill_unrecorded_usage(gate_dir)
        _write_json(gate_dir / "slice.json", _slice_output(gate_number, gate_slice))

    semantic_records: list[dict[str, Any]] = []
    audit_records: list[dict[str, Any]] = []
    llm_chat_files: dict[str, str] = {}
    analysis_failures: list[dict[str, object]] = []
    reused_semantics = 0
    generated_semantics = 0
    new_llm_usages: list[dict[str, int | bool]] = []
    effective_model = _effective_model(model, runner)
    configured_research_tools = _research_tools_for_runner(
        runner,
        agent_transport=agent_transport,
        enable_lsp=enable_lsp,
    )
    if not build_slices_only:
        for gate_number, gate_slice in selected:
            gate_dir = Path(selected_dirs[str(gate_number)])
            chat_path = gate_dir / "chat.json"
            reusable = None
            if not debug_fidelity_review:
                reusable = _load_reusable_semantic(
                    gate_slice=gate_slice,
                    repository_dir=gate_dir,
                    source_root=source_root,
                )
            if reusable is not None:
                ir, audit_record = reusable
                audit_record.update(
                    {
                        "gate_number": gate_number,
                        "gate_uid": gate_slice.gate_uid,
                        "content_digest": gate_slice.content_digest,
                    }
                )
                semantic_records.append(ir)
                audit_records.append(audit_record)
                _write_json(gate_dir / "semantic.json", ir)
                _write_json(gate_dir / "audit.json", audit_record)
                if chat_path.is_file():
                    llm_chat_files[str(gate_number)] = str(chat_path)
                reused_semantics += 1
                continue

            invalidated_semantics += int(
                _archive_repository_result(
                    gate_dir,
                    current_content_digest=gate_slice.content_digest,
                    force=True,
                )
            )

            base_runner = runner or _default_runner(
                source_root=source_root,
                model=model,
                timeout=timeout,
                max_turns=max_turns,
                agent_transport=agent_transport,
                enable_lsp=enable_lsp,
            )
            active_runner = _ConversationRunner(base_runner)
            llm_chat_files[str(gate_number)] = str(chat_path)
            try:
                ir, evidence, raw_responses, prior_errors, analysis_audit = (
                    analyze_gate_detailed(
                        gate_slice,
                        runner=active_runner,
                        repair_runner=active_runner,
                        source_root=source_root,
                        debug_fidelity_review=debug_fidelity_review,
                    )
                )
            except Exception as exc:
                llm_usage = _runner_token_usage(active_runner)
                new_llm_usages.append(llm_usage)
                analysis_failures.append(
                    {
                        "gate_number": gate_number,
                        "gate_id": gate_slice.gate_id,
                        "gate_uid": gate_slice.gate_uid,
                        "gate_name": gate_slice.gate["name"],
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                audit_record = {
                    "gate_number": gate_number,
                    "gate_id": gate_slice.gate_id,
                    "gate_uid": gate_slice.gate_uid,
                    "prompt_version": PROMPT_VERSION,
                    "project_revision": gate_slice.project["revision"],
                    "source_digest": gate_slice.source_digest,
                    "content_digest": gate_slice.content_digest,
                    "source_chunks": _source_chunk_audit(gate_slice),
                    "model": effective_model,
                    "llm_usage": llm_usage,
                    "chain_refs": gate_slice.chain_refs,
                    "unresolved_symbols": gate_slice.unresolved_symbols,
                    "analysis_profile": (
                        gate_slice.compound_profile.get("profile_id")
                        if gate_slice.compound_profile
                        else None
                    ),
                    "debug_fidelity_review": debug_fidelity_review,
                    "status": "failed",
                    "error": f"{type(exc).__name__}: {exc}",
                    "raw_responses": getattr(exc, "raw_responses", []),
                }
                agent_session = _runner_audit(active_runner)
                if agent_session is not None:
                    audit_record["agent_session"] = agent_session
                audit_records.append(audit_record)
                _write_json(gate_dir / "audit.json", audit_record)
                _write_llm_chat(
                    chat_path,
                    gate_number=gate_number,
                    gate_slice=gate_slice,
                    runner=active_runner,
                    model=effective_model,
                    debug_fidelity_review=debug_fidelity_review,
                )
                if runner is None:
                    _close_runner(active_runner)
                continue
            llm_usage = _runner_token_usage(active_runner)
            new_llm_usages.append(llm_usage)
            semantic_records.append(ir)
            audit_record = {
                "gate_number": gate_number,
                "gate_id": gate_slice.gate_id,
                "gate_uid": gate_slice.gate_uid,
                "prompt_version": PROMPT_VERSION,
                "project_revision": gate_slice.project["revision"],
                "source_digest": gate_slice.source_digest,
                "content_digest": gate_slice.content_digest,
                "source_chunks": _source_chunk_audit(gate_slice),
                "model": effective_model,
                "llm_usage": llm_usage,
                "chain_refs": gate_slice.chain_refs,
                "unresolved_symbols": gate_slice.unresolved_symbols,
                "evidence": evidence,
                "raw_responses": raw_responses,
                "repair_validation_errors": prior_errors,
                "source_research": _source_research_audit(
                    gate_slice,
                    evidence,
                    max_turns=max_turns,
                    allowed_tools=configured_research_tools,
                ),
                "analysis_profile": (
                    gate_slice.compound_profile.get("profile_id")
                    if gate_slice.compound_profile
                    else None
                ),
                "debug_fidelity_review": debug_fidelity_review,
                "status": "complete",
            }
            agent_session = _runner_audit(active_runner)
            if agent_session is not None:
                audit_record["agent_session"] = agent_session
            if analysis_audit is not None:
                if "checker_version" in analysis_audit:
                    audit_record["semantic_check"] = analysis_audit
                else:
                    audit_record["compound_analysis"] = analysis_audit
            audit_records.append(audit_record)
            _write_json(gate_dir / "semantic.json", ir)
            _write_json(gate_dir / "audit.json", audit_record)
            _write_llm_chat(
                chat_path,
                gate_number=gate_number,
                gate_slice=gate_slice,
                runner=active_runner,
                model=effective_model,
                debug_fidelity_review=debug_fidelity_review,
            )
            generated_semantics += 1
            if runner is None:
                _close_runner(active_runner)
        _write_jsonl(semantics_path, semantic_records)
        _write_jsonl(audit_path, audit_records)

    current_gate_uids = {gate_slice.gate_uid for gate_slice in all_slices}
    stale_semantics = sum(
        1
        for path in repository_root.iterdir()
        if path.is_dir()
        and path.name not in current_gate_uids
        and (path / "semantic.json").is_file()
    ) if repository_root.is_dir() else 0
    run_llm_usage = aggregate_token_usage(new_llm_usages)

    manifest = {
        "schema_version": "gate-semantics-manifest/v1",
        "generation_command": generation_command,
        "prompt_version": PROMPT_VERSION,
        "model": effective_model,
        "agent": {
            "transport": "injected" if runner is not None else agent_transport,
            "lsp_enabled": any(
                tool.startswith("mcp__lsp__") for tool in configured_research_tools
            ),
            "research_tools": list(configured_research_tools),
            "debug_fidelity_review": debug_fidelity_review,
        },
        "llm_usage": {
            "scope": "model calls executed during this run; reused artifacts excluded",
            **run_llm_usage,
        },
        "project": {
            "name": slicer.project_name,
            "revision": slicer.revision,
            "language": source_language,
            "source_root": str(source_root.resolve()),
        },
        "inputs": {
            "dominance_candidates": str(dominance_candidates),
            "filter_candidates": str(filter_candidates),
            "transform_candidates": str(transform_candidates),
        },
        "outputs": {
            "gate_index_csv": str(catalog_csv_path),
            "gate_index_markdown": str(catalog_markdown_path),
            "gate_slices": str(slice_path),
            "gate_semantics": None if build_slices_only else str(semantics_path),
            "audit": None if build_slices_only else str(audit_path),
            "repository_root": str(repository_root),
            "selected_gate_dirs": selected_dirs,
            "llm_chat_files": llm_chat_files,
        },
        "selection": {
            "requested_gate_numbers": requested_numbers,
            "only": sorted(only or []),
            "max_gates": max_gates,
            "selected_gate_numbers": [number for number, _ in selected],
            "selected_gate_ids": [gate_slice.gate_id for _, gate_slice in selected],
            "selected_gate_uids": [gate_slice.gate_uid for _, gate_slice in selected],
        },
        "counts": {
            "candidate_rows": len(seeds),
            "catalog_gates": len(numbered_slices),
            "selected_gates": len(selected),
            "gate_slices": len(selected),
            "semantic_records": len(semantic_records),
            "slice_failures": len(slice_failures),
            "analysis_failures": len(analysis_failures),
            "llm_chat_records": len(llm_chat_files),
            "migrated_semantics": migrated_semantics,
            "reused_semantics": reused_semantics,
            "generated_semantics": generated_semantics,
            "stale_semantics": stale_semantics,
            "invalidated_semantics": invalidated_semantics,
            "llm_input_tokens": run_llm_usage["total_input_tokens"],
            "llm_output_tokens": run_llm_usage["output_tokens"],
            "llm_total_tokens": run_llm_usage["total_tokens"],
        },
        "slice_failures": slice_failures,
        "analysis_failures": analysis_failures,
        "source_bundle_digest": hashlib.sha256(
            "".join(gate_slice.source_digest for _, gate_slice in selected).encode(
                "utf-8"
            )
        ).hexdigest(),
        "catalog_source_bundle_digest": hashlib.sha256(
            "".join(gate_slice.source_digest for gate_slice in all_slices).encode(
                "utf-8"
            )
        ).hexdigest(),
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return manifest
