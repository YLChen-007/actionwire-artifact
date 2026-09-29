"""Deterministic source-evidence packets for low-turn candidate validation."""

from __future__ import annotations

import csv
import copy
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.projects import ProjectSpec

from .contracts import (
    CoverageComparisonError,
    canonical_json,
    digest,
    parse_json_response,
    sha256_file,
)
from .inputs import CoverageChain
from .prompts import redact_credentials


PACKET_SCHEMA_VERSION = "source-validation-evidence-packet/v1"
PACKET_PROMPT_VERSION = "source-validation-packet-fast/v2"
MAX_SPAN_LINES = 160
SOURCE_HOP_SUFFIXES = {".py", ".ts", ".tsx", ".js", ".mjs", ".cjs"}

PACKET_VALIDATION_SYSTEM = """\
Validate provisional security candidates using only the supplied revision-bound evidence
packet. You have no tools. First try to refute each candidate. Confirm only when the packet
proves the model-facing handler, controlled value, ordered propagation, exact sink argument,
applicable policy boundary, relevant gates or their absence, concrete impact, and
preconditions. Capability alone is not policy. Never use or infer ground truth.
The policy_basis enum describes the source-backed basis for the security rule, not requirement
provenance. Never return group-oracle, source-derived, or capability-card as policy_basis. For a
learned catalog rule return learned-security-invariant. For another rule choose only from the
listed source-policy/boundary enums when the packet spans prove that basis.
Each source span is exact for every numbered line from line_start through line_end; an endpoint
line contained inside that interval is present even when the excerpt includes surrounding lines.
The ordered gate semantics are revision-bound generated source evidence. Do not demand an
entire unrelated function when the packet contains the relevant decision branches, handler
line, sink line, propagation hops, and whole-file SHA-256.
When handler_to_sink_source_coverage says continuous_pre_sink_coverage=true, the supplied spans
contain every source line from the handler entry through the sink call. Use the structured
exact_chain_value_search_results to follow transformations and exact_chain_guard_search_results
to determine whether any approval/authorization term occurs before the sink; these search rows
are citations into the same digest-bound source spans, not inferred facts.
For a multi-file chain, continuous_pre_sink_coverage is intentionally false. Instead, each
ordered_structural_hop has a digest-bound source_anchor pointing to the exact function definition
or terminal call span. The source_anchor.source_span_id names the exact source_spans row and
anchor_line_text is the exact definition/call line. Use those ordered anchors to prove
interprocedural propagation; do not mistake same_file=false for missing handler or sink evidence.
An intermediate database, queue, or file resource may instead carry
anchor_kind=non-source-resource with no source_span_id. It preserves the structural hop but is
not source evidence and cannot independently prove flow, policy, gate coverage, or impact.

Shell grammar coverage is structural, not thematic. A direct curl|sh pattern and an outer-shell
bash <(curl URL) pattern do not cover eval $(curl URL), source <(curl URL), . <(wget URL), or
equivalent nested builtins that consume command/process substitution. Do not generalize one
grammar family to another solely because both ultimately execute remote content. Treat them as
covered only when an exact pattern or a sound parser in the supplied spans normalizes the nested
form to an already checked semantic.

Return JSON only. For a complete packet return:
{"decision":"complete","project":"<exact>","revision":"<exact>",
"chain_id":"<exact>","reason":"<packet sufficiency reason>","validations":[
 {"provisional_candidate_id":"<exact>",
  "verdict":"confirmed-uncovered|not-applicable|covered|upstream-inconsistent|unknown",
  "final_decision":"wrong-check|missing-check|covered|not-applicable|unknown",
  "covering_gate_ids":["<exact GU>"],
  "policy_basis":"explicit-source-policy|fixed-delta|inherent-security-boundary|learned-security-invariant|capability-only|none|unknown",
  "controlled_flow":"confirmed|refuted|unknown",
  "sink_reachability":"confirmed|refuted|unknown",
  "gate_coverage":"uncovered|covered|uncatalogued-check|unknown",
  "impact":"concrete|none|unknown","impact_severity":"high|medium|low|unknown",
  "source_research_complete":true,
  "source_evidence":[{"role":"handler|controlled-value|gate|sink|policy|impact",
    "file":"source-root-relative/path","line_start":1,"line_end":1,
    "claim":"claim supported by the packet span"}],
  "preconditions":["concrete precondition"],"security_effect":"effect or null",
  "uncertainties":["unresolved fact"],"reason":"source-backed verdict"}]}.

When the packet lacks a fact required for a defensible verdict, do not browse or guess. Return
{"decision":"needs-deep","project":"<exact>","revision":"<exact>",
"chain_id":"<exact>","reason":"<specific missing facts>","validations":[]}.
Copy all identifiers exactly. Every source citation must be contained in a supplied packet
span. A complete confirmed-uncovered verdict must satisfy the full ordinary source-validation
contract and contain no uncertainties. The source_evidence role must be exactly one of handler,
controlled-value, gate, sink, policy, or impact. Packet span labels such as propagation and
gate-definition describe packet construction and are not valid source_evidence roles; cite a
propagation span as controlled-value and a gate-definition span as gate.
Every source_evidence.file must equal a file in source_spans. Never cite a capability-card,
requirement-catalog, design, output, or repository metadata path as source_evidence. A single
packet source line may be cited more than once with different roles when its code supports both
claims: for example, a model-controlled fetch call can be cited as sink and as policy evidence
for an inherent network-boundary rule. The policy claim must describe what that source line
proves, not quote external metadata.
"""

PACKET_REPAIR_SYSTEM = """\
Repair a packet-only source-validation JSON response to satisfy the supplied schema error.
Use only identifiers, source spans, facts, and citations already present in the packet or the
invalid response. Do not use tools and do not strengthen an unsupported verdict. A confirmed
verdict must cite handler, controlled-value, gate when relevant, sink, policy, and impact;
must confirm flow/reachability; and must contain no uncertainty. Otherwise return needs-deep.
Return JSON only in the packet-validation response shape.
"""


def _read_structural_row(spec: ProjectSpec, chain_id: str) -> dict[str, str]:
    path = spec.output_root / "static/call-chains/handler-sink-chains.csv"
    with path.open(newline="", encoding="utf-8") as handle:
        rows = [row for row in csv.DictReader(handle) if row["chain_id"] == chain_id]
    if len(rows) != 1:
        raise CoverageComparisonError(
            f"{spec.project_id}:{chain_id}: expected one structural chain row"
        )
    return rows[0]


def _parse_hops(call_chain: str) -> list[tuple[str, str]]:
    _depth, separator, body = call_chain.partition("#")
    if not separator:
        raise CoverageComparisonError("packet structural chain has no depth separator")
    output: list[tuple[str, str]] = []
    for raw in body.split("->"):
        symbol, separator, location = raw.partition("@")
        if not separator:
            raise CoverageComparisonError("packet structural hop has no source location")
        output.append((symbol, Path(location.split("$$", 1)[0]).name))
    return output


def _is_source_hop(basename: str) -> bool:
    return Path(basename).suffix.lower() in SOURCE_HOP_SUFFIXES


def _symbol_needles(symbol: str) -> tuple[str, ...]:
    plain = symbol.strip("<>")
    values = {plain, plain.split(":", 1)[0]}
    values.update(token for token in re.split(r"[-_.:]", plain) if len(token) >= 4)
    return tuple(sorted(value for value in values if value))


def _resolve_hop_file(
    source_root: Path,
    *,
    symbol: str,
    basename: str,
    preferred: str | None = None,
    neighbor_symbols: Sequence[str] = (),
) -> Path:
    if preferred:
        path = (source_root / preferred).resolve(strict=False)
        try:
            path.relative_to(source_root)
        except ValueError as exc:
            raise CoverageComparisonError(
                f"packet preferred source file escapes source root: {preferred}"
            ) from exc
        if path.is_file() and path.name == basename:
            return path
    candidates = sorted(
        path
        for path in source_root.rglob(basename)
        if path.is_file() and "node_modules" not in path.parts
    )
    if not candidates:
        raise CoverageComparisonError(f"packet cannot resolve source file {basename}")
    needles = _symbol_needles(symbol)
    path_matches = [
        path
        for path in candidates
        if any(needle.lower() in path.as_posix().lower() for needle in needles)
    ]
    if len(path_matches) == 1:
        return path_matches[0]
    matched = []
    for path in candidates:
        text = path.read_text(encoding="utf-8", errors="replace")
        if any(needle in text for needle in needles):
            matched.append(path)
    if len(matched) == 1:
        return matched[0]
    contextual = []
    neighbor_needles = {
        needle
        for neighbor in neighbor_symbols
        for needle in _symbol_needles(neighbor)
    }
    for path in matched:
        text = path.read_text(encoding="utf-8", errors="replace")
        if any(needle in text for needle in neighbor_needles):
            contextual.append(path)
    if len(contextual) == 1:
        return contextual[0]
    ranked = []
    for path in contextual or matched:
        searchable = path.as_posix() + "\n" + path.read_text(
            encoding="utf-8", errors="replace"
        )
        score = sum(needle in searchable for needle in {*needles, *neighbor_needles})
        ranked.append((score, path))
    if ranked:
        best = max(score for score, _path in ranked)
        winners = [path for score, path in ranked if score == best]
        if len(winners) == 1:
            return winners[0]
    if len(candidates) == 1:
        return candidates[0]
    raise CoverageComparisonError(
        f"packet source file resolution is ambiguous for {symbol}@{basename}: "
        + ", ".join(str(path.relative_to(source_root)) for path in matched or candidates)
    )


def _find_symbol_line(path: Path, symbol: str, fallback: int) -> int:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    leaf = symbol.strip("<>").rsplit(".", 1)[-1].split(":", 1)[0]
    definition_patterns = (
        re.compile(rf"^\s*(?:async\s+)?def\s+{re.escape(leaf)}\b"),
        re.compile(
            rf"^\s*(?:export\s+)?(?:async\s+)?function\s+{re.escape(leaf)}\b"
        ),
        re.compile(
            rf"^\s*(?:public\s+|private\s+|protected\s+|static\s+|async\s+)*"
            rf"{re.escape(leaf)}\s*\("
        ),
        re.compile(
            rf"^\s*(?:export\s+)?(?:const|let|var)\s+{re.escape(leaf)}\b"
        ),
    )
    for number, line in enumerate(lines, 1):
        if any(pattern.search(line) for pattern in definition_patterns):
            return number
    needles = _symbol_needles(symbol)
    for number, line in enumerate(lines, 1):
        if any(needle in line for needle in needles):
            return number
    return max(1, min(fallback, len(lines) or 1))


def _source_span(
    source_root: Path,
    path: Path,
    *,
    center: int,
    role: str,
    symbol: str,
) -> dict[str, Any]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, center - 40)
    end = min(len(lines), start + MAX_SPAN_LINES - 1)
    if end - start + 1 < MAX_SPAN_LINES:
        start = max(1, end - MAX_SPAN_LINES + 1)
    return {
        "role": role,
        "symbol": symbol,
        "file": path.relative_to(source_root).as_posix(),
        "line_start": start,
        "line_end": end,
        "sha256": sha256_file(path),
        "excerpt": "\n".join(lines[start - 1 : end]),
    }


def _resolve_security_symbol(
    source_root: Path, symbol: str
) -> tuple[Path, int] | None:
    patterns = (
        re.compile(rf"^\s*(?:async\s+)?def\s+{re.escape(symbol)}\b"),
        re.compile(rf"^\s*(?:export\s+)?(?:async\s+)?function\s+{re.escape(symbol)}\b"),
        re.compile(rf"^\s*(?:export\s+)?(?:const|let|var)\s+{re.escape(symbol)}\b"),
        re.compile(rf"^\s*{re.escape(symbol)}\s*="),
    )
    matches: list[tuple[Path, int]] = []
    for path in source_root.rglob("*"):
        if (
            not path.is_file()
            or "node_modules" in path.parts
            or path.suffix not in {".py", ".ts", ".tsx", ".js", ".mjs", ".cjs"}
        ):
            continue
        for number, line in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
        ):
            if any(pattern.search(line) for pattern in patterns):
                matches.append((path, number))
                break
    return matches[0] if len(matches) == 1 else None


def _security_symbols(gates: Sequence[Mapping[str, Any]]) -> list[str]:
    values: set[str] = set()
    for gate in gates:
        gate_name = str(gate["gate_name"])
        values.add(gate_name)
        if gate_name.startswith("_") and gate_name.endswith("_guards"):
            values.add(gate_name.removeprefix("_").replace("all_guards", "all_command_guards"))
        blob = canonical_json(gate.get("semantic", {}))
        for symbol in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{5,}\b", blob):
            lowered = symbol.lower()
            if ("_" in symbol or symbol.isupper()) and any(
                token in lowered
                for token in ("guard", "approv", "danger", "hardline", "pattern", "security")
            ):
                values.add(symbol)
        if "P_DANGEROUS" in blob:
            values.add("DANGEROUS_PATTERNS")
            values.add("detect_dangerous_command")
        if "P_HARDLINE" in blob:
            values.add("HARDLINE_PATTERNS")
            values.add("detect_hardline_command")
    return sorted(values)[:32]


def _merge_packet_spans(
    source_root: Path, spans: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    by_file: dict[str, list[Mapping[str, Any]]] = {}
    for span in spans:
        by_file.setdefault(str(span["file"]), []).append(span)
    output: list[dict[str, Any]] = []
    for relative, rows in sorted(by_file.items()):
        path = source_root / relative
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        clusters: list[dict[str, Any]] = []
        for row in sorted(rows, key=lambda item: (item["line_start"], item["line_end"])):
            if clusters and row["line_start"] <= clusters[-1]["line_end"] + 1:
                clusters[-1]["line_end"] = max(
                    clusters[-1]["line_end"], row["line_end"]
                )
                clusters[-1]["roles"].add(str(row["role"]))
                clusters[-1]["symbols"].add(str(row["symbol"]))
            else:
                clusters.append(
                    {
                        "line_start": int(row["line_start"]),
                        "line_end": int(row["line_end"]),
                        "roles": {str(row["role"])},
                        "symbols": {str(row["symbol"])},
                    }
                )
        for cluster in clusters:
            for start in range(
                cluster["line_start"], cluster["line_end"] + 1, MAX_SPAN_LINES
            ):
                end = min(cluster["line_end"], start + MAX_SPAN_LINES - 1)
                output.append(
                    {
                        "role": "+".join(sorted(cluster["roles"])),
                        "symbol": ",".join(sorted(cluster["symbols"])),
                        "file": relative,
                        "line_start": start,
                        "line_end": end,
                        "sha256": sha256_file(path),
                        "excerpt": "\n".join(lines[start - 1 : end]),
                    }
                )
    return output


def _exact_chain_search_results(
    source_root: Path,
    *,
    structural: Mapping[str, str],
    merged_spans: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    handler_file = str(structural["handler_file"])
    sink_file = str(structural["sink_file"])
    handler_line = int(structural["handler_line"])
    sink_line = int(structural["sink_line"])
    same_file = handler_file == sink_file
    coverage = {
        "same_file": same_file,
        "file": handler_file if same_file else None,
        "line_start": handler_line if same_file else None,
        "line_end": sink_line if same_file else None,
        "continuous_pre_sink_coverage": False,
        "uncovered_line_ranges": [],
    }
    if same_file:
        path = source_root / handler_file
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    else:
        lines = []
    covered_lines: set[int] = set()
    if same_file:
        for span in merged_spans:
            if span["file"] != handler_file:
                continue
            covered_lines.update(
                range(int(span["line_start"]), int(span["line_end"]) + 1)
            )
    missing = (
        [line for line in range(handler_line, sink_line + 1) if line not in covered_lines]
        if same_file
        else []
    )
    ranges: list[list[int]] = []
    for line in missing:
        if ranges and line == ranges[-1][1] + 1:
            ranges[-1][1] = line
        else:
            ranges.append([line, line])
    coverage["continuous_pre_sink_coverage"] = not missing
    coverage["uncovered_line_ranges"] = ranges

    source_parameters = [
        value.strip()
        for value in str(structural["source_parameter"]).split(";")
        if value.strip()
    ]
    sink_needles = {
        value
        for value in re.findall(
            r"[A-Za-z_][A-Za-z0-9_]*", str(structural["sink_argument"])
        )
        if len(value) >= 4
    }
    sink_needles.update(_symbol_needles(str(structural["sink_label"])))
    guard_pattern = re.compile(
        r"\b(approv(?:e|al|ed)?|authori[sz](?:e|ation|ed)?|permission|consent|confirm)\b",
        re.IGNORECASE,
    )
    value_results: list[dict[str, Any]] = []
    guard_results: list[dict[str, Any]] = []
    search_spans = (
        [
            {
                "file": handler_file,
                "line_start": handler_line,
                "line_end": min(len(lines), sink_line + 8),
                "excerpt": "\n".join(lines[handler_line - 1 : min(len(lines), sink_line + 8)]),
            }
        ]
        if same_file
        else list(merged_spans)
    )
    seen_values: set[tuple[str, int]] = set()
    seen_guards: set[tuple[str, int]] = set()
    for span in search_spans:
        span_lines = str(span["excerpt"]).splitlines()
        start = int(span["line_start"])
        direct_offsets = {
            offset
            for offset, text in enumerate(span_lines)
            if any(
                re.search(rf"\b{re.escape(value)}\b", text)
                for value in source_parameters
            )
            or any(value in text for value in sink_needles)
        }
        for offset in sorted(
            {
                neighbor
                for hit in direct_offsets
                for neighbor in range(max(0, hit - 2), min(len(span_lines), hit + 3))
            }
        ):
            key = (str(span["file"]), start + offset)
            if key in seen_values:
                continue
            seen_values.add(key)
            value_results.append(
                {"file": key[0], "line": key[1], "text": span_lines[offset]}
            )
        for offset, text in enumerate(span_lines):
            if not guard_pattern.search(text):
                continue
            key = (str(span["file"]), start + offset)
            if key in seen_guards:
                continue
            seen_guards.add(key)
            guard_results.append({"file": key[0], "line": key[1], "text": text})
    value_results.sort(key=lambda row: (row["file"], row["line"]))
    guard_results.sort(key=lambda row: (row["file"], row["line"]))
    value_results = value_results[:160]
    guard_results = guard_results[:160]
    return coverage, value_results, guard_results


def build_source_validation_packet(
    *,
    chain: CoverageChain,
    candidates: Sequence[Mapping[str, Any]],
    assessments: Mapping[str, Mapping[str, Any]],
    requirements: Mapping[str, Mapping[str, Any]],
    spec: ProjectSpec,
    same_origin_witnesses: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    resolved = spec.resolved()
    source_root = resolved.source_root
    structural = _read_structural_row(resolved, chain.chain_id)
    hops = _parse_hops(structural["call_chain"])
    spans: list[dict[str, Any]] = []
    hop_source_anchors: list[dict[str, Any]] = []
    for index, (symbol, basename) in enumerate(hops):
        preferred = None
        fallback = 1
        role = "propagation"
        if index == 0:
            preferred = structural["handler_file"]
            fallback = int(structural["handler_line"])
            role = "handler"
        elif index == len(hops) - 1:
            preferred = structural["sink_file"]
            fallback = int(structural["sink_line"])
            role = "sink"
        neighbors = [
            hops[neighbor][0]
            for neighbor in (index - 1, index + 1)
            if 0 <= neighbor < len(hops)
        ]
        if index not in {0, len(hops) - 1} and not _is_source_hop(basename):
            hop_source_anchors.append(
                {
                    "anchor_kind": "non-source-resource",
                    "ordinal": index,
                    "symbol": symbol,
                    "file": basename,
                    "definition_or_call_line": None,
                    "span_line_start": None,
                    "span_line_end": None,
                    "sha256": None,
                    "source_span_id": None,
                    "anchor_line_text": None,
                }
            )
            continue
        path = _resolve_hop_file(
            source_root,
            symbol=symbol,
            basename=basename,
            preferred=preferred,
            neighbor_symbols=neighbors,
        )
        center = fallback if index in {0, len(hops) - 1} else _find_symbol_line(
            path, symbol, fallback
        )
        hop_span = _source_span(
            source_root, path, center=center, role=role, symbol=symbol
        )
        spans.append(hop_span)
        hop_source_anchors.append(
            {
                "anchor_kind": "source",
                "ordinal": index,
                "symbol": symbol,
                "file": hop_span["file"],
                "definition_or_call_line": center,
                "span_line_start": hop_span["line_start"],
                "span_line_end": hop_span["line_end"],
                "sha256": hop_span["sha256"],
            }
        )
    for gate in chain.semantic_ir["gates"]:
        raw_file, raw_line, _column = str(gate["callsite"]).split(":", 2)
        path = source_root / raw_file
        if not path.is_file():
            raise CoverageComparisonError(
                f"packet gate source file is absent: {raw_file}"
            )
        spans.append(
            _source_span(
                source_root,
                path,
                center=int(raw_line),
                role="gate",
                symbol=str(gate["gate_name"]),
            )
        )
    definition_spans: list[dict[str, Any]] = []
    for symbol in _security_symbols(chain.semantic_ir["gates"]):
        resolved_symbol = _resolve_security_symbol(source_root, symbol)
        if resolved_symbol is None:
            continue
        path, line = resolved_symbol
        definition_spans.append(
            _source_span(
                source_root, path, center=line, role="gate-definition", symbol=symbol
            )
        )
        if symbol == "check_all_command_guards":
            definition_spans.append(
                _source_span(
                    source_root,
                    path,
                    center=line + MAX_SPAN_LINES,
                    role="gate-definition",
                    symbol=symbol + "-continuation",
                )
            )
    spans.extend(definition_spans)
    dependency_symbols = {
        symbol
        for span in definition_spans
        for symbol in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]{5,})\s*\(", span["excerpt"])
        if "_" in symbol
        and any(
            token in symbol.lower()
            for token in ("guard", "approv", "danger", "hardline", "security")
        )
    }
    for symbol in sorted(dependency_symbols)[:32]:
        if any(span["symbol"] == symbol for span in definition_spans):
            continue
        resolved_symbol = _resolve_security_symbol(source_root, symbol)
        if resolved_symbol is None:
            continue
        path, line = resolved_symbol
        spans.append(
            _source_span(
                source_root, path, center=line, role="gate-definition", symbol=symbol
            )
        )
        if symbol == "check_all_command_guards":
            spans.append(
                _source_span(
                    source_root,
                    path,
                    center=line + MAX_SPAN_LINES,
                    role="gate-definition",
                    symbol=symbol + "-continuation",
                )
            )
    merged_spans = _merge_packet_spans(source_root, spans)
    for span in merged_spans:
        span["source_span_id"] = "SPAN-" + digest(
            [span["file"], span["line_start"], span["line_end"], span["sha256"]]
        )[:16]
    for anchor in hop_source_anchors:
        if anchor["anchor_kind"] == "non-source-resource":
            continue
        matching = [
            span
            for span in merged_spans
            if span["file"] == anchor["file"]
            and span["line_start"] <= anchor["definition_or_call_line"] <= span["line_end"]
        ]
        if len(matching) != 1:
            raise CoverageComparisonError(
                f"packet hop anchor does not resolve one span: {anchor['symbol']}"
            )
        path = source_root / str(anchor["file"])
        source_lines = path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
        anchor["source_span_id"] = matching[0]["source_span_id"]
        anchor["anchor_line_text"] = source_lines[
            int(anchor["definition_or_call_line"]) - 1
        ]
    source_coverage, value_search, guard_search = _exact_chain_search_results(
        source_root, structural=structural, merged_spans=merged_spans
    )
    packet = {
        "schema_version": PACKET_SCHEMA_VERSION,
        "prompt_version": PACKET_PROMPT_VERSION,
        "project": chain.project,
        "revision": chain.revision,
        "chain_id": chain.chain_id,
        "allowed_candidate_ids": sorted(str(row["candidate_id"]) for row in candidates),
        "allowed_gate_ids": sorted(
            str(row["gate_uid"]) for row in chain.semantic_ir["gates"]
        ),
        "handler": chain.semantic_ir["handler"],
        "sink_constraint": chain.semantic_ir["sink_constraint"],
        "controlled_values": chain.semantic_ir["values"],
        "ordered_structural_hops": [
            {
                "ordinal": index,
                "symbol": symbol,
                "file_basename": basename,
                "source_anchor": hop_source_anchors[index],
            }
            for index, (symbol, basename) in enumerate(hops)
        ],
        "ordered_gate_semantics": chain.semantic_ir["gates"],
        "same_origin_witnesses": [dict(row) for row in same_origin_witnesses],
        "handler_to_sink_source_coverage": source_coverage,
        "exact_chain_value_search_results": value_search,
        "exact_chain_guard_search_results": guard_search,
        "requirements": [
            dict(requirements[str(candidate["requirement_id"])])
            for candidate in candidates
        ],
        "provisional_candidates": [
            {
                "candidate": dict(candidate),
                "primary_assessment": dict(
                    assessments[str(candidate["requirement_id"])]
                ),
            }
            for candidate in candidates
        ],
        "source_spans": merged_spans,
    }
    packet["packet_digest"] = digest(packet)
    return packet


def build_packet_validation_user(packet: Mapping[str, Any]) -> str:
    return "Validate this source evidence packet:\n" + redact_credentials(
        canonical_json(packet)
    )


def parse_packet_validation_response(
    raw: str,
    *,
    packet: Mapping[str, Any],
) -> tuple[str, dict[str, Any] | None, str]:
    value = parse_json_response(raw)
    required = {"decision", "project", "revision", "chain_id", "reason", "validations"}
    if set(value) != required:
        raise CoverageComparisonError("packet validation response fields mismatch")
    if any(
        value[field] != packet[field] for field in ("project", "revision", "chain_id")
    ):
        raise CoverageComparisonError("packet validation response identity mismatch")
    decision = value["decision"]
    reason = value["reason"]
    if decision not in {"complete", "needs-deep"}:
        raise CoverageComparisonError("packet validation decision is invalid")
    if not isinstance(reason, str) or not reason.strip():
        raise CoverageComparisonError("packet validation reason is empty")
    validations = value["validations"]
    if decision == "needs-deep":
        if validations != []:
            raise CoverageComparisonError("needs-deep packet response must not validate")
        return decision, None, " ".join(reason.split())
    if not isinstance(validations, list):
        raise CoverageComparisonError("complete packet validations must be an array")
    return (
        decision,
        {
            "project": value["project"],
            "revision": value["revision"],
            "chain_id": value["chain_id"],
            "validations": validations,
        },
        " ".join(reason.split()),
    )


def normalize_packet_validation_payload(
    payload: Mapping[str, Any], *, packet: Mapping[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    """Normalize transport-only enum mistakes without changing a model verdict."""
    output = copy.deepcopy(dict(payload))
    candidate_failure_modes = {
        str(row["candidate"]["candidate_id"]): str(
            row["candidate"]["failure_mode"]
        )
        for row in packet["provisional_candidates"]
    }
    candidate_requirement_ids = {
        str(row["candidate"]["candidate_id"]): str(
            row["candidate"]["requirement_id"]
        )
        for row in packet["provisional_candidates"]
    }
    requirement_policy_basis = {
        str(row["requirement_id"]): str(row.get("policy_basis", ""))
        for row in packet["requirements"]
    }
    expected_final = {
        "not-applicable": "not-applicable",
        "covered": "covered",
        "upstream-inconsistent": "unknown",
        "unknown": "unknown",
    }
    role_aliases = {
        "propagation": "controlled-value",
        "gate-definition": "gate",
    }
    changes: list[str] = []
    validations = output.get("validations")
    if not isinstance(validations, list):
        return output, changes
    for row in validations:
        if not isinstance(row, dict):
            continue
        candidate_id = row.get("provisional_candidate_id")
        verdict = row.get("verdict")
        final = (
            candidate_failure_modes.get(str(candidate_id))
            if verdict == "confirmed-uncovered"
            else expected_final.get(str(verdict))
        )
        if final is not None and row.get("final_decision") != final:
            row["final_decision"] = final
            changes.append(f"{candidate_id}:normalized-final-decision")
        if verdict == "confirmed-uncovered" and row.get("covering_gate_ids"):
            row["covering_gate_ids"] = []
            changes.append(f"{candidate_id}:cleared-noncovering-gate-ids")
        policy_basis = row.get("policy_basis")
        canonical_basis = requirement_policy_basis.get(
            candidate_requirement_ids.get(str(candidate_id), ""), ""
        )
        if (
            policy_basis
            not in {
                "explicit-source-policy",
                "fixed-delta",
                "inherent-security-boundary",
                "learned-security-invariant",
                "capability-only",
                "none",
                "unknown",
            }
            and canonical_basis == "learned-security-invariant"
        ):
            row["policy_basis"] = canonical_basis
            changes.append(f"{candidate_id}:normalized-learned-policy-basis")
        evidence = row.get("source_evidence")
        if not isinstance(evidence, list):
            continue
        for index, citation in enumerate(evidence):
            if not isinstance(citation, dict):
                continue
            original = citation.get("role")
            replacement = role_aliases.get(str(original))
            if replacement is not None:
                citation["role"] = replacement
                changes.append(
                    f"{candidate_id}:evidence-{index}-{original}-to-{replacement}"
                )
    return output, changes


def build_packet_repair_user(
    *, packet: Mapping[str, Any], invalid_response: str, error: str
) -> str:
    return redact_credentials(
        "PACKET:\n"
        + canonical_json(packet)
        + "\nINVALID RESPONSE:\n"
        + invalid_response
        + "\nVALIDATION ERROR:\n"
        + error
    )
