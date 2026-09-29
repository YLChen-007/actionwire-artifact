"""Compiler-API-backed TypeScript handler-specification adapters."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.projects import ProjectSpec

from .core import (
    AdapterResult,
    HandlerEntry,
    SpecificationError,
    evidence_record,
    group_handlers,
)


BRIDGE = Path(__file__).with_name("typescript_bridge.cjs")

EXTERNAL_FORMS = {
    "sdk-default-tool-boundary": (
        "sdk-owned-tool-schema",
        "The installed agent SDK owns this model-facing tool definition.",
    ),
}

VENDORED_LETTA_FORM = "allowed-vendored-letta-code-tool:0.19.5"


def _vendored_letta_result(
    spec: ProjectSpec, entry: HandlerEntry
) -> AdapterResult | None:
    if entry.form != VENDORED_LETTA_FORM:
        return None

    marker = "/src/tools/impl/"
    if marker not in entry.file:
        raise SpecificationError(
            f"lettabot:{entry.tool_name}: vendored handler path has unexpected shape: "
            f"{entry.file}"
        )
    vendor_root = entry.file.split(marker, 1)[0]
    definitions_relative = f"{vendor_root}/src/tools/toolDefinitions.ts"
    schema_relative = f"{vendor_root}/src/tools/schemas/{entry.tool_name}.json"
    description_relative = (
        f"{vendor_root}/src/tools/descriptions/{entry.tool_name}.md"
    )
    handler_path = spec.source_root / entry.file
    definitions_path = spec.source_root / definitions_relative
    schema_path = spec.source_root / schema_relative
    description_path = spec.source_root / description_relative

    handler_lines = handler_path.read_text(encoding="utf-8").splitlines()
    if entry.line > len(handler_lines) or not re.search(
        rf"\bexport\s+(?:async\s+)?function\s+{re.escape(entry.handler_func)}\s*\(",
        handler_lines[entry.line - 1],
    ):
        raise SpecificationError(
            f"lettabot:{entry.tool_name}: expected exported handler "
            f"{entry.handler_func!r} at {entry.file}:{entry.line}"
        )

    definitions = definitions_path.read_text(encoding="utf-8")
    match = re.search(
        rf"(?ms)^\s{{2}}{re.escape(entry.tool_name)}:\s*\{{(?P<body>.*?)^\s{{2}}\}},",
        definitions,
    )
    if match is None:
        raise SpecificationError(
            f"lettabot:{entry.tool_name}: definition is absent from "
            f"{definitions_relative}"
        )
    body = match.group("body")
    expected_fragments = (
        f"schema: {entry.tool_name}Schema",
        f"description: {entry.tool_name}Description.trim()",
        f"impl: {entry.handler_func} as unknown as ToolImplementation",
    )
    missing = [fragment for fragment in expected_fragments if fragment not in body]
    if missing:
        raise SpecificationError(
            f"lettabot:{entry.tool_name}: vendored definition provenance mismatch; "
            f"missing={missing}"
        )
    definition_line = definitions.count("\n", 0, match.start()) + 1

    try:
        parameters = json.loads(schema_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SpecificationError(
            f"lettabot:{entry.tool_name}: invalid vendored JSON schema: "
            f"{schema_relative}"
        ) from exc
    description = description_path.read_text(encoding="utf-8").strip()
    if not description:
        raise SpecificationError(
            f"lettabot:{entry.tool_name}: empty vendored description: "
            f"{description_relative}"
        )

    return AdapterResult(
        tool_name=entry.tool_name,
        interface_kind="function-tool",
        function={
            "name": entry.tool_name,
            "description": description,
            "parameters": parameters,
        },
        evidence=[
            evidence_record(
                spec.source_root,
                entry.file,
                entry.line,
                kind="typescript-handler-function",
                detail=entry.handler_func,
            ),
            evidence_record(
                spec.source_root,
                definitions_relative,
                definition_line,
                kind="vendored-tool-definition",
                detail="schema + description + implementation binding",
            ),
            evidence_record(
                spec.source_root,
                schema_relative,
                1,
                kind="vendored-json-schema",
            ),
            evidence_record(
                spec.source_root,
                description_relative,
                1,
                kind="vendored-markdown-description",
            ),
        ],
        consumed_files=(
            entry.file,
            definitions_relative,
            schema_relative,
            description_relative,
        ),
    )


def _run_bridge(spec: ProjectSpec, requests: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    payload = json.dumps(
        {"sourceRoot": str(spec.source_root), "requests": list(requests)},
        ensure_ascii=False,
    )
    completed = subprocess.run(
        ["node", str(BRIDGE)],
        input=payload,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise SpecificationError(
            f"{spec.project_id}: TypeScript static extraction failed:\n{detail}"
        )
    try:
        parsed = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise SpecificationError(
            f"{spec.project_id}: TypeScript bridge returned invalid JSON"
        ) from exc
    results = parsed.get("results")
    if not isinstance(results, list) or len(results) != len(requests):
        raise SpecificationError(
            f"{spec.project_id}: TypeScript bridge result count mismatch"
        )
    return results


def _external_result(spec: ProjectSpec, entry: HandlerEntry) -> AdapterResult | None:
    reason = EXTERNAL_FORMS.get(entry.form)
    if reason is None and spec.project_id in {"openclaw", "openclaw-cn"}:
        if entry.tool_name in {"read", "write", "edit"}:
            reason = (
                "imported-coding-tool-schema",
                "The imported coding-tool package owns this model-facing definition.",
            )
    if reason is None:
        return None
    reason_code, explanation = reason
    return AdapterResult(
        tool_name=entry.tool_name,
        interface_kind="external-tool-boundary",
        function=None,
        evidence=[
            evidence_record(
                spec.source_root,
                entry.file,
                entry.line,
                kind="external-tool-wrapper",
                detail=entry.form,
            )
        ],
        status="unresolved",
        reason_code=reason_code,
        reason=explanation,
    )


def _runtime_rules(project_id: str, tool_name: str) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    source_lines = {
        "openclaw": {"message": 342, "web_search": 473, "browser": 224},
        "openclaw-cn": {"message": 386, "web_search": 454, "browser": 252},
    }
    source_files = {
        "message": "message-tool.ts",
        "web_search": "web-search.ts",
        "browser": "browser-tool.ts",
    }

    def source(tool: str) -> dict[str, Any]:
        return {
            "file": (
                f"benchmark/typescript/{project_id}/src/agents/tools/"
                f"{source_files[tool]}"
            ),
            "line": source_lines[project_id][tool],
        }

    if project_id in {"openclaw", "openclaw-cn"} and tool_name == "message":
        rules.append(
            {
                "rule_id": f"{project_id}-message-channel-capabilities",
                "condition": {"configured_channel_capabilities": "present"},
                "source": source("message"),
                "effect": "filter-actions-and-description-for-runtime-channel",
                "affected_fields": ["/description", "/parameters/properties/action"],
            }
        )
    if project_id in {"openclaw", "openclaw-cn"} and tool_name == "web_search":
        rules.append(
            {
                "rule_id": f"{project_id}-web-search-provider-description",
                "condition": {"provider": "perplexity"},
                "source": source("web_search"),
                "effect": "replace-Brave-description-with-Perplexity-description",
                "affected_fields": ["/description"],
            }
        )
    if project_id in {"openclaw", "openclaw-cn"} and tool_name == "browser":
        rules.append(
            {
                "rule_id": f"{project_id}-browser-runtime-target-description",
                "condition": {"sandbox_or_host_policy": "configured"},
                "source": source("browser"),
                "effect": "replace-default-target-and-host-policy-hints",
                "affected_fields": ["/description"],
            }
        )
    return rules


def extract_typescript_project(
    spec: ProjectSpec, handlers: Sequence[HandlerEntry]
) -> dict[str, AdapterResult]:
    grouped = group_handlers(handlers)
    results: dict[str, AdapterResult] = {}
    requests: list[dict[str, Any]] = []
    request_tools: list[str] = []

    for tool_name, entries in grouped.items():
        vendored = [_vendored_letta_result(spec, entry) for entry in entries]
        vendored_results = [item for item in vendored if item is not None]
        if vendored_results:
            if len(vendored_results) != len(entries):
                raise SpecificationError(
                    f"{spec.project_id}:{tool_name}: mixed vendored and local handlers"
                )
            first = vendored_results[0]
            if any(item.function != first.function for item in vendored_results[1:]):
                raise SpecificationError(
                    f"{spec.project_id}:{tool_name}: conflicting vendored definitions"
                )
            results[tool_name] = AdapterResult(
                tool_name=tool_name,
                interface_kind=first.interface_kind,
                function=first.function,
                evidence=[
                    evidence
                    for item in vendored_results
                    for evidence in item.evidence
                ],
                consumed_files=sorted(
                    {
                        path
                        for item in vendored_results
                        for path in item.consumed_files
                    }
                ),
            )
            continue

        unresolved = [_external_result(spec, entry) for entry in entries]
        external = [item for item in unresolved if item is not None]
        if external:
            if len(external) != len(entries):
                raise SpecificationError(
                    f"{spec.project_id}:{tool_name}: mixed external and local handlers"
                )
            evidence = [record for item in external for record in item.evidence]
            first = external[0]
            results[tool_name] = AdapterResult(
                tool_name,
                first.interface_kind,
                None,
                evidence,
                status="unresolved",
                reason_code=first.reason_code,
                reason=first.reason,
            )
            continue

        entry = entries[0]
        request: dict[str, Any] = {
            "tool_name": tool_name,
            "file": entry.file,
            "line": entry.line,
            "handler_func": entry.handler_func,
        }
        if spec.project_id == "droidclaw":
            request.update(
                {
                    "mode": "structured-output",
                    "schemaFile": "src/llm-providers.ts",
                    "schemaIdentifier": "actionDecisionSchema",
                }
            )
        requests.append(request)
        request_tools.append(tool_name)

    bridge_results = _run_bridge(spec, requests) if requests else []
    for tool_name, extracted in zip(request_tools, bridge_results):
        entries = grouped[tool_name]
        declared_name = extracted.get("declared_name", tool_name)
        if declared_name != tool_name:
            raise SpecificationError(
                f"{spec.project_id}:{tool_name}: source declares name {declared_name!r}"
            )
        description = extracted.get("description")
        parameters = extracted.get("parameters")
        if not isinstance(description, str) or not description.strip():
            raise SpecificationError(
                f"{spec.project_id}:{tool_name}: source description is not static text"
            )
        if not isinstance(parameters, Mapping):
            raise SpecificationError(
                f"{spec.project_id}:{tool_name}: source parameter schema is not an object"
            )
        function = {
            "name": tool_name,
            "description": description.strip(),
            "parameters": dict(parameters),
        }
        evidence = [
            evidence_record(
                spec.source_root,
                entry.file,
                entry.line,
                kind="typescript-handler-wrapper",
                detail=entry.form,
            )
            for entry in entries
        ]
        schema_file = str(extracted.get("schema_file", entries[0].file))
        schema_line = int(extracted.get("schema_line", entries[0].line))
        evidence.append(
            evidence_record(
                spec.source_root,
                schema_file,
                schema_line,
                kind=(
                    "structured-output-schema"
                    if spec.project_id == "droidclaw"
                    else "typescript-tool-definition"
                ),
                detail="compiler-api static evaluation",
            )
        )
        interface_kind = {
            "droidclaw": "structured-output-action",
            "nanoclaw": "mcp-tool",
        }.get(spec.project_id, "function-tool")
        results[tool_name] = AdapterResult(
            tool_name,
            interface_kind,
            function,
            evidence,
            _runtime_rules(spec.project_id, tool_name),
            consumed_files=extracted.get("consumed_files", ()),
        )
    return results
