"""Fail-closed Python project adapters for model-facing tool specifications."""

from __future__ import annotations

import ast
import copy
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.projects import ProjectSpec

from . import hermes
from .core import (
    AdapterResult,
    HandlerEntry,
    SpecificationError,
    evidence_record,
    group_handlers,
)


def _function(name: str, description: str, parameters: Mapping[str, Any]) -> dict[str, Any]:
    schema = copy.deepcopy(dict(parameters))
    schema.setdefault("type", "object")
    schema.setdefault("properties", {})
    return {"name": name, "description": description.strip(), "parameters": schema}


def _module(path: Path, source_root: Path) -> hermes.StaticModule:
    return hermes.StaticModule(path, source_root=source_root)


def _function_at(tree: ast.AST, line: int) -> ast.FunctionDef | ast.AsyncFunctionDef:
    matches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno == line
    ]
    if len(matches) != 1:
        raise SpecificationError(f"expected one function at line {line}, found {len(matches)}")
    return matches[0]


def _class_for(tree: ast.AST, function: ast.AST) -> ast.ClassDef:
    matches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and function in set(ast.walk(node))
    ]
    if not matches:
        raise SpecificationError(f"function at line {function.lineno} is not in a class")
    return min(matches, key=lambda node: len(list(ast.walk(node))))


def _assignment_value(class_node: ast.ClassDef, name: str) -> ast.expr | None:
    for statement in class_node.body:
        if isinstance(statement, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in statement.targets
        ):
            return statement.value
        if (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.target.id == name
            and statement.value is not None
        ):
            return statement.value
    return None


def _method_return(class_node: ast.ClassDef, name: str) -> ast.expr | None:
    for statement in class_node.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)) and statement.name == name:
            returns = [node.value for node in statement.body if isinstance(node, ast.Return)]
            if len(returns) == 1 and returns[0] is not None:
                return returns[0]
    return None


def _eval_metadata(
    module: hermes.StaticModule,
    node: ast.expr,
    line: int,
    scope: Mapping[str, Any] | None = None,
) -> Any:
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {
        "field",
        "Field",
    }:
        keywords = {item.arg: item.value for item in node.keywords if item.arg}
        factory = keywords.get("default_factory")
        default = keywords.get("default")
        if isinstance(factory, ast.Lambda):
            return module.eval_expr(factory.body, line, scope)
        if default is not None:
            return module.eval_expr(default, line, scope)
        if node.args:
            return module.eval_expr(node.args[0], line, scope)
        raise SpecificationError(f"{module.path}:{line}: field has no static default")
    return module.eval_expr(node, line, scope)


def _class_scope(module: hermes.StaticModule, class_node: ast.ClassDef) -> dict[str, Any]:
    """Resolve preceding class constants needed by model-facing metadata."""

    scope: dict[str, Any] = {}
    for statement in class_node.body:
        assignments: list[tuple[str, ast.expr]] = []
        if isinstance(statement, ast.Assign):
            assignments = [
                (target.id, statement.value)
                for target in statement.targets
                if isinstance(target, ast.Name)
            ]
        elif (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.value is not None
        ):
            assignments = [(statement.target.id, statement.value)]
        for name, value_node in assignments:
            try:
                scope[name] = _eval_metadata(
                    module,
                    value_node,
                    getattr(value_node, "lineno", statement.lineno),
                    scope,
                )
            except hermes.StaticResolutionError:
                # Class initialization often contains runtime-only state after
                # the declarative metadata. It is irrelevant unless a later
                # metadata expression references it, in which case evaluation
                # of that expression still fails closed.
                continue
    return scope


def _class_specification(
    spec: ProjectSpec,
    entry: HandlerEntry,
    *,
    parameter_names: Sequence[str],
    property_fallback: bool = False,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    path = (spec.source_root / entry.file).resolve()
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    function = _function_at(tree, entry.line)
    class_node = _class_for(tree, function)
    module = _module(path, spec.source_root)
    class_scope = _class_scope(module, class_node)

    values: dict[str, Any] = {}
    name_node = _assignment_value(class_node, "name")
    description_node = _assignment_value(class_node, "description")
    parameters_node = next(
        (
            node
            for field in parameter_names
            if (node := _assignment_value(class_node, field)) is not None
        ),
        None,
    )
    if property_fallback:
        name_node = name_node or _method_return(class_node, "name")
        description_node = description_node or _method_return(class_node, "description")
        parameters_node = parameters_node or _method_return(class_node, "parameters")
    for field, node in (
        ("name", name_node),
        ("description", description_node),
        ("parameters", parameters_node),
    ):
        if node is None:
            raise SpecificationError(
                f"{entry.tool_name}: {class_node.name} has no static {field} declaration"
            )
        values[field] = _eval_metadata(
            module,
            node,
            getattr(node, "lineno", entry.line),
            class_scope,
        )
    if values["name"] != entry.tool_name:
        raise SpecificationError(
            f"{entry.tool_name}: class metadata name is {values['name']!r}"
        )
    evidence = [
        evidence_record(
            spec.source_root,
            entry.file,
            class_node.lineno,
            kind="python-class-tool-definition",
            detail=class_node.name,
        )
    ]
    consumed = [
        path.relative_to(spec.source_root).as_posix()
        for path in sorted(module.module_cache)
    ]
    return (
        _function(entry.tool_name, values["description"], values["parameters"]),
        evidence,
        consumed,
    )


def extract_hermes(
    spec: ProjectSpec,
    handlers: Sequence[HandlerEntry],
    reproduction_command: str,
    handler_csv: Path,
) -> dict[str, AdapterResult]:
    raw = hermes.build_inventory(
        spec.source_root,
        handler_csv,
        "registry-pinned",
        spec.analysis_revision,
        reproduction_command,
        expected_count=len(handlers),
    )
    results: dict[str, AdapterResult] = {}
    prefix = "benchmark/python/hermes-agent/"
    consumed = [
        file_name[len(prefix) :]
        if file_name.startswith(prefix)
        else file_name
        for file_name in raw.get("consumed_source_files", [])
    ]
    for item in raw["tools"]:
        registration_file = str(item["registration"]["file"])
        relative = (
            registration_file[len(prefix) :]
            if registration_file.startswith(prefix)
            else Path(registration_file).name
        )
        evidence = [
            evidence_record(
                spec.source_root,
                relative,
                int(item["registration"]["line"]),
                kind="registry-register-schema",
                detail=str(item["registration"]["schema_expression"]),
            )
        ]
        for rule in item["runtime_rules"]:
            source = rule.get("source") or {}
            file_name = str(source.get("file", ""))
            if file_name.startswith(prefix):
                evidence.append(
                    evidence_record(
                        spec.source_root,
                        file_name[len(prefix) :],
                        int(source.get("line", 1)),
                        kind="runtime-schema-rule",
                        detail=str(rule.get("rule_id", "")),
                    )
                )
        results[item["tool_name"]] = AdapterResult(
            tool_name=item["tool_name"],
            interface_kind="function-tool",
            function=item["function"],
            runtime_rules=item["runtime_rules"],
            evidence=evidence,
            consumed_files=consumed,
        )
    return results


def extract_cowagent(
    spec: ProjectSpec, handlers: Sequence[HandlerEntry]
) -> dict[str, AdapterResult]:
    results: dict[str, AdapterResult] = {}
    for entry in handlers:
        function, evidence, consumed = _class_specification(
            spec, entry, parameter_names=("params", "parameters")
        )
        rules: list[dict[str, Any]] = []
        if entry.tool_name == "bash":
            rules.append(
                {
                    "rule_id": "cowagent-bash-platform-description",
                    "condition": {"sys.platform": "win32"},
                    "source": {
                        "file": (
                            "benchmark/python/chatgpt-on-wechat/"
                            "agent/tools/bash/bash.py"
                        ),
                        "line": 21,
                    },
                    "effect": "append-windows-command-guidance",
                    "affected_fields": ["/description"],
                }
            )
        results[entry.tool_name] = AdapterResult(
            entry.tool_name,
            "function-tool",
            function,
            evidence,
            rules,
            consumed_files=consumed,
        )
    return results


def extract_astrbot(
    spec: ProjectSpec, handlers: Sequence[HandlerEntry]
) -> dict[str, AdapterResult]:
    results: dict[str, AdapterResult] = {}
    for entry in handlers:
        if entry.tool_name == "mcp-dynamic":
            results[entry.tool_name] = AdapterResult(
                entry.tool_name,
                "dynamic-mcp-boundary",
                None,
                [
                    evidence_record(
                        spec.source_root,
                        entry.file,
                        entry.line,
                        kind="runtime-mcp-tool-wrapper",
                        detail=(
                            "name, description, and inputSchema come from the "
                            "mcp.Tool supplied to MCPTool.__init__"
                        ),
                    )
                ],
                status="unresolved",
                reason_code="runtime-mcp-schema",
                reason=(
                    "The configured MCP service supplies the model-facing tool "
                    "definition at runtime."
                ),
            )
            continue
        function, evidence, consumed = _class_specification(
            spec, entry, parameter_names=("parameters",)
        )
        rules: list[dict[str, Any]] = []
        if entry.tool_name in {"astrbot_execute_ipython", "astrbot_execute_python"}:
            rules.append(
                {
                    "rule_id": "astrbot-python-platform-description",
                    "condition": {"platform.system": "non-Linux"},
                    "source": {
                        "file": (
                            "benchmark/python/AstrBot/astrbot/core/tools/"
                            "computer_tools/python.py"
                        ),
                        "line": 16,
                    },
                    "effect": "replace-Linux-with-runtime-platform-in-description",
                    "affected_fields": ["/description"],
                }
            )
        results[entry.tool_name] = AdapterResult(
            entry.tool_name,
            "function-tool",
            function,
            evidence,
            rules,
            consumed_files=consumed,
        )
    return results


def extract_nanobot(
    spec: ProjectSpec, handlers: Sequence[HandlerEntry]
) -> dict[str, AdapterResult]:
    results: dict[str, AdapterResult] = {}
    for entry in handlers:
        if entry.tool_name == "mcp-dynamic":
            results[entry.tool_name] = AdapterResult(
                entry.tool_name,
                "dynamic-mcp-boundary",
                None,
                [
                    evidence_record(
                        spec.source_root,
                        entry.file,
                        entry.line,
                        kind="runtime-mcp-tool-wrapper",
                        detail="name, description, and inputSchema come from session.list_tools()",
                    )
                ],
                status="unresolved",
                reason_code="runtime-mcp-schema",
                reason="The configured MCP server supplies the model-facing tool definition at runtime.",
            )
            continue
        function, evidence, consumed = _class_specification(
            spec,
            entry,
            parameter_names=("parameters",),
            property_fallback=True,
        )
        results[entry.tool_name] = AdapterResult(
            entry.tool_name,
            "function-tool",
            function,
            evidence,
            consumed_files=consumed,
        )
    return results


_TYPE_SCHEMAS: dict[str, dict[str, Any]] = {
    "str": {"type": "string"},
    "Path": {"type": "string"},
    "int": {"type": "integer"},
    "float": {"type": "number"},
    "bool": {"type": "boolean"},
    "dict": {"type": "object", "properties": {}},
    "Any": {},
}


def _annotation_schema(node: ast.expr | None) -> tuple[dict[str, Any], bool]:
    if node is None:
        return {}, False
    if isinstance(node, ast.Name):
        return copy.deepcopy(_TYPE_SCHEMAS.get(node.id, {})), False
    if isinstance(node, ast.Constant) and node.value is None:
        return {"type": "null"}, True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left, left_nullable = _annotation_schema(node.left)
        right, right_nullable = _annotation_schema(node.right)
        nullable = left_nullable or right_nullable or left.get("type") == "null" or right.get("type") == "null"
        non_null = [item for item in (left, right) if item.get("type") != "null"]
        if len(non_null) == 1:
            schema = non_null[0]
            if nullable:
                schema = {**schema, "nullable": True}
            return schema, nullable
        return {"anyOf": [left, right]}, nullable
    if isinstance(node, ast.Subscript):
        base = ast.unparse(node.value).split(".")[-1]
        if base in {"Optional"}:
            schema, _ = _annotation_schema(node.slice)
            return {**schema, "nullable": True}, True
        if base in {"list", "List", "Sequence", "Iterable", "set", "Set"}:
            item, _ = _annotation_schema(node.slice)
            return {"type": "array", "items": item}, False
        if base in {"dict", "Dict", "Mapping"}:
            parts = node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
            value, _ = _annotation_schema(parts[-1])
            return {"type": "object", "additionalProperties": value or True}, False
        if base == "Literal":
            values = node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
            literals = [value.value for value in values if isinstance(value, ast.Constant)]
            kind = "string" if all(isinstance(value, str) for value in literals) else "integer"
            return {"type": kind, "enum": literals}, False
        if base in {"tuple", "Tuple"}:
            values = node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
            items = [_annotation_schema(value)[0] for value in values]
            return {
                "type": "array",
                "prefixItems": items,
                "minItems": len(items),
                "maxItems": len(items),
            }, False
    return {}, False


def _doc_parts(doc: str) -> tuple[str, dict[str, str]]:
    lines = doc.splitlines()
    summary_lines: list[str] = []
    parameters: dict[str, str] = {}
    in_args = False
    current: str | None = None
    for line in lines:
        stripped = line.strip()
        if stripped in {"Args:", "Arguments:", "Parameters:"}:
            in_args = True
            current = None
            continue
        if in_args and re.match(r"^(Returns?|Raises?|Examples?):$", stripped):
            in_args = False
            current = None
            continue
        if not in_args:
            if stripped:
                summary_lines.append(stripped)
            continue
        match = re.match(r"^([A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*:\s*(.*)$", stripped)
        if match:
            current = match.group(1)
            parameters[current] = match.group(2).strip()
        elif current and stripped:
            parameters[current] = (parameters[current] + " " + stripped).strip()
    return "\n".join(summary_lines).strip() or doc.strip(), parameters


def _literal_default(module: hermes.StaticModule, node: ast.expr) -> Any:
    value = module.eval_expr(node, getattr(node, "lineno", 1))
    if isinstance(value, Path):
        return str(value)
    return value


def _function_signature_spec(
    tool_name: str,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    module: hermes.StaticModule,
) -> dict[str, Any]:
    doc = ast.get_docstring(function, clean=True) or ""
    if not doc:
        raise SpecificationError(f"{tool_name}: handler has no docstring")
    description, parameter_docs = _doc_parts(doc)
    positional = [*function.args.posonlyargs, *function.args.args]
    defaults: list[ast.expr | None] = [None] * (
        len(positional) - len(function.args.defaults)
    ) + list(function.args.defaults)
    properties: dict[str, Any] = {}
    required: list[str] = []
    for argument, default in zip(positional, defaults):
        if argument.arg in {"self", "cls"}:
            continue
        schema, _ = _annotation_schema(argument.annotation)
        schema = copy.deepcopy(schema)
        if parameter_docs.get(argument.arg):
            schema["description"] = parameter_docs[argument.arg]
        if default is None:
            required.append(argument.arg)
        else:
            value = _literal_default(module, default)
            if value is not None:
                schema["default"] = value
        properties[argument.arg] = schema
    for argument, default in zip(function.args.kwonlyargs, function.args.kw_defaults):
        schema, _ = _annotation_schema(argument.annotation)
        schema = copy.deepcopy(schema)
        if parameter_docs.get(argument.arg):
            schema["description"] = parameter_docs[argument.arg]
        if default is None:
            required.append(argument.arg)
        else:
            value = _literal_default(module, default)
            if value is not None:
                schema["default"] = value
        properties[argument.arg] = schema
    parameters: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        parameters["required"] = required
    return _function(tool_name, description, parameters)


def extract_qwenpaw(
    spec: ProjectSpec, handlers: Sequence[HandlerEntry]
) -> dict[str, AdapterResult]:
    grouped = group_handlers(handlers)
    results: dict[str, AdapterResult] = {}
    for tool_name, entries in grouped.items():
        variants: list[
            tuple[HandlerEntry, dict[str, Any], dict[str, Any], list[str]]
        ] = []
        for entry in entries:
            path = spec.source_root / entry.file
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            function_node = _function_at(tree, entry.line)
            module = _module(path, spec.source_root)
            function = _function_signature_spec(tool_name, function_node, module)
            evidence = evidence_record(
                spec.source_root,
                entry.file,
                entry.line,
                kind="signature-docstring-tool-definition",
                detail=function_node.name,
            )
            consumed = [
                used.relative_to(spec.source_root).as_posix()
                for used in sorted(module.module_cache)
            ]
            variants.append((entry, function, evidence, consumed))
        canonical = variants[0]
        rules: list[dict[str, Any]] = []
        if tool_name == "memory_search" and len(variants) == 2:
            canonical = next(
                item for item in variants if "reme_light_memory_manager.py" in item[0].file
            )
            alternative = next(item for item in variants if item is not canonical)
            rules.append(
                {
                    "rule_id": "qwenpaw-memory-backend-description",
                    "condition": {"memory_manager_backend": "adbpg"},
                    "source": {
                        "file": "benchmark/python/QwenPaw/src/qwenpaw/config/config.py",
                        "line": 1001,
                    },
                    "effect": "replace-function-description",
                    "affected_fields": ["/description"],
                    "value": alternative[1]["description"],
                }
            )
        elif any(item[1] != canonical[1] for item in variants[1:]):
            raise SpecificationError(f"{tool_name}: multiple handlers expose conflicting schemas")
        results[tool_name] = AdapterResult(
            tool_name,
            "function-tool",
            canonical[1],
            [item[2] for item in variants],
            rules,
            consumed_files=sorted(
                {file_name for item in variants for file_name in item[3]}
            ),
        )
    return results


def _type_value_to_schema(value: Any) -> Any:
    if value is str:
        return {"type": "string"}
    if value is int:
        return {"type": "integer"}
    if value is float:
        return {"type": "number"}
    if value is bool:
        return {"type": "boolean"}
    if value is list:
        return {"type": "array", "items": {}}
    if value is dict:
        return {"type": "object", "additionalProperties": True}
    if isinstance(value, dict):
        if "type" in value:
            return {key: _type_value_to_schema(item) for key, item in value.items()}
        return {
            "type": "object",
            "properties": {key: _type_value_to_schema(item) for key, item in value.items()},
        }
    if isinstance(value, list):
        return [_type_value_to_schema(item) for item in value]
    return value


def extract_poco(
    spec: ProjectSpec, handlers: Sequence[HandlerEntry]
) -> dict[str, AdapterResult]:
    results: dict[str, AdapterResult] = {}
    for entry in handlers:
        path = spec.source_root / entry.file
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        function_node = _function_at(tree, entry.line)
        decorators = [
            node
            for node in function_node.decorator_list
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "tool"
        ]
        if len(decorators) != 1 or len(decorators[0].args) < 3:
            raise SpecificationError(f"{entry.tool_name}: expected one @tool(name, description, schema)")
        module = _module(path, spec.source_root)
        decorator = decorators[0]
        name = module.eval_expr(decorator.args[0], decorator.lineno)
        description = module.eval_expr(decorator.args[1], decorator.lineno)
        parameters = _type_value_to_schema(
            module.eval_expr(decorator.args[2], decorator.lineno)
        )
        if name != entry.tool_name:
            raise SpecificationError(f"{entry.tool_name}: decorator name is {name!r}")
        results[entry.tool_name] = AdapterResult(
            entry.tool_name,
            "function-tool",
            _function(entry.tool_name, description, parameters),
            [
                evidence_record(
                    spec.source_root,
                    entry.file,
                    decorator.lineno,
                    kind="decorated-tool-definition",
                    detail="@tool(name, description, schema)",
                )
            ],
            consumed_files=[
                used.relative_to(spec.source_root).as_posix()
                for used in sorted(module.module_cache)
            ],
        )
    return results


def extract_python_project(
    spec: ProjectSpec,
    handlers: Sequence[HandlerEntry],
    reproduction_command: str,
    handler_csv: Path | None = None,
) -> dict[str, AdapterResult]:
    if spec.project_id == "hermes-agent":
        return extract_hermes(
            spec,
            handlers,
            reproduction_command,
            handler_csv
            or spec.design_root / "handler-entry/debug/tool-handler-entries.csv",
        )
    if spec.project_id == "chatgpt-on-wechat":
        return extract_cowagent(spec, handlers)
    if spec.project_id == "AstrBot":
        return extract_astrbot(spec, handlers)
    if spec.project_id == "QwenPaw":
        return extract_qwenpaw(spec, handlers)
    if spec.project_id == "nanobot":
        return extract_nanobot(spec, handlers)
    if spec.project_id == "poco-agent":
        return extract_poco(spec, handlers)
    raise SpecificationError(f"no Python handler-specification adapter for {spec.project_id}")
