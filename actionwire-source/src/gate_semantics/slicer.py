"""Build deterministic, callsite-bound Python source slices for gate analysis."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

from .candidates import CandidateSeed
from .compound_profiles import CompoundGateProfile, find_compound_profile


SCHEMA_VERSION = "gate-slice/v1"
SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__", "site-packages"}
BUILTIN_NAMES = {
    "all",
    "any",
    "bool",
    "bytes",
    "dict",
    "enumerate",
    "filter",
    "float",
    "getattr",
    "hasattr",
    "int",
    "isinstance",
    "issubclass",
    "len",
    "list",
    "map",
    "max",
    "min",
    "next",
    "open",
    "print",
    "range",
    "repr",
    "reversed",
    "set",
    "sorted",
    "str",
    "sum",
    "tuple",
    "type",
    "zip",
}
RECEIVER_CHECK_METHODS = {
    "endswith",
    "exists",
    "is_absolute",
    "is_dir",
    "is_file",
    "is_relative_to",
    "startswith",
}
ARG_CHECK_METHODS = {"fullmatch", "match", "search"}
LOCAL_DERIVATION_MAX_CHUNKS = 16
LOCAL_DERIVATION_MAX_SYMBOLS = 24
CONTENT_DIGEST_IGNORED_KEYS = {
    "end_column",
    "end_line",
    "gate_id",
    "gate_uid",
    "line_end",
    "line_start",
    "output_value_id",
    "revision",
    "source_root",
    "start_column",
    "start_line",
    "value_id",
}


def _digest(value: str, length: int = 16) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


def _normalized_ast(node: ast.AST) -> str:
    """Return a location-independent structural identity for one Python node."""

    return ast.dump(node, annotate_fields=True, include_attributes=False)


def _content_digest_value(value: object) -> object:
    """Remove revision, generated IDs, and source coordinates from slice content."""

    if isinstance(value, dict):
        return {
            key: _content_digest_value(item)
            for key, item in sorted(value.items())
            if key not in CONTENT_DIGEST_IGNORED_KEYS
            and key not in {"detector_role", "static_verdict"}
        }
    if isinstance(value, list):
        return [_content_digest_value(item) for item in value]
    return value


def content_digest_from_payload(payload: dict[str, object]) -> str:
    """Hash semantic slice content without revision, ordinal, IDs, or coordinates."""

    material = {
        key: value
        for key, value in payload.items()
        if key
        not in {
            "chain_refs",
            "content_digest",
            "gate_number",
            "schema_version",
            "source_digest",
        }
    }
    normalized = _content_digest_value(material)
    serialized = json.dumps(
        normalized, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _node_span(node: ast.AST, rel: str) -> dict[str, object]:
    return {
        "file": rel,
        "start_line": int(getattr(node, "lineno", 0) or 0),
        "start_column": int(getattr(node, "col_offset", 0) or 0) + 1,
        "end_line": int(getattr(node, "end_lineno", 0) or 0),
        "end_column": int(getattr(node, "end_col_offset", 0) or 0) + 1,
    }


def _call_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ""


def _iter_names(node: ast.AST) -> set[str]:
    return {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}


def _iter_calls(node: ast.AST) -> list[ast.Call]:
    return sorted(
        (item for item in ast.walk(node) if isinstance(item, ast.Call)),
        key=lambda item: (
            int(getattr(item, "lineno", 0)),
            int(getattr(item, "col_offset", 0)),
            _call_name(item),
        ),
    )


def _ordered_load_names(node: ast.AST) -> list[ast.Name]:
    """Return distinct loaded names in source order for a composite expression."""
    result: list[ast.Name] = []
    seen: set[str] = set()
    for item in sorted(
        (
            child
            for child in ast.walk(node)
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)
        ),
        key=lambda child: (
            int(getattr(child, "lineno", 0)),
            int(getattr(child, "col_offset", 0)),
        ),
    ):
        if item.id not in seen:
            result.append(item)
            seen.add(item.id)
    return result


def _assigned_names(node: ast.AST) -> list[str]:
    """Return distinct assignment-target names in source order."""
    result: list[str] = []
    seen: set[str] = set()
    for item in sorted(
        (
            child
            for child in ast.walk(node)
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)
        ),
        key=lambda child: (
            int(getattr(child, "lineno", 0)),
            int(getattr(child, "col_offset", 0)),
        ),
    ):
        if item.id not in seen:
            result.append(item.id)
            seen.add(item.id)
    return result


def _statement_effect(statements: list[ast.stmt], parsed: "ParsedPython") -> str:
    effects: list[str] = []
    for statement in statements[:3]:
        if isinstance(statement, ast.Return):
            value = parsed.segment(statement.value) if statement.value else "None"
            effects.append(f"return {value}")
        elif isinstance(statement, ast.Raise):
            effects.append("raise")
        elif isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            effects.append(parsed.segment(statement).strip())
        elif isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
            effects.append(parsed.segment(statement.value).strip())
        elif isinstance(statement, ast.If):
            effects.append(
                f"evaluate nested condition {parsed.segment(statement.test).strip()}"
            )
        else:
            effects.append(type(statement).__name__)
    return "; ".join(filter(None, effects)) or "continue"


@dataclass
class SourceChunk:
    role: str
    symbol: str
    file: str
    line_start: int
    line_end: int
    sha256: str
    source: str


@dataclass
class GateSlice:
    gate_id: str
    gate_uid: str
    project: dict[str, str]
    gate: dict[str, object]
    callsite: dict[str, object]
    checked_value: dict[str, object]
    dataflow: dict[str, object]
    source_bundle: list[SourceChunk]
    unresolved_symbols: list[str]
    compound_profile: dict[str, object] | None = None
    chain_refs: list[dict[str, object]] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION

    @property
    def input_value_id(self) -> str:
        return str(self.checked_value["value_id"])

    @property
    def output_value_id(self) -> str:
        return str(self.gate["output_value_id"])

    @property
    def source_digest(self) -> str:
        material = "\n".join(
            f"{chunk.file}:{chunk.line_start}:{chunk.line_end}:{chunk.sha256}"
            for chunk in self.source_bundle
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    @property
    def content_digest(self) -> str:
        """Digest the gate semantics input while ignoring revision and locations."""

        return content_digest_from_payload(self.prompt_payload())

    def prompt_payload(self) -> dict[str, object]:
        """Return the LLM-facing payload; sink/chain details stay audit-only."""
        result = {
            "schema_version": self.schema_version,
            "gate_id": self.gate_id,
            "gate_uid": self.gate_uid,
            "project": self.project,
            "gate": self.gate,
            "callsite": self.callsite,
            "checked_value": self.checked_value,
            "dataflow": self.dataflow,
            "source_bundle": [asdict(chunk) for chunk in self.source_bundle],
            "unresolved_symbols": self.unresolved_symbols,
        }
        if self.compound_profile is not None:
            result["compound_profile"] = self.compound_profile
        return result

    def audit_payload(self) -> dict[str, object]:
        result = self.prompt_payload()
        result["chain_refs"] = self.chain_refs
        result["source_digest"] = self.source_digest
        result["content_digest"] = self.content_digest
        return result


class ParsedPython:
    def __init__(self, root: Path, path: Path):
        self.path = path
        self.rel = path.relative_to(root).as_posix()
        self.source = path.read_text(encoding="utf-8")
        self.lines = self.source.splitlines()
        self.tree = ast.parse(self.source, filename=self.rel)
        self.parents: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(self.tree):
            for child in ast.iter_child_nodes(parent):
                self.parents[child] = parent

        self.functions = [
            node
            for node in ast.walk(self.tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        self.assignments: dict[str, ast.stmt] = {}
        self.imports: dict[str, ast.Import | ast.ImportFrom] = {}
        for node in self.tree.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets: list[ast.expr]
                if isinstance(node, ast.Assign):
                    targets = list(node.targets)
                else:
                    targets = [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        self.assignments[target.id] = node
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    self.imports[alias.asname or alias.name] = node
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    self.imports[alias.asname or alias.name.split(".")[0]] = node

    def segment(self, node: ast.AST | None) -> str:
        if node is None:
            return ""
        value = ast.get_source_segment(self.source, node)
        if value is not None:
            return value
        start = int(getattr(node, "lineno", 1)) - 1
        end = int(getattr(node, "end_lineno", start + 1))
        return "\n".join(self.lines[start:end])

    def line_window(self, line: int, before: int = 5, after: int = 12) -> str:
        start = max(1, line - before)
        end = min(len(self.lines), line + after)
        return "\n".join(
            f"{number:>6}: {self.lines[number - 1]}" for number in range(start, end + 1)
        )

    def enclosing(
        self, node: ast.AST, kinds: tuple[type[ast.AST], ...]
    ) -> ast.AST | None:
        current: ast.AST | None = node
        while current is not None:
            if isinstance(current, kinds):
                return current
            current = self.parents.get(current)
        return None

    def function_at(self, line: int, exact_start: bool = False) -> ast.AST | None:
        matches = []
        for function in self.functions:
            start = int(getattr(function, "lineno", 0))
            end = int(getattr(function, "end_lineno", start))
            if (exact_start and start == line) or (
                not exact_start and start <= line <= end
            ):
                matches.append(function)
        if not matches:
            return None
        return min(
            matches, key=lambda item: int(getattr(item, "end_lineno", 0)) - item.lineno
        )


class PythonSourceIndex:
    def __init__(self, source_root: Path):
        self.root = source_root.resolve()
        self.files: dict[str, ParsedPython] = {}
        self.functions_by_name: dict[str, list[tuple[ParsedPython, ast.AST]]] = {}
        self.parse_errors: dict[str, str] = {}
        self._build()

    def _build(self) -> None:
        for directory, dirnames, filenames in os.walk(self.root, followlinks=False):
            dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
            for filename in filenames:
                if not filename.endswith(".py"):
                    continue
                path = Path(directory) / filename
                rel = path.relative_to(self.root).as_posix()
                try:
                    parsed = ParsedPython(self.root, path)
                except (OSError, SyntaxError, UnicodeDecodeError) as exc:
                    self.parse_errors[rel] = str(exc)
                    continue
                self.files[rel] = parsed
                for function in parsed.functions:
                    self.functions_by_name.setdefault(function.name, []).append(
                        (parsed, function)
                    )

    def get(self, rel: str) -> ParsedPython | None:
        normalized = rel.replace("\\", "/").lstrip("./")
        return self.files.get(normalized)

    def resolve_function(
        self,
        name: str,
        *,
        caller: ParsedPython | None = None,
        definition_file: str = "",
        definition_line: int = 0,
    ) -> tuple[ParsedPython, ast.AST] | None:
        if definition_file:
            parsed = self.get(definition_file)
            if parsed:
                if definition_line:
                    function = parsed.function_at(definition_line, exact_start=True)
                    if function and function.name == name:
                        return parsed, function
                same_name = [
                    function for function in parsed.functions if function.name == name
                ]
                if len(same_name) == 1:
                    return parsed, same_name[0]

        if caller:
            same_file = [
                function
                for function in caller.functions
                if getattr(function, "name", "") == name
            ]
            if len(same_file) == 1:
                return caller, same_file[0]
            imported = caller.imports.get(name)
            if isinstance(imported, ast.ImportFrom) and imported.module:
                module_path = imported.module.replace(".", "/") + ".py"
                parsed = self.get(module_path)
                if parsed:
                    imported_name = next(
                        (
                            alias.name
                            for alias in imported.names
                            if (alias.asname or alias.name) == name
                        ),
                        name,
                    )
                    matches = [
                        function
                        for function in parsed.functions
                        if function.name == imported_name
                    ]
                    if len(matches) == 1:
                        return parsed, matches[0]

        matches = self.functions_by_name.get(name, [])
        return matches[0] if len(matches) == 1 else None


class PythonGateSlicer:
    """Turn detector rows into deterministic, sink-free GateSlice records."""

    def __init__(
        self,
        source_root: Path,
        *,
        project_name: str = "hermes-agent",
        revision: str | None = None,
        max_dependency_depth: int = 2,
        max_source_chars: int = 100_000,
    ):
        self.source_root = source_root.resolve()
        self.index = PythonSourceIndex(self.source_root)
        self.project_name = project_name
        self.revision = revision or self._revision()
        self.max_dependency_depth = max_dependency_depth
        self.max_source_chars = max_source_chars

    def _revision(self) -> str:
        for cwd in (self.source_root, Path.cwd()):
            try:
                result = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=cwd,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            except (OSError, subprocess.SubprocessError):
                continue
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        return "unknown-revision"

    def _find_gate_node(
        self, parsed: ParsedPython, seed: CandidateSeed
    ) -> ast.AST | None:
        calls = [
            node
            for node in ast.walk(parsed.tree)
            if isinstance(node, ast.Call)
            and int(getattr(node, "lineno", 0)) == seed.call_line
            and _call_name(node) == seed.gate_name
        ]
        if seed.call_column:
            exact = [
                node
                for node in calls
                if int(getattr(node, "col_offset", 0)) + 1 == seed.call_column
            ]
            if exact:
                calls = exact
        if calls:
            return min(calls, key=lambda node: int(getattr(node, "col_offset", 0)))

        expressions = [
            node
            for node in ast.walk(parsed.tree)
            if isinstance(node, (ast.Compare, ast.BoolOp, ast.UnaryOp, ast.Name))
            and int(getattr(node, "lineno", 0)) == seed.call_line
        ]
        return min(
            expressions,
            key=lambda node: (
                int(getattr(node, "end_lineno", seed.call_line)) - seed.call_line,
                int(getattr(node, "col_offset", 0)),
            ),
            default=None,
        )

    def _checked_node(
        self, parsed: ParsedPython, gate_node: ast.AST, seed: CandidateSeed
    ) -> ast.AST:
        candidates: list[ast.AST] = []
        if isinstance(gate_node, ast.Call):
            candidates.extend(gate_node.args)
            candidates.extend(keyword.value for keyword in gate_node.keywords)
            if isinstance(gate_node.func, ast.Attribute):
                candidates.append(gate_node.func.value)
        elif isinstance(gate_node, ast.Compare):
            candidates.extend([gate_node.left, *gate_node.comparators])

        # Enriched detector rows identify the exact tainted expression. Prefer
        # that witness over call-shape heuristics, especially for APIs whose
        # checked value is not the first argument (for example re.fullmatch).
        if seed.checked_line or seed.checked_column:
            location_matches = [
                candidate
                for candidate in candidates
                if (
                    not seed.checked_line
                    or int(getattr(candidate, "lineno", 0)) == seed.checked_line
                )
                and (
                    not seed.checked_column
                    or int(getattr(candidate, "col_offset", 0)) + 1
                    == seed.checked_column
                )
            ]
            if len(location_matches) == 1:
                return location_matches[0]
        if seed.checked_hint:
            expression_matches = [
                candidate
                for candidate in candidates
                if parsed.segment(candidate).strip() == seed.checked_hint.strip()
            ]
            if len(expression_matches) == 1:
                return expression_matches[0]

        if not isinstance(gate_node, ast.Call):
            if isinstance(gate_node, ast.Compare):
                return gate_node.left
            return gate_node
        name = _call_name(gate_node)
        if isinstance(gate_node.func, ast.Attribute):
            if name in RECEIVER_CHECK_METHODS:
                return gate_node.func.value
            if name in ARG_CHECK_METHODS and gate_node.args:
                return gate_node.args[0]
            if not gate_node.args:
                return gate_node.func.value
        if gate_node.args:
            return gate_node.args[0]
        return gate_node

    @staticmethod
    def _contains(parsed: ParsedPython, owner: ast.AST, node: ast.AST) -> bool:
        current: ast.AST | None = node
        while current is not None:
            if current is owner:
                return True
            current = parsed.parents.get(current)
        return False

    @staticmethod
    def _owner_region(
        parsed: ParsedPython, owner: ast.AST, node: ast.AST
    ) -> str | None:
        """Return the direct AST field of ``owner`` containing ``node``."""
        current: ast.AST | None = node
        while current is not None and parsed.parents.get(current) is not owner:
            current = parsed.parents.get(current)
        if current is None:
            return None
        for field_name, value in ast.iter_fields(owner):
            if value is current:
                return field_name
            if isinstance(value, list) and current in value:
                return field_name
        return None

    def _derivation_control_owner(
        self,
        parsed: ParsedPython,
        assignment: ast.AST,
        gate_node: ast.AST,
        enclosing: ast.AST,
    ) -> tuple[bool, ast.AST | None]:
        """Find a preceding control statement that conditionally defines a value.

        The boolean reports whether the assignment can reach the selected gate.
        An assignment in a mutually exclusive sibling branch cannot. When the
        gate follows a conditional definition, returning the outermost control
        owner retains all conditions governing that definition.
        """

        controls = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.Match)
        current: ast.AST | None = assignment
        conditional_owner: ast.AST | None = None
        while current is not None and current is not enclosing:
            parent = parsed.parents.get(current)
            if isinstance(parent, controls):
                if self._contains(parsed, parent, gate_node):
                    assignment_region = self._owner_region(parsed, parent, assignment)
                    gate_region = self._owner_region(parsed, parent, gate_node)
                    if assignment_region != gate_region:
                        return False, None
                else:
                    conditional_owner = parent
            current = parent
        return True, conditional_owner

    def _local_derivations(
        self, parsed: ParsedPython, gate_node: ast.AST, checked_names: list[str]
    ) -> tuple[list[tuple[str, ast.AST]], list[str]]:
        """Recover a bounded, branch-aware current-function derivation closure.

        This applies equally to inline gates, call arguments, and method
        receivers. Conditional reassignments retain their controlling statement
        and continue backward to the prior reaching definition.
        """
        enclosing = parsed.enclosing(
            gate_node, (ast.FunctionDef, ast.AsyncFunctionDef)
        )
        if enclosing is None:
            return [], []
        gate_line = int(getattr(gate_node, "lineno", 0))
        assignments: dict[str, list[ast.Assign | ast.AnnAssign | ast.NamedExpr]] = {}
        for node in ast.walk(enclosing):
            if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                continue
            if parsed.enclosing(
                node, (ast.FunctionDef, ast.AsyncFunctionDef)
            ) is not enclosing:
                continue
            if int(getattr(node, "lineno", 0)) >= gate_line:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                for name in _assigned_names(target):
                    assignments.setdefault(name, []).append(node)

        for candidates in assignments.values():
            candidates.sort(
                key=lambda node: (
                    int(getattr(node, "lineno", 0)),
                    int(getattr(node, "col_offset", 0)),
                )
            )

        pending = [(name, gate_line) for name in checked_names if name in assignments]
        selected: dict[tuple[int, int], tuple[str, ast.AST]] = {}
        visited: set[tuple[str, int]] = set()
        visited_symbols: set[str] = set()
        unresolved: set[str] = set()
        while pending:
            name, before_line = pending.pop(0)
            query = (name, before_line)
            if query in visited:
                continue
            visited.add(query)
            visited_symbols.add(name)
            if len(visited_symbols) > LOCAL_DERIVATION_MAX_SYMBOLS:
                unresolved.add(f"local-derivation-symbol-budget:{name}")
                continue
            candidates = [
                node
                for node in assignments.get(name, [])
                if int(getattr(node, "lineno", 0)) < before_line
            ]
            if not candidates:
                continue
            assignment = candidates[-1]
            can_reach, control_owner = self._derivation_control_owner(
                parsed, assignment, gate_node, enclosing
            )
            if not can_reach:
                pending.append(
                    (name, int(getattr(assignment, "lineno", before_line)))
                )
                continue

            source_node = control_owner or assignment
            key = (
                int(getattr(source_node, "lineno", 0)),
                int(getattr(source_node, "col_offset", 0)),
            )
            selected[key] = (name, source_node)
            if len(selected) > LOCAL_DERIVATION_MAX_CHUNKS:
                selected.pop(key, None)
                unresolved.add(f"local-derivation-chunk-budget:{name}")
                continue

            value = getattr(assignment, "value", None)
            dependency_nodes = [value] if isinstance(value, ast.AST) else []
            if isinstance(control_owner, (ast.If, ast.For, ast.AsyncFor, ast.While)):
                dependency_nodes.append(
                    control_owner.test
                    if isinstance(control_owner, (ast.If, ast.While))
                    else control_owner.iter
                )
            elif isinstance(control_owner, ast.Match):
                dependency_nodes.append(control_owner.subject)

            dependency_before = int(getattr(source_node, "lineno", before_line))
            dependencies: list[str] = []
            for dependency_node in dependency_nodes:
                dependencies.extend(
                    item.id for item in _ordered_load_names(dependency_node)
                )
            for dependency in dict.fromkeys(dependencies):
                if dependency in assignments:
                    pending.append((dependency, dependency_before))

            # A conditional reassignment may not execute. Continue before the
            # control statement to retain the value reaching its false path.
            if control_owner is not None:
                pending.append((name, dependency_before))

        return [selected[key] for key in sorted(selected)], sorted(unresolved)

    def _condition_context(
        self, parsed: ParsedPython, gate_node: ast.AST, seed: CandidateSeed
    ) -> tuple[str, str, dict[str, str], ast.AST]:
        current: ast.AST | None = gate_node
        condition_owner: ast.If | ast.While | ast.Assert | None = None
        while current is not None:
            parent = parsed.parents.get(current)
            if isinstance(parent, (ast.If, ast.While, ast.Assert)):
                test = parent.test
                if current is test or current in ast.walk(test):
                    condition_owner = parent
                    break
            current = parent

        # (B2) shape: result = gate(value); if result: return/raise. The CodeQL
        # candidate is the assignment call, so recover the immediately-following
        # result test to expose the gate's real polarity to the LLM.
        if condition_owner is None:
            assignment = parsed.enclosing(
                gate_node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)
            )
            assignment_value = getattr(assignment, "value", None)
            if isinstance(assignment_value, ast.Await):
                assignment_value = assignment_value.value
            assigned_names: set[str] = set()
            # Only recover B2 when the gate result itself is assigned. A gate
            # nested in an outer call/f-string does not decide a later branch
            # on the outer assignment result.
            if assignment_value is not gate_node:
                assignment = None
            if isinstance(assignment, ast.Assign):
                for target in assignment.targets:
                    assigned_names.update(_iter_names(target))
            elif isinstance(assignment, (ast.AnnAssign, ast.NamedExpr)):
                assigned_names.update(_iter_names(assignment.target))
            enclosing_function = parsed.enclosing(
                gate_node, (ast.FunctionDef, ast.AsyncFunctionDef)
            )
            if assigned_names and enclosing_function is not None:
                following = [
                    node
                    for node in ast.walk(enclosing_function)
                    if isinstance(node, ast.If)
                    and node.lineno
                    >= int(getattr(assignment, "lineno", seed.call_line))
                    and node.lineno
                    <= int(getattr(assignment, "end_lineno", seed.call_line)) + 12
                    and assigned_names.intersection(_iter_names(node.test))
                ]
                if following:
                    condition_owner = min(following, key=lambda node: node.lineno)

        if condition_owner is None:
            condition = seed.condition_hint
            statement = parsed.enclosing(gate_node, (ast.stmt,))
            if isinstance(
                statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                statement = None
            context_node = statement or gate_node
            return (
                condition,
                parsed.segment(context_node),
                {"condition_true": "unknown", "condition_false": "unknown"},
                context_node,
            )

        condition = parsed.segment(condition_owner.test).strip() or seed.condition_hint
        source = parsed.segment(condition_owner)
        if source.count("\n") > 80:
            # Keep source text and its evidence span aligned. Branch effects
            # below retain the outcome summary when the full branch is huge.
            source = parsed.segment(condition_owner.test)
            context_node = condition_owner.test
        else:
            context_node = condition_owner
        effects = {"condition_true": "continue", "condition_false": "continue"}
        if isinstance(condition_owner, ast.If):
            effects = {
                "condition_true": _statement_effect(condition_owner.body, parsed),
                "condition_false": _statement_effect(condition_owner.orelse, parsed),
            }
        elif isinstance(condition_owner, ast.Assert):
            effects = {
                "condition_true": "continue",
                "condition_false": "raise AssertionError",
            }
        return condition, source, effects, context_node

    @staticmethod
    def _lexical_activation(
        parsed: ParsedPython, gate_node: ast.AST
    ) -> list[dict[str, str]]:
        """Collect enclosing branch conditions that decide whether the call executes."""

        activation: list[dict[str, str]] = []
        current: ast.AST | None = gate_node
        while current is not None:
            parent = parsed.parents.get(current)
            if isinstance(parent, ast.If):
                if current in parent.body:
                    activation.append(
                        {
                            "condition": parsed.segment(parent.test).strip(),
                            "required_branch": "true",
                        }
                    )
                elif current in parent.orelse:
                    activation.append(
                        {
                            "condition": parsed.segment(parent.test).strip(),
                            "required_branch": "false",
                        }
                    )
            current = parent
        activation.reverse()
        return activation

    def _resolve_definition(
        self, parsed: ParsedPython, seed: CandidateSeed
    ) -> tuple[ParsedPython, ast.AST] | None:
        return self.index.resolve_function(
            seed.gate_name,
            caller=parsed,
            definition_file=seed.definition_file,
            definition_line=seed.definition_line,
        )

    def _resolve_called_helper(
        self, parsed: ParsedPython, call: ast.Call
    ) -> tuple[ParsedPython, ast.AST] | None:
        name = _call_name(call)
        if not name:
            return None
        if isinstance(call.func, ast.Name):
            return self.index.resolve_function(name, caller=parsed)
        if (
            isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id in {"self", "cls"}
        ):
            matches = [
                function
                for function in parsed.functions
                if getattr(function, "name", "") == name
            ]
            if len(matches) == 1:
                return parsed, matches[0]
        # Never resolve an arbitrary receiver method by a global function name:
        # `value.replace(...)` is unrelated to a project `def replace(...)`.
        return None

    def _binding(
        self,
        parsed: ParsedPython,
        gate_node: ast.AST,
        checked_node: ast.AST,
        definition: tuple[ParsedPython, ast.AST] | None,
        checked_expr: str,
    ) -> tuple[str, str]:
        if not isinstance(gate_node, ast.Call) or definition is None:
            return (
                f"{checked_expr} -> {self._display_callee(seed_name=None, gate_node=gate_node)} input",
                "heuristic",
            )

        _, function = definition
        args = list(function.args.posonlyargs) + list(function.args.args)
        if (
            isinstance(gate_node.func, ast.Attribute)
            and args
            and args[0].arg in {"self", "cls"}
        ):
            args = args[1:]
        actuals = list(gate_node.args)
        for index, actual in enumerate(actuals):
            if actual is checked_node and index < len(args):
                return (
                    f"{checked_expr} -> {function.name}.{args[index].arg}",
                    "resolved",
                )
        for keyword in gate_node.keywords:
            if keyword.value is checked_node and keyword.arg:
                return f"{checked_expr} -> {function.name}.{keyword.arg}", "resolved"
        if (
            isinstance(gate_node.func, ast.Attribute)
            and gate_node.func.value is checked_node
        ):
            receiver = (
                args[0].arg if args and args[0].arg in {"self", "cls"} else "receiver"
            )
            return f"{checked_expr} -> {function.name}.{receiver}", "resolved"
        return f"{checked_expr} -> {function.name} input", "heuristic"

    @staticmethod
    def _display_callee(seed_name: str | None, gate_node: ast.AST) -> str:
        if seed_name:
            return seed_name
        if isinstance(gate_node, ast.Call):
            return _call_name(gate_node) or "gate"
        return "inline gate"

    def _output_description(
        self, parsed: ParsedPython, gate_node: ast.AST, mode: str, gate_id: str
    ) -> tuple[str, str]:
        if mode == "predicate":
            value_id = "D" + _digest(gate_id + ":decision", 12)
            return value_id, "boolean branch decision; input remains unchanged"
        if mode == "filter":
            owner = parsed.enclosing(gate_node, (ast.If,))
            collection = "filtered collection"
            if isinstance(owner, ast.If):
                for call in ast.walk(owner):
                    if (
                        isinstance(call, ast.Call)
                        and isinstance(call.func, ast.Attribute)
                        and call.func.attr in {"append", "add", "extend", "update"}
                    ):
                        collection = (
                            parsed.segment(call.func.value).strip() or collection
                        )
                        break
            value_id = "V" + _digest(gate_id + ":filtered", 12)
            return value_id, f"admitted {collection}"
        if mode == "transform":
            parent = parsed.parents.get(gate_node)
            output = "transformed value"
            if isinstance(parent, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                target = (
                    parent.targets[0]
                    if isinstance(parent, ast.Assign)
                    else parent.target
                )
                output = parsed.segment(target).strip() or output
            value_id = "V" + _digest(gate_id + ":transformed", 12)
            return value_id, output
        value_id = "C" + _digest(gate_id + ":constraint", 12)
        return value_id, "constrained capability"

    def _chunk(
        self,
        role: str,
        symbol: str,
        parsed: ParsedPython,
        node: ast.AST,
        source: str | None = None,
    ) -> SourceChunk:
        text = source if source is not None else parsed.segment(node)
        span = _node_span(node, parsed.rel)
        return SourceChunk(
            role=role,
            symbol=symbol,
            file=parsed.rel,
            line_start=int(span["start_line"]),
            line_end=int(span["end_line"]),
            sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            source=text,
        )

    @staticmethod
    def _top_level_symbol(parsed: ParsedPython, symbol: str) -> ast.AST | None:
        """Resolve an exact module-level function, class, or assignment."""

        for node in parsed.tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name == symbol:
                    return node
                continue
            if isinstance(node, ast.Assign):
                if any(
                    isinstance(target, ast.Name) and target.id == symbol
                    for target in node.targets
                ):
                    return node
                continue
            if (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.target.id == symbol
            ):
                return node
        return None

    @staticmethod
    def _compound_callsite_guard(
        parsed: ParsedPython, gate_node: ast.AST
    ) -> ast.If | None:
        """Find the caller-side ``if not force`` that decides gate invocation."""

        current: ast.AST | None = gate_node
        while current is not None:
            if isinstance(current, ast.If) and any(
                isinstance(item, ast.Name) and item.id == "force"
                for item in ast.walk(current.test)
            ):
                return current
            current = parsed.parents.get(current)
        return None

    def _compound_source_bundle(
        self,
        profile: CompoundGateProfile,
        *,
        callsite_parsed: ParsedPython,
        gate_node: ast.AST,
        definition: tuple[ParsedPython, ast.AST],
    ) -> tuple[list[SourceChunk], list[str], dict[str, object], ast.If | None]:
        """Build the curated, role-labelled source bundle for one compound gate."""

        chunks: list[SourceChunk] = []
        unresolved: set[str] = set(profile.forced_unresolved)
        seen: set[tuple[str, int, int, str]] = set()
        used_chars = 0

        def append(role: str, symbol: str, parsed: ParsedPython, node: ast.AST) -> None:
            nonlocal used_chars
            chunk = self._chunk(role, symbol, parsed, node)
            key = (chunk.file, chunk.line_start, chunk.line_end, chunk.role)
            if key in seen:
                return
            if used_chars + len(chunk.source) > self.max_source_chars:
                unresolved.add(f"compound-source-budget:{symbol}")
                return
            chunks.append(chunk)
            seen.add(key)
            used_chars += len(chunk.source)

        callsite_guard = self._compound_callsite_guard(callsite_parsed, gate_node)
        if callsite_guard is None:
            unresolved.add("compound-profile:missing-callsite-force-guard")
        else:
            append(
                "compound-shared-callsite",
                "force-bypass",
                callsite_parsed,
                callsite_guard,
            )

        append("compound-shared-wrapper", str(definition[1].name), *definition)

        semantic_parsed = self.index.get(profile.semantic_root.file)
        semantic_root = (
            self._top_level_symbol(semantic_parsed, profile.semantic_root.symbol)
            if semantic_parsed is not None
            else None
        )
        if semantic_parsed is None or semantic_root is None:
            unresolved.add(
                "compound-profile:missing-semantic-root:"
                f"{profile.semantic_root.file}:{profile.semantic_root.symbol}"
            )
        else:
            append(
                "compound-shared-orchestrator",
                profile.semantic_root.symbol,
                semantic_parsed,
                semantic_root,
            )

        fragment_payloads: list[dict[str, object]] = []
        for fragment in profile.fragments:
            role = f"compound-fragment:{fragment.fragment_id}"
            selected_symbols: list[str] = []
            for selection in fragment.selections:
                selected_parsed = self.index.get(selection.file)
                selected_node = (
                    self._top_level_symbol(selected_parsed, selection.symbol)
                    if selected_parsed is not None
                    else None
                )
                if selected_parsed is None or selected_node is None:
                    unresolved.add(
                        "compound-profile:missing-symbol:"
                        f"{selection.file}:{selection.symbol}"
                    )
                    continue
                append(role, selection.symbol, selected_parsed, selected_node)
                if selection.symbol == "_PATTERN_KEY_ALIASES":
                    for statement in selected_parsed.tree.body:
                        statement_source = selected_parsed.segment(statement)
                        if (
                            isinstance(statement, ast.For)
                            and "_PATTERN_KEY_ALIASES" in statement_source
                        ):
                            append(
                                role,
                                "_PATTERN_KEY_ALIASES-population",
                                selected_parsed,
                                statement,
                            )
                selected_symbols.append(f"{selection.file}:{selection.symbol}")
            fragment_payloads.append(
                {
                    "fragment_id": fragment.fragment_id,
                    "title": fragment.title,
                    "focus": fragment.focus,
                    "source_role": role,
                    "check_ids": list(fragment.check_ids),
                    "policy_ids": list(fragment.policy_ids),
                    "selected_symbols": selected_symbols,
                }
            )

        required_checks: list[dict[str, object]] = []
        for check in profile.checks:
            check_parsed = self.index.get(check.source.file)
            check_root = (
                self._top_level_symbol(check_parsed, check.source.symbol)
                if check_parsed is not None
                else None
            )
            if check_parsed is None or check_root is None:
                unresolved.add(
                    "compound-profile:missing-check-source:"
                    f"{check.check_id}:{check.source.file}:{check.source.symbol}"
                )
                continue
            search_text = check_parsed.segment(check_root)
            matches: list[int] = []
            offset = 0
            while True:
                index = search_text.find(check.source_contains, offset)
                if index < 0:
                    break
                matches.append(index)
                offset = index + 1
            if len(matches) != 1:
                unresolved.add(
                    "compound-profile:ambiguous-check-anchor:"
                    f"{check.check_id}:{check.source.file}:{check.source.symbol}:"
                    f"{check.source_contains}"
                )
                continue
            line_start = int(getattr(check_root, "lineno", 1)) + search_text[
                : matches[0]
            ].count("\n")
            required_checks.append(
                {
                    "id": check.check_id,
                    "fragment_id": check.fragment_id,
                    "title": check.title,
                    "op": check.op,
                    "outcomes": dict(check.outcomes),
                    "policy_refs": list(check.policy_refs),
                    "required_unresolved": list(check.required_unresolved),
                    "reject_examples": [
                        {
                            "input": example_input,
                            "rejected_by": check.check_id,
                            "reason": reason,
                            "precondition": precondition,
                        }
                        for example_input, reason, precondition in check.reject_examples
                    ],
                    "anchor": {
                        "file": check.source.file,
                        "line_start": line_start,
                        "line_end": line_start + check.source_contains.count("\n"),
                    },
                }
            )

        policies: list[dict[str, object]] = []
        for policy in profile.policies:
            policy_parsed = self.index.get(policy.source.file)
            policy_node = (
                self._top_level_symbol(policy_parsed, policy.source.symbol)
                if policy_parsed is not None
                else None
            )
            if policy_parsed is None or policy_node is None:
                unresolved.add(
                    "compound-profile:missing-policy-source:"
                    f"{policy.policy_id}:{policy.source.file}:{policy.source.symbol}"
                )
                continue
            value = None
            if isinstance(policy_node, ast.Assign):
                value = policy_node.value
            elif isinstance(policy_node, ast.AnnAssign):
                value = policy_node.value
            if not isinstance(value, (ast.List, ast.Tuple)):
                unresolved.add(
                    f"compound-profile:invalid-policy-table:{policy.policy_id}"
                )
                continue
            items: list[dict[str, object]] = []
            for index, item in enumerate(value.elts, 1):
                if not isinstance(item, (ast.Tuple, ast.List)) or len(item.elts) < 2:
                    unresolved.add(
                        f"compound-profile:invalid-policy-entry:{policy.policy_id}:{index}"
                    )
                    continue
                description_node = item.elts[1]
                description = (
                    description_node.value
                    if isinstance(description_node, ast.Constant)
                    and isinstance(description_node.value, str)
                    else policy_parsed.segment(description_node).strip()
                )
                items.append(
                    {
                        "id": f"{policy.item_prefix}{index:02d}",
                        "source_expression": policy_parsed.segment(
                            item.elts[0]
                        ).strip(),
                        "source_description": description,
                    }
                )
            policies.append(
                {
                    "id": policy.policy_id,
                    "fragment_id": policy.fragment_id,
                    "title": policy.title,
                    "source_symbol": (f"{policy.source.file}:{policy.source.symbol}"),
                    "anchor": {
                        "file": policy.source.file,
                        "line_start": int(getattr(policy_node, "lineno", 1)),
                        "line_end": int(getattr(policy_node, "end_lineno", 1)),
                    },
                    "items": items,
                }
            )

        payload: dict[str, object] = {
            "profile_id": profile.profile_id,
            "semantic_root": (
                f"{profile.semantic_root.file}:{profile.semantic_root.symbol}"
            ),
            "summary": profile.summary,
            "entry_check": profile.entry_check,
            "fragments": fragment_payloads,
            "required_checks": required_checks,
            "policies": policies,
            "terminals": dict(profile.terminals),
            "default": profile.default,
            "on_error": profile.on_error,
            "opaque_boundaries": list(profile.opaque_boundaries),
            "forced_unresolved": list(profile.forced_unresolved),
        }
        return chunks, sorted(unresolved), payload, callsite_guard

    def _dependency_chunks(
        self,
        starts: Iterable[tuple[ParsedPython, ast.AST]],
        *,
        initial_chunks: list[SourceChunk],
    ) -> tuple[list[SourceChunk], list[str]]:
        chunks = list(initial_chunks)
        seen_chunks = {
            (chunk.file, chunk.line_start, chunk.line_end, chunk.role)
            for chunk in chunks
        }
        seen_functions: set[tuple[str, int]] = set()
        unresolved: set[str] = set()
        used_chars = sum(len(chunk.source) for chunk in chunks)

        queue: list[tuple[ParsedPython, ast.AST, int]] = [
            (parsed, node, 0) for parsed, node in starts
        ]
        while queue:
            parsed, function, depth = queue.pop(0)
            function_key = (parsed.rel, int(getattr(function, "lineno", 0)))
            if function_key in seen_functions:
                continue
            seen_functions.add(function_key)

            referenced_names = _iter_names(function)
            assignment_names = list(sorted(referenced_names))
            seen_assignment_names: set[str] = set()
            while assignment_names:
                name = assignment_names.pop(0)
                if name in seen_assignment_names:
                    continue
                seen_assignment_names.add(name)
                assignment = parsed.assignments.get(name)
                if assignment is not None:
                    key = (
                        parsed.rel,
                        int(getattr(assignment, "lineno", 0)),
                        int(getattr(assignment, "end_lineno", 0)),
                        "policy-constant",
                    )
                    if key not in seen_chunks:
                        chunk = self._chunk("policy-constant", name, parsed, assignment)
                        if used_chars + len(chunk.source) <= self.max_source_chars:
                            chunks.append(chunk)
                            seen_chunks.add(key)
                            used_chars += len(chunk.source)
                            assignment_names.extend(
                                sorted(
                                    referenced
                                    for referenced in _iter_names(assignment)
                                    if referenced not in seen_assignment_names
                                )
                            )
                        else:
                            unresolved.add(f"source-budget:{name}")

                imported = parsed.imports.get(name)
                if imported is not None:
                    key = (
                        parsed.rel,
                        int(getattr(imported, "lineno", 0)),
                        int(getattr(imported, "end_lineno", 0)),
                        "import",
                    )
                    if key not in seen_chunks:
                        chunk = self._chunk("import", name, parsed, imported)
                        if used_chars + len(chunk.source) <= self.max_source_chars:
                            chunks.append(chunk)
                            seen_chunks.add(key)
                            used_chars += len(chunk.source)

            if depth >= self.max_dependency_depth:
                continue
            for call in _iter_calls(function):
                name = _call_name(call)
                if not name:
                    continue
                if name in BUILTIN_NAMES:
                    continue
                resolved = self._resolve_called_helper(parsed, call)
                if resolved is None:
                    receiver_root = (
                        call.func.value.id
                        if isinstance(call.func, ast.Attribute)
                        and isinstance(call.func.value, ast.Name)
                        else ""
                    )
                    imported_module = ""
                    imported_node = parsed.imports.get(receiver_root)
                    if isinstance(imported_node, ast.Import):
                        imported_module = next(
                            (
                                alias.name.split(".")[0]
                                for alias in imported_node.names
                                if (alias.asname or alias.name.split(".")[0])
                                == receiver_root
                            ),
                            "",
                        )
                    if imported_module in sys.stdlib_module_names:
                        continue
                    if (
                        name.startswith("_")
                        or (isinstance(call.func, ast.Name) and name in parsed.imports)
                        or receiver_root in parsed.imports
                        or (
                            isinstance(call.func, ast.Name)
                            and self.index.functions_by_name.get(name)
                        )
                    ):
                        unresolved.add(f"unresolved-helper:{name}")
                    continue
                helper_parsed, helper = resolved
                helper_key = (
                    helper_parsed.rel,
                    int(getattr(helper, "lineno", 0)),
                    int(getattr(helper, "end_lineno", 0)),
                    "helper",
                )
                if helper_key not in seen_chunks:
                    chunk = self._chunk("helper", name, helper_parsed, helper)
                    if used_chars + len(chunk.source) <= self.max_source_chars:
                        chunks.append(chunk)
                        seen_chunks.add(helper_key)
                        used_chars += len(chunk.source)
                        queue.append((helper_parsed, helper, depth + 1))
                    else:
                        unresolved.add(f"source-budget:{name}")
        return chunks, sorted(unresolved)

    def build_slice(self, seed: CandidateSeed) -> GateSlice:
        parsed = self.index.get(seed.call_file)
        if parsed is None:
            raise FileNotFoundError(
                f"candidate source is unavailable under {self.source_root}: {seed.call_file}"
            )
        gate_node = self._find_gate_node(parsed, seed)
        if gate_node is None:
            raise ValueError(
                f"cannot locate gate {seed.gate_name!r} at {seed.call_file}:{seed.call_line}"
            )

        checked_node = self._checked_node(parsed, gate_node, seed)
        checked_expr = parsed.segment(checked_node).strip() or seed.checked_hint.strip()
        if not checked_expr:
            checked_expr = parsed.segment(gate_node).strip() or seed.gate_name

        call_column = int(getattr(gate_node, "col_offset", 0)) + 1
        identity = "|".join(
            [
                self.project_name,
                self.revision,
                seed.mode,
                parsed.rel,
                str(seed.call_line),
                str(call_column),
                seed.gate_name,
                checked_expr,
            ]
        )
        gate_id = "G" + _digest(identity, 16)
        input_value_id = "V" + _digest(gate_id + ":" + checked_expr, 12)
        output_value_id, output_meaning = self._output_description(
            parsed, gate_node, seed.mode, gate_id
        )

        definition = self._resolve_definition(parsed, seed)
        qualified_function = (
            f"{definition[0].rel.replace('/', '.')[:-3]}.{seed.gate_name}"
            if definition
            else seed.gate_name
        )
        compound_profile = find_compound_profile(
            qualified_function, project_id=self.project_name
        )
        binding, binding_status = self._binding(
            parsed, gate_node, checked_node, definition, checked_expr
        )
        checked_components: list[dict[str, object]] = []
        component_names: list[str] = []
        if not isinstance(gate_node, ast.Call):
            component_nodes = _ordered_load_names(gate_node)
            component_names = [node.id for node in component_nodes]
            checked_components = [
                {"expression": node.id, "span": _node_span(node, parsed.rel)}
                for node in component_nodes
            ]
            if component_names:
                binding = (
                    f"{' and '.join(component_names)} -> inline condition operands"
                )
                binding_status = "resolved"
        checked_names = [node.id for node in _ordered_load_names(checked_node)]
        condition, callsite_source, branch_effects, context_node = (
            self._condition_context(parsed, gate_node, seed)
        )
        semantic_context = (
            context_node.test
            if isinstance(context_node, (ast.If, ast.While, ast.Assert))
            else gate_node
        )

        gate_source_owner = definition
        enclosing = parsed.enclosing(gate_node, (ast.FunctionDef, ast.AsyncFunctionDef))
        compound_payload: dict[str, object] | None = None
        if compound_profile is not None and gate_source_owner is not None:
            source_bundle, unresolved, compound_payload, callsite_guard = (
                self._compound_source_bundle(
                    compound_profile,
                    callsite_parsed=parsed,
                    gate_node=gate_node,
                    definition=gate_source_owner,
                )
            )
            if callsite_guard is not None:
                condition = parsed.segment(callsite_guard.test).strip()
                callsite_source = parsed.segment(callsite_guard).strip()
                branch_effects = {
                    "condition_true": "invoke the compound gate and enforce its decision",
                    "condition_false": "skip the compound gate and continue",
                }
                context_node = callsite_guard
            callee_kind = "project-compound-function"
        else:
            local_derivations, local_unresolved = self._local_derivations(
                parsed, gate_node, checked_names or component_names
            )
            initial_chunks = [
                self._chunk("local-derivation", symbol, parsed, derivation)
                for symbol, derivation in local_derivations
            ]
            initial_chunks.append(
                self._chunk(
                    "callsite",
                    seed.gate_name,
                    parsed,
                    context_node,
                    source=callsite_source,
                )
            )
            if gate_source_owner is not None:
                initial_chunks.append(
                    self._chunk(
                        "gate-function",
                        seed.gate_name,
                        gate_source_owner[0],
                        gate_source_owner[1],
                    )
                )
                dependency_starts = [gate_source_owner, (parsed, semantic_context)]
                callee_kind = "project-function"
            elif enclosing is not None:
                # The whole handler can be thousands of lines and contains helpers
                # unrelated to this gate. The exact condition/callsite plus branch
                # effects are sufficient context for a library or inline check.
                dependency_starts = [(parsed, semantic_context)]
                callee_kind = (
                    "library-primitive"
                    if isinstance(gate_node, ast.Call)
                    else "inline-expression"
                )
            else:
                dependency_starts = [(parsed, semantic_context)]
                callee_kind = "inline-expression"

            source_bundle, unresolved = self._dependency_chunks(
                dependency_starts, initial_chunks=initial_chunks
            )
            unresolved.extend(local_unresolved)
            if (
                callee_kind == "library-primitive"
                and isinstance(gate_node, ast.Call)
                and isinstance(gate_node.func, ast.Attribute)
                and gate_node.func.attr in {"exists", "is_dir", "is_file"}
                and isinstance(checked_node, ast.Name)
                and any(
                    symbol == checked_node.id
                    and any(
                        isinstance(item, (ast.Assign, ast.AnnAssign))
                        and isinstance(getattr(item, "value", None), ast.Call)
                        and _call_name(item.value) == "Path"
                        for item in ast.walk(derivation)
                    )
                    for symbol, derivation in local_derivations
                )
            ):
                unresolved.append(
                    f"library-contract:pathlib.Path.{gate_node.func.attr}"
                    "@supported-python-version-unpinned"
                )
        if seed.mode == "predicate" and not seed.source_param:
            unresolved.append(
                "source-witness:not-exported; regenerate enriched dominance candidates"
            )
        unresolved = sorted(set(unresolved))

        checked_span = _node_span(checked_node, parsed.rel)
        if seed.checked_file:
            checked_span["file"] = seed.checked_file
        if seed.checked_line:
            checked_span["start_line"] = seed.checked_line
        if seed.checked_column:
            checked_span["start_column"] = seed.checked_column

        owner_name = (
            getattr(enclosing, "name", "")
            if enclosing is not None
            else seed.owner_function
        )
        # CodeQL's generic AST toString can be `Attribute()`; the parsed source
        # is the exact call expression and should win whenever it is available.
        call_expr = parsed.segment(gate_node).strip() or seed.call_expr_hint
        activation = self._lexical_activation(parsed, gate_node)
        normalized_gate = _normalized_ast(gate_node)
        occurrence_owner: ast.AST = enclosing if enclosing is not None else parsed.tree
        equivalent_nodes = sorted(
            (
                node
                for node in ast.walk(occurrence_owner)
                if type(node) is type(gate_node)
                and _normalized_ast(node) == normalized_gate
            ),
            key=lambda node: (
                int(getattr(node, "lineno", 0)),
                int(getattr(node, "col_offset", 0)),
            ),
        )
        occurrence = next(
            (
                index
                for index, node in enumerate(equivalent_nodes, start=1)
                if node is gate_node
            ),
            1,
        )
        uid_identity = json.dumps(
            {
                "project": self.project_name,
                "module": parsed.rel,
                "enclosing_function": owner_name,
                "mode": seed.mode,
                "qualified_function": qualified_function,
                "normalized_gate_ast": normalized_gate,
                "normalized_checked_ast": _normalized_ast(checked_node),
                "normalized_callsite_context": _normalized_ast(context_node),
                "lexical_activation": activation,
                "equivalent_occurrence": occurrence,
            },
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        gate_uid = "GU" + _digest(uid_identity, 20)
        dataflow_path: list[str] = []
        for value in [seed.source_param or "unknown source parameter", checked_expr]:
            if value and (not dataflow_path or dataflow_path[-1] != value):
                dataflow_path.append(value)

        return GateSlice(
            gate_id=gate_id,
            gate_uid=gate_uid,
            project={
                "name": self.project_name,
                "revision": self.revision,
                "language": "python",
                "source_root": str(self.source_root),
            },
            gate={
                "mode": seed.mode,
                "static_verdict": seed.static_verdict,
                "name": seed.gate_name,
                "qualified_function": (qualified_function),
                "callee_kind": callee_kind,
                "detector_role": seed.detector_role,
                "call_expression": call_expr,
                "definition_span": (
                    _node_span(definition[1], definition[0].rel) if definition else None
                ),
                "output_value_id": output_value_id,
                "output_meaning": output_meaning,
            },
            callsite={
                "span": _node_span(gate_node, parsed.rel),
                "enclosing_function": owner_name,
                "condition": condition,
                "source": callsite_source,
                "branch_effects": branch_effects,
                "activation": activation,
            },
            checked_value={
                "value_id": input_value_id,
                "expression": checked_expr,
                "span": checked_span,
                "actual_to_formal_binding": binding,
                "binding_status": binding_status,
                "semantic_role_hint": checked_expr,
                "type": "unknown",
                **(
                    {"components": checked_components}
                    if checked_components
                    else {}
                ),
            },
            dataflow={
                "source_symbol": seed.source_param or "unknown",
                "t_to_g_path": dataflow_path,
            },
            source_bundle=source_bundle,
            unresolved_symbols=unresolved,
            compound_profile=compound_payload,
            chain_refs=list(seed.chain_refs),
        )

    def build_slices(self, seeds: Iterable[CandidateSeed]) -> list[GateSlice]:
        deduplicated: dict[str, GateSlice] = {}
        for seed in seeds:
            gate_slice = self.build_slice(seed)
            existing = deduplicated.get(gate_slice.gate_uid)
            if existing is None:
                deduplicated[gate_slice.gate_uid] = gate_slice
                continue
            seen_refs = {
                json.dumps(ref, sort_keys=True, ensure_ascii=False)
                for ref in existing.chain_refs
            }
            for ref in gate_slice.chain_refs:
                serialized = json.dumps(ref, sort_keys=True, ensure_ascii=False)
                if serialized not in seen_refs:
                    existing.chain_refs.append(ref)
                    seen_refs.add(serialized)
        return sorted(deduplicated.values(), key=lambda item: item.gate_id)
