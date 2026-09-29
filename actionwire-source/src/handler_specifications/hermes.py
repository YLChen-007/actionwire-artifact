#!/usr/bin/env python3
"""Extract Hermes model-facing tool specifications without importing Hermes.

The CodeQL-generated handler inventory is the authoritative tool universe. This
script parses the corresponding registration modules with Python's AST, resolves
the registered schema expressions using a fail-closed static evaluator, applies
the deterministic final-schema normalization, and writes JSON/Markdown reports.
"""

from __future__ import annotations

import argparse
import ast
import copy
import csv
import hashlib
import json
import operator
import re
import shlex
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parents[2]
DEFAULT_SOURCE_ROOT = REPO_ROOT / "benchmark/python/hermes-agent"
DEFAULT_HANDLER_CSV = (
    REPO_ROOT / "design/hermes-agent/handler-entry/debug/tool-handler-entries.csv"
)
DEFAULT_OUTPUT_DIR = REPO_ROOT / "output/hermes/handler-specifications"
DEFAULT_OUT_JSON = DEFAULT_OUTPUT_DIR / "tool-handler-specifications.json"
DEFAULT_OUT_MD = DEFAULT_OUTPUT_DIR / "tool-handler-specifications.md"
DEFAULT_BENCHMARK_README = REPO_ROOT / "benchmark/python/readme.md"
EXPECTED_HANDLER_COUNT = 67

SCHEMA_VERSION = "hermes-tool-handler-specifications/v1"
HANDLER_FIELDS = [
    "tool_name",
    "form",
    "handler_func",
    "file",
    "line",
    "forwarded_body",
]
WEB_TOOL_SENTENCE = (
    " For simple information retrieval, prefer web_search or web_extract "
    "(faster, cheaper)."
)


class StaticResolutionError(ValueError):
    """Raised when a schema expression cannot be resolved without execution."""


@dataclass(frozen=True, order=True)
class HandlerEntry:
    tool_name: str
    form: str
    handler_func: str
    file: str
    line: int
    forwarded_body: str


@dataclass(frozen=True)
class Registration:
    tool_name: str
    file: str
    line: int
    schema_expression: str
    schema_node: ast.expr


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repo_path(path: Path) -> str:
    path = path.resolve()
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def read_handlers(path: Path) -> list[HandlerEntry]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != HANDLER_FIELDS:
            raise ValueError(
                f"unexpected columns in {path}: {reader.fieldnames}; "
                f"expected {HANDLER_FIELDS}"
            )
        entries: list[HandlerEntry] = []
        seen: set[str] = set()
        for row_number, row in enumerate(reader, 2):
            try:
                line = int(row["line"])
            except (TypeError, ValueError) as error:
                raise ValueError(f"invalid line at {path}:{row_number}") from error
            tool_name = row["tool_name"]
            if not tool_name or tool_name in seen:
                raise ValueError(
                    f"duplicate or empty tool_name at {path}:{row_number}: {tool_name!r}"
                )
            seen.add(tool_name)
            entries.append(
                HandlerEntry(
                    tool_name=tool_name,
                    form=row["form"],
                    handler_func=row["handler_func"],
                    file=row["file"],
                    line=line,
                    forwarded_body=row["forwarded_body"],
                )
            )
    return sorted(entries)


def read_benchmark_identity(path: Path) -> tuple[str, str]:
    pattern = re.compile(
        r"^\|\s*`hermes-agent`\s*\|\s*([^|]+?)\s*\|\s*`([0-9a-f]{40})`\s*\|\s*$"
    )
    for line in path.read_text(encoding="utf-8").splitlines():
        match = pattern.match(line)
        if match:
            return match.group(1).strip(), match.group(2)
    raise ValueError(f"cannot find hermes-agent release identity in {path}")


def _target_names(target: ast.expr) -> list[tuple[str, ast.expr | None]]:
    if isinstance(target, ast.Name):
        return [(target.id, None)]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [
            (name, ast.Constant(index))
            for index, element in enumerate(target.elts)
            for name, _ in _target_names(element)
        ]
    return []


class StaticModule:
    """Restricted evaluator for a single Python module's static schema data."""

    def __init__(
        self,
        path: Path,
        source_root: Path | None = None,
        module_cache: dict[Path, "StaticModule"] | None = None,
    ):
        self.path = path.resolve()
        self.source_root = source_root.resolve() if source_root is not None else None
        self.module_cache = module_cache if module_cache is not None else {}
        self.module_cache[self.path] = self
        self.source = self.path.read_text(encoding="utf-8")
        self.tree = ast.parse(self.source, filename=str(self.path))
        self.bindings: dict[str, list[tuple[int, ast.expr]]] = {}
        self.functions: dict[str, ast.FunctionDef] = {}
        self.imports: dict[str, tuple[str, str]] = {}
        self._cache: dict[tuple[str, int], Any] = {}
        self._collect_module_statements(self.tree.body)

    @classmethod
    def from_source(cls, source: str, path: Path) -> "StaticModule":
        instance = cls.__new__(cls)
        instance.path = path.resolve()
        instance.source_root = None
        instance.module_cache = {instance.path: instance}
        instance.source = source
        instance.tree = ast.parse(source, filename=str(path))
        instance.bindings = {}
        instance.functions = {}
        instance.imports = {}
        instance._cache = {}
        instance._collect_module_statements(instance.tree.body)
        return instance

    def _collect_module_statements(self, statements: Sequence[ast.stmt]) -> None:
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if isinstance(statement, ast.FunctionDef):
                    self.functions[statement.name] = statement
                continue
            if isinstance(statement, ast.ImportFrom) and statement.level == 0:
                if statement.module:
                    for alias in statement.names:
                        if alias.name != "*":
                            self.imports[alias.asname or alias.name] = (
                                statement.module,
                                alias.name,
                            )
                continue
            if isinstance(statement, (ast.ClassDef, ast.For, ast.While, ast.With)):
                continue
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    for name, subscript in _target_names(target):
                        value: ast.expr = statement.value
                        if subscript is not None:
                            value = ast.Subscript(value=statement.value, slice=subscript)
                            ast.copy_location(value, statement.value)
                        self.bindings.setdefault(name, []).append(
                            (statement.lineno, value)
                        )
            elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
                for name, _ in _target_names(statement.target):
                    self.bindings.setdefault(name, []).append(
                        (statement.lineno, statement.value)
                    )
            elif isinstance(statement, ast.If):
                # Only TYPE_CHECKING blocks and optional imports normally occur
                # here. Conditional module assignments are intentionally not
                # guessed because their runtime branch is environment-specific.
                continue
            elif isinstance(statement, ast.Try):
                continue

    def registration(self, tool_name: str) -> Registration:
        matches = self.literal_registrations({tool_name})
        if len(matches) != 1:
            raise StaticResolutionError(
                f"{self.path}: expected exactly one literal registry.register for "
                f"{tool_name!r}, found {len(matches)}"
            )
        return matches[0]

    def literal_registrations(
        self, tool_names: set[str] | None = None
    ) -> list[Registration]:
        matches: list[Registration] = []
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            if not (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "registry"
                and node.func.attr == "register"
            ):
                continue
            keywords = {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg}
            name_node = keywords.get("name")
            schema_node = keywords.get("schema")
            if not (isinstance(name_node, ast.Constant) and isinstance(name_node.value, str)):
                continue
            tool_name = name_node.value
            if tool_names is not None and tool_name not in tool_names:
                continue
            if not isinstance(schema_node, ast.expr):
                raise StaticResolutionError(
                    f"{self.path}:{node.lineno}: {tool_name} has no schema= expression"
                )
            matches.append(
                Registration(
                    tool_name=tool_name,
                    file=self.path.as_posix(),
                    line=node.lineno,
                    schema_expression=ast.unparse(schema_node),
                    schema_node=schema_node,
                )
            )
        return sorted(matches, key=lambda item: (item.line, item.tool_name))

    def resolve_name(
        self,
        name: str,
        at_line: int,
        local_scope: Mapping[str, Any] | None = None,
        stack: tuple[str, ...] = (),
    ) -> Any:
        if local_scope is not None and name in local_scope:
            return copy.deepcopy(local_scope[name])
        static_builtins = {
            "int": int,
            "float": float,
            "str": str,
            "bool": bool,
            "list": list,
            "tuple": tuple,
            "set": set,
            "dict": dict,
        }
        if name in static_builtins:
            return static_builtins[name]
        # Cross-project extraction uses the benchmark's canonical Linux runtime.
        # Platform-conditioned text is retained separately as a runtime rule by
        # the owning adapter; benchmark modules are never imported.
        if name == "sys":
            return {"platform": "linux"}
        if name == "os":
            return {"name": "posix"}
        candidates = [item for item in self.bindings.get(name, []) if item[0] <= at_line]
        if not candidates:
            if name in self.imports:
                return self._resolve_imported_name(name)
            raise self.error(at_line, None, f"unbound name {name!r}")
        binding_line, node = candidates[-1]
        key = (name, at_line)
        if key in self._cache:
            return copy.deepcopy(self._cache[key])
        if name in stack:
            raise self.error(at_line, node, f"cyclic binding: {' -> '.join((*stack, name))}")
        value = self.eval_expr(node, at_line, local_scope, (*stack, name))
        self._cache[key] = value
        return copy.deepcopy(value)

    def _resolve_imported_name(self, local_name: str) -> Any:
        if self.source_root is None:
            raise self.error(1, None, f"cannot resolve imported name {local_name!r}")
        module_name, imported_name = self.imports[local_name]
        relative = Path(*module_name.split("."))
        candidates = [
            self.source_root / relative.with_suffix(".py"),
            self.source_root / relative / "__init__.py",
        ]
        target_path = next((path.resolve() for path in candidates if path.is_file()), None)
        if target_path is None:
            raise self.error(1, None, f"local import module {module_name!r} not found")
        try:
            target_path.relative_to(self.source_root)
        except ValueError as error:
            raise self.error(1, None, f"import escapes source root: {module_name!r}") from error
        target_module = self.module_cache.get(target_path)
        if target_module is None:
            target_module = StaticModule(
                target_path,
                source_root=self.source_root,
                module_cache=self.module_cache,
            )
        return target_module.resolve_name(imported_name, 10**9)

    def error(self, line: int, node: ast.AST | None, message: str) -> StaticResolutionError:
        shape = "<none>" if node is None else f"{type(node).__name__}: {ast.unparse(node)}"
        node_line = getattr(node, "lineno", line)
        return StaticResolutionError(f"{self.path}:{node_line}: {message}; AST={shape}")

    def eval_expr(
        self,
        node: ast.expr,
        at_line: int,
        local_scope: Mapping[str, Any] | None = None,
        stack: tuple[str, ...] = (),
    ) -> Any:
        scope = dict(local_scope or {})
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            return self.resolve_name(node.id, at_line, scope, stack)
        if isinstance(node, ast.Attribute):
            receiver = self.eval_expr(node.value, at_line, scope, stack)
            if isinstance(receiver, Mapping) and node.attr in receiver:
                return copy.deepcopy(receiver[node.attr])
            raise self.error(at_line, node, "unsupported static attribute")
        if isinstance(node, ast.Dict):
            result: dict[Any, Any] = {}
            for key_node, value_node in zip(node.keys, node.values):
                value = self.eval_expr(value_node, at_line, scope, stack)
                if key_node is None:
                    if not isinstance(value, Mapping):
                        raise self.error(at_line, value_node, "dict unpack is not a mapping")
                    result.update(copy.deepcopy(dict(value)))
                else:
                    key = self.eval_expr(key_node, at_line, scope, stack)
                    result[key] = value
            return result
        if isinstance(node, ast.List):
            return [self.eval_expr(item, at_line, scope, stack) for item in node.elts]
        if isinstance(node, ast.Tuple):
            return tuple(self.eval_expr(item, at_line, scope, stack) for item in node.elts)
        if isinstance(node, ast.Set):
            return {self.eval_expr(item, at_line, scope, stack) for item in node.elts}
        if isinstance(node, ast.Subscript):
            value = self.eval_expr(node.value, at_line, scope, stack)
            index = self._eval_slice(node.slice, at_line, scope, stack)
            try:
                return copy.deepcopy(value[index])
            except (KeyError, IndexError, TypeError) as error:
                raise self.error(at_line, node, f"invalid static subscript: {error}") from error
        if isinstance(node, ast.BinOp):
            left = self.eval_expr(node.left, at_line, scope, stack)
            right = self.eval_expr(node.right, at_line, scope, stack)
            operations = {
                ast.Add: operator.add,
                ast.Sub: operator.sub,
                ast.Mult: operator.mul,
                ast.Div: operator.truediv,
                ast.FloorDiv: operator.floordiv,
                ast.Mod: operator.mod,
                ast.BitOr: operator.or_,
                ast.BitAnd: operator.and_,
            }
            operation = operations.get(type(node.op))
            if operation is None:
                raise self.error(at_line, node, "unsupported binary operator")
            try:
                return operation(left, right)
            except (TypeError, ValueError) as error:
                raise self.error(at_line, node, f"invalid binary operation: {error}") from error
        if isinstance(node, ast.JoinedStr):
            parts: list[str] = []
            for item in node.values:
                if isinstance(item, ast.Constant):
                    parts.append(str(item.value))
                elif isinstance(item, ast.FormattedValue):
                    value = self.eval_expr(item.value, at_line, scope, stack)
                    if item.conversion == ord("r"):
                        value = repr(value)
                    elif item.conversion == ord("s"):
                        value = str(value)
                    format_spec = ""
                    if item.format_spec is not None:
                        format_spec = self.eval_expr(item.format_spec, at_line, scope, stack)
                    parts.append(format(value, format_spec))
                else:
                    raise self.error(at_line, item, "unsupported f-string component")
            return "".join(parts)
        if isinstance(node, ast.IfExp):
            branch = node.body if self._truth(node.test, at_line, scope, stack) else node.orelse
            return self.eval_expr(branch, at_line, scope, stack)
        if isinstance(node, ast.UnaryOp):
            operand = self.eval_expr(node.operand, at_line, scope, stack)
            if isinstance(node.op, ast.Not):
                return not operand
            if isinstance(node.op, ast.USub):
                return -operand
            if isinstance(node.op, ast.UAdd):
                return +operand
            raise self.error(at_line, node, "unsupported unary operator")
        if isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                result: Any = True
                for value_node in node.values:
                    result = self.eval_expr(value_node, at_line, scope, stack)
                    if not result:
                        return result
                return result
            if isinstance(node.op, ast.Or):
                result = False
                for value_node in node.values:
                    result = self.eval_expr(value_node, at_line, scope, stack)
                    if result:
                        return result
                return result
            raise self.error(at_line, node, "unsupported boolean operator")
        if isinstance(node, ast.Compare):
            return self._compare(node, at_line, scope, stack)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            return self._eval_comprehension(node, at_line, scope, stack)
        if isinstance(node, ast.Call):
            return self._eval_call(node, at_line, scope, stack)
        raise self.error(at_line, node, "unsupported static expression")

    def _eval_slice(
        self,
        node: ast.expr | ast.Slice,
        at_line: int,
        scope: Mapping[str, Any],
        stack: tuple[str, ...],
    ) -> Any:
        if isinstance(node, ast.Slice):
            return slice(
                self.eval_expr(node.lower, at_line, scope, stack) if node.lower else None,
                self.eval_expr(node.upper, at_line, scope, stack) if node.upper else None,
                self.eval_expr(node.step, at_line, scope, stack) if node.step else None,
            )
        return self.eval_expr(node, at_line, scope, stack)

    def _compare(
        self,
        node: ast.Compare,
        at_line: int,
        scope: Mapping[str, Any],
        stack: tuple[str, ...],
    ) -> bool:
        left = self.eval_expr(node.left, at_line, scope, stack)
        operations = {
            ast.Eq: operator.eq,
            ast.NotEq: operator.ne,
            ast.In: lambda a, b: a in b,
            ast.NotIn: lambda a, b: a not in b,
            ast.Is: operator.is_,
            ast.IsNot: operator.is_not,
            ast.Lt: operator.lt,
            ast.LtE: operator.le,
            ast.Gt: operator.gt,
            ast.GtE: operator.ge,
        }
        for op_node, comparator in zip(node.ops, node.comparators):
            right = self.eval_expr(comparator, at_line, scope, stack)
            operation = operations.get(type(op_node))
            if operation is None:
                raise self.error(at_line, node, "unsupported comparison")
            if not operation(left, right):
                return False
            left = right
        return True

    def _truth(
        self,
        node: ast.expr,
        at_line: int,
        scope: Mapping[str, Any],
        stack: tuple[str, ...],
    ) -> bool:
        return bool(self.eval_expr(node, at_line, scope, stack))

    def _bind_target(self, target: ast.expr, value: Any, scope: dict[str, Any]) -> None:
        if isinstance(target, ast.Name):
            scope[target.id] = copy.deepcopy(value)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            values = list(value)
            if len(values) != len(target.elts):
                raise self.error(target.lineno, target, "comprehension unpack length mismatch")
            for child, child_value in zip(target.elts, values):
                self._bind_target(child, child_value, scope)
            return
        raise self.error(target.lineno, target, "unsupported comprehension target")

    def _comprehension_scopes(
        self,
        generators: Sequence[ast.comprehension],
        at_line: int,
        scope: dict[str, Any],
        stack: tuple[str, ...],
        index: int = 0,
    ) -> Iterable[dict[str, Any]]:
        if index >= len(generators):
            yield scope
            return
        generator = generators[index]
        if generator.is_async:
            raise self.error(at_line, generator, "async comprehension is unsupported")
        iterable = self.eval_expr(generator.iter, at_line, scope, stack)
        for item in iterable:
            child_scope = dict(scope)
            self._bind_target(generator.target, item, child_scope)
            if all(self._truth(cond, at_line, child_scope, stack) for cond in generator.ifs):
                yield from self._comprehension_scopes(
                    generators, at_line, child_scope, stack, index + 1
                )

    def _eval_comprehension(
        self,
        node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp,
        at_line: int,
        scope: Mapping[str, Any],
        stack: tuple[str, ...],
    ) -> Any:
        scopes = self._comprehension_scopes(
            node.generators, at_line, dict(scope), stack
        )
        if isinstance(node, ast.DictComp):
            return {
                self.eval_expr(node.key, at_line, child, stack): self.eval_expr(
                    node.value, at_line, child, stack
                )
                for child in scopes
            }
        values = [self.eval_expr(node.elt, at_line, child, stack) for child in scopes]
        if isinstance(node, ast.SetComp):
            return set(values)
        return values

    def _eval_call(
        self,
        node: ast.Call,
        at_line: int,
        scope: Mapping[str, Any],
        stack: tuple[str, ...],
    ) -> Any:
        args = [self.eval_expr(arg, at_line, scope, stack) for arg in node.args]
        kwargs = {
            keyword.arg: self.eval_expr(keyword.value, at_line, scope, stack)
            for keyword in node.keywords
            if keyword.arg is not None
        }
        if any(keyword.arg is None for keyword in node.keywords):
            raise self.error(at_line, node, "call keyword unpack is unsupported")
        if isinstance(node.func, ast.Name):
            name = node.func.id
            constructors = {
                "list": list,
                "tuple": tuple,
                "set": set,
                "frozenset": frozenset,
                "sorted": sorted,
                "str": str,
                "int": int,
                "float": float,
                "bool": bool,
                "dict": dict,
                "all": all,
                "any": any,
                "len": len,
            }
            if name in constructors:
                try:
                    return constructors[name](*args, **kwargs)
                except (TypeError, ValueError) as error:
                    raise self.error(at_line, node, f"invalid {name}() call: {error}") from error
            if name == "display_hermes_home" and not args and not kwargs:
                # Canonical documented default. The environment/profile-driven
                # runtime variation is preserved as metadata on cronjob.
                return "~/.hermes"
            if name == "_safe_parse_import_env" and len(args) == 4 and not kwargs:
                # Canonical schema uses the source-declared fallback. Runtime
                # environment overrides are captured in the terminal rule.
                return args[1]
            if name == "build_execute_code_schema":
                # The registration-time no-argument call reads runtime config.
                # Canonical extraction deliberately supplies the documented
                # project mode and all statically declared sandbox tools.
                if not args and not kwargs:
                    allowed = self.resolve_name("SANDBOX_ALLOWED_TOOLS", at_line)
                    kwargs = {
                        "enabled_sandbox_tools": set(allowed),
                        "mode": "project",
                    }
                return self.call_function(name, args, kwargs, at_line)
            raise self.error(at_line, node, f"call to non-whitelisted function {name!r}")
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "platform"
            and node.func.attr == "system"
            and not args
            and not kwargs
        ):
            # Registered benchmark snapshots are analyzed with Linux as the
            # canonical runtime. Adapters retain the platform-dependent field
            # as an explicit runtime rule instead of executing platform.system.
            return "Linux"
        if isinstance(node.func, ast.Attribute) and node.func.attr == "join":
            receiver = self.eval_expr(node.func.value, at_line, scope, stack)
            if not isinstance(receiver, str) or len(args) != 1 or kwargs:
                raise self.error(at_line, node, "only str.join(iterable) is allowed")
            return receiver.join(args[0])
        if isinstance(node.func, ast.Attribute) and node.func.attr in {
            "items",
            "keys",
            "values",
        }:
            receiver = self.eval_expr(node.func.value, at_line, scope, stack)
            if not isinstance(receiver, Mapping) or args or kwargs:
                raise self.error(
                    at_line, node, "only no-argument mapping views are allowed"
                )
            return list(getattr(receiver, node.func.attr)())
        if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            receiver = self.eval_expr(node.func.value, at_line, scope, stack)
            if not isinstance(receiver, Mapping) or not (1 <= len(args) <= 2) or kwargs:
                raise self.error(at_line, node, "only mapping.get(key[, default]) is allowed")
            return receiver.get(*args)
        if isinstance(node.func, ast.Attribute) and node.func.attr in {
            "startswith",
            "endswith",
        }:
            receiver = self.eval_expr(node.func.value, at_line, scope, stack)
            if not isinstance(receiver, str) or not (1 <= len(args) <= 3) or kwargs:
                raise self.error(at_line, node, "invalid static string predicate")
            return getattr(receiver, node.func.attr)(*args)
        raise self.error(at_line, node, "unsupported call shape")

    def call_function(
        self,
        name: str,
        args: Sequence[Any],
        kwargs: Mapping[str, Any],
        at_line: int,
    ) -> Any:
        if name != "build_execute_code_schema":
            raise self.error(at_line, None, f"static function {name!r} is not whitelisted")
        function = self.functions.get(name)
        if function is None:
            raise self.error(at_line, None, f"function {name!r} is not defined")
        parameter_names = [argument.arg for argument in function.args.args]
        scope: dict[str, Any] = {}
        if len(args) > len(parameter_names):
            raise self.error(at_line, function, f"too many arguments for {name}")
        for parameter, value in zip(parameter_names, args):
            scope[parameter] = copy.deepcopy(value)
        for parameter, value in kwargs.items():
            if parameter not in parameter_names or parameter in scope:
                raise self.error(at_line, function, f"invalid argument {parameter!r} for {name}")
            scope[parameter] = copy.deepcopy(value)
        defaults = [None] * (len(parameter_names) - len(function.args.defaults)) + list(
            function.args.defaults
        )
        for parameter, default in zip(parameter_names, defaults):
            if parameter not in scope:
                if default is None:
                    raise self.error(at_line, function, f"missing argument {parameter!r}")
                scope[parameter] = self.eval_expr(default, at_line, scope)
        returned, value = self._execute_statements(function.body, at_line, scope)
        if not returned:
            raise self.error(at_line, function, f"static function {name!r} did not return")
        return value

    def _execute_statements(
        self,
        statements: Sequence[ast.stmt],
        at_line: int,
        scope: dict[str, Any],
    ) -> tuple[bool, Any]:
        for statement in statements:
            if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
                continue
            if isinstance(statement, ast.Assign):
                value = self.eval_expr(statement.value, at_line, scope)
                for target in statement.targets:
                    self._bind_target(target, value, scope)
                continue
            if isinstance(statement, ast.AnnAssign) and statement.value is not None:
                value = self.eval_expr(statement.value, at_line, scope)
                self._bind_target(statement.target, value, scope)
                continue
            if isinstance(statement, ast.If):
                branch = statement.body if self._truth(statement.test, at_line, scope, ()) else statement.orelse
                returned, value = self._execute_statements(branch, at_line, scope)
                if returned:
                    return True, value
                continue
            if isinstance(statement, ast.Return):
                value = None if statement.value is None else self.eval_expr(statement.value, at_line, scope)
                return True, value
            raise self.error(at_line, statement, "unsupported statement in static function")
        return False, None


def _sanitize_node(node: Any) -> Any:
    if isinstance(node, str):
        if node in {"object", "string", "number", "integer", "boolean", "array", "null"}:
            if node == "object":
                return {"type": "object", "properties": {}}
            return {"type": node}
        return {"type": "object", "properties": {}}
    if isinstance(node, list):
        return [_sanitize_node(item) for item in node]
    if not isinstance(node, dict):
        return node

    output: dict[str, Any] = {}
    for key, value in node.items():
        if key == "type" and isinstance(value, list):
            non_null = [item for item in value if item != "null"]
            if len(non_null) == 1 and isinstance(non_null[0], str):
                output["type"] = non_null[0]
                if "null" in value:
                    output.setdefault("nullable", True)
                continue
            first = next(
                (item for item in value if isinstance(item, str) and item != "null"),
                None,
            )
            output["type"] = first or "object"
            continue
        if key in {"properties", "$defs", "definitions"} and isinstance(value, dict):
            output[key] = {sub_key: _sanitize_node(sub_value) for sub_key, sub_value in value.items()}
        elif key in {"items", "additionalProperties"}:
            output[key] = value if isinstance(value, bool) else _sanitize_node(value)
        elif key in {"anyOf", "oneOf", "allOf"} and isinstance(value, list):
            output[key] = [_sanitize_node(item) for item in value]
        elif key in {"required", "enum", "examples"}:
            output[key] = copy.deepcopy(value)
        else:
            output[key] = _sanitize_node(value) if isinstance(value, (dict, list)) else value
    if output.get("type") == "object" and not isinstance(output.get("properties"), dict):
        output["properties"] = {}
    if output.get("type") == "object" and isinstance(output.get("required"), list):
        properties = output.get("properties") or {}
        valid = [item for item in output["required"] if isinstance(item, str) and item in properties]
        if not valid:
            output.pop("required", None)
        else:
            output["required"] = valid
    return output


def _strip_nullable_unions(node: Any) -> Any:
    if isinstance(node, list):
        return [_strip_nullable_unions(item) for item in node]
    if not isinstance(node, dict):
        return node
    output = {key: _strip_nullable_unions(value) for key, value in node.items()}
    for key in ("anyOf", "oneOf"):
        variants = output.get(key)
        if not isinstance(variants, list):
            continue
        non_null = [
            item
            for item in variants
            if not (isinstance(item, dict) and item.get("type") == "null")
        ]
        if len(non_null) == 1 and len(non_null) != len(variants):
            replacement = dict(non_null[0]) if isinstance(non_null[0], dict) else {}
            replacement.setdefault("nullable", True)
            for metadata_key in ("title", "description", "default", "examples"):
                if metadata_key in output and metadata_key not in replacement:
                    replacement[metadata_key] = output[metadata_key]
            return _strip_nullable_unions(replacement)
    return output


def sanitize_function_specification(function: Mapping[str, Any]) -> dict[str, Any]:
    output = copy.deepcopy(dict(function))
    parameters = output.get("parameters")
    if not isinstance(parameters, dict):
        output["parameters"] = {"type": "object", "properties": {}}
        return output
    parameters = _sanitize_node(parameters)
    if not isinstance(parameters, dict):
        parameters = {"type": "object", "properties": {}}
    parameters["type"] = "object"
    if not isinstance(parameters.get("properties"), dict):
        parameters["properties"] = {}
    parameters = _strip_nullable_unions(parameters)
    for key in ("allOf", "anyOf", "oneOf", "enum", "not"):
        parameters.pop(key, None)
    output["parameters"] = parameters
    return output


def _line_for(path: Path, needle: str) -> int:
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if needle in line:
            return line_number
    raise ValueError(f"cannot locate {needle!r} in {path}")


def materialize_execute_code(
    module: StaticModule,
    registration_line: int,
    enabled_sandbox_tools: set[str],
    mode: str,
) -> dict[str, Any]:
    if mode not in {"project", "strict"}:
        raise ValueError(f"unsupported execute_code mode: {mode!r}")
    allowed = set(module.resolve_name("SANDBOX_ALLOWED_TOOLS", registration_line))
    unknown = enabled_sandbox_tools - allowed
    if unknown:
        raise ValueError(f"unknown execute_code sandbox tools: {sorted(unknown)}")
    schema = module.call_function(
        "build_execute_code_schema",
        (),
        {"enabled_sandbox_tools": set(enabled_sandbox_tools), "mode": mode},
        registration_line,
    )
    schema = {**schema, "name": "execute_code"}
    return sanitize_function_specification(schema)


def materialize_browser_navigate(
    canonical_function: Mapping[str, Any], available_tool_names: set[str]
) -> dict[str, Any]:
    output = copy.deepcopy(dict(canonical_function))
    if not ({"web_search", "web_extract"} & available_tool_names):
        output["description"] = output.get("description", "").replace(WEB_TOOL_SENTENCE, "")
    return sanitize_function_specification(output)


def _runtime_rules(
    tool_name: str,
    module: StaticModule,
    registration_line: int,
    source_root: Path,
) -> list[dict[str, Any]]:
    model_tools = source_root / "model_tools.py"
    if tool_name == "execute_code":
        allowed = sorted(module.resolve_name("SANDBOX_ALLOWED_TOOLS", registration_line))
        return [
            {
                "rule_id": "execute-code-runtime-rebuild",
                "source": {
                    "file": repo_path(model_tools),
                    "line": _line_for(model_tools, "dynamic_schema = build_execute_code_schema"),
                },
                "inputs": {
                    "enabled_sandbox_tools": {
                        "domain": allowed,
                        "canonical_value": allowed,
                        "derivation": "SANDBOX_ALLOWED_TOOLS intersect final available tool names",
                    },
                    "execution_mode": {
                        "domain": ["project", "strict"],
                        "canonical_value": "project",
                    },
                },
                "effect": "rebuild-function-schema",
                "affected_fields": [
                    "/description",
                    "/parameters/properties/code/description",
                ],
            }
        ]
    if tool_name == "browser_navigate":
        return [
            {
                "rule_id": "browser-navigate-web-tool-description",
                "source": {
                    "file": repo_path(model_tools),
                    "line": _line_for(model_tools, "desc = desc.replace"),
                },
                "condition": {
                    "none_available": ["web_search", "web_extract"]
                },
                "effect": "remove-exact-description-fragment",
                "affected_fields": ["/description"],
                "fragment": WEB_TOOL_SENTENCE,
            }
        ]
    if tool_name == "cronjob":
        constants = source_root / "hermes_constants.py"
        return [
            {
                "rule_id": "cronjob-hermes-home-display",
                "source": {
                    "file": repo_path(constants),
                    "line": _line_for(constants, "def display_hermes_home"),
                },
                "inputs": {
                    "HERMES_HOME": {
                        "canonical_value": "~/.hermes",
                        "derivation": "active Hermes home or profile display path",
                    }
                },
                "effect": "substitute-display-path",
                "affected_fields": [
                    "/parameters/properties/script/description"
                ],
            }
        ]
    if tool_name == "terminal":
        return [
            {
                "rule_id": "terminal-foreground-timeout-description",
                "source": {
                    "file": repo_path(module.path),
                    "line": _line_for(module.path, "FOREGROUND_MAX_TIMEOUT ="),
                },
                "inputs": {
                    "TERMINAL_MAX_FOREGROUND_TIMEOUT": {
                        "canonical_value": 600,
                        "type": "integer",
                    }
                },
                "effect": "substitute-description-value",
                "affected_fields": [
                    "/parameters/properties/timeout/description"
                ],
            }
        ]
    return []


def build_inventory(
    source_root: Path,
    handler_csv: Path,
    version: str,
    revision: str,
    generation_command: str,
    *,
    expected_count: int | None = EXPECTED_HANDLER_COUNT,
) -> dict[str, Any]:
    source_root = source_root.resolve()
    handler_csv = handler_csv.resolve()
    handlers = read_handlers(handler_csv)
    if expected_count is not None and len(handlers) != expected_count:
        raise ValueError(
            f"expected {expected_count} handler rows in {handler_csv}, found {len(handlers)}"
        )

    modules: dict[Path, StaticModule] = {}
    handler_names = {handler.tool_name for handler in handlers}
    registrations_by_name: dict[str, list[Registration]] = {
        name: [] for name in handler_names
    }
    tools_root = source_root / "tools"
    for registration_file in sorted(tools_root.glob("*.py")):
        module = StaticModule(
            registration_file,
            source_root=source_root,
            module_cache=modules,
        )
        for registration in module.literal_registrations(handler_names):
            registrations_by_name[registration.tool_name].append(registration)

    for tool_name, matches in sorted(registrations_by_name.items()):
        if len(matches) != 1:
            locations = [f"{match.file}:{match.line}" for match in matches]
            raise StaticResolutionError(
                f"expected exactly one production literal registry.register for "
                f"{tool_name!r}, found {len(matches)}: {locations}"
            )

    tools: list[dict[str, Any]] = []
    for handler in handlers:
        handler_file = (source_root / handler.file).resolve()
        try:
            handler_file.relative_to(source_root)
        except ValueError as error:
            raise ValueError(f"handler path escapes source root: {handler.file}") from error
        if not handler_file.is_file():
            raise ValueError(f"handler source does not exist: {handler_file}")
        registration = registrations_by_name[handler.tool_name][0]
        source_file = Path(registration.file)
        module = modules[source_file]
        try:
            raw_schema = module.eval_expr(
                registration.schema_node,
                registration.line,
            )
        except StaticResolutionError as error:
            raise StaticResolutionError(
                f"cannot resolve schema for {handler.tool_name!r}: {error}"
            ) from error
        if not isinstance(raw_schema, dict):
            raise StaticResolutionError(
                f"{source_file}:{registration.line}: schema for {handler.tool_name!r} "
                f"resolved to {type(raw_schema).__name__}, expected dict"
            )
        function = sanitize_function_specification(
            {**raw_schema, "name": handler.tool_name}
        )
        if function.get("name") != handler.tool_name:
            raise ValueError(f"name injection failed for {handler.tool_name}")
        if not isinstance(function.get("description"), str):
            raise ValueError(f"{handler.tool_name} has no string description")
        if not isinstance(function.get("parameters"), dict):
            raise ValueError(f"{handler.tool_name} has no object parameters schema")

        tools.append(
            {
                "tool_name": handler.tool_name,
                "handler": asdict(handler),
                "registration": {
                    "file": repo_path(source_file),
                    "line": registration.line,
                    "schema_expression": registration.schema_expression,
                },
                "function": function,
                "runtime_rules": _runtime_rules(
                    handler.tool_name,
                    module,
                    registration.line,
                    source_root,
                ),
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "project": {
            "name": "hermes-agent",
            "version": version,
            "revision": revision,
            "source_root": repo_path(source_root),
        },
        "handler_inventory": {
            "path": repo_path(handler_csv),
            "sha256": sha256_file(handler_csv),
            "count": len(handlers),
        },
        "generation_command": generation_command,
        "consumed_source_files": [
            repo_path(path) for path in sorted(modules)
        ],
        "tools": sorted(tools, key=lambda item: item["tool_name"]),
    }


def _fenced(text: str, language: str = "") -> str:
    runs = [len(match.group(0)) for match in re.finditer(r"`+", text)]
    fence = "`" * max(3, (max(runs) + 1) if runs else 3)
    return f"{fence}{language}\n{text}\n{fence}"


def render_markdown(inventory: Mapping[str, Any]) -> str:
    project = inventory["project"]
    handler_inventory = inventory["handler_inventory"]
    tools = inventory["tools"]
    lines = [
        "# Hermes-Agent Tool Handler Specifications",
        "",
        "> Generation command (repository root): "
        f"`{inventory['generation_command']}`",
        "",
        "> Generated file. Do not edit by hand.",
        "",
        f"- Benchmark: `{project['name']}` `{project['version']}` / `{project['revision']}`",
        f"- Source root: `{project['source_root']}`",
        f"- Handler inventory: `{handler_inventory['path']}`",
        f"- Handler inventory SHA-256: `{handler_inventory['sha256']}`",
        f"- Tool specifications: **{len(tools)}**",
        "",
        "Each `function` below is the canonical model-facing `{name, description, parameters}` "
        "definition after registry name injection and schema sanitization. Runtime-dependent "
        "changes are recorded separately and are not expanded into duplicate tool records.",
        "",
    ]
    for tool in tools:
        handler = tool["handler"]
        registration = tool["registration"]
        function = tool["function"]
        lines.extend(
            [
                f"## `{tool['tool_name']}`",
                "",
                f"- Handler: `{handler['handler_func']}` ({handler['form']}) at "
                f"`{handler['file']}:{handler['line']}`",
                f"- Forwarded body: `{handler['forwarded_body']}`",
                f"- Registration: `{registration['file']}:{registration['line']}`",
                f"- Schema expression: `{registration['schema_expression']}`",
                "",
                "### Description",
                "",
                _fenced(function["description"], "text"),
                "",
                "### Parameters",
                "",
                _fenced(
                    json.dumps(function["parameters"], ensure_ascii=False, indent=2, sort_keys=True),
                    "json",
                ),
                "",
                "### Runtime rules",
                "",
            ]
        )
        if tool["runtime_rules"]:
            lines.extend(
                [
                    _fenced(
                        json.dumps(tool["runtime_rules"], ensure_ascii=False, indent=2, sort_keys=True),
                        "json",
                    ),
                    "",
                ]
            )
        else:
            lines.extend(["None.", ""])
    return "\n".join(lines).rstrip() + "\n"


def write_artifacts(
    inventory: Mapping[str, Any], out_json: Path, out_md: Path
) -> None:
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(
        json.dumps(inventory, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    out_md.write_text(render_markdown(inventory), encoding="utf-8")


def generation_command(arguments: Sequence[str]) -> str:
    command = ["python", repo_path(SCRIPT_PATH), *arguments]
    return shlex.join(command)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handler-csv", type=Path, default=DEFAULT_HANDLER_CSV)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--analysis-revision")
    parser.add_argument("--out-json", type=Path, default=DEFAULT_OUT_JSON)
    parser.add_argument("--out-md", type=Path, default=DEFAULT_OUT_MD)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    raw_arguments = list(sys.argv[1:] if argv is None else argv)
    args = parse_args(raw_arguments)
    version, benchmark_revision = read_benchmark_identity(DEFAULT_BENCHMARK_README)
    revision = args.analysis_revision or benchmark_revision
    inventory = build_inventory(
        args.source_root,
        args.handler_csv,
        version,
        revision,
        generation_command(raw_arguments),
    )
    write_artifacts(inventory, args.out_json, args.out_md)
    print(
        f"Wrote {len(inventory['tools'])} Hermes tool specifications to "
        f"{repo_path(args.out_json)} and {repo_path(args.out_md)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
