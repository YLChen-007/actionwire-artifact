from __future__ import annotations

import csv
import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src.handler_specifications import hermes
from src.handler_specifications.core import (
    AdapterResult,
    HANDLER_FIELDS,
    HandlerEntry,
    SpecificationError,
    build_inventory,
    ensure_within,
    group_handlers,
    render_markdown,
    sha256_file,
    validate_function,
    write_artifacts,
)
from src.handler_specifications.service import build_all_inventories
from src.handler_specifications.typescript_adapters import _run_bridge
from src.projects import get_project, list_projects


REPO_ROOT = Path(__file__).resolve().parents[3]


class StaticFailureTests(unittest.TestCase):
    def test_path_traversal_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            root.mkdir()
            outside = Path(directory) / "outside.py"
            outside.write_text("pass\n", encoding="utf-8")
            with self.assertRaisesRegex(SpecificationError, "escapes root"):
                ensure_within(root, "../outside.py")

    def test_unsafe_python_call_reports_ast(self) -> None:
        module = hermes.StaticModule.from_source(
            'SCHEMA = os.getenv("SCHEMA")\n', Path("unsafe.py")
        )
        with self.assertRaisesRegex(
            hermes.StaticResolutionError, r"unsupported call shape; AST=Call"
        ):
            module.resolve_name("SCHEMA", 2)

    def test_unsupported_typescript_call_reports_file_line_and_shape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_root = Path(directory)
            source = source_root / "tool.ts"
            source.write_text(
                "export function createTool() {\n"
                "  return {\n"
                "    name: 'bad',\n"
                "    description: 'bad schema',\n"
                "    parameters: JSON.parse('{}'),\n"
                "    execute: async () => null,\n"
                "  };\n"
                "}\n",
                encoding="utf-8",
            )
            spec = get_project("openclaw").with_overrides(
                source_root=source_root,
                analysis_revision="a" * 40,
            )
            with self.assertRaisesRegex(
                SpecificationError,
                r"tool\.ts:5:.*unsupported static call.*AST=CallExpression",
            ):
                _run_bridge(
                    spec,
                    [
                        {
                            "tool_name": "bad",
                            "file": "tool.ts",
                            "line": 6,
                            "handler_func": "execute",
                        }
                    ],
                )


class CoreContractTests(unittest.TestCase):
    def test_duplicate_handler_rows_group_under_one_tool(self) -> None:
        entries = [
            HandlerEntry("read", "wrapper-a", "execute", "a.ts", 2, "-"),
            HandlerEntry("read", "wrapper-b", "execute", "b.ts", 3, "-"),
        ]
        grouped = group_handlers(entries)
        self.assertEqual(list(grouped), ["read"])
        self.assertEqual(len(grouped["read"]), 2)

    def test_function_schema_is_exact(self) -> None:
        valid = {
            "name": "demo",
            "description": "demo",
            "parameters": {"type": "object", "properties": {}},
        }
        validate_function("demo", valid)
        with self.assertRaisesRegex(SpecificationError, "exactly"):
            validate_function("demo", {**valid, "extra": True})

    def test_source_and_inventory_hashes_are_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "tool.py"
            source.write_text("def call():\n    pass\n", encoding="utf-8")
            handlers = root / "handlers.csv"
            with handlers.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=HANDLER_FIELDS)
                writer.writeheader()
                writer.writerow(
                    {
                        "tool_name": "demo",
                        "form": "fixture",
                        "handler_func": "call",
                        "file": "tool.py",
                        "line": "1",
                        "forwarded_body": "-",
                    }
                )
            spec = get_project("QwenPaw").with_overrides(
                source_root=root,
                analysis_revision="b" * 40,
            )
            result = AdapterResult(
                "demo",
                "function-tool",
                {
                    "name": "demo",
                    "description": "demo",
                    "parameters": {"type": "object", "properties": {}},
                },
                [
                    {
                        "kind": "fixture",
                        "file": str(source),
                        "line": 1,
                        "sha256": sha256_file(source),
                    }
                ],
            )
            inventory = build_inventory(
                spec, handlers, {"demo": result}, "python fixture.py"
            )
            handler_digest = sha256_file(handlers)
            source_digest = sha256_file(source)
            self.assertEqual(
                inventory["inputs"]["handler_inventory"]["sha256"],
                handler_digest,
            )
            self.assertEqual(
                inventory["inputs"]["source_files"],
                [{"path": str(source), "sha256": source_digest}],
            )

    def test_render_failure_does_not_replace_existing_pair(self) -> None:
        inventory = build_all_inventories()[0][1]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            out_json = output / "tool-handler-specifications.json"
            out_md = output / "tool-handler-specifications.md"
            out_json.write_text("old-json\n", encoding="utf-8")
            out_md.write_text("old-md\n", encoding="utf-8")
            with mock.patch(
                "src.handler_specifications.core.render_markdown",
                side_effect=SpecificationError("render failed"),
            ):
                with self.assertRaisesRegex(SpecificationError, "render failed"):
                    write_artifacts(inventory, output)
            self.assertEqual(out_json.read_text(encoding="utf-8"), "old-json\n")
            self.assertEqual(out_md.read_text(encoding="utf-8"), "old-md\n")

    def test_all_project_build_failure_writes_nothing(self) -> None:
        from src.handler_specifications import service

        with mock.patch.object(
            service, "build_all_inventories", side_effect=SpecificationError("fixture")
        ), mock.patch.object(service, "write_project_inventory") as writer:
            with self.assertRaisesRegex(SpecificationError, "fixture"):
                service.generate_all()
            writer.assert_not_called()


class RegisteredProjectSnapshots(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.built = build_all_inventories()

    def test_all_registered_projects_and_counts(self) -> None:
        expected = {
            "AstrBot": (27, 27, 26, 1),
            "QwenPaw": (23, 22, 22, 0),
            "chatgpt-on-wechat": (14, 14, 14, 0),
            "droidclaw": (20, 20, 20, 0),
            "hermes-agent": (67, 67, 67, 0),
            "lettabot": (8, 8, 8, 0),
            "mercury-agent": (51, 51, 51, 0),
            "nanobot": (11, 11, 10, 1),
            "nanoclaw": (15, 15, 15, 0),
            "openclaw": (27, 24, 21, 3),
            "openclaw-cn": (28, 25, 22, 3),
            "poco-agent": (25, 25, 25, 0),
        }
        self.assertEqual(len(self.built), 12)
        self.assertEqual(
            [spec.project_id for spec, _ in self.built], list(list_projects())
        )
        for spec, inventory in self.built:
            counts = inventory["counts"]
            self.assertEqual(
                (
                    counts["handler_rows"],
                    counts["unique_tools"],
                    counts["resolved"],
                    counts["unresolved"],
                ),
                expected[spec.project_id],
            )
        totals = {
            key: sum(inventory["counts"][key] for _, inventory in self.built)
            for key in ("handler_rows", "unique_tools", "resolved", "unresolved")
        }
        self.assertEqual(
            totals,
            {
                "handler_rows": 316,
                "unique_tools": 309,
                "resolved": 301,
                "unresolved": 8,
            },
        )

    def test_registry_covers_every_benchmark_project_directory(self) -> None:
        discovered = {
            project.resolve()
            for language in ("python", "typescript")
            for project in (REPO_ROOT / "benchmark" / language).iterdir()
            if project.is_dir()
        }
        registered = {
            get_project(project_id).source_root.resolve()
            for project_id in list_projects()
        }
        self.assertEqual(discovered, registered)

    def test_revisions_and_markdown_commands_are_pinned(self) -> None:
        for spec, inventory in self.built:
            with self.subTest(project=spec.project_id):
                self.assertEqual(
                    inventory["project"]["analysis_revision"],
                    spec.analysis_revision,
                )
                markdown = render_markdown(inventory).splitlines()
                self.assertTrue(markdown[2].startswith("> Reproduction command"))
                self.assertIn(
                    "python -m src.handler_specifications --all", markdown[2]
                )

    def test_serialization_is_byte_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = {}
            second = {}
            for spec, inventory in self.built:
                output = root / spec.project_id
                paths = write_artifacts(inventory, output)
                first[spec.project_id] = tuple(
                    hashlib.sha256(path.read_bytes()).hexdigest() for path in paths
                )
                paths = write_artifacts(inventory, output)
                second[spec.project_id] = tuple(
                    hashlib.sha256(path.read_bytes()).hexdigest() for path in paths
                )
            self.assertEqual(first, second)

    def test_dynamic_mcp_boundaries_are_explicit(self) -> None:
        by_project = {spec.project_id: inventory for spec, inventory in self.built}
        for project_id in ("AstrBot", "nanobot"):
            tool = next(
                item
                for item in by_project[project_id]["tools"]
                if item["tool_name"] == "mcp-dynamic"
            )
            self.assertIsNone(tool["function"])
            self.assertEqual(tool["resolution"]["status"], "unresolved")

        unresolved = {
            (project_id, tool["tool_name"])
            for project_id, inventory in by_project.items()
            for tool in inventory["tools"]
            if tool["resolution"]["status"] == "unresolved"
        }
        self.assertEqual(
            unresolved,
            {
                ("AstrBot", "mcp-dynamic"),
                ("nanobot", "mcp-dynamic"),
                *((project_id, name) for project_id in ("openclaw", "openclaw-cn")
                  for name in ("edit", "read", "write")),
            },
        )

    def test_lettabot_vendored_definitions_are_resolved(self) -> None:
        inventory = next(
            inventory
            for spec, inventory in self.built
            if spec.project_id == "lettabot"
        )
        tools = {tool["tool_name"]: tool for tool in inventory["tools"]}
        vendored = {"Bash", "Edit", "Glob", "Grep", "Read", "Task", "Write"}
        self.assertEqual(vendored | {"manage_todo"}, set(tools))
        for tool_name in vendored:
            with self.subTest(tool=tool_name):
                tool = tools[tool_name]
                self.assertEqual("resolved", tool["resolution"]["status"])
                self.assertTrue(tool["function"]["description"].startswith(f"# {tool_name}"))
                self.assertEqual("object", tool["function"]["parameters"]["type"])
                self.assertEqual(
                    {
                        "typescript-handler-function",
                        "vendored-tool-definition",
                        "vendored-json-schema",
                        "vendored-markdown-description",
                    },
                    {evidence["kind"] for evidence in tool["evidence"]},
                )

    def test_legacy_hermes_launcher_matches_new_cli(self) -> None:
        legacy = REPO_ROOT / (
            "design/hermes-agent/handler-entry/debug/script/"
            "generate_tool_handler_specifications.py"
        )
        subprocess.run(["python", str(legacy)], cwd=REPO_ROOT, check=True)
        output = REPO_ROOT / "output/hermes/handler-specifications"
        legacy_hashes = tuple(
            hashlib.sha256((output / name).read_bytes()).hexdigest()
            for name in (
                "tool-handler-specifications.json",
                "tool-handler-specifications.md",
            )
        )
        subprocess.run(
            ["python", "-m", "src.handler_specifications", "--project", "hermes-agent"],
            cwd=REPO_ROOT,
            check=True,
        )
        new_hashes = tuple(
            hashlib.sha256((output / name).read_bytes()).hexdigest()
            for name in (
                "tool-handler-specifications.json",
                "tool-handler-specifications.md",
            )
        )
        self.assertEqual(legacy_hashes, new_hashes)


if __name__ == "__main__":
    unittest.main()
