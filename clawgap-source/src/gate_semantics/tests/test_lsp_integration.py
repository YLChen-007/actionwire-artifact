"""Real LSP-MCP integration tests for the supported source languages."""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any, AsyncIterator

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError:  # pragma: no cover - exercised by the skip condition
    ClientSession = None  # type: ignore[assignment,misc]
    StdioServerParameters = None  # type: ignore[assignment,misc]
    stdio_client = None  # type: ignore[assignment]

from src.gate_semantics.agent_sdk import LSP_BIN_DIR, LSP_BRIDGE, LSP_TOOL_NAMES


REPO_ROOT = Path(__file__).resolve().parents[3]
HERMES_ROOT = REPO_ROOT / "benchmark/python/hermes-agent"
TOOL_TIMEOUT = timedelta(seconds=60)
MCP_AVAILABLE = ClientSession is not None and LSP_BRIDGE.is_file()


def _position(source: str, needle: str) -> tuple[int, int]:
    for line_number, line in enumerate(source.splitlines()):
        character = line.find(needle)
        if character >= 0:
            return line_number, character
    raise AssertionError(f"missing test symbol: {needle}")


@unittest.skipUnless(MCP_AVAILABLE, "install the pinned SDK and LSP-MCP bridge")
class LSPMCPIntegrationTest(unittest.IsolatedAsyncioTestCase):
    @asynccontextmanager
    async def lsp_session(
        self, root: Path, languages: list[str]
    ) -> AsyncIterator[Any]:
        assert StdioServerParameters is not None
        assert stdio_client is not None
        server = StdioServerParameters(
            command=str(LSP_BRIDGE),
            env={
                **os.environ,
                "LSP_MCP_LOG_LEVEL": "error",
                "PATH": f"{LSP_BIN_DIR}{os.pathsep}{os.environ.get('PATH', '')}",
                "NODE_PATH": str(LSP_BIN_DIR.parent),
            },
        )
        with tempfile.TemporaryFile(mode="w+") as stderr:
            async with stdio_client(server, errlog=stderr) as (read, write):
                assert ClientSession is not None
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    listed = await session.list_tools()
                    listed_names = {tool.name for tool in listed.tools}
                    self.assertTrue(set(LSP_TOOL_NAMES).issubset(listed_names))
                    initialized = await self.call_text(
                        session,
                        "lsp_init",
                        {"root": str(root.resolve()), "languages": languages},
                    )
                    self.assertIn("0 errors", initialized)
                    yield session

    async def call_text(
        self, session: Any, tool_name: str, arguments: dict[str, Any] | None = None
    ) -> str:
        result = await session.call_tool(
            tool_name,
            arguments or {},
            read_timeout_seconds=TOOL_TIMEOUT,
        )
        self.assertFalse(result.isError, f"{tool_name} failed: {result.content}")
        return "\n".join(getattr(item, "text", str(item)) for item in result.content)

    @unittest.skipUnless(
        shutil.which("pyright-langserver"), "pyright-langserver is required"
    )
    async def test_python_navigation_on_hermes(self) -> None:
        call_file = HERMES_ROOT / "tools/browser_tool.py"
        definition_file = HERMES_ROOT / "tools/website_policy.py"
        call_source = call_file.read_text(encoding="utf-8")
        definition_source = definition_file.read_text(encoding="utf-8")
        call_line, call_character = _position(
            call_source, "check_website_access(url)"
        )
        definition_line, definition_character = _position(
            definition_source, "def check_website_access"
        )
        definition_character += len("def ")

        async with self.lsp_session(HERMES_ROOT, ["python"]) as session:
            health = await self.call_text(session, "lsp_health")
            self.assertIn("python", health.lower())
            self.assertIn("ready", health.lower())
            self.assertNotIn("typescript", health.lower())

            definitions = await self.call_text(
                session,
                "lsp_definition",
                {
                    "file": str(call_file),
                    "line": call_line,
                    "character": call_character,
                },
            )
            self.assertIn("tools/website_policy.py:232", definitions)

            references = await self.call_text(
                session,
                "lsp_references",
                {
                    "file": str(definition_file),
                    "line": definition_line,
                    "character": definition_character,
                },
            )
            self.assertIn("tools/browser_tool.py:2116", references)
            self.assertIn("tools/vision_tools.py", references)

            document_symbols = await self.call_text(
                session,
                "lsp_document_symbols",
                {"file": str(definition_file)},
            )
            self.assertIn("check_website_access", document_symbols)
            self.assertIn("_DEFAULT_WEBSITE_BLOCKLIST", document_symbols)

            workspace_symbols = await self.call_text(
                session,
                "lsp_workspace_symbols",
                {"query": "check_website_access"},
            )
            self.assertIn("tools/website_policy.py:232", workspace_symbols)

            diagnostics = await self.call_text(
                session,
                "lsp_diagnostics",
                {"file": str(definition_file), "scope": "file"},
            )
            self.assertTrue(diagnostics.strip())

            type_definitions = await self.call_text(
                session,
                "lsp_type_definition",
                {
                    "file": str(definition_file),
                    "line": definition_line,
                    "character": definition_character,
                },
            )
            self.assertTrue(type_definitions.strip())

            implementations = await self.call_text(
                session,
                "lsp_implementation",
                {
                    "file": str(definition_file),
                    "line": definition_line,
                    "character": definition_character,
                },
            )
            self.assertTrue(implementations.strip())

    @unittest.skipUnless(
        (LSP_BIN_DIR / "typescript-language-server").is_file()
        or shutil.which("typescript-language-server"),
        "typescript-language-server is required",
    )
    async def test_typescript_navigation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            library = root / "library.ts"
            caller = root / "main.ts"
            library_source = """\
export interface Greeter {
  greet(name: string): string;
}

export class BasicGreeter implements Greeter {
  greet(name: string): string {
    return `Hello ${name}`;
  }
}

export function welcome(greeter: Greeter, name: string): string {
  return greeter.greet(name);
}
"""
            caller_source = """\
import { BasicGreeter, welcome } from "./library";

const greeter = new BasicGreeter();
console.log(welcome(greeter, "Ada"));
"""
            library.write_text(library_source, encoding="utf-8")
            caller.write_text(caller_source, encoding="utf-8")
            call_line, call_character = _position(caller_source, "welcome(greeter")
            interface_line, interface_character = _position(
                library_source, "Greeter"
            )

            async with self.lsp_session(root, ["typescript"]) as session:
                health = await self.call_text(session, "lsp_health")
                self.assertIn("typescript", health.lower())
                self.assertIn("ready", health.lower())
                self.assertNotIn("python", health.lower())

                definitions = await self.call_text(
                    session,
                    "lsp_definition",
                    {
                        "file": str(caller),
                        "line": call_line,
                        "character": call_character,
                    },
                )
                self.assertIn("main.ts:1", definitions)

                references = await self.call_text(
                    session,
                    "lsp_references",
                    {
                        "file": str(library),
                        "line": interface_line,
                        "character": interface_character,
                    },
                )
                self.assertIn("library.ts", references)

                document_symbols = await self.call_text(
                    session,
                    "lsp_document_symbols",
                    {"file": str(library)},
                )
                self.assertIn("BasicGreeter", document_symbols)
                self.assertIn("welcome", document_symbols)

                workspace_symbols = await self.call_text(
                    session,
                    "lsp_workspace_symbols",
                    {"query": "welcome"},
                )
                self.assertIn("library.ts", workspace_symbols)

                diagnostics = await self.call_text(
                    session,
                    "lsp_diagnostics",
                    {"file": str(caller), "scope": "file"},
                )
                self.assertTrue(diagnostics.strip())

                type_definitions = await self.call_text(
                    session,
                    "lsp_type_definition",
                    {
                        "file": str(library),
                        "line": interface_line,
                        "character": interface_character,
                    },
                )
                self.assertTrue(type_definitions.strip())

                implementations = await self.call_text(
                    session,
                    "lsp_implementation",
                    {
                        "file": str(library),
                        "line": interface_line,
                        "character": interface_character,
                    },
                )
                self.assertIn("library.ts:5", implementations)


if __name__ == "__main__":
    unittest.main()
