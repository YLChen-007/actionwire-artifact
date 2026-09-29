from __future__ import annotations

import csv
import io
import json
import os
import tempfile
import unittest
import urllib.error
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from src.call_chain_semantics.v3 import ChainV3Error, assemble_all_chains
from src.gate_semantics.behavior_checker import build_behavior_profile
from src.pipeline.codeql import CodeQLPipelineError, preflight_project, run_query
from src.pipeline.orchestrator import _record_pipeline_stage
from src.pipeline.provider import OpenAICompatibleRunner, _decode_response
from src.pipeline.static_stages import (
    _attach_chain_gates,
    _catalog_match,
    _canonical_chains,
    _sink_card,
    _sink_constraints,
)
from src.projects import LLMConfig, ProjectSpec, get_project, list_projects


def write_csv(path: Path, fields: list[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


class RegistryAndProviderTest(unittest.TestCase):
    def test_registry_has_explicit_revisions_and_environment_only_llm(self) -> None:
        self.assertEqual(
            (
                "AstrBot",
                "QwenPaw",
                "chatgpt-on-wechat",
                "droidclaw",
                "hermes-agent",
                "lettabot",
                "mercury-agent",
                "nanobot",
                "nanoclaw",
                "openclaw",
                "openclaw-cn",
                "poco-agent",
            ),
            list_projects(),
        )
        astrbot = get_project("AstrBot")
        self.assertEqual(
            "0e973bd4d483d18e1672c4dfa2eb7aae31bc1f83",
            astrbot.analysis_revision,
        )
        self.assertEqual("astrbot", astrbot.codeql_adapter)
        self.assertEqual("DEEPSEEK_API_KEY", astrbot.llm.api_key_env)
        self.assertEqual((), astrbot.semantic_profiles)
        self.assertEqual("AstrBot", astrbot.output_root.name)

        cow = get_project("chatgpt-on-wechat")
        self.assertEqual(
            "55aaf60a57ea6e9f4b8a54797572d98f65e88d2f",
            cow.analysis_revision,
        )
        self.assertEqual("cowagent", cow.codeql_adapter)
        self.assertEqual("DEEPSEEK_API_KEY", cow.llm.api_key_env)
        self.assertEqual((), cow.semantic_profiles)
        self.assertNotIn("hermes", str(cow.output_root))

        expected = {
            "QwenPaw": (
                "6d1e936f1ba08ad2e0398367f8c27529e9d1d5df",
                "qwenpaw",
            ),
            "nanobot": (
                "337c4600f3d78797bb4ed845b5a02118c7ac2d00",
                "nanobot",
            ),
            "poco-agent": (
                "7a61cb9f0e871f75f5623448f849f1e3d1958e35",
                "poco-agent",
            ),
        }
        for project_id, (revision, adapter) in expected.items():
            with self.subTest(project=project_id):
                spec = get_project(project_id)
                self.assertEqual(revision, spec.analysis_revision)
                self.assertEqual(adapter, spec.codeql_adapter)
                self.assertEqual("DEEPSEEK_API_KEY", spec.llm.api_key_env)
                self.assertEqual((), spec.semantic_profiles)
                self.assertEqual(project_id, spec.output_root.name)

        openclaw = get_project("openclaw")
        self.assertEqual(
            "d842b28a1517f95aae2a5bcd97f2f726e42b93d8",
            openclaw.analysis_revision,
        )
        self.assertEqual("openclaw-ts", openclaw.codeql_adapter)
        self.assertEqual("typescript", openclaw.source_language)
        self.assertEqual("javascript", openclaw.codeql_language)
        self.assertEqual("ql-js", openclaw.query_pack.name)

        nanoclaw = get_project("nanoclaw")
        self.assertEqual(
            "36cbf17e107fd0f8daea4ceb2ac523d9f0d88915",
            nanoclaw.analysis_revision,
        )
        self.assertEqual("nanoclaw-ts", nanoclaw.codeql_adapter)
        self.assertEqual("typescript", nanoclaw.source_language)
        self.assertEqual("javascript", nanoclaw.codeql_language)
        self.assertEqual("ql-js", nanoclaw.query_pack.name)
        self.assertEqual("DEEPSEEK_API_KEY", nanoclaw.llm.api_key_env)

        expected_typescript = {
            "openclaw-cn": (
                "558f272e6c90e7e0c37644e505e161b91ef738f0",
                "openclaw-cn-ts",
            ),
            "mercury-agent": ("587fad1bf9449598d1b27833f8c7db55d164741a", "mercury-agent-ts"),
            "droidclaw": ("c7c991933e4a0c03cec6044aa7fb9067d391f4d4", "droidclaw-ts"),
            "lettabot": ("99c3b5dd73550fe0a4eac2ee31b1c3229ca9e550", "lettabot-ts"),
        }
        for project_id, (revision, adapter) in expected_typescript.items():
            with self.subTest(project_id=project_id):
                project = get_project(project_id)
                self.assertEqual(revision, project.analysis_revision)
                self.assertEqual(adapter, project.codeql_adapter)
                self.assertEqual("typescript", project.source_language)
                self.assertEqual("javascript", project.codeql_language)
                self.assertEqual("ql-js", project.query_pack.name)
                self.assertEqual("DEEPSEEK_API_KEY", project.llm.api_key_env)

        openclaw_cn = get_project("openclaw-cn")
        self.assertIn("extensions", openclaw_cn.extraction_exclusions)
        self.assertEqual(
            (
                "extensions/feishu/src/outbound.ts",
                "extensions/feishu/src/media.ts",
            ),
            openclaw_cn.extraction_inclusions,
        )

    def test_path_and_revision_overrides_are_resolved(self) -> None:
        cow = get_project("chatgpt-on-wechat").with_overrides(
            source_root=Path("benchmark/python/chatgpt-on-wechat"),
            output_root=Path("relative-output"),
            analysis_revision="fixture-revision",
        )
        self.assertTrue(cow.source_root.is_absolute())
        self.assertTrue(cow.output_root.is_absolute())
        self.assertEqual("fixture-revision", cow.analysis_revision)

    def test_retired_projects_are_not_registered(self) -> None:
        for project_id in ("LobsterAI", "codeg", "tinyclaw"):
            with self.subTest(project=project_id):
                with self.assertRaisesRegex(KeyError, "unknown project"):
                    get_project(project_id)

    def test_provider_uses_v1_contract_without_auditing_secret(self) -> None:
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self) -> bytes:
                return json.dumps(
                    {
                        "choices": [{"message": {"content": "  result  "}}],
                        "usage": {
                            "prompt_tokens": 3,
                            "completion_tokens": 2,
                            "total_tokens": 5,
                        },
                    }
                ).encode()

        runner = OpenAICompatibleRunner(
            base_url="https://api.deepseek.com/v1/",
            model="deepseek-v4-flash",
        )
        with (
            patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-secret"}),
            patch("urllib.request.urlopen", return_value=Response()) as urlopen,
        ):
            self.assertEqual("result", runner("system", "user"))
        request = urlopen.call_args.args[0]
        self.assertEqual(
            "https://api.deepseek.com/v1/chat/completions", request.full_url
        )
        self.assertEqual(
            {"type": "json_object"},
            json.loads(request.data)["response_format"],
        )
        self.assertTrue(json.loads(request.data)["stream"])
        self.assertEqual(
            {"include_usage": True}, json.loads(request.data)["stream_options"]
        )
        self.assertEqual({"type": "disabled"}, json.loads(request.data)["thinking"])
        self.assertEqual(8192, json.loads(request.data)["max_tokens"])
        audit = runner.audit_payload()
        self.assertEqual("DEEPSEEK_API_KEY", audit["credential_env"])
        self.assertNotIn("test-secret", json.dumps(audit))
        self.assertEqual(5, audit["token_usage"]["total_tokens"])

    def test_provider_decodes_streamed_json_and_usage(self) -> None:
        raw = b"\n".join(
            [
                b'data: {"choices":[{"delta":{"reasoning_content":"hidden","content":null}}],"usage":null}',
                b'data: {"choices":[{"delta":{"content":"{\\"ok\\":"}}],"usage":null}',
                b'data: {"choices":[{"delta":{"content":"true}"}}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}',
                b"data: [DONE]",
            ]
        )
        content, usage = _decode_response(raw)
        self.assertEqual('{"ok":true}', content)
        self.assertEqual(5, usage["total_tokens"])

    def test_provider_retries_transient_http_failure(self) -> None:
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self) -> bytes:
                return json.dumps(
                    {"choices": [{"message": {"content": "{}"}}]}
                ).encode()

        busy = urllib.error.HTTPError(
            "https://api.deepseek.com/v1/chat/completions",
            503,
            "busy",
            {},
            io.BytesIO(b'{"error":"busy"}'),
        )
        runner = OpenAICompatibleRunner(
            base_url="https://api.deepseek.com/v1",
            model="deepseek-v4-flash",
        )
        with (
            patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-secret"}),
            patch("urllib.request.urlopen", side_effect=[busy, Response()]) as urlopen,
            patch("src.pipeline.provider.time.sleep"),
        ):
            self.assertEqual("{}", runner("system", "user"))

        self.assertEqual(2, urlopen.call_count)
        audit = runner.audit_payload()
        self.assertEqual(1, len(audit["calls"][0]["transient_errors"]))
        self.assertNotIn("test-secret", json.dumps(audit))

    def test_provider_retries_transient_deepseek_edge_resets(self) -> None:
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self) -> bytes:
                return json.dumps(
                    {"choices": [{"message": {"content": "{}"}}]}
                ).encode()

        edge_405 = urllib.error.HTTPError(
            "https://api.deepseek.com/v1/chat/completions",
            405,
            "method not allowed",
            {},
            io.BytesIO(b""),
        )
        edge_551 = urllib.error.HTTPError(
            "https://api.deepseek.com/v1/chat/completions",
            551,
            "Connection Reset by EdgeOne",
            {},
            io.BytesIO(b""),
        )
        runner = OpenAICompatibleRunner(
            base_url="https://api.deepseek.com/v1",
            model="deepseek-v4-flash",
        )
        with (
            patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-secret"}),
            patch(
                "urllib.request.urlopen",
                side_effect=[
                    edge_405,
                    edge_551,
                    OSError("remote disconnected"),
                    Response(),
                ],
            ) as urlopen,
            patch("src.pipeline.provider.time.sleep"),
        ):
            self.assertEqual("{}", runner("system", "user"))

        self.assertEqual(4, urlopen.call_count)
        audit = runner.audit_payload()
        self.assertEqual(3, len(audit["calls"][0]["transient_errors"]))
        self.assertNotIn("test-secret", json.dumps(audit))

    def test_provider_audits_transients_when_all_retries_fail(self) -> None:
        failures = [
            urllib.error.HTTPError(
                "https://api.deepseek.com/v1/chat/completions",
                405,
                "method not allowed",
                {},
                io.BytesIO(b""),
            )
            for _ in range(5)
        ]
        runner = OpenAICompatibleRunner(
            base_url="https://api.deepseek.com/v1",
            model="deepseek-v4-flash",
        )
        with (
            patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-secret"}),
            patch("urllib.request.urlopen", side_effect=failures) as urlopen,
            patch("src.pipeline.provider.time.sleep"),
        ):
            with self.assertRaisesRegex(RuntimeError, "HTTP 405"):
                runner("system", "user")

        self.assertEqual(5, urlopen.call_count)
        call = runner.audit_payload()["calls"][0]
        self.assertEqual(4, len(call["transient_errors"]))
        self.assertIn("HTTP 405", call["error"])
        self.assertNotIn("test-secret", json.dumps(call))

    def test_provider_retries_empty_message_content(self) -> None:
        class Response:
            def __init__(self, content: str | None) -> None:
                self.content = content

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self) -> bytes:
                return json.dumps(
                    {"choices": [{"message": {"content": self.content}}]}
                ).encode()

        runner = OpenAICompatibleRunner(
            base_url="https://api.deepseek.com/v1",
            model="deepseek-v4-flash",
        )
        with (
            patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-secret"}),
            patch(
                "urllib.request.urlopen",
                side_effect=[Response(""), Response("{}")],
            ) as urlopen,
            patch("src.pipeline.provider.time.sleep"),
        ):
            self.assertEqual("{}", runner("system", "user"))

        self.assertEqual(2, urlopen.call_count)
        audit = runner.audit_payload()
        self.assertEqual(
            ["OpenAI-compatible response returned empty content"],
            audit["calls"][0]["transient_errors"],
        )

    def test_provider_does_not_retry_response_timeout(self) -> None:
        runner = OpenAICompatibleRunner(
            base_url="https://api.deepseek.com/v1",
            model="deepseek-v4-flash",
        )
        with (
            patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-secret"}),
            patch(
                "urllib.request.urlopen", side_effect=TimeoutError("response stalled")
            ) as urlopen,
            patch("src.pipeline.provider.time.sleep") as sleep,
        ):
            with self.assertRaisesRegex(RuntimeError, "response stalled"):
                runner("system", "user")

        self.assertEqual(1, urlopen.call_count)
        sleep.assert_not_called()

    def test_explicit_cow_project_never_uses_hermes_behavior_profile(self) -> None:
        payload = {
            "project": {"name": "chatgpt-on-wechat"},
            "gate": {"qualified_function": "tools.approval.detect_hardline_command"},
        }
        self.assertIsNone(build_behavior_profile(payload, Path("/does/not/matter")))


class StaticContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.spec = ProjectSpec(
            project_id="fixture",
            source_root=self.source,
            analysis_revision="revision",
            codeql_database=self.root / "db",
            design_root=self.root / "design",
            output_root=self.root / "output",
            ground_truth_root=self.root / "groundtruth",
            codeql_adapter="fixture",
            source_language="python",
            codeql_language="python",
            query_pack=self.root / "ql",
            llm=LLMConfig(),
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_chain_id_ignores_absolute_checkout_prefix(self) -> None:
        base = {
            "tool_name": "tool",
            "source_parameter": "args",
            "sink_label": "open",
            "sink_file": "tool.py",
            "sink_line": "8",
            "sink_column": "5",
            "sink_argument": "path",
        }
        first = {
            **base,
            "call_chain": "1#Tool.execute@tool.py->open@/checkout/a/tool.py$$8:5$$8:15",
        }
        second = {
            **base,
            "call_chain": "1#Tool.execute@tool.py->open@/other/root/tool.py$$8:5$$8:15",
        }
        self.assertEqual(
            _canonical_chains(self.spec, [first])[0]["chain_id"],
            _canonical_chains(self.spec, [second])[0]["chain_id"],
        )

    def test_chain_identity_merges_controlled_facets(self) -> None:
        base = {
            "tool_name": "write",
            "handler_file": "tool.ts",
            "handler_line": "8",
            "source_parameter": "args",
            "sink_label": "tool.execute",
            "sink_file": "tool.ts",
            "sink_line": "12",
            "sink_column": "5",
            "call_chain": "1#execute@tool.ts->tool.execute@tool.ts",
        }
        chains = _canonical_chains(
            self.spec,
            [
                {**base, "sink_argument": "path"},
                {**base, "sink_argument": "content"},
            ],
        )
        self.assertEqual(1, len(chains))
        self.assertEqual("content;path", chains[0]["sink_argument"])

    def test_one_constraint_per_concrete_sink_point(self) -> None:
        (self.source / "tool.py").write_text(
            "def read(path):\n    return open(path, 'r')\n", encoding="utf-8"
        )
        chains = [
            {
                "sink_id": "S-1111111111111111",
                "sink_label": "open",
                "sink_file": "tool.py",
                "sink_line": "2",
                "sink_column": "12",
                "sink_argument": "path",
            },
            {
                "sink_id": "S-1111111111111111",
                "sink_label": "open",
                "sink_file": "tool.py",
                "sink_line": "2",
                "sink_column": "12",
                "sink_argument": "encoding;path",
            },
        ]
        constraints = _sink_constraints(self.spec, chains)
        self.assertEqual(1, len(constraints))
        self.assertEqual("file-read", constraints[0]["capability_class"])
        self.assertEqual("encoding;path", constraints[0]["controlled_argument"])
        self.assertRegex(constraints[0]["capability_card_sha256"], r"^[0-9a-f]{64}$")

    def test_typescript_call_shape_and_constraint_cardinality(self) -> None:
        (self.source / "tool.ts").write_text(
            "function launch(spawnImpl: Function, argv: string[], options: object) {\n"
            "  return spawnImpl(argv[0], argv.slice(1), options);\n"
            "}\n",
            encoding="utf-8",
        )
        spec = replace(self.spec, source_language="typescript")
        common = {
            "sink_id": "S-2222222222222222",
            "sink_label": "spawnImpl",
            "sink_file": "tool.ts",
            "sink_line": "2",
            "sink_column": "10",
        }
        constraints = _sink_constraints(
            spec,
            [
                {**common, "sink_argument": "command"},
                {**common, "sink_argument": "argv"},
            ],
        )
        self.assertEqual(1, len(constraints))
        self.assertEqual("node:child_process.spawn", constraints[0]["sink_api"])
        self.assertEqual("argv;command", constraints[0]["controlled_argument"])
        self.assertIn("spawnImpl(argv[0]", constraints[0]["call_shape"])

    def test_project_sink_variants_select_capability_cards(self) -> None:
        self.assertEqual(
            (
                "openclaw-cn.browser-navigation.md",
                "CDP.Target.createTarget",
                "browser-navigation",
            ),
            _sink_card(
                "CDP.Target.createTarget",
                'send("Target.createTarget", { url: opts.url })',
            ),
        )
        self.assertEqual(
            ("node.child-process.md", "node-pty.spawn", "process-spawn"),
            _sink_card(
                "node-pty.spawn",
                "spawnPty(shell, [...shellArgs, opts.command], options)",
            ),
        )
        self.assertEqual(
            (
                "openclaw-cn.browser-navigation.md",
                "page.goto",
                "browser-navigation",
            ),
            _sink_card(
                "page.goto",
                "page.goto(targetUrl, { timeout: 30_000 })",
                enclosing_functions=("createPageViaPlaywright",),
            ),
        )
        self.assertEqual(
            (
                "openclaw-cn.browser-interaction.md",
                "locator.click",
                "browser-interaction",
            ),
            _sink_card("locator.click", "locator.click({ timeout })"),
        )
        self.assertEqual(
            ("openclaw-cn.code-eval.md", "page.evaluate", "code-eval"),
            _sink_card(
                "page.evaluate",
                "page.evaluate(browserEvaluator, fnText)",
            ),
        )
        self.assertEqual(
            ("_run_browser_command.eval.md", "_run_browser_command", "code-eval"),
            _sink_card(
                "_run_browser_command",
                '_run_browser_command(task_id, "eval", [expression])',
            ),
        )
        self.assertEqual(
            ("aiohttp.session.put.md", "aiohttp.ClientSession.put", "delivery-render"),
            _sink_card("session.put", "session.put(url, json=payload)"),
        )
        self.assertEqual(
            (
                "slack.chat_postMessage.md",
                "slack_sdk.WebClient.chat_postMessage",
                "delivery-render",
            ),
            _sink_card(
                "Attribute().chat_postMessage",
                "self._get_client(chat_id).chat_postMessage(**kwargs)",
            ),
        )
        self.assertEqual(
            ("pathlib.Path.open.md", "pathlib.Path.open", "file-read"),
            _sink_card("file_path.open", 'file_path.open("rb")'),
        )
        self.assertEqual(
            ("pathlib.Path.read_bytes.md", "pathlib.Path.read_bytes", "file-read"),
            _sink_card("read_bytes", "to_thread(Path(path).read_bytes)"),
        )
        self.assertEqual(
            ("builtins.open.write.md", "builtins.open", "file-write"),
            _sink_card(
                "open",
                "open(abs_path, mode, encoding=encoding)",
                enclosing_functions=("write_file", "_run"),
            ),
        )
        self.assertEqual(
            (
                "asyncio.create_subprocess_shell.md",
                "asyncio.create_subprocess_shell",
                "process-spawn",
            ),
            _sink_card(
                "asyncio.create_subprocess_shell",
                "asyncio.create_subprocess_shell(command)",
            ),
        )
        self.assertEqual(
            (
                "httpx.AsyncClient.post.md",
                "httpx.AsyncClient.post",
                "network-egress",
            ),
            _sink_card("client.post", "client.post(url, json=payload)"),
        )
        self.assertEqual(
            (
                "httpx.AsyncClient.request.md",
                "httpx.AsyncClient.request",
                "network-egress",
            ),
            _sink_card("client.request", "client.request(method, url, json=body)"),
        )
        self.assertEqual(
            ("openclaw.gateway-rpc.md", "callGatewayTool:config.patch", "rpc-boundary"),
            _sink_card(
                "callGatewayTool:config.patch",
                'callGatewayTool("config.patch", opts, payload)',
            ),
        )
        self.assertEqual(
            (
                "openclaw.chrome-mcp-rpc.md",
                "Chrome MCP client.callTool",
                "rpc-boundary",
            ),
            _sink_card(
                "Chrome MCP client.callTool",
                "client.callTool({ name, arguments: args })",
            ),
        )
        self.assertEqual(
            ("node.fs.copy.md", "node:fs.copyFileSync", "file-copy"),
            _sink_card(
                "copyFileSync",
                "fs.copyFileSync(source, destination)",
            ),
        )
        self.assertEqual(
            (
                "lobsterai.browser-navigation.md",
                "playwright.Page.goto",
                "browser-navigation",
            ),
            _sink_card(
                "page.goto",
                "opts.page.goto(opts.url, { timeout: opts.timeoutMs })",
            ),
        )
        self.assertEqual(
            (
                "codeg.external-agent-execution.md",
                "CodeG.Transport.call:acp_prompt",
                "external-agent-execution",
            ),
            _sink_card(
                "getTransport.call:acp_prompt",
                'getTransport().call("acp_prompt", { connectionId, blocks })',
            ),
        )
        self.assertEqual(
            (
                "tinyclaw.external-agent-execution.md",
                "node:child_process.spawn:external-agent-cli",
                "external-agent-execution",
            ),
            _sink_card(
                "spawn:external-agent-cli",
                "spawn(command, args, options)",
            ),
        )
        self.assertEqual(
            (
                "mercury.tool-capability-exposure.md",
                "ai.generateText.tools",
                "tool-capability-exposure",
            ),
            _sink_card(
                "generateText.tools",
                "generateText({ tools: this.capabilities.getTools() })",
            ),
        )
        droidclaw_actions = {
            "executeTap": ("droidclaw.device-tap.md", "device-tap"),
            "findAndTap": ("droidclaw.device-tap.md", "device-tap"),
            "executeType": ("droidclaw.device-text-input.md", "device-text-input"),
            "executeSwipe": ("droidclaw.device-swipe.md", "device-swipe"),
            "executeScroll": ("droidclaw.device-swipe.md", "device-swipe"),
            "executeLaunch": ("droidclaw.app-launch.md", "app-launch"),
            "executeSwitchApp": ("droidclaw.app-launch.md", "app-launch"),
            "executePaste": ("droidclaw.clipboard-paste.md", "clipboard-paste"),
            "executeScreenshot": ("droidclaw.screen-capture.md", "screen-capture"),
            "executeLongPress": (
                "droidclaw.device-long-press.md",
                "device-long-press",
            ),
            "executeClipboardSet": (
                "droidclaw.clipboard-write.md",
                "clipboard-write",
            ),
            "copyVisibleText": ("droidclaw.clipboard-write.md", "clipboard-write"),
            "executeOpenUrl": (
                "droidclaw.browser-navigation.md",
                "browser-navigation",
            ),
            "executeKeyevent": (
                "droidclaw.device-keyevent.md",
                "device-keyevent",
            ),
            "executeOpenSettings": (
                "droidclaw.settings-navigation.md",
                "settings-navigation",
            ),
            "executePullFile": (
                "droidclaw.device-file-pull.md",
                "device-file-pull",
            ),
            "executePushFile": (
                "droidclaw.device-file-push.md",
                "device-file-push",
            ),
            "executeShell": (
                "droidclaw.adb-shell-execution.md",
                "adb-shell-execution",
            ),
            "composeEmail": ("droidclaw.email-compose.md", "email-compose"),
        }
        for label, (card, capability) in droidclaw_actions.items():
            self.assertEqual(
                (card, f"DroidClaw.{label}", capability),
                _sink_card(label, f"{label}(modelDecision)"),
            )
        nanoclaw_actions = {
            "create_agent": ("nanoclaw.agent-creation.md", "agent-creation"),
            "send_message": ("nanoclaw.message-delivery.md", "message-delivery"),
            "send_file": ("nanoclaw.file-delivery.md", "file-delivery"),
            "edit_message": ("nanoclaw.message-edit.md", "message-edit"),
            "add_reaction": ("nanoclaw.message-reaction.md", "message-reaction"),
            "ask_user_question": (
                "nanoclaw.interactive-question.md",
                "interactive-question",
            ),
            "send_card": ("nanoclaw.card-delivery.md", "card-delivery"),
            "schedule_task": ("nanoclaw.task-scheduling.md", "task-scheduling"),
            "list_tasks": ("nanoclaw.task-read.md", "task-read"),
            "cancel_task": ("nanoclaw.task-cancel.md", "task-cancel"),
            "pause_task": ("nanoclaw.task-pause.md", "task-pause"),
            "resume_task": ("nanoclaw.task-resume.md", "task-resume"),
            "update_task": ("nanoclaw.task-update.md", "task-update"),
            "install_packages": (
                "nanoclaw.package-installation.md",
                "package-installation",
            ),
            "add_mcp_server": (
                "nanoclaw.mcp-server-registration.md",
                "mcp-server-registration",
            ),
        }
        for label, (card, capability) in nanoclaw_actions.items():
            self.assertEqual(
                (card, f"NanoClaw.{label}", capability),
                _sink_card(label, f"{label}(args)"),
            )
        lettabot_actions = {
            "Bash": ("lettabot.command-execution.md", "command-execution"),
            "Read": ("lettabot.file-read.md", "file-read"),
            "Edit": ("lettabot.file-edit.md", "file-edit"),
            "Write": ("lettabot.file-write.md", "file-write"),
            "Glob": ("lettabot.file-enumeration.md", "file-enumeration"),
            "Grep": ("lettabot.content-search.md", "content-search"),
            "Task": ("lettabot.subagent-delegation.md", "subagent-delegation"),
        }
        for label, (card, capability) in lettabot_actions.items():
            self.assertEqual(
                (card, f"LettaCode.{label}", capability),
                _sink_card(label, f"{label}(args)"),
            )
        self.assertEqual(
            (
                "nanoclaw.approval-persistence.md",
                "better-sqlite3.Statement.run:pending_approvals",
                "approval-persistence",
            ),
            _sink_card("Statement.run:pending_approvals", "statement.run(payload)"),
        )
        self.assertEqual(
            (
                "nanoclaw.runtime-config-mutation.md",
                "better-sqlite3.Statement.run:container_configs.mcp_servers",
                "runtime-config-mutation",
            ),
            _sink_card("Statement.run:container_configs", "statement.run(config)"),
        )
        self.assertEqual(
            (
                "nanoclaw.approval-presentation.md",
                "ChannelDeliveryAdapter.deliver:approval-card",
                "approval-presentation",
            ),
            _sink_card("adapter.deliver:approval-card", "adapter.deliver(card)"),
        )
        with self.assertRaises(ValueError):
            _sink_card(
                "_run_browser_command", "_run_browser_command(task_id, command, args)"
            )

    def test_gate_order_uses_ordered_hops_and_excludes_needs_review(self) -> None:
        chain = {
            "chain_id": "C-111111111111",
            "sink_id": "S-1111111111111111",
            "sink_file": "tool.py",
            "sink_line": "30",
            "call_chain": (
                "2#Tool.execute@tool.py->Tool.helper@tool.py->"
                "open@/tmp/tool.py$$30:1$$30:9"
            ),
        }
        candidates = {
            "dominance": [
                {
                    "gate_fn": "helper_gate",
                    "gate_file": "tool.py",
                    "gate_line": "5",
                    "in_func": "helper",
                    "sink_file": "tool.py",
                    "sink_line": "30",
                    "taint_verdict": "confirmed",
                },
                {
                    "gate_fn": "entry_gate",
                    "gate_file": "tool.py",
                    "gate_line": "20",
                    "in_func": "execute",
                    "sink_file": "tool.py",
                    "sink_line": "30",
                    "taint_verdict": "branch-confirmed",
                },
                {
                    "gate_fn": "review_gate",
                    "gate_file": "tool.py",
                    "gate_line": "21",
                    "in_func": "execute",
                    "sink_file": "tool.py",
                    "sink_line": "30",
                    "taint_verdict": "needs-review",
                },
                {
                    "gate_fn": "off_chain_gate",
                    "gate_file": "tool.py",
                    "gate_line": "4",
                    "in_func": "unrelated",
                    "sink_file": "tool.py",
                    "sink_line": "30",
                    "taint_verdict": "confirmed",
                },
            ],
            "filter": [],
            "transform": [],
        }
        catalog = [
            {
                "gate_uid": "GU" + "1" * 20,
                "gate_id": "G-entry",
                "gate_name": "entry_gate",
                "callsite_file": "tool.py",
                "callsite_line": "20",
                "enclosing_function": "execute",
            },
            {
                "gate_uid": "GU" + "2" * 20,
                "gate_id": "G-helper",
                "gate_name": "helper_gate",
                "callsite_file": "tool.py",
                "callsite_line": "5",
                "enclosing_function": "helper",
            },
            {
                "gate_uid": "GU" + "3" * 20,
                "gate_id": "G-off-chain",
                "gate_name": "off_chain_gate",
                "callsite_file": "tool.py",
                "callsite_line": "4",
                "enclosing_function": "unrelated",
            },
        ]
        rows = _attach_chain_gates([chain], candidates, catalog)
        self.assertEqual(
            ["entry_gate", "helper_gate"], [row["gate_name"] for row in rows]
        )
        self.assertEqual([1, 2], [row["gate_seq"] for row in rows])

    def test_catalog_match_uses_checked_expression_at_shared_callsite(self) -> None:
        chain = {
            "chain_id": "C-111111111111",
            "sink_id": "S-1111111111111111",
            "sink_file": "tool.py",
            "sink_line": "30",
            "call_chain": "1#Tool.execute@tool.py->open@/tmp/tool.py$$30:1$$30:9",
        }
        candidate = {
            "gate_fn": "check",
            "gate_file": "tool.py",
            "gate_line": "10",
            "checked_expr": "command",
            "in_func": "execute",
            "sink_file": "tool.py",
            "sink_line": "30",
            "taint_verdict": "confirmed",
        }
        catalog = [
            {
                "gate_number": "1",
                "gate_uid": "GU" + "1" * 20,
                "gate_id": "G-path",
                "gate_name": "check",
                "callsite_file": "tool.py",
                "callsite_line": "10",
                "checked_expression": "path",
                "enclosing_function": "execute",
            },
            {
                "gate_number": "2",
                "gate_uid": "GU" + "2" * 20,
                "gate_id": "G-command",
                "gate_name": "check",
                "callsite_file": "tool.py",
                "callsite_line": "10",
                "checked_expression": "command",
                "enclosing_function": "execute",
            },
        ]

        rows = _attach_chain_gates(
            [chain], {"dominance": [candidate], "filter": [], "transform": []}, catalog
        )

        self.assertEqual("GU" + "2" * 20, rows[0]["gate_uid"])

    def test_lobsterai_policy_gates_follow_configuration_then_runtime_order(self) -> None:
        chain = {
            "chain_id": "C-lobster",
            "sink_id": "S-lobster",
            "project_id": "LobsterAI",
            "tool_name": "browser",
            "handler_func": "execute",
            "handler_file": "vendor/browser-tool.ts",
            "sink_file": "vendor/pw-session.ts",
            "sink_line": "829",
            "call_chain": (
                "5#execute@browser-tool.ts->assertBrowserNavigationAllowed@navigation-guard.ts->"
                "shouldSkipPrivateNetworkChecks@ssrf.ts->gotoPageWithNavigationGuard@pw-session.ts->"
                "page.goto@pw-session.ts"
            ),
        }
        names = [
            "MANAGED_BROWSER_POLICY_PROMPT",
            "isPrivateNetworkAllowedByPolicy",
            "buildBrowserConfig",
            "assertBrowserNavigationAllowed",
            "defaultBrowserWebAccessConfig",
        ]
        candidates = {
            "dominance": [
                {
                    "gate_fn": name,
                    "gate_file": "src/policy.ts",
                    "gate_line": str(index + 10),
                    "guard_kind": "[pre-handler] policy",
                    "in_func": "execute",
                    "handler_func": "execute",
                    "handler_file": "vendor/browser-tool.ts",
                    "tool_name": "browser",
                    "sink_file": "vendor/pw-session.ts",
                    "sink_line": "829",
                    "taint_verdict": "confirmed",
                }
                for index, name in enumerate(names)
            ],
            "filter": [],
            "transform": [],
        }
        catalog = [
            {
                "gate_number": str(index),
                "gate_uid": "GU" + str(index) * 20,
                "gate_id": f"G-{name}",
                "gate_name": name,
                "callsite_file": "src/policy.ts",
                "callsite_line": str(index + 9),
                "enclosing_function": "execute",
            }
            for index, name in enumerate(names, 1)
        ]

        rows = _attach_chain_gates([chain], candidates, catalog)

        self.assertEqual(
            [
                "defaultBrowserWebAccessConfig",
                "buildBrowserConfig",
                "MANAGED_BROWSER_POLICY_PROMPT",
                "assertBrowserNavigationAllowed",
                "isPrivateNetworkAllowedByPolicy",
            ],
            [row["gate_name"] for row in rows],
        )

    def test_catalog_match_expands_codeql_abbreviated_checked_expression(self) -> None:
        candidate = {
            "gate_fn": "evaluateSegments",
            "gate_file": "src/infra/exec-approvals.ts",
            "gate_line": "1034",
            "checked_expr": "params. ... egments",
        }
        catalog = [
            {
                "gate_uid": "GU" + "1" * 20,
                "gate_id": "G-params",
                "gate_name": "evaluateSegments",
                "callsite_file": "src/infra/exec-approvals.ts",
                "callsite_line": "1034",
                "checked_expression": "params.analysis.segments",
            },
            {
                "gate_uid": "GU" + "2" * 20,
                "gate_id": "G-options",
                "gate_name": "evaluateSegments",
                "callsite_file": "src/infra/exec-approvals.ts",
                "callsite_line": "1034",
                "checked_expression": "{\n    allowlist: params.allowlist,\n  }",
            },
        ]

        matched = _catalog_match(candidate, catalog, "dominance")

        self.assertIsNotNone(matched)
        self.assertEqual("G-params", matched["gate_id"])

    def test_side_policy_gate_attaches_only_to_same_handler_and_tool(self) -> None:
        chain = {
            "chain_id": "C-111111111111",
            "sink_id": "S-1111111111111111",
            "tool_name": "exec",
            "handler_func": "execute",
            "handler_file": "src/agents/bash-tools.exec.ts",
            "sink_file": "src/node-host/runner.ts",
            "sink_line": "405",
            "call_chain": (
                "4#execute@bash-tools.exec.ts->handleInvoke@runner.ts->"
                "runCommand@runner.ts-><runner-promise-callback>@runner.ts->"
                "spawn@runner.ts"
            ),
        }
        common = {
            "gate_file": "src/infra/exec-approvals.ts",
            "in_func": "evaluateSegments.<callback>",
            "handler_func": "execute",
            "guard_kind": "decision-return-branch",
            "sink_file": "src/node-host/runner.ts",
            "sink_line": "405",
            "taint_verdict": "branch-confirmed",
        }
        candidates = {
            "dominance": [
                {
                    **common,
                    "gate_fn": "isSafeBinUsage",
                    "gate_line": "986",
                    "handler_file": "src/agents/bash-tools.exec.ts",
                    "tool_name": "exec",
                },
                {
                    **common,
                    "gate_fn": "wrongHandlerPolicy",
                    "gate_line": "987",
                    "handler_file": "src/agents/tools/nodes-tool.ts",
                    "tool_name": "nodes",
                },
            ],
            "filter": [],
            "transform": [],
        }
        catalog = [
            {
                "gate_number": str(index),
                "gate_uid": "GU" + str(index) * 20,
                "gate_id": f"G-{name}",
                "gate_name": name,
                "callsite_file": "src/infra/exec-approvals.ts",
                "callsite_line": line,
                "enclosing_function": "<anonymous>",
            }
            for index, (name, line) in enumerate(
                (("isSafeBinUsage", "986"), ("wrongHandlerPolicy", "987")), 1
            )
        ]

        rows = _attach_chain_gates([chain], candidates, catalog)

        self.assertEqual(["isSafeBinUsage"], [row["gate_name"] for row in rows])
        self.assertEqual("execute", rows[0]["_chain_owner"])

    def test_confirmed_duplicate_is_not_overwritten_by_needs_review(self) -> None:
        chain = {
            "chain_id": "C-111111111111",
            "sink_id": "S-1111111111111111",
            "sink_file": "tool.py",
            "sink_line": "30",
            "call_chain": "1#Tool.execute@tool.py->open@/tmp/tool.py$$30:1$$30:9",
        }
        common = {
            "gate_fn": "normalize",
            "gate_file": "tool.py",
            "gate_line": "10",
            "in_func": "execute",
            "sink_file": "tool.py",
            "sink_line": "30",
        }
        candidates = {
            "dominance": [
                {**common, "taint_verdict": "confirmed"},
                {**common, "taint_verdict": "needs-review"},
            ],
            "filter": [],
            "transform": [],
        }
        catalog = [
            {
                "gate_uid": "GU" + "1" * 20,
                "gate_id": "G-normalize",
                "gate_name": "normalize",
                "callsite_file": "tool.py",
                "callsite_line": "10",
                "enclosing_function": "execute",
            }
        ]

        rows = _attach_chain_gates([chain], candidates, catalog)

        self.assertEqual(1, len(rows))
        self.assertEqual("confirmed", rows[0]["static_verdict"])
        self.assertEqual("normalize", rows[0]["gate_name"])

    def test_adapter_preflight_requires_exactly_one_matching_row(self) -> None:
        output = self.root / "model.csv"
        with patch(
            "src.pipeline.codeql.run_query",
            return_value=[{"project_id": "fixture", "adapter_name": "fixture"}],
        ):
            self.assertEqual(
                "fixture", preflight_project(self.spec, output)["project_id"]
            )
        with patch("src.pipeline.codeql.run_query", return_value=[]):
            with self.assertRaises(CodeQLPipelineError):
                preflight_project(self.spec, output)

    def test_preflight_selects_the_project_query_pack(self) -> None:
        output = self.root / "model.csv"
        with patch(
            "src.pipeline.codeql.run_query",
            return_value=[{"project_id": "fixture", "adapter_name": "fixture"}],
        ) as mocked:
            preflight_project(self.spec, output)
        self.assertEqual(self.spec.query_pack, mocked.call_args.kwargs["query_pack"])
        self.assertEqual("python", mocked.call_args.kwargs["expected_language"])

    def test_database_language_mismatch_fails_before_query_execution(self) -> None:
        self.spec.codeql_database.mkdir()
        self.spec.query_pack.mkdir()
        (self.spec.query_pack / "fixture.ql").write_text("select 1\n", encoding="utf-8")
        with (
            patch(
                "src.pipeline.codeql.database_languages", return_value=("javascript",)
            ),
            patch("src.pipeline.codeql._run") as execute,
        ):
            with self.assertRaisesRegex(CodeQLPipelineError, "language mismatch"):
                run_query(
                    self.spec.codeql_database,
                    "fixture.ql",
                    self.root / "result.csv",
                    query_pack=self.spec.query_pack,
                    expected_language="python",
                )
        execute.assert_not_called()

    def test_pipeline_manifest_records_stage_dependencies(self) -> None:
        self.spec.output_root.mkdir(parents=True, exist_ok=True)
        (self.spec.output_root / "pipeline-manifest.json").write_text(
            json.dumps(
                {
                    "schema_version": "python-benchmark-pipeline/v1",
                    "stages": {"infer-gates": {"status": "complete"}},
                }
            ),
            encoding="utf-8",
        )
        _record_pipeline_stage(
            self.spec,
            "infer-call-chain-semantics",
            {"schema_version": "fixture/v1", "counts": {"records": 1}},
        )
        manifest = json.loads(
            (self.spec.output_root / "pipeline-manifest.json").read_text()
        )
        stage = manifest["stages"]["infer-call-chain-semantics"]
        self.assertEqual("clawgap-benchmark-pipeline/v2", manifest["schema_version"])
        self.assertEqual("python", manifest["project"]["source_language"])
        self.assertEqual("complete", manifest["stages"]["infer-gates"]["status"])
        self.assertEqual(
            ["infer-call-chains", "infer-gate-semantics"],
            stage["depends_on"],
        )
        self.assertEqual("complete", stage["status"])


class V3AssemblyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.chains = self.root / "chains.csv"
        self.chain_gates = self.root / "chain-gates.csv"
        self.constraints = self.root / "constraints.csv"
        self.catalog = self.root / "gate-index.csv"
        self.store = self.root / "gate-semantics"
        self.out = self.root / "out"
        self.chain_row = {
            "chain_id": "C-111111111111",
            "sink_id": "S-1111111111111111",
            "tool_name": "read",
            "handler_qualified_name": "Read.execute",
            "handler_file": "tool.py",
            "handler_line": "1",
            "source_parameter": "args",
            "sink_label": "open",
            "sink_file": "tool.py",
            "sink_line": "9",
            "sink_column": "4",
            "call_chain": "1#Read.execute@tool.py->open@/tmp/tool.py$$9:4$$9:14",
        }
        write_csv(self.chains, list(self.chain_row), [self.chain_row])
        constraint = {
            "constraint_id": "SC-1111111111111111",
            "sink_id": "S-1111111111111111",
            "sink_api": "builtins.open",
            "sink_label": "open",
            "sink_file": "tool.py",
            "sink_line": "9",
            "sink_column": "4",
            "controlled_argument": "path",
            "capability_class": "file-read",
            "call_shape": "open(path, 'r')",
            "capability_card": "src/sink_capacity/sink-capability-cards/builtins.open.read.md",
            "capability_card_sha256": "a" * 64,
        }
        write_csv(self.constraints, list(constraint), [constraint])

    def tearDown(self) -> None:
        self.temp.cleanup()

    def assemble(self) -> dict[str, object]:
        return assemble_all_chains(
            project_id="fixture",
            project_revision="revision",
            handler_sink_chains_csv=self.chains,
            chain_gates_csv=self.chain_gates,
            sink_constraints_csv=self.constraints,
            gate_index_csv=self.catalog,
            gate_semantics_dir=self.store,
            out_dir=self.out,
            generation_command="python -m fixture",
        )

    def test_empty_gates_is_a_complete_semantic_record(self) -> None:
        write_csv(
            self.chain_gates,
            ["chain_id", "gate_seq", "gate_uid", "static_verdict"],
            [
                {
                    "chain_id": self.chain_row["chain_id"],
                    "gate_seq": "",
                    "gate_uid": "",
                    "static_verdict": "",
                }
            ],
        )
        write_csv(self.catalog, ["gate_uid"], [])
        manifest = self.assemble()
        self.assertEqual(1, manifest["counts"]["semantic_records"])
        self.assertEqual(1, manifest["counts"]["zero_gate_chains"])
        semantic = json.loads(
            (self.out / "call-chain-semantics.jsonl").read_text().strip()
        )
        self.assertEqual([], semantic["gates"])
        self.assertEqual("complete", semantic["status"])
        self.assertEqual(
            "SC-1111111111111111", semantic["sink_constraint"]["constraint_id"]
        )

    def test_duplicate_constraint_for_one_sink_is_rejected(self) -> None:
        with self.constraints.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        write_csv(self.constraints, list(rows[0]), [rows[0], rows[0]])
        write_csv(self.chain_gates, ["chain_id", "gate_uid", "static_verdict"], [])
        write_csv(self.catalog, ["gate_uid"], [])
        with self.assertRaises(ChainV3Error):
            self.assemble()

    def test_64k_limit_accepts_records_larger_than_12k(self) -> None:
        from src.call_chain_semantics.contracts import HARD_TOKEN_LIMIT

        self.assertEqual(64_000, HARD_TOKEN_LIMIT)

    def test_excluded_chains_are_accounted_without_semantic_assembly(self) -> None:
        write_csv(
            self.chain_gates,
            ["chain_id", "gate_seq", "gate_uid", "static_verdict"],
            [],
        )
        write_csv(self.catalog, ["gate_uid"], [])
        manifest = assemble_all_chains(
            project_id="fixture",
            project_revision="revision",
            handler_sink_chains_csv=self.chains,
            chain_gates_csv=self.chain_gates,
            sink_constraints_csv=self.constraints,
            gate_index_csv=self.catalog,
            gate_semantics_dir=self.store,
            out_dir=self.out,
            generation_command="python -m fixture",
            excluded_chains=[
                {
                    "chain_id": self.chain_row["chain_id"],
                    "handler_id": "H-" + "1" * 16,
                    "tool_name": "read",
                    "impact_verdict": "no-security-impact",
                    "reason_code": "llm-confirmed-no-impact",
                }
            ],
        )
        self.assertEqual("call-chain-semantics-manifest/v4", manifest["schema_version"])
        self.assertEqual(1, manifest["counts"]["structural_chains"])
        self.assertEqual(0, manifest["counts"]["eligible_chains"])
        self.assertEqual(1, manifest["counts"]["excluded_chains"])
        self.assertEqual(0, manifest["counts"]["semantic_records"])

if __name__ == "__main__":
    unittest.main()
