from __future__ import annotations

import unittest
from pathlib import Path

from src.runtime_validation.contracts import ValidationError
from src.runtime_validation.source_revised_native_l2 import (
    CAMPAIGN_ID,
    EVIDENCE_SCOPE,
    EVIDENCE_TIER,
    EXPECTED_REPORTS,
    PROJECT_REPORTS,
    SourceRevisedNativeL2RunRequest,
    _selected_projects,
)
from src.runtime_validation.nanobot_login_shell_l2 import _arguments as _nanobot_arguments
from src.runtime_validation.openclaw_source_revised_l2 import _arguments as _openclaw_arguments
from src.runtime_validation.chatgpt_on_wechat_file_native_l2 import (
    _arguments as _cowagent_arguments,
)


REPO_ROOT = Path(__file__).resolve().parents[3]


class SourceRevisedNativeL2Test(unittest.TestCase):
    def test_exact_four_reports_and_projects_are_selected(self) -> None:
        self.assertEqual(4, len(EXPECTED_REPORTS))
        self.assertEqual(
            {
                "GT-0d6ed4cec085773c",
                "GT-c6a9e97a28acf193",
                "GT-f1647abba5c44969",
                "GT-e03e7f2d88091689",
            },
            EXPECTED_REPORTS,
        )
        request = SourceRevisedNativeL2RunRequest(
            out_dir=Path("/tmp/clawgap-source-revised"),
            all_reports=True,
        )
        self.assertEqual(["nanobot", "openclaw", "chatgpt-on-wechat"], _selected_projects(request))
        with self.assertRaisesRegex(ValidationError, "cannot be combined"):
            _selected_projects(
                SourceRevisedNativeL2RunRequest(
                    out_dir=Path("/tmp/clawgap-source-revised"),
                    all_reports=True,
                    project="nanobot",
                )
            )

    def test_provider_interfaces_are_project_native(self) -> None:
        exploit, control = _nanobot_arguments("exploit"), _nanobot_arguments("control")
        self.assertNotIn("login", exploit)
        self.assertIs(False, control["login"])
        self.assertEqual("exec", "exec")

        browser = _openclaw_arguments(
            "GT-c6a9e97a28acf193",
            "exploit",
            Path("/workspace"),
            Path("/outside"),
        )
        self.assertEqual("act", browser["action"])
        self.assertEqual("browser", "browser")
        self.assertIn("window.location", browser["request"]["fn"])
        self.assertIn("127.0.0.1", browser["request"]["fn"])

        media = _openclaw_arguments(
            "GT-f1647abba5c44969",
            "exploit",
            Path("/workspace"),
            Path("/outside"),
        )
        self.assertEqual("send", media["action"])
        self.assertEqual("message", "message")
        self.assertIn("/outside/secret-media.txt", media["filePath"])

        navigation = _cowagent_arguments("exploit")
        self.assertEqual("navigate", navigation["action"])
        self.assertEqual("browser", "browser")
        self.assertTrue(navigation["url"].startswith("file:///"))

    def test_native_source_markers_and_retired_additive_sources(self) -> None:
        nanobot_shell = (
            REPO_ROOT
            / "benchmark/python/nanobot/nanobot/agent/tools/shell.py"
        ).read_text(encoding="utf-8")
        openclaw_message = (
            REPO_ROOT
            / "benchmark/typescript/openclaw/src/agents/tools/message-tool.ts"
        ).read_text(encoding="utf-8")
        cowagent_browser = (
            REPO_ROOT
            / "benchmark/python/chatgpt-on-wechat/agent/tools/browser/browser_tool.py"
        ).read_text(encoding="utf-8")
        self.assertIn("login_shell_profile", nanobot_shell)
        self.assertIn("create_subprocess_exec", nanobot_shell)
        self.assertIn("CLAWGAP_SOURCE_REVISED_MESSAGE_MEDIA", openclaw_message)
        self.assertIn("CLAWGAP_SOURCE_REVISED_FILE_SCHEME", cowagent_browser)
        self.assertFalse(
            (
                REPO_ROOT / "benchmark/python/nanobot/clawgap_login_shell_mcp.py"
            ).exists()
        )
        self.assertFalse(
            (
                REPO_ROOT
                / "benchmark/typescript/openclaw/extensions/clawgap-additive"
            ).exists()
        )
        self.assertFalse(
            (
                REPO_ROOT
                / "benchmark/python/chatgpt-on-wechat/agent/tools/browser/clawgap_additive_browser.py"
            ).exists()
        )

    def test_campaign_evidence_boundary(self) -> None:
        self.assertEqual(
            "runtime-dynamic-trigger-source-revised-native-l2-v1",
            CAMPAIGN_ID,
        )
        self.assertEqual("source-revised-native-tool", EVIDENCE_SCOPE)
        self.assertEqual(
            "L2-forced-provider-E2E-source-revised",
            EVIDENCE_TIER,
        )
        self.assertEqual(
            {
                "GT-0d6ed4cec085773c",
                "GT-c6a9e97a28acf193",
                "GT-f1647abba5c44969",
                "GT-e03e7f2d88091689",
            },
            set(PROJECT_REPORTS["nanobot"])
            | set(PROJECT_REPORTS["openclaw"])
            | set(PROJECT_REPORTS["chatgpt-on-wechat"]),
        )


if __name__ == "__main__":
    unittest.main()
