from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("count_detected_call_chains.py")
SPEC = importlib.util.spec_from_file_location("chatgpt_on_wechat_call_chain_report", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CountDetectedCallChainsWrapperTest(unittest.TestCase):
    def test_delegates_to_shared_reporter_with_project_identity(self) -> None:
        argv = ["--refresh"]
        with mock.patch.object(MODULE, "run_call_chain_report", return_value=17) as run:
            self.assertEqual(17, MODULE.main(argv))

        self.assertEqual("chatgpt-on-wechat", MODULE.PROJECT_ID)
        self.assertEqual(Path("design/chatgpt-on-wechat/call-chain/debug/script/count_detected_call_chains.py"), MODULE.SCRIPT_PATH)
        run.assert_called_once_with(MODULE.PROJECT_ID, MODULE.SCRIPT_PATH, argv)


if __name__ == "__main__":
    unittest.main()
