from __future__ import annotations

import unittest

from src.runtime_validation.contracts import ValidationError
from src.runtime_validation.qualification_provider import (
    MockProviderCall,
    MockProviderServer,
    provider_response,
    request_mock_provider,
)


class QualificationProviderTest(unittest.TestCase):
    def test_loopback_provider_returns_exactly_one_reviewed_call(self) -> None:
        call = MockProviderCall(
            side="exploit",
            prompt="Read the device fixture",
            model="clawgap-mock-provider/v1",
            tool_name="read_file",
            arguments={"path": "/dev/./zero"},
        )
        with MockProviderServer(call) as server:
            record = request_mock_provider(server.origin, call)
            server_record = server.records[0]
        self.assertEqual(1, len(server.records))
        self.assertEqual(record, server_record)
        self.assertEqual("read_file", record["response"]["choices"][0]["message"]["tool_calls"][0]["function"]["name"])
        self.assertNotIn("api_key", str(record).lower())

    def test_prompt_drift_is_rejected(self) -> None:
        call = MockProviderCall(
            side="control",
            prompt="safe prompt",
            model="clawgap-mock-provider/v1",
            tool_name="read_file",
            arguments={"path": "/dev/zero"},
        )
        request = {
            "model": call.model,
            "messages": [{"role": "user", "content": "attacker prompt"}],
        }
        with self.assertRaises(ValidationError):
            from src.runtime_validation.qualification_provider import (
                validate_provider_exchange,
            )

            validate_provider_exchange(
                call.prompt,
                call.model,
                call.tool_name,
                call.arguments,
                request,
                provider_response(call),
            )


if __name__ == "__main__":
    unittest.main()
