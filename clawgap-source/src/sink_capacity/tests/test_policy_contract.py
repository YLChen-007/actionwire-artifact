from __future__ import annotations

import unittest
from pathlib import Path

from src.sink_capacity.policy_contract import (
    CapabilityPolicyError,
    parse_approval_policy_contract,
)


ROOT = Path(__file__).resolve().parents[3]
CARDS = ROOT / "src/sink_capacity/sink-capability-cards"
EXPECTED = {
    "indirect-file-operands",
    "shell-expansion-semantics",
    "redirection-effect",
    "command-action-semantics",
}


class ApprovalPolicyContractTests(unittest.TestCase):
    def test_ordinary_opaque_card_does_not_require_strict_yaml(self) -> None:
        card = """# legacy factual card
```yaml
api: ordinary
capability_class: process-spawn
controlled_param: command: string
```
"""
        self.assertEqual((), parse_approval_policy_contract(card))

    def test_both_approval_cards_carry_the_same_four_policies(self) -> None:
        for name in (
            "prompt_dangerous_approval.md",
            "mercury.command-approval.md",
        ):
            with self.subTest(card=name):
                rows = parse_approval_policy_contract(
                    (CARDS / name).read_text(encoding="utf-8")
                )
                self.assertEqual(EXPECTED, {row["policy_id"] for row in rows})
                self.assertTrue(all(row["exact_quote"] for row in rows))
                self.assertTrue(all(row["examples"] for row in rows))

    def test_policy_contract_is_rejected_for_non_consent_card(self) -> None:
        card = """# bad
```yaml
api: bad
capability_class: process-spawn
policy_contract:
  schema_version: approval-policy-contract/v1
  boundary: dangerous-command-user-consent
  requirements:
    - policy_id: example
      rule: rule
      applicability: applies
      security_effect: effect
      examples: [example]
```
"""
        with self.assertRaisesRegex(CapabilityPolicyError, "user-consent"):
            parse_approval_policy_contract(card)

    def test_duplicate_policy_ids_fail_closed(self) -> None:
        card = """# bad
```yaml
api: bad
capability_class: user-consent
policy_contract:
  schema_version: approval-policy-contract/v1
  boundary: dangerous-command-user-consent
  requirements:
    - policy_id: example
      rule: first
      applicability: applies
      security_effect: effect
      examples: [one]
    - policy_id: example
      rule: second
      applicability: applies
      security_effect: effect
      examples: [two]
```
"""
        with self.assertRaisesRegex(CapabilityPolicyError, "duplicate policy_id"):
            parse_approval_policy_contract(card)


if __name__ == "__main__":
    unittest.main()
