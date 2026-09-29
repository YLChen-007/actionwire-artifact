from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.sink_capacity.card_contract import (
    CARD_AUTHORITY,
    CapabilityCardError,
    parse_capability_card,
    render_capability_card,
    stable_card_id,
    validate_card_directory,
)
from src.sink_capacity.card_migration import (
    migrate_card_directory,
    migrate_markdown_card_to_v2,
    validates_digest_transition,
)
from src.sink_capacity.extract_sinks import SinkAPI
from src.sink_capacity.generate import run
from src.sink_capacity.policy_contract import parse_approval_policy_contract


ROOT = Path(__file__).resolve().parents[3]
CARDS = ROOT / "src/sink_capacity/sink-capability-cards"


def valid_card(*, capability_class: str = "network-egress") -> dict:
    runtime = {
        "language": "python",
        "ecosystem": "pypi",
        "package": "requests",
        "version": "2.32.5",
    }
    return {
        "schema_version": "sink-capability-card/v2",
        "card_id": stable_card_id(
            api_family="requests.request",
            runtime=runtime,
            capability_class=capability_class,
        ),
        "api": "requests.request(method, url, **kwargs)",
        "api_family": "requests.request",
        "runtime": runtime,
        "capability_class": capability_class,
        "normative_authority": CARD_AUTHORITY,
        "bound_sinks": ["requests.request(url)"],
        "roles": [
            {
                "role_id": "destination-url",
                "description": "Destination URL.",
                "bindings": [{"expression": "url", "caller_bindable": True}],
            }
        ],
        "facets": [
            {
                "facet_id": "http-request",
                "capability": "Issue an HTTP request to the selected URL.",
                "role_ids": ["destination-url"],
                "activation": {
                    "all_of": [
                        {
                            "predicate": "role-bound",
                            "subject": "destination-url",
                            "operator": "equals",
                            "value": True,
                        }
                    ]
                },
            }
        ],
        "library_guarantees": [
            {
                "guarantee_id": "http-https-adapters-only",
                "statement": "Default adapters exist only for http:// and https://.",
                "activation": {
                    "all_of": [
                        {
                            "predicate": "always",
                            "subject": "requests-default-session",
                            "operator": "equals",
                            "value": True,
                        }
                    ]
                },
            }
        ],
        "defaults": [],
        "example_usage": {
            "benign": "requests.get('https://example.com')",
            "capability_edge": "requests.get('http://127.0.0.1')",
        },
        "provenance": ["Requests 2.32.5 API"],
    }


class CapabilityCardContractTests(unittest.TestCase):
    def test_v2_ledger_authorizes_only_the_exact_digest_transition(self) -> None:
        ledger = CARDS / "identity-migration.jsonl"
        row = json.loads(ledger.read_text(encoding="utf-8").splitlines()[0])
        actual = hashlib.sha256((CARDS / row["path"]).read_bytes()).hexdigest()
        self.assertTrue(
            validates_digest_transition(
                card_path=f"src/sink_capacity/sink-capability-cards/{row['path']}",
                expected_sha256=row["previous_markdown_sha256"],
                actual_sha256=actual,
                ledger_path=ledger,
            )
        )
        self.assertFalse(
            validates_digest_transition(
                card_path=row["path"],
                expected_sha256="0" * 64,
                actual_sha256=actual,
                ledger_path=ledger,
            )
        )

    def test_v2_round_trip_and_stable_identity(self) -> None:
        card = valid_card()
        markdown = render_capability_card(card)
        self.assertEqual(card, parse_capability_card(markdown))
        self.assertEqual("capability-facts-only", card["normative_authority"])

    def test_policy_contract_does_not_change_card_identity(self) -> None:
        card = valid_card(capability_class="user-consent")
        before = card["card_id"]
        card["policy_contract"] = {
            "schema_version": "approval-policy-contract/v1",
            "boundary": "dangerous-command-user-consent",
            "requirements": [
                {
                    "policy_id": "indirect-operands",
                    "rule": "Inspect indirect operands.",
                    "applicability": "When a command bypasses approval.",
                    "security_effect": "Prevent unintended reads.",
                    "examples": ["wc --files0-from=list.txt"],
                }
            ],
        }
        parsed = parse_capability_card(render_capability_card(card))
        self.assertEqual(before, parsed["card_id"])
        self.assertEqual("capability-facts-only", parsed["normative_authority"])

    def test_unknown_facet_role_fails_closed(self) -> None:
        card = valid_card()
        card["facets"][0]["role_ids"] = ["missing-role"]
        with self.assertRaisesRegex(CapabilityCardError, "unknown role"):
            render_capability_card(card)

    def test_all_current_cards_migrate_and_validate(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            staging = Path(raw)
            rows = migrate_card_directory(CARDS, staging)
            migrated = sorted(
                path for path in staging.glob("*.md") if path.name != "index.md"
            )
            self.assertEqual(114, len(rows))
            self.assertEqual(114, len(migrated))
            languages = set()
            for path in migrated:
                card = parse_capability_card(path.read_text(encoding="utf-8"))
                languages.add(card["runtime"]["language"])
                self.assertFalse(
                    any(
                        token in str(value).lower()
                        for value in card["runtime"].values()
                        for token in ("unspecified", "unresolved")
                    )
                )
            self.assertEqual({"python", "typescript"}, languages)
            self.assertEqual(114, len(validate_card_directory(staging)))

            requests_card = parse_capability_card(
                (staging / "requests.get-post-request.md").read_text(encoding="utf-8")
            )
            statements = {
                row["statement"] for row in requests_card["library_guarantees"]
            }
            self.assertTrue(any("only for http:// and https://" in row for row in statements))
            self.assertFalse(
                any(
                    token in row["capability"].lower()
                    for row in requests_card["facets"]
                    for token in ("file://", "ftp://", "dict://", "gopher://")
                )
            )
            for name in (
                "prompt_dangerous_approval.md",
                "mercury.command-approval.md",
            ):
                before = parse_approval_policy_contract(
                    (CARDS / name).read_text(encoding="utf-8")
                )
                after = parse_approval_policy_contract(
                    (staging / name).read_text(encoding="utf-8")
                )
                self.assertEqual(
                    [
                        {key: value for key, value in row.items() if key != "exact_quote"}
                        for row in before
                    ],
                    [
                        {key: value for key, value in row.items() if key != "exact_quote"}
                        for row in after
                    ],
                )
            self.assertFalse(
                any(
                    token in str(row["value"]).lower()
                    for row in requests_card["defaults"]
                    for token in ("file://", "ftp://", "dict://", "gopher://")
                )
            )

    def test_legacy_migration_is_byte_deterministic(self) -> None:
        source = (CARDS / "subprocess.Popen.md").read_text(encoding="utf-8")
        left = migrate_markdown_card_to_v2(source, path="subprocess.Popen.md")
        right = migrate_markdown_card_to_v2(source, path="subprocess.Popen.md")
        self.assertEqual(left, right)
        self.assertEqual(
            left,
            migrate_markdown_card_to_v2(left, path="subprocess.Popen.md"),
        )

    def test_directory_validation_rejects_legacy_or_scaffold_cards(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "legacy.md").write_text("# legacy\n")
            with self.assertRaises(CapabilityCardError):
                validate_card_directory(root)

            (root / "legacy.md").unlink()
            scaffold = valid_card()
            scaffold["facets"][0]["facet_id"] = "source-review-required"
            (root / "scaffold.md").write_text(render_capability_card(scaffold))
            with self.assertRaisesRegex(CapabilityCardError, "unresolved scaffold"):
                validate_card_directory(root)

    def test_full_regeneration_is_atomic_and_preserves_unowned_cards(self) -> None:
        sink = SinkAPI(
            slug="fixture.request",
            api="fixture.request",
            capability_class="network-egress",
            kind="library",
            import_path=None,
            match="fixture.request(url)",
            ql_index=0,
            ql_start_line=1,
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            qll = root / "sinks.qll"
            qll.write_text("fixture")
            out = root / "cards"
            out.mkdir()
            legacy = """# fixture
```yaml
api: fixture.request
capability_class: network-egress
bound_sinks: [fixture.request]
controlled_param: url
capability: |
  - Issue an HTTP request to the selected URL.
implicit_defaults: |
  - Runtime defaults apply.
example_usage:
  benign: fixture.request('https://example.com')
  capability_edge: fixture.request('http://127.0.0.1')
provenance: [fixture]
```
"""
            (out / "fixture.request.md").write_text(legacy)
            (out / "source-owned.md").write_text(
                legacy.replace("fixture.request", "source.owned")
            )
            with patch("src.sink_capacity.generate.extract", return_value=[sink]):
                result = run(
                    qll_path=str(qll),
                    out_dir=str(out),
                    source_roots=[],
                    use_llm=False,
                    full_regeneration=True,
                )
            self.assertTrue(result["published"])
            parse_capability_card((out / "source-owned.md").read_text())
            parse_capability_card((out / "fixture.request.md").read_text())
            self.assertEqual(2, len(result["migration_rows"]))


if __name__ == "__main__":
    unittest.main()
