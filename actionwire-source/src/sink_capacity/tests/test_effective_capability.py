from __future__ import annotations

import unittest

from src.sink_capacity.card_contract import CARD_AUTHORITY, stable_card_id
from src.sink_capacity.effective_capability import (
    EffectiveCapabilityError,
    derive_effective_capability_view,
    derive_effective_capability_views,
)


def capability_card() -> dict:
    runtime = {
        "language": "python",
        "ecosystem": "pypi",
        "package": "requests",
        "version": "2.32.5",
    }
    roles = [
        ("destination-url", "url"),
        ("request-body", "json"),
        ("redirect-policy", "allow_redirects"),
    ]
    return {
        "schema_version": "sink-capability-card/v2",
        "card_id": stable_card_id(
            api_family="requests.request",
            runtime=runtime,
            capability_class="network-egress",
        ),
        "api": "requests.request(method, url, **kwargs)",
        "api_family": "requests.request",
        "runtime": runtime,
        "capability_class": "network-egress",
        "normative_authority": CARD_AUTHORITY,
        "bound_sinks": ["requests.request(url, json=json)"],
        "roles": [
            {
                "role_id": role_id,
                "description": role_id,
                "bindings": [{"expression": binding, "caller_bindable": True}],
            }
            for role_id, binding in roles
        ],
        "facets": [
            {
                "facet_id": "model-selected-network-destination",
                "capability": "Connect to a destination selected by the model.",
                "role_ids": ["destination-url"],
                "activation": {
                    "all_of": [
                        {
                            "predicate": "role-bound",
                            "subject": "destination-url",
                            "operator": "equals",
                            "value": True,
                        },
                        {
                            "predicate": "role-authority",
                            "subject": "destination-url",
                            "operator": "contains",
                            "value": "model-arbitrary",
                        },
                    ]
                },
            },
            {
                "facet_id": "request-body-transmission",
                "capability": "Transmit the caller-supplied JSON body.",
                "role_ids": ["request-body"],
                "activation": {
                    "all_of": [
                        {
                            "predicate": "role-bound",
                            "subject": "request-body",
                            "operator": "equals",
                            "value": True,
                        }
                    ]
                },
            },
        ],
        "library_guarantees": [
            {
                "guarantee_id": "http-https-adapters-only",
                "statement": "Default adapters support only http:// and https://.",
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
        "defaults": [
            {
                "default_id": "redirects-enabled",
                "role_id": "redirect-policy",
                "value": True,
                "security_effect": "GET requests follow redirects by default.",
                "activation": {
                    "all_of": [
                        {
                            "predicate": "always",
                            "subject": "requests-get-default",
                            "operator": "equals",
                            "value": True,
                        }
                    ]
                },
            }
        ],
        "example_usage": {
            "benign": "requests.get('https://example.com')",
            "capability_edge": "requests.get('http://127.0.0.1')",
        },
        "provenance": ["Requests 2.32.5"],
    }


def constraint(controlled: str) -> dict:
    return {
        "constraint_id": "SC-" + "1" * 16,
        "controlled_argument": controlled,
        "call_shape": "requests.request('POST', fixed_origin + path, json=json)",
        "capability_card": {"path": "cards/requests.md", "sha256": "0" * 64},
    }


def flow(*, argument: str, authority: str, project: str = "p") -> dict:
    return {
        "project": project,
        "revision": "rev",
        "chain_id": "C-111111111111",
        "sink_argument": argument,
        "source_facet": f"args.{argument}",
        "authority": authority,
        "transforms": ["json-serialization"] if argument == "json" else [],
        "verdict": "same-origin-confirmed",
    }


class EffectiveCapabilityTests(unittest.TestCase):
    def test_json_binding_does_not_activate_url_ssrf_facet(self) -> None:
        row = flow(argument="json", authority="model-arbitrary")
        view = derive_effective_capability_view(
            card=capability_card(),
            project="p",
            revision="rev",
            chain_id=row["chain_id"],
            sink_constraint=constraint("json"),
            origin_witnesses=[row],
            authority_by_binding={"json": "model-arbitrary"},
            transforms_by_binding={"json": ["json-serialization"]},
        )
        self.assertEqual(
            ["request-body-transmission"],
            [row["facet_id"] for row in view["active_facets"]],
        )
        self.assertEqual("network-egress", view["capability_class"])
        self.assertEqual("p", view["project"])
        self.assertEqual(["redirects-enabled"], view["call_shape_predicates"]["active_default_ids"])
        self.assertEqual("json", view["boundaries"][0]["sink_bindings"][0])

    def test_operator_configured_url_is_not_model_selected(self) -> None:
        row = flow(argument="url", authority="operator-config")
        view = derive_effective_capability_view(
            card=capability_card(),
            project="p",
            revision="rev",
            chain_id=row["chain_id"],
            sink_constraint=constraint("url"),
            origin_witnesses=[row],
            authority_by_binding={"url": "operator-config"},
        )
        self.assertEqual([], view["active_facets"])
        self.assertIn(
            "model-selected-network-destination",
            [row["facet_id"] for row in view["inactive_facets"]],
        )

    def test_confirmed_caller_binding_defaults_to_model_arbitrary(self) -> None:
        row = flow(argument="url", authority="model-arbitrary")
        row.pop("authority")
        view = derive_effective_capability_view(
            card=capability_card(),
            project="p",
            revision="rev",
            chain_id=row["chain_id"],
            sink_constraint=constraint("url"),
            origin_witnesses=[row],
        )
        self.assertEqual(
            ["model-selected-network-destination"],
            [item["facet_id"] for item in view["actual_effects"]],
        )
        self.assertEqual(["model-arbitrary"], view["boundaries"][0]["authorities"])

    def test_batch_join_uses_project_revision_and_chain(self) -> None:
        semantic = []
        rows = []
        for project in ("a", "b"):
            semantic.append(
                {
                    "project": {"id": project, "revision": "rev"},
                    "chain_id": "C-111111111111",
                    "sink_constraint": constraint("json"),
                }
            )
            rows.append(flow(argument="json", authority="model-component", project=project))
        views = derive_effective_capability_views(
            semantic_chains=semantic,
            cards_by_path={"cards/requests.md": capability_card()},
            field_flow_rows=rows,
        )
        self.assertEqual(["a", "b"], [row["project"] for row in views])

    def test_conflicting_authority_fails_closed(self) -> None:
        semantic = {
            "project": {"id": "p", "revision": "rev"},
            "chain_id": "C-111111111111",
            "sink_constraint": constraint("url"),
        }
        rows = [
            flow(argument="url", authority="operator-config"),
            flow(argument="url", authority="model-arbitrary"),
        ]
        with self.assertRaisesRegex(EffectiveCapabilityError, "conflicting"):
            derive_effective_capability_views(
                semantic_chains=[semantic],
                cards_by_path={"cards/requests.md": capability_card()},
                field_flow_rows=rows,
            )


if __name__ == "__main__":
    unittest.main()
