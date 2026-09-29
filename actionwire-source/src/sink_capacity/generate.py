"""Orchestrator: sink registry -> index table + one English capability card per API."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping

from .extract_sinks import SinkAPI, extract
from .doc_sources import introspect, project_source, web_doc, DOC_URLS, DEFAULT_DOCS_CACHE
from . import prompts, agent
from .card_contract import (
    CARD_AUTHORITY,
    CARD_SCHEMA_VERSION,
    CapabilityCardError,
    extract_policy_contract,
    parse_capability_card,
    payload_sha256,
    render_capability_card,
    stable_card_id,
    validate_card_directory,
)
from .card_migration import (
    build_identity_migration,
    identity_migration_row,
    migrate_card_directory,
    migrate_markdown_card_to_v2,
    read_previous_card,
)


EXTRA_PROJECT_CARDS = (
    {
        "slug": "mercury.command-approval",
        "api": "PermissionManager.askHandler",
        "capability_class": "user-consent",
        "kind": "project",
        "doc_source": "Mercury project source",
    },
)

PRIMARY_ROLE_BY_CLASS = {
    "process-spawn": ("command", "args"),
    "file-read": ("path", "path"),
    "file-write": ("path", "path"),
    "network-egress": ("destination-url", "url"),
    "code-eval": ("code", "expression"),
    "browser-nav": ("destination-url", "url"),
    "user-consent": ("command", "command"),
    "sql-exec": ("statement", "statement"),
    "template-injection": ("template", "source"),
    "delivery-render": ("content", "content"),
}


def _api_family(sink: SinkAPI) -> str:
    return sink.slug


def _runtime(sink: SinkAPI, doc: Mapping[str, Any] | None) -> dict[str, str]:
    if sink.kind == "project":
        return {
            "language": "python",
            "ecosystem": "project-source",
            "package": "hermes-agent",
            "version": "source-bound",
        }
    package = (sink.import_path or sink.slug).split(".", 1)[0]
    stdlib = package == "builtins" or package in sys.stdlib_module_names
    version = str((doc or {}).get("version") or "")
    if stdlib:
        version = f"python-{sys.version_info.major}.{sys.version_info.minor}"
    return {
        "language": "python",
        "ecosystem": "python-stdlib" if stdlib else "pypi",
        "package": package,
        "version": version or "installed-runtime",
    }


def card_identity(sink: SinkAPI, doc: Mapping[str, Any] | None) -> dict[str, Any]:
    runtime = _runtime(sink, doc)
    api_family = _api_family(sink)
    return {
        "schema_version": CARD_SCHEMA_VERSION,
        "card_id": stable_card_id(
            api_family=api_family,
            runtime=runtime,
            capability_class=sink.capability_class,
        ),
        "api_family": api_family,
        "runtime": runtime,
        "normative_authority": CARD_AUTHORITY,
    }


def method_hint(sink: SinkAPI) -> str:
    base = re.sub(r"\s*\(.*$", "", sink.api).strip()
    return base.split(".")[-1].strip()


def _concrete_apis(rows: list[SinkAPI]) -> tuple[list[SinkAPI], list[SinkAPI]]:
    adapter_hooks = [row for row in rows if "projectAdditionalSink(cn)" in row.ql_snippet]
    concrete = [row for row in rows if row not in adapter_hooks]
    unknown = [row.slug for row in concrete if row.slug.startswith("unclassified.")]
    if unknown:
        raise CapabilityCardError(f"unclassified concrete sink APIs: {unknown}")
    return concrete, adapter_hooks


def build_index(apis: list[SinkAPI], qll_rel: str) -> str:
    extracted_slugs = {row.slug for row in apis}
    extras = [
        row for row in EXTRA_PROJECT_CARDS if row["slug"] not in extracted_slugs
    ]
    lines = [
        "# Sink API capability cards — index",
        "",
        f"Auto-generated from `{qll_rel}` by `src/sink_capacity`. "
        f"Each row is one `is_sink_af` disjunct; each has its own card file `<slug>.md`.",
        "",
        f"Total sink APIs: **{len(apis) + len(extras)}**",
        "",
        "| # | card | api | capability_class | kind | doc source | qll line |",
        "|---|------|-----|------------------|------|-----------|----------|",
    ]
    for a in apis:
        doc_src = a.import_path or "project source"
        lines.append(
            f"| {a.ql_index} | [{a.slug}]({a.slug}.md) | `{a.api}` | {a.capability_class} "
            f"| {a.kind} | {doc_src} | {a.ql_start_line} |"
        )
    for index, row in enumerate(extras, len(apis)):
        lines.append(
            f"| {index} | [{row['slug']}]({row['slug']}.md) | `{row['api']}` | "
            f"{row['capability_class']} | {row['kind']} | {row['doc_source']} | - |"
        )
    lines.append("")
    return "\n".join(lines)


def _scaffold_card(
    sink: SinkAPI,
    doc: dict | None,
    source: dict | None,
    policy_contract: Mapping[str, Any] | None = None,
) -> str:
    """Emit a deterministic, valid v2 scaffold without inventing capabilities."""

    identity = card_identity(sink, doc)
    role_id, binding = PRIMARY_ROLE_BY_CLASS.get(
        sink.capability_class, ("primary-input", "primary")
    )
    provenance = [f"src/ql/call/sinks_af.qll:{sink.ql_start_line}"]
    if sink.import_path in DOC_URLS:
        provenance.append(DOC_URLS[sink.import_path])
    if source:
        provenance.append(f"{source['file']}:{source['line']}")
    card: dict[str, Any] = {
        **identity,
        "api": sink.api,
        "capability_class": sink.capability_class,
        "bound_sinks": [sink.match],
        "roles": [
            {
                "role_id": role_id,
                "description": "Primary API input; refine bindings during source-backed regeneration.",
                "bindings": [{"expression": binding, "caller_bindable": True}],
            }
        ],
        "facets": [
            {
                "facet_id": "source-review-required",
                "capability": "Capability facets require source-backed regeneration.",
                "role_ids": [role_id],
                "activation": {
                    "all_of": [
                        {
                            "predicate": "role-bound",
                            "subject": role_id,
                            "operator": "equals",
                            "value": True,
                        }
                    ]
                },
            }
        ],
        "library_guarantees": (
            [
                {
                    "guarantee_id": "http-https-adapters-only",
                    "statement": (
                        "The default Requests session registers adapters only for "
                        "http:// and https://; other schemes raise InvalidSchema."
                    ),
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
            ]
            if _api_family(sink).startswith("requests.")
            else []
        ),
        "defaults": [],
        "example_usage": {
            "benign": "# Source-backed example required.",
            "capability_edge": "# Source-backed capability-edge example required.",
        },
        "provenance": provenance,
    }
    if policy_contract is not None:
        card["policy_contract"] = dict(policy_contract)
    return render_capability_card(card)


def generate_card(
    sink: SinkAPI, source_roots: list[str], use_llm: bool,
    docs_cache: str = DEFAULT_DOCS_CACHE, refresh_docs: bool = False,
    preserved_policy_contract: Mapping[str, Any] | None = None, **agent_kw,
) -> str:
    doc = introspect(sink.import_path)
    # cached official-doc excerpt (crawl once, reuse local); None if no URL / offline
    wdoc = web_doc(sink.import_path, docs_cache, refresh=refresh_docs)
    # for project-internal wrappers: locate the def so we can point the agent at it
    # (the agent then Reads the file + follows what it calls — we do NOT embed the body)
    source = project_source(method_hint(sink), source_roots) if sink.kind == "project" else None
    if not use_llm:
        return _scaffold_card(sink, doc, source, preserved_policy_contract)
    identity = card_identity(sink, doc)
    user = prompts.build_user(
        sink,
        doc,
        source,
        web_doc=wdoc,
        source_roots=source_roots,
        card_identity=identity,
        preserved_policy_contract=preserved_policy_contract,
    )
    # give the agent read access to the source tree so it can open the implementation itself
    card = _clean_card(
        agent.run_agent(prompts.SYSTEM, user, add_dirs=source_roots, **agent_kw)
    ) + "\n"
    parsed = parse_capability_card(card)
    if parsed["card_id"] != identity["card_id"]:
        raise CapabilityCardError(
            f"{sink.slug}: generated card identity differs from deterministic input"
        )
    if preserved_policy_contract is not None and payload_sha256(
        parsed.get("policy_contract")
    ) != payload_sha256(preserved_policy_contract):
        raise CapabilityCardError(
            f"{sink.slug}: source-owned approval policy contract drift"
        )
    return card


def _clean_card(card: str) -> str:
    """Strip any agent chatter around the card (keep from the first `# ` heading)."""
    card = card.strip()
    idx = card.find("\n# ")
    if card.startswith("# "):
        return card
    if idx >= 0:
        return card[idx + 1:].strip()
    return card


def _atomic_publish(staging: Path, out: Path) -> None:
    backup = out.parent / f".{out.name}.previous"
    if backup.exists():
        raise CapabilityCardError(f"stale capability-card backup exists: {backup}")
    had_previous = out.exists()
    try:
        if had_previous:
            os.replace(out, backup)
        os.replace(staging, out)
    except Exception:
        if had_previous and backup.exists() and not out.exists():
            os.replace(backup, out)
        raise
    if backup.exists():
        shutil.rmtree(backup)


def run(
    qll_path: str,
    out_dir: str,
    source_roots: list[str],
    use_llm: bool = True,
    only: list[str] | None = None,
    docs_cache: str = DEFAULT_DOCS_CACHE,
    refresh_docs: bool = False,
    full_regeneration: bool = False,
    **agent_kw,
) -> dict:
    if full_regeneration and only:
        raise CapabilityCardError("full regeneration cannot be combined with --only")
    apis, adapter_hooks = _concrete_apis(extract(qll_path))
    out = Path(out_dir)
    out.parent.mkdir(parents=True, exist_ok=True)
    staging: Path | None = None
    if full_regeneration:
        staging = Path(
            tempfile.mkdtemp(prefix=f".{out.name}.v2-", dir=out.parent)
        )
        if out.is_dir():
            baseline_migration_rows = migrate_card_directory(out, staging)
        else:
            baseline_migration_rows = ()
        target = staging
    else:
        out.mkdir(parents=True, exist_ok=True)
        baseline_migration_rows = ()
        target = out

    qll_rel = qll_path
    (target / "index.md").write_text(build_index(apis, qll_rel), encoding="utf-8")

    results: dict[str, Any] = {
        "schema_version": "sink-capability-card-regeneration/v2",
        "total": len(apis),
        "excluded_adapter_hooks": [row.api for row in adapter_hooks],
        "written": [],
        "failed": [],
        "migration_rows": list(baseline_migration_rows),
        "published": False,
    }
    for a in apis:
        if only and a.slug not in only and a.api not in only:
            continue
        try:
            previous = read_previous_card(out, a.slug)
            policy_contract = (
                extract_policy_contract(previous) if previous is not None else None
            )
            if not use_llm and previous is not None:
                card = migrate_markdown_card_to_v2(
                    previous, path=f"{a.slug}.md"
                )
            elif not use_llm:
                raise CapabilityCardError(
                    f"{a.slug}: no prior source-owned card to migrate; "
                    "unresolved scaffolds cannot be published"
                )
            else:
                card = generate_card(
                    a,
                    source_roots,
                    use_llm,
                    docs_cache,
                    refresh_docs,
                    preserved_policy_contract=policy_contract,
                    **agent_kw,
                )
            parse_capability_card(card)
            (target / f"{a.slug}.md").write_text(card, encoding="utf-8")
            results["written"].append(a.slug)
            migration_row = identity_migration_row(
                path=f"{a.slug}.md",
                previous_markdown=previous,
                v2_markdown=card,
            )
            results["migration_rows"] = [
                row
                for row in results["migration_rows"]
                if row["path"] != migration_row["path"]
            ]
            results["migration_rows"].append(migration_row)
        except Exception as e:  # keep going; record failure
            results["failed"].append({"slug": a.slug, "error": str(e)})
    results["migration_rows"] = list(
        build_identity_migration(results["migration_rows"])
    )
    if not full_regeneration:
        return results
    if results["failed"]:
        assert staging is not None
        shutil.rmtree(staging)
        return results
    assert staging is not None
    validated_cards = validate_card_directory(staging)
    (staging / "identity-migration.jsonl").write_text(
        "".join(
            json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n"
            for row in results["migration_rows"]
        ),
        encoding="utf-8",
    )
    qll_sha256 = hashlib.sha256(Path(qll_path).read_bytes()).hexdigest()
    manifest = {
        "schema_version": "sink-capability-card-regeneration/v2",
        "card_schema_version": CARD_SCHEMA_VERSION,
        "qll_path": qll_rel,
        "qll_sha256": qll_sha256,
        "owned_card_slugs": sorted(results["written"]),
        "validated_v2_cards": len(validated_cards),
        "migration_rows": len(results["migration_rows"]),
        "non_generator_owned_migrated": sorted(
            path.name
            for path in staging.glob("*.md")
            if path.name != "index.md" and path.stem not in set(results["written"])
        ),
        "migration_sha256": payload_sha256(results["migration_rows"]),
    }
    (staging / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    _atomic_publish(staging, out)
    results["published"] = True
    return results


def regenerate_all_cards(
    *,
    qll_path: str,
    out_dir: str,
    source_roots: list[str],
    use_llm: bool = True,
    docs_cache: str = DEFAULT_DOCS_CACHE,
    refresh_docs: bool = False,
    **agent_kw,
) -> dict[str, Any]:
    """Deterministically stage and atomically publish every Python-owned card."""

    return run(
        qll_path=qll_path,
        out_dir=out_dir,
        source_roots=source_roots,
        use_llm=use_llm,
        docs_cache=docs_cache,
        refresh_docs=refresh_docs,
        full_regeneration=True,
        **agent_kw,
    )
