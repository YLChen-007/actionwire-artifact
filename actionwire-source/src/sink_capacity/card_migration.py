"""Deterministic identity ledger for capability-card v2 regeneration."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

from .card_contract import (
    CARD_AUTHORITY,
    CARD_SCHEMA_VERSION,
    CapabilityCardError,
    YAML_FENCE_RE,
    extract_policy_contract,
    parse_capability_card,
    payload_sha256,
    policy_contract_digest,
    render_capability_card,
    stable_card_id,
    validate_card_directory,
)


MIGRATION_SCHEMA_VERSION = "sink-capability-card-identity-migration/v1"
TYPESCRIPT_FAMILIES = {
    "codeg",
    "droidclaw",
    "javascript",
    "lettabot",
    "lobsterai",
    "mercury",
    "nanoclaw",
    "node",
    "openclaw",
    "openclaw-cn",
    "tinyclaw",
}
PYTHON_PROJECT_FAMILIES = {
    "_run_browser_command",
    "camofox_navigate",
    "execute_code",
    "file_ops",
    "provider",
    "supervisor",
}
BINDING_ROLES = {
    "args": "command",
    "command": "command",
    "shell": "shell-mode",
    "env": "environment",
    "cwd": "working-directory",
    "executable": "executable",
    "url": "destination-url",
    "urls": "destination-url",
    "path": "path",
    "file": "path",
    "content": "content",
    "text": "content",
    "message": "content",
    "payload": "payload",
    "json": "request-body",
    "data": "request-body",
    "params": "query-parameters",
    "headers": "headers",
    "code": "code",
    "expression": "code",
    "statement": "statement",
    "query": "statement",
}
PRIMARY_ROLE_BY_CLASS = {
    "process-spawn": ("command", "args"),
    "file-read": ("path", "path"),
    "file-write": ("path", "path"),
    "network-egress": ("destination-url", "url"),
    "code-eval": ("code", "code"),
    "user-consent": ("command", "command"),
    "delivery-render": ("content", "content"),
}


def markdown_sha256(markdown: str) -> str:
    return hashlib.sha256(markdown.encode("utf-8")).hexdigest()


def legacy_card_identity(markdown: str) -> tuple[str, str | None]:
    """Return the prior schema and card ID without treating legacy YAML as strict."""

    match = YAML_FENCE_RE.search(markdown)
    if match is None:
        return "sink-capability-card/legacy-v1", None
    try:
        payload = yaml.safe_load(match.group("body"))
    except yaml.YAMLError:
        return "sink-capability-card/legacy-v1", None
    if not isinstance(payload, dict):
        return "sink-capability-card/legacy-v1", None
    if payload.get("schema_version") != CARD_SCHEMA_VERSION:
        return "sink-capability-card/legacy-v1", None
    card_id = payload.get("card_id")
    return CARD_SCHEMA_VERSION, card_id if isinstance(card_id, str) else None


def identity_migration_row(
    *, path: str, previous_markdown: str | None, v2_markdown: str
) -> dict[str, Any]:
    """Bind one previous card payload to its validated v2 identity."""

    card = parse_capability_card(v2_markdown)
    if previous_markdown is None:
        previous_schema, previous_id = None, None
        disposition = "new"
        previous_sha = None
        previous_policy_sha = None
    else:
        previous_schema, previous_id = legacy_card_identity(previous_markdown)
        previous_sha = markdown_sha256(previous_markdown)
        previous_policy_sha = policy_contract_digest(previous_markdown)
        disposition = (
            "unchanged"
            if previous_id == card["card_id"]
            else "legacy-to-v2"
            if previous_id is None
            else "identity-changed"
        )
    return {
        "schema_version": MIGRATION_SCHEMA_VERSION,
        "path": path,
        "previous_schema_version": previous_schema,
        "previous_card_id": previous_id,
        "previous_markdown_sha256": previous_sha,
        "previous_policy_contract_sha256": previous_policy_sha,
        "card_id": card["card_id"],
        "v2_payload_sha256": payload_sha256(card),
        "v2_markdown_sha256": markdown_sha256(v2_markdown),
        "policy_contract_sha256": policy_contract_digest(v2_markdown),
        "disposition": disposition,
    }


def build_identity_migration(
    rows: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Return a path-sorted, duplicate-free migration ledger."""

    output = sorted((dict(row) for row in rows), key=lambda row: row["path"])
    paths = [row["path"] for row in output]
    if len(paths) != len(set(paths)):
        raise ValueError("identity migration contains duplicate card paths")
    return tuple(output)


def read_previous_card(root: Path, slug: str) -> str | None:
    path = root / f"{slug}.md"
    return path.read_text(encoding="utf-8") if path.is_file() else None


def validates_digest_transition(
    *,
    card_path: str,
    expected_sha256: str,
    actual_sha256: str,
    ledger_path: Path,
) -> bool:
    """Accept an old digest only when the v2 migration ledger binds it exactly."""

    if expected_sha256 == actual_sha256:
        return True
    if not ledger_path.is_file():
        return False
    basename = Path(card_path).name
    matches = []
    for line in ledger_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("path") == basename:
            matches.append(row)
    if len(matches) != 1:
        return False
    row = matches[0]
    return bool(
        row.get("schema_version") == MIGRATION_SCHEMA_VERSION
        and row.get("previous_markdown_sha256") == expected_sha256
        and row.get("v2_markdown_sha256") == actual_sha256
        and row.get("disposition") in {"legacy-to-v2", "identity-changed"}
    )


def _legacy_fields(markdown: str) -> dict[str, Any]:
    match = YAML_FENCE_RE.search(markdown)
    body = match.group("body") if match else ""
    try:
        parsed = yaml.safe_load(body) if body else None
    except yaml.YAMLError:
        parsed = None
    if isinstance(parsed, dict):
        return parsed

    def field(name: str, fallback_pattern: str | None = None) -> str:
        found = re.search(rf"(?m)^{re.escape(name)}:\s*(.+)$", body)
        if found:
            return found.group(1).strip().strip("`\"'")
        if fallback_pattern:
            found = re.search(fallback_pattern, markdown, re.IGNORECASE | re.MULTILINE)
            if found:
                return found.group(1).strip().strip("`\"'")
        return ""

    def block(name: str, next_name: str) -> str:
        found = re.search(
            rf"(?ms)^{re.escape(name)}:\s*\|[-+]?\s*\n(.*?)(?=^{re.escape(next_name)}:|\Z)",
            body,
        )
        return found.group(1).strip() if found else ""

    title = re.search(r"(?m)^#\s+`?([^`\n]+)`?", markdown)
    capability = block("capability", "implicit_defaults")
    if not capability:
        section = re.search(r"(?ms)^##\s+Capability\s*\n(.*?)(?=^##\s+|\Z)", markdown)
        capability = section.group(1).strip() if section else markdown.strip()
    defaults = block("implicit_defaults", "example_usage")
    return {
        "api": field("api", r"^-\s*API:\s*(.+)$")
        or (title.group(1).strip() if title else "legacy-api"),
        "capability_class": field("capability_class", r"^-\s*Capability class:\s*(.+)$")
        or "other",
        "controlled_param": field(
            "controlled_param", r"^-\s*Controlled argument:\s*(.+)$"
        ),
        "bound_sinks": [],
        "capability": capability,
        "implicit_defaults": defaults,
        "example_usage": {
            "benign": "See the source-owned legacy card for the original benign example.",
            "capability_edge": "See the source-owned legacy card for the original capability-edge example.",
        },
        "provenance": ["source-owned legacy capability card"],
    }


def _api_family(api: str, path: str) -> str:
    del api
    return Path(path).stem


def _runtime(api_family: str) -> dict[str, str]:
    package = api_family.split(".", 1)[0]
    typescript = package in TYPESCRIPT_FAMILIES
    python_project = package in PYTHON_PROJECT_FAMILIES
    return {
        "language": "typescript" if typescript else "python",
        "ecosystem": (
            "node-or-project-source"
            if typescript
            else "project-source"
            if python_project
            else "python-runtime"
        ),
        "package": package or "project-source",
        "version": "legacy-source-bound",
    }


def _roles(controlled: str, capability_class: str) -> list[dict[str, Any]]:
    grouped: dict[str, list[str]] = {}
    lowered = controlled.lower()
    for binding, role_id in BINDING_ROLES.items():
        if re.search(rf"\b{re.escape(binding)}\b", lowered):
            if capability_class in {
                "delivery",
                "delivery-render",
                "message-delivery",
                "message-edit",
                "card-delivery",
                "email-compose",
            } and binding in {"payload", "json", "data", "message", "text"}:
                role_id = "content"
            grouped.setdefault(role_id, []).append(binding)
    if not grouped:
        role_id, binding = PRIMARY_ROLE_BY_CLASS.get(
            capability_class, ("primary-input", "primary")
        )
        grouped[role_id] = [binding]
    return [
        {
            "role_id": role_id,
            "description": f"Legacy controlled role {role_id}.",
            "bindings": [
                {"expression": binding, "caller_bindable": True}
                for binding in sorted(set(bindings))
            ],
        }
        for role_id, bindings in sorted(grouped.items())
    ]


def _bullets(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(row).strip() for row in value if str(row).strip()]
    text = str(value or "").strip()
    rows = [
        re.sub(r"^\s*-\s*", "", row).strip()
        for row in text.splitlines()
        if re.match(r"^\s*-\s+", row)
    ]
    return rows or ([" ".join(text.split())] if text else [])


def _activation(role_ids: Sequence[str]) -> dict[str, Any]:
    return {
        "any_of": [
            {
                "predicate": "role-bound",
                "subject": role_id,
                "operator": "equals",
                "value": True,
            }
            for role_id in role_ids
        ]
    }


def _facet_rows(
    capability: object, *, role_ids: Sequence[str], requests_family: bool
) -> list[dict[str, Any]]:
    rows = _bullets(capability)
    if requests_family:
        forbidden = ("non-http", "file://", "ftp://", "dict://", "gopher://")
        rows = [
            row for row in rows if not any(token in row.lower() for token in forbidden)
        ]
    if not rows:
        rows = [
            "The API exercises its documented capability through the bound caller role."
        ]
    return [
        {
            "facet_id": "legacy-facet-" + hashlib.sha256(row.encode()).hexdigest()[:8],
            "capability": row,
            "role_ids": list(role_ids),
            "activation": _activation(role_ids),
        }
        for row in rows
    ]


def migrate_markdown_card_to_v2(
    markdown: str,
    *,
    path: str,
    runtime: Mapping[str, str] | None = None,
) -> str:
    """Deterministically preserve a current card in the strict v2 envelope."""

    try:
        return render_capability_card(parse_capability_card(markdown))
    except CapabilityCardError:
        pass
    legacy = _legacy_fields(markdown)
    api = str(legacy.get("api") or Path(path).stem)
    api_family = _api_family(api, path)
    capability_class = str(legacy.get("capability_class") or "other")
    runtime_row = dict(runtime or _runtime(api_family))
    roles = _roles(str(legacy.get("controlled_param") or ""), capability_class)
    role_ids = [row["role_id"] for row in roles]
    requests_family = api_family.startswith("requests.") or "requests.get-post" in path
    guarantees = []
    if requests_family:
        guarantees.append(
            {
                "guarantee_id": "http-https-adapters-only",
                "statement": (
                    "The default Requests session registers adapters only for http:// "
                    "and https://; other schemes raise InvalidSchema."
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
        )
    default_claims = _bullets(legacy.get("implicit_defaults"))
    if requests_family:
        unsupported = ("file://", "ftp://", "dict://", "gopher://")
        default_claims = [
            row
            for row in default_claims
            if not any(token in row.lower() for token in unsupported)
        ]
    defaults = [
        {
            "default_id": "legacy-default-"
            + hashlib.sha256(row.encode()).hexdigest()[:8],
            "role_id": None,
            "value": row,
            "security_effect": row,
            "activation": {
                "all_of": [
                    {
                        "predicate": "always",
                        "subject": "legacy-default",
                        "operator": "equals",
                        "value": True,
                    }
                ]
            },
        }
        for row in default_claims
    ]
    examples = legacy.get("example_usage")
    if not isinstance(examples, dict):
        examples = {}
    card: dict[str, Any] = {
        "schema_version": CARD_SCHEMA_VERSION,
        "card_id": stable_card_id(
            api_family=api_family,
            runtime=runtime_row,
            capability_class=capability_class,
        ),
        "api": api,
        "api_family": api_family,
        "runtime": runtime_row,
        "capability_class": capability_class,
        "normative_authority": CARD_AUTHORITY,
        "bound_sinks": [str(row) for row in legacy.get("bound_sinks", [])],
        "roles": roles,
        "facets": _facet_rows(
            legacy.get("capability"), role_ids=role_ids, requests_family=requests_family
        ),
        "library_guarantees": guarantees,
        "defaults": defaults,
        "example_usage": {
            "benign": str(
                examples.get("benign") or "Legacy benign example unavailable."
            ),
            "capability_edge": str(
                examples.get("capability_edge")
                or "Legacy capability-edge example unavailable."
            ),
        },
        "provenance": [
            str(row) for row in legacy.get("provenance", []) if str(row).strip()
        ]
        or [f"legacy-card:{path}"],
    }
    contract = extract_policy_contract(markdown)
    if contract is not None:
        card["policy_contract"] = contract
    return render_capability_card(card)


def migrate_card_directory(
    source_dir: Path,
    staging_dir: Path,
) -> tuple[dict[str, Any], ...]:
    """Regenerate every current Markdown card into a supplied staging directory."""

    if staging_dir.exists() and any(staging_dir.iterdir()):
        raise ValueError(f"staging directory is not empty: {staging_dir}")
    staging_dir.mkdir(parents=True, exist_ok=True)
    source_index = source_dir / "index.md"
    if source_index.is_file():
        shutil.copy2(source_index, staging_dir / "index.md")
    rows = []
    for source in sorted(source_dir.glob("*.md")):
        if source.name == "index.md":
            continue
        previous = source.read_text(encoding="utf-8")
        migrated = migrate_markdown_card_to_v2(previous, path=source.name)
        parse_capability_card(migrated)
        (staging_dir / source.name).write_text(migrated, encoding="utf-8")
        rows.append(
            identity_migration_row(
                path=source.name,
                previous_markdown=previous,
                v2_markdown=migrated,
            )
        )
    ledger = build_identity_migration(rows)
    (staging_dir / "identity-migration.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in ledger),
        encoding="utf-8",
    )
    validate_card_directory(staging_dir)
    return ledger


def migrate_card_directory_in_place(source_dir: Path) -> tuple[dict[str, Any], ...]:
    """Atomically migrate a directory, restoring the previous tree on publication failure."""

    staging = Path(
        tempfile.mkdtemp(prefix=f".{source_dir.name}.v2-", dir=source_dir.parent)
    )
    backup = source_dir.parent / f".{source_dir.name}.pre-v2"
    if backup.exists():
        shutil.rmtree(staging)
        raise ValueError(f"stale capability-card migration backup: {backup}")
    try:
        ledger = migrate_card_directory(source_dir, staging)
        os.replace(source_dir, backup)
        try:
            os.replace(staging, source_dir)
        except Exception:
            os.replace(backup, source_dir)
            raise
        shutil.rmtree(backup)
        return ledger
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        raise
