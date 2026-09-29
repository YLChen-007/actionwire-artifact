"""Content-addressed identities shared by handler-level analyses."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def sha256_value(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def stable_handler_id(
    project_id: str,
    revision: str,
    tool_name: str,
    handlers: Sequence[Mapping[str, Any]],
) -> str:
    identity = {
        "project": project_id,
        "revision": revision,
        "tool_name": tool_name,
        "handlers": [
            {
                key: handler.get(key)
                for key in (
                    "tool_name",
                    "form",
                    "handler_func",
                    "file",
                    "line",
                    "forwarded_body",
                )
            }
            for handler in sorted(
                handlers,
                key=lambda row: (
                    str(row.get("file", "")),
                    int(row.get("line", 0)),
                    str(row.get("handler_func", "")),
                    str(row.get("form", "")),
                ),
            )
        ],
    }
    return "H-" + sha256_value(identity)[:16]
