"""Deterministic human- and machine-readable gate catalogs."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable

from .slicer import GateSlice


CATALOG_FIELDS = (
    "gate_number",
    "gate_uid",
    "gate_id",
    "mode",
    "static_verdict",
    "gate_name",
    "qualified_function",
    "enclosing_function",
    "callsite_file",
    "callsite_line",
    "callsite_column",
    "call_expression",
    "checked_expression",
    "actual_to_formal_binding",
    "binding_status",
    "unresolved_count",
    "content_digest",
)


def build_catalog(
    numbered_slices: Iterable[tuple[int, GateSlice]],
) -> list[dict[str, object]]:
    """Represent every successfully sliced gate without source or sink details."""
    rows: list[dict[str, object]] = []
    for gate_number, gate_slice in numbered_slices:
        span = gate_slice.callsite["span"]
        rows.append(
            {
                "gate_number": gate_number,
                "gate_uid": gate_slice.gate_uid,
                "gate_id": gate_slice.gate_id,
                "mode": gate_slice.gate["mode"],
                "static_verdict": gate_slice.gate["static_verdict"],
                "gate_name": gate_slice.gate["name"],
                "qualified_function": gate_slice.gate["qualified_function"],
                "enclosing_function": gate_slice.callsite["enclosing_function"],
                "callsite_file": span["file"],
                "callsite_line": span["start_line"],
                "callsite_column": span["start_column"],
                "call_expression": gate_slice.gate["call_expression"],
                "checked_expression": gate_slice.checked_value["expression"],
                "actual_to_formal_binding": gate_slice.checked_value[
                    "actual_to_formal_binding"
                ],
                "binding_status": gate_slice.checked_value["binding_status"],
                "unresolved_count": len(gate_slice.unresolved_symbols),
                "content_digest": gate_slice.content_digest,
            }
        )
    return rows


def _markdown(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", "<br>")


def write_catalog(
    *,
    csv_path: Path,
    markdown_path: Path,
    rows: list[dict[str, object]],
    generation_command: str,
    independent_example_command: str,
) -> None:
    """Write a deterministic CSV and a reproducible debug Markdown report."""
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CATALOG_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    lines = [
        "# Check Gate Catalog",
        "",
        f"> Generation command: `{generation_command}`",
        "",
        (
            f"Total: **{len(rows)}** distinct callsite-bound gates. Numbering is one-based, "
            "sorted by the current detector `gate_id`, and assigned before selection. "
            "Use `gate_uid` for persistent repository lookup; `needs-review` "
            "candidates are excluded."
        ),
        "",
        "Analyze gate #4 independently (replace `4` with any catalog number):",
        "",
        "```bash",
        independent_example_command,
        "```",
        "",
        (
            "The selected run writes `slice.json`, `semantic.json`, `audit.json`, and "
            "`chat.json` under `repository/<gate_uid>/`."
        ),
        "",
        "| # | Gate UID | Gate ID | Mode | Verdict | Gate | Enclosing function | Callsite | Checked expression | Binding | Unresolved | Content digest |",
        "|---:|---|---|---|---|---|---|---|---|---|---:|---|",
    ]
    for row in rows:
        callsite = (
            f"{row['callsite_file']}:{row['callsite_line']}:{row['callsite_column']}"
        )
        cells = [
            row["gate_number"],
            f"`{row['gate_uid']}`",
            f"`{row['gate_id']}`",
            row["mode"],
            row["static_verdict"],
            f"`{row['gate_name']}`",
            f"`{row['enclosing_function']}`",
            f"`{callsite}`",
            f"`{row['checked_expression']}`",
            f"`{row['actual_to_formal_binding']}` ({row['binding_status']})",
            row["unresolved_count"],
            f"`{str(row['content_digest'])[:12]}...`",
        ]
        lines.append("| " + " | ".join(_markdown(cell) for cell in cells) + " |")

    markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
