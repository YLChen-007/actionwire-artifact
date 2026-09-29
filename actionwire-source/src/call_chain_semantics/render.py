"""Human-readable rendering for ordered call-chain semantic artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .assembler import CallChainSliceV2


def render_semantic(ir: dict[str, Any]) -> str:
    lines = [f"{ir['chain_id']}: {ir['summary']}"]
    for index, gate in enumerate(ir["gates"], 1):
        semantic = gate["semantic"]
        lines.append(
            f"{index}. {gate['gate_uid']} ({semantic['gate_id']}) {gate['gate_name']} "
            f"[{gate['static_verdict']}] at {gate['callsite']}"
        )
    lines.append("status: " + ir["status"])
    return "\n".join(lines)


def write_chain_index(
    *,
    path: Path,
    generation_command: str,
    chain_slice: CallChainSliceV2,
    semantic_ir: dict[str, Any] | None,
) -> None:
    lines = [
        "# Ordered Call-Chain Gate Semantics",
        "",
        f"> Generation command: `{generation_command}`",
        "",
        f"Chain: `{chain_slice.chain_id}`",
        "",
        f"Handler: `{chain_slice.handler['tool_name']}` via `{chain_slice.handler['call_graph_root']}`",
        "",
        f"Sink boundary: `{chain_slice.sink['name']}@{chain_slice.sink['location']}`",
        "",
        "## Exact-Chain Detected Gates",
        "",
        "The table order is the authoritative gate order.",
        "",
        "| Position | Catalog | Gate UID | Gate ID | Gate | Callsite | Verdict |",
        "|---:|---:|---|---|---|---|---|",
    ]
    for index, gate in enumerate(chain_slice.selected_gates, 1):
        lines.append(
            f"| {index} | #{gate['gate_number']} | `{gate['gate_uid']}` | "
            f"`{gate['gate_id']}` | "
            f"`{gate['gate_name']}` | `{gate['callsite']}` | "
            f"`{gate['static_verdict']}` |"
        )
    if semantic_ir is not None:
        lines.extend(
            [
                "",
                "## Result",
                "",
                f"Summary: {semantic_ir['summary']}",
                "",
                f"Ordered gates: **{len(semantic_ir['gates'])}**",
                "",
                f"Unresolved dependencies: **{len(semantic_ir['unresolved'])}**",
                "",
                f"Status: `{semantic_ir['status']}`",
            ]
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
