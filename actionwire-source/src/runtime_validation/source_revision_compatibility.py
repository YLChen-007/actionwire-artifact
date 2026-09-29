"""Explicit compatibility bindings for synthetic runtime source revisions."""

from __future__ import annotations

from pathlib import Path


HERMES_BASE_REVISION = "04439ac77f08915b4886bc3c79165a9538af6219"
HERMES_SOURCE_REVISION = (
    HERMES_BASE_REVISION + "+legacy-command-bypass-source-v1"
)
HERMES_APPROVAL_BASE_SHA256 = (
    "22c4ada14c5f85460eab5c1972a903748e8d90dc7e2beb21b30b061bcbe1f15b"
)
HERMES_APPROVAL_SOURCE_REVISED_SHA256 = (
    "3c3c85d12ad1aa936ee7600f49a69ba3136ecd1949af3e19635e225ed2f6e180"
)
SOURCE_REVISION_HASHES = {
    (
        "hermes-agent",
        "tools/approval.py",
        HERMES_APPROVAL_BASE_SHA256,
    ): (HERMES_APPROVAL_SOURCE_REVISED_SHA256, "_CLAWGAP_LEGACY_BYPASS_COMMANDS"),
    (
        "nanobot",
        "nanobot/agent/tools/shell.py",
        "fba339ac46a437dc9ced1871e13f06dda1119521bf3d740d7c709c082120e128",
    ): ("7e5e9a7afd6dbf4afb98e0a0e2f92ec2af9ed30e7d01e13298524a2a6b6ab292", "login_shell_profile"),
    (
        "nanobot",
        "nanobot/config/schema.py",
        "6514f5c9366f8c4f2d3b0ac3611658ba2640a5a77a07a3cbf88d51fb512f38ba",
    ): ("2637ddcf65ca4fb4a1fd4df7fdbcc90644f1ac46f7c4039ab187e859dfa34b80", "login_shell_profile"),
    (
        "nanobot",
        "nanobot/agent/loop.py",
        "d9cf50665c6153808c495621f7d3e42415f383754fea35ebd0c7b735ebd58701",
    ): ("cfae98f20c7c1aa8d42ef2574311d832ed5684d7758638ed2b048c632b70aeec", "login_shell_profile"),
    (
        "openclaw",
        "src/agents/tools/message-tool.ts",
        "304c5f1b076a0770d386dfd508b54fe77b11709623d8ed02d8ecd92b0cee0c59",
    ): (
        "9d505696336edbf186416c3757aae5773e10d1340213f676e6e9232c7ef780c3",
        "CLAWGAP_SOURCE_REVISED_MESSAGE_MEDIA",
    ),
    (
        "chatgpt-on-wechat",
        "agent/tools/browser/browser_tool.py",
        "c3bde33b955e8a98a5cd3b62bd809f6b274eade8ab14e97041a9b20d6650f4d6",
    ): (
        "ce7e77a4cafc4591220db20aadfdf9933bb19a3a0024a48fa97402f41c73bad8",
        "CLAWGAP_SOURCE_REVISED_FILE_SCHEME",
    ),
}


def binding_hash_matches(
    *,
    project: str,
    relative: str,
    expected: str,
    actual: str,
    source_root: Path,
) -> bool:
    """Allow frozen base bindings to read explicitly revised native sources.

    The compatibility is intentionally limited to one file and requires the exact
    source marker. It prevents unrelated source drift from passing silently.
    """

    if expected == actual:
        return True
    compatibility = SOURCE_REVISION_HASHES.get((project, relative, expected))
    if compatibility is None or actual != compatibility[0]:
        return False
    source = (source_root / relative).read_text(encoding="utf-8")
    return compatibility[1] in source
