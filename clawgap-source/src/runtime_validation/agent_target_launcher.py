"""Deterministic Hermes launcher used inside the Bubblewrap sandbox."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--runtime-config", required=True)
    parser.add_argument("target", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    target = list(args.target)
    if target and target[0] == "--":
        target = target[1:]
    if not target:
        raise SystemExit("agent target launcher requires a target command")
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    config["owner_pid"] = os.getpid()
    runtime_config = Path(args.runtime_config)
    runtime_config.write_text(
        json.dumps(config, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment["CLAWGAP_AGENT_INSTRUMENTATION_PATH"] = str(runtime_config)
    os.execve(target[0], target, environment)
    return 0  # pragma: no cover - execve replaces this process


if __name__ == "__main__":
    raise SystemExit(main())
