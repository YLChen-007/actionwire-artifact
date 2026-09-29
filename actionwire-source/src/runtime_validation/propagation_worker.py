"""Direct native-dispatch worker for one propagation smoke role."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", type=Path, required=True)
    parser.add_argument("--role", choices=("exploit", "control"), required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    case = json.loads(args.case.read_text(encoding="utf-8"))
    source_root = Path(os.environ["CLAWGAP_HERMES_SOURCE_ROOT"])
    sys.path.insert(0, str(source_root))
    import tools.file_tools  # noqa: F401
    from tools.registry import registry

    tool_call = case["tool_calls"][args.role]
    result = registry.dispatch(tool_call["name"], tool_call["arguments"], task_id="smoke")
    args.result.write_text(
        json.dumps({"role": args.role, "result": result}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
