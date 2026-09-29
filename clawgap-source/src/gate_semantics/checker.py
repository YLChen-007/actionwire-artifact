"""CLI for checking and upgrading stored gate semantic artifacts."""

from __future__ import annotations

import argparse
import csv
import json
import shlex
import sys
from pathlib import Path
from typing import Any

from .behavior_checker import CHECKER_VERSION, check_and_upgrade_semantic


DEFAULT_STORE = Path("output/hermes/gate-semantics")


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, values: list[object]) -> None:
    path.write_text(
        "".join(
            json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            + "\n"
            for value in values
        ),
        encoding="utf-8",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify stored gate semantics against deterministic source profiles."
    )
    parser.add_argument(
        "--source-root", type=Path, default=Path("benchmark/python/hermes-agent")
    )
    parser.add_argument("--gate-semantics-dir", type=Path, default=DEFAULT_STORE)
    parser.add_argument(
        "--gate-number",
        action="append",
        type=int,
        default=None,
        help="restrict checking to one or more catalog ordinals",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="replace profiled semantic.json files with checked V3 records and update audits",
    )
    return parser


def _command(args: argparse.Namespace) -> str:
    parts = [
        "python",
        "-m",
        "src.gate_semantics.checker",
        "--source-root",
        str(args.source_root),
        "--gate-semantics-dir",
        str(args.gate_semantics_dir),
    ]
    for number in args.gate_number or []:
        parts.extend(["--gate-number", str(number)])
    if args.write:
        parts.append("--write")
    return shlex.join(parts)


def run(args: argparse.Namespace) -> dict[str, Any]:
    store = args.gate_semantics_dir
    repository_root = store / "repository"
    catalog_path = store / "gate-index.csv"
    with catalog_path.open(newline="", encoding="utf-8") as handle:
        catalog = list(csv.DictReader(handle))
    requested = set(args.gate_number or [])
    records: list[dict[str, Any]] = []
    for row in catalog:
        gate_number = int(row["gate_number"])
        if requested and gate_number not in requested:
            continue
        gate_uid = row.get("gate_uid", "")
        if not gate_uid:
            records.append(
                {
                    "gate_number": gate_number,
                    "verdict": "failed",
                    "findings": ["current catalog row has no gate_uid"],
                }
            )
            continue
        gate_dir = repository_root / gate_uid
        paths = {
            "slice": gate_dir / "slice.json",
            "semantic": gate_dir / "semantic.json",
            "audit": gate_dir / "audit.json",
        }
        if not all(path.is_file() for path in paths.values()):
            records.append(
                {
                    "gate_number": gate_number,
                    "gate_uid": gate_uid,
                    "gate_dir": str(gate_dir),
                    "verdict": "failed",
                    "findings": ["missing slice.json, semantic.json, or audit.json"],
                }
            )
            continue
        slice_payload = json.loads(paths["slice"].read_text(encoding="utf-8"))
        semantic = json.loads(paths["semantic"].read_text(encoding="utf-8"))
        audit = json.loads(paths["audit"].read_text(encoding="utf-8"))
        upgraded, evidence, check = check_and_upgrade_semantic(
            slice_payload=slice_payload,
            semantic_ir=semantic,
            evidence=audit.get("evidence", {}),
            source_root=args.source_root.resolve(),
        )
        record = {
            "gate_number": gate_number,
            "gate_uid": gate_uid,
            "gate_id": upgraded.get("gate_id"),
            "gate_dir": str(gate_dir),
            **check,
        }
        records.append(record)
        if args.write:
            audit["evidence"] = evidence
            previous_check = audit.get("semantic_check")
            if (
                isinstance(previous_check, dict)
                and "original_semantic_ir" in previous_check
                and "original_semantic_ir" not in check
            ):
                # A verified idempotent rewrite must not erase the first recovery's
                # LLM IR and findings. Keep that recovery record as provenance and
                # attach the latest source-profile verification separately.
                preserved_check = dict(previous_check)
                preserved_check["latest_verification"] = check
                audit["semantic_check"] = preserved_check
            else:
                audit["semantic_check"] = check
            _write_json(paths["semantic"], upgraded)
            _write_json(paths["audit"], audit)

    if requested:
        found = {record["gate_number"] for record in records}
        missing = sorted(requested - found)
        if missing:
            raise ValueError("unknown current gate numbers: " + ", ".join(map(str, missing)))

    counts = {
        "checked": len(records),
        "verified": sum(record.get("verdict") == "verified" for record in records),
        "recovered": sum(record.get("verdict") == "recovered" for record in records),
        "not_profiled": sum(record.get("verdict") == "not-profiled" for record in records),
        "failed": sum(record.get("verdict") == "failed" for record in records),
    }
    report = {
        "schema_version": "gate-semantic-check-report/v1",
        "checker_version": CHECKER_VERSION,
        "command": _command(args),
        "source_root": str(args.source_root.resolve()),
        "gate_semantics_dir": str(store),
        "write": bool(args.write),
        "counts": counts,
        "records": records,
    }
    if args.write:
        _write_json(store / "semantic-check-report.json", report)
        manifest_path = store / "manifest.json"
        if manifest_path.is_file():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["semantic_checker"] = {
                "checker_version": CHECKER_VERSION,
                "command": _command(args),
                "report": str(store / "semantic-check-report.json"),
                "counts": counts,
            }
            _write_json(manifest_path, manifest)
            selected_dirs = manifest.get("outputs", {}).get("selected_gate_dirs", {})
            semantic_records: list[dict[str, Any]] = []
            audit_records: list[dict[str, Any]] = []
            for _number, raw_dir in sorted(
                selected_dirs.items(), key=lambda item: int(item[0])
            ):
                selected_dir = Path(raw_dir)
                semantic_path = selected_dir / "semantic.json"
                audit_path = selected_dir / "audit.json"
                if semantic_path.is_file():
                    semantic_records.append(json.loads(semantic_path.read_text(encoding="utf-8")))
                if audit_path.is_file():
                    audit_records.append(json.loads(audit_path.read_text(encoding="utf-8")))
            _write_jsonl(store / "gate-semantics.jsonl", semantic_records)
            _write_jsonl(store / "gate-semantics-audit.jsonl", audit_records)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        report = run(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(report["counts"], indent=2, ensure_ascii=False))
    return 1 if report["counts"]["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
