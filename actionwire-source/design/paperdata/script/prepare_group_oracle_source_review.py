#!/usr/bin/env python3
"""Bind sampled group review to structural artifacts and archived CodeQL sources."""

import argparse
import csv
import hashlib
import json
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from src.projects import get_project  # noqa: E402


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", default="design/paperdata/group-oracle-review-10pct")
    parser.add_argument("--sources-dir", default="/tmp/clawgap-group-oracle-review-sources")
    parser.add_argument("--output", default="design/paperdata/group-oracle-review-10pct/validation/source-review-v1")
    args = parser.parse_args()
    packet, output, sources = ROOT / args.packet, ROOT / args.output, Path(args.sources_dir)
    records = [json.loads(p.read_text()) for p in sorted((packet / "groups").glob("G*.json"))]
    wanted = {(m["semantic"]["project"]["id"], m["semantic"]["chain_id"])
              for r in records for m in r["members"]}
    sink_manifest = json.loads((ROOT / "output/cross-project/sink-types/manifest.json").read_text())
    contexts, basis = {}, {}
    for project in sorted({p for p, _ in wanted}):
        spec = get_project(project).resolved()
        archive = spec.codeql_database / "src.zip"
        expected = sink_manifest["inputs"]["projects"][project]
        chain_path = spec.output_root / "static/call-chains/handler-sink-chains.csv"
        manifest_path = chain_path.parent / "manifest.json"
        if digest(chain_path) != expected["handler_sink_chains"] or digest(manifest_path) != expected["structural_manifest"]:
            raise ValueError(f"Structural artifact drift: {project}")
        with chain_path.open() as handle:
            for row in csv.DictReader(handle):
                if (project, row["chain_id"]) in wanted:
                    contexts[f"{project}:{row['chain_id']}"] = row
        prefix = str(spec.source_root).lstrip("/") + "/"
        inventory = {}
        with zipfile.ZipFile(archive) as zipped:
            for entry in zipped.infolist():
                if entry.is_dir() or not entry.filename.startswith(prefix):
                    continue
                relative = Path(entry.filename[len(prefix):])
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError(f"Unsafe source path: {relative}")
                content = zipped.read(entry)
                target = sources / project / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists() and target.read_bytes() != content:
                    raise ValueError(f"Refusing changed source snapshot: {target}")
                target.write_bytes(content)
                inventory[str(relative)] = hashlib.sha256(content).hexdigest()
        basis[project] = {"revision": expected["revision"], "archive": str(archive.relative_to(ROOT)),
                          "archive_sha256": digest(archive), "source_prefix": prefix,
                          "extracted_root": str(sources / project), "files": inventory,
                          "structural_csv_sha256": digest(chain_path), "structural_manifest_sha256": digest(manifest_path)}
    if len(contexts) != len(wanted):
        raise ValueError("Not every sampled chain has an exact structural row")
    output.mkdir(parents=True, exist_ok=True)
    for name, data in (("chain-context.json", contexts), ("source-basis.json", basis)):
        target = output / name
        text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        if target.exists() and target.read_text() != text:
            raise ValueError(f"Refusing changed review context: {target}")
        target.write_text(text)
    print(f"Prepared {len(contexts)} chains in {len(basis)} archived projects; sources: {sources}")


if __name__ == "__main__":
    main()
