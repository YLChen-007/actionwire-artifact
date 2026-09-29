"""CLI: generate the sink-API capability-card index table + per-API card files.

Examples
--------
# deterministically migrate existing cards to v2 (no LLM):
python -m src.sink_capacity.main --no-llm

# generate English cards for all sink APIs via DeepSeek:
python -m src.sink_capacity.main

# only specific sink APIs (by slug):
python -m src.sink_capacity.main --only subprocess.Popen pathlib.Path.read_text
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .generate import run
from .card_migration import migrate_card_directory, migrate_card_directory_in_place
from .doc_sources import crawl_all, DEFAULT_DOCS_CACHE


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Generate sink-API capability cards from sinks_af.qll")
    ap.add_argument("--qll", default="src/ql/call/sinks_af.qll", help="path to sinks_af.qll")
    ap.add_argument("--out", default="src/sink_capacity/sink-capability-cards",
                    help="output directory for index.md + <slug>.md cards")
    ap.add_argument("--source-root", action="append", dest="source_roots",
                    help="source tree(s) to grep for project-internal sink APIs (repeatable)")
    ap.add_argument(
        "--no-llm",
        action="store_true",
        help="migrate existing source-owned cards to v2 without model calls",
    )
    ap.add_argument("--only", nargs="*", default=None, help="restrict to these slugs / api ids")
    ap.add_argument("--docs-cache", default=DEFAULT_DOCS_CACHE,
                    help="local doc snapshot dir (crawl once, reuse from disk)")
    ap.add_argument("--refresh-docs", action="store_true", help="force re-crawl even if cached")
    ap.add_argument("--crawl-docs", action="store_true",
                    help="only crawl official docs into the local snapshot, then exit")
    migration = ap.add_mutually_exclusive_group()
    migration.add_argument(
        "--migrate-v2-staging",
        help="deterministically migrate every current card into this empty staging directory",
    )
    migration.add_argument(
        "--migrate-v2-in-place",
        action="store_true",
        help="atomically migrate every current card in --out to v2",
    )
    ap.add_argument(
        "--full-regeneration",
        action="store_true",
        help="stage all cards as v2 and atomically publish after full validation",
    )
    ap.add_argument("--model", default=None, help="override DeepSeek model id")
    ap.add_argument("--timeout", type=int, default=900, help="per-card agent timeout (s)")
    ap.add_argument("--max-turns", type=int, default=20, help="max agent tool-use turns per card")
    args = ap.parse_args(argv)

    if args.crawl_docs:
        res = crawl_all(args.docs_cache, refresh=args.refresh_docs)
        ok = sum(1 for v in res.values() if v)
        print(json.dumps({"cache_dir": args.docs_cache, "crawled_ok": ok,
                          "total": len(res), "results": res}, indent=2, ensure_ascii=False))
        return 0 if ok else 1

    if args.migrate_v2_staging or args.migrate_v2_in_place:
        source = Path(args.out)
        rows = (
            migrate_card_directory_in_place(source)
            if args.migrate_v2_in_place
            else migrate_card_directory(source, Path(args.migrate_v2_staging))
        )
        print(
            json.dumps(
                {"source": str(source), "migrated_cards": len(rows), "rows": rows},
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    source_roots = args.source_roots or ["/root/my-project/agent-research/clawgap/benchmark/python/hermes-agent"]
    agent_kw = {"timeout": args.timeout, "max_turns": args.max_turns}
    if args.model:
        agent_kw["model"] = args.model

    results = run(
        qll_path=args.qll,
        out_dir=args.out,
        source_roots=source_roots,
        use_llm=not args.no_llm,
        only=args.only,
        docs_cache=args.docs_cache,
        refresh_docs=args.refresh_docs,
        full_regeneration=args.full_regeneration,
        **agent_kw,
    )
    print(json.dumps(results, indent=2, ensure_ascii=False))
    return 1 if results["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
