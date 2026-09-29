#!/usr/bin/env python3
"""Sample the 129 baseline group oracles into a new, reproducible review packet."""

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import random
import shlex
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from src.projects import get_project  # noqa: E402
from group_oracle_sample_render import render


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pretty(value):
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20260922)
    parser.add_argument("--fraction", type=float, default=0.1)
    parser.add_argument("--extend-from", help="Preserve a previous single-stage draw and randomly extend it")
    parser.add_argument("--out-dir", default="design/paperdata/group-oracle-review-10pct")
    args = parser.parse_args()
    output = ROOT / args.out_dir
    if output.exists():
        parser.error("Output already exists; choose a new --out-dir to preserve manual notes.")
    fingerprints = {}

    def read(relative, jsonl=False, expected=None):
        data = (ROOT / relative).read_bytes()
        fingerprints[str(relative)] = sha(data)
        if expected and sha(data) != expected:
            raise ValueError(f"Input drift: {relative}")
        return [json.loads(line) for line in data.splitlines()] if jsonl else json.loads(data)

    base = Path("output/cross-project")
    manifest = read(base / "group-oracles/manifest.json")
    alignment = read(base / "sink-types/manifest.json", expected=manifest["inputs"]["sink_alignment"]["manifest"])
    groups = read(base / "sink-types/handler-sink-groups.jsonl", True,
                  manifest["inputs"]["sink_alignment"]["handler_sink_groups"])
    groups = {g["handler_sink_group_id"]: g for g in groups if g["downstream_oracle_eligible"]}
    oracles = sorted(read(base / "group-oracles/oracles.jsonl", True), key=lambda o: o["group_id"])
    ids = [o["group_id"] for o in oracles]
    counts = alignment["counts"]
    if (len(ids), len(set(ids)), sum(g["chain_count"] for g in groups.values()),
        sum(g["chain_count"] == 1 for g in groups.values()), counts["structural_chains"],
        counts["excluded_chains"]) != (129, 129, 485, 68, 603, 118) or set(ids) != set(groups):
        raise ValueError("Population differs from the requested 129/485/68/603/118 snapshot.")
    for oracle in oracles:
        group = groups[oracle["group_id"]]
        refs = oracle["member_chain_refs"]
        if (len(refs) != group["chain_count"] or
            {(r["project"], r["chain_id"]) for r in refs} != {(r["project"], r["chain_id"]) for r in group["chain_refs"]} or
            any(oracle[k] != group[k] for k in ("handler_criterion_id", "sink_type_id"))):
            raise ValueError(f"Oracle/group mismatch: {oracle['group_id']}")
    if not 0 < args.fraction <= 1:
        parser.error("--fraction must be in (0, 1]")
    count = math.ceil(len(oracles) * args.fraction)
    rng = random.Random(args.seed)
    extension = None
    if args.extend_from:
        prior = ROOT / args.extend_from
        prior_manifest = read((prior / "manifest.json").relative_to(ROOT))
        prior_population = read((prior / "population.json").relative_to(ROOT))
        if prior_population != oracles or prior_manifest["seed"] != args.seed:
            raise ValueError("Prior draw population/seed mismatch")
        retained = rng.sample(oracles, prior_manifest["sample_count"])
        if [o["group_id"] for o in retained] != prior_manifest["selected_group_ids"] or count < len(retained):
            raise ValueError("Cannot reproduce or shrink the prior single-stage draw")
        chosen = {o["group_id"] for o in retained}
        selected = retained + rng.sample([o for o in oracles if o["group_id"] not in chosen], count - len(retained))
        extension = {"previous_packet": args.extend_from, "retained_count": len(retained), "additional_count": count - len(retained),
                     "method": "Replay previous random.sample; continue same RNG sampling the sorted complement without replacement"}
    else:
        selected = rng.sample(oracles, count)
    hc = read(base / "handler-types/catalog.json", expected=manifest["inputs"]["handler_alignment"]["catalog"])
    st = read(base / "sink-types/catalog.json", expected=manifest["inputs"]["sink_alignment"]["catalog"])
    hc = {r["handler_criterion_id"]: r for r in hc["criteria"]}
    st = {r["sink_type_id"]: r for r in st["sink_types"]}
    evidence = {r["evidence_id"]: r for r in read(base / "group-oracles/evidence-index.json")["evidence"]}
    auxiliary = {name: read(base / f"group-oracles/{name}.jsonl", True)
                 for name in ("proposals", "proposal-assessments", "seed-profiles")}
    members = {}
    for project in sorted({r["project"] for o in selected for r in o["member_chain_refs"]}):
        spec = get_project(project).resolved()
        expected = manifest["inputs"]["projects"][project]
        folder = spec.output_root.relative_to(ROOT) / "call-chain-semantics"
        read(folder / "manifest.json", expected=expected["semantic_manifest"])
        path = folder / "call-chain-semantics.jsonl"
        for line, sem in enumerate(read(path, True, expected["call_chain_semantics"]), 1):
            if sem["project"] != {"id": project, "revision": expected["revision"]}:
                raise ValueError(f"Semantic revision mismatch: {project}")
            members[(project, sem["chain_id"])] = {"semantic": sem, "artifact": str(path), "line": line,
                                                  "codeql_source_archive": str(spec.codeql_database / "src.zip")}
    command = shlex.join(["python", str(Path(__file__).relative_to(ROOT)), "--seed", str(args.seed), "--fraction", str(args.fraction), "--out-dir", args.out_dir] + (["--extend-from", args.extend_from] if args.extend_from else []))
    records = []
    for number, oracle in enumerate(selected, 1):
        record = {"sample_id": f"G{number:02d}", "oracle": oracle, "group": groups[oracle["group_id"]],
                  "handler_criterion": hc[oracle["handler_criterion_id"]], "sink_type": st[oracle["sink_type_id"]],
                  "members": [members[(r["project"], r["chain_id"])] for r in oracle["member_chain_refs"]]}
        if any(r["revision"] != m["semantic"]["project"]["revision"] for r, m in zip(oracle["member_chain_refs"], record["members"])):
            raise ValueError(f"Oracle member revision mismatch: {oracle['group_id']}")
        for name, rows in auxiliary.items():
            record["assessments" if name == "proposal-assessments" else name] = [r for r in rows if r["group_id"] == oracle["group_id"]]
        ev_ids = {e for row in oracle["requirements"] + record["assessments"] for e in row["evidence_ids"]}
        cards = {(m["semantic"]["sink_constraint"]["capability_card"]["path"],
                  m["semantic"]["sink_constraint"]["capability_card"]["sha256"]) for m in record["members"]}
        context_ids = {e["evidence_id"] for e in evidence.values() if (e["source_path"], e["sha256"]) in cards}
        record["evidence"] = []
        for ev_id in sorted(ev_ids | context_ids):
            ev = dict(evidence[ev_id])
            ev["review_context"] = "requirement-or-assessment" if ev_id in ev_ids else "member-capability-context"
            ev["quote_matches_recorded_source"] = sha(ev["exact_quote"].encode()) == ev["sha256"]
            source = ROOT / ev["source_path"]
            ev["current_source_sha256"] = sha(source.read_bytes()) if source.is_file() else None
            ev["current_source_matches"] = ev["current_source_sha256"] == ev["sha256"]
            record["evidence"].append(ev)
        records.append(record)
    # All input validation completes before creating any review files.
    (output / "groups").mkdir(parents=True)
    summary = ["# Group oracle 随机人工检查样本", "", f"> 从仓库根复现（请使用新输出目录）：`{command}`", "",
               "总体：原始 baseline 的 **129 个 group oracle（68 singleton + 61 多链组）**，覆盖 485 条 eligible chains。",
               "603 条 structural chains 中排除 107 条 no-security-impact 和 11 条 unresolved-handler-alignment。", "",
               f"目标比例 {args.fraction:.0%}，向上取整为 **{count}/129 = {count / 129:.2%}**；总体按 group_id 排序，seed=`{args.seed}`，等概率无放回抽样。",
               (f"扩样：重放原 {extension['retained_count']} 个抽样，再沿用同一 RNG 从剩余总体抽取 {extension['additional_count']} 个。完整算法与旧总体哈希见 manifest。" if extension else f"算法：random.Random({args.seed}).sample(population, {count})。"),
               "随机种子在首次抽取前固定；不按项目、组大小、oracle 状态或 requirement 数筛选，也不重新抽取以平衡结果。", "",
               f"本次：{sum(len(o['member_chain_refs']) == 1 for o in selected)} singleton、{sum(len(o['member_chain_refs']) > 1 for o in selected)} 多链组；"
               f"{sum(len(o['member_chain_refs']) for o in selected)} 条成员链；{sum(len(o['requirements']) for o in selected)} 条 requirements。",
               "抽样单位是 group；这些链是抽中组的全部成员，并非另从 485 条链中按同一比例抽样。", "",
               "每组 Markdown 提供人工填写栏；JSON 保存原始 oracle、完整成员 semantic IR、类型定义、seed、proposal、审核理由和证据引文。",
               "证据来源文件若已变化会逐项标记；审查原始推导时使用保存的引文和指定 revision。", "",
               "检查：成员是否共享 HC/ST；要求是否具有安全意义和规范依据；条件适用范围及门控来源是否准确；是否遗漏或错误拒绝要求。",
               "Capability card 描述能力，不能仅凭其描述自动推出安全策略。partial 或空 requirements 均需保留检查，不能自动判正确或错误。",
               "所有人工结论均留空；生成器拒绝覆盖已有目录，保护检查笔记。", "",
               "| 样本 | Group | Handler → Sink | 链数 | 原状态 | Requirements |", "|---|---|---|---:|---|---:|"]
    for record in records:
        sid, o = record["sample_id"], record["oracle"]
        (output / "groups" / f"{sid}.json").write_text(pretty(record), encoding="utf-8")
        (output / "groups" / f"{sid}.md").write_text(render(record, command, ROOT), encoding="utf-8")
        label = record["handler_criterion"]["canonical_label"] + " → " + record["sink_type"]["criterion"]["canonical_label"]
        summary.append(f"| [{sid}](groups/{sid}.md) | `{o['group_id']}` | {label.replace('|', '/')} | {len(o['member_chain_refs'])} | {o['status']} | {len(o['requirements'])} |")
    (output / "README.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    (output / "population.json").write_text(pretty(oracles), encoding="utf-8")
    audit = {"generation_command": command, "seed": args.seed, "sample_unit": "global group oracle", "without_replacement": True,
             "population_count": 129, "sample_count": count, "requested_fraction": args.fraction, "extension": extension, "selected_group_ids": [o["group_id"] for o in selected],
             "sample_status_counts": dict(Counter(o["status"] for o in selected)), "manual_reviewed_count_at_generation": 0,
             "input_sha256": fingerprints, "generator_sha256": sha(Path(__file__).read_bytes())}
    (output / "manifest.json").write_text(pretty(audit), encoding="utf-8")
    print(output / "README.md")


if __name__ == "__main__":
    main()
