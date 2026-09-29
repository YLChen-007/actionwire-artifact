#!/usr/bin/env python3
"""Publish call-chain-input-to-oracle reviews; never inspect project sources."""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shlex

ROOT = Path(__file__).resolve().parents[3]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pointer(value, locator):
    if not locator.startswith("/"):
        raise ValueError(f"Expected a JSON pointer: {locator}")
    for key in locator.split("/")[1:]:
        key = key.replace("~1", "/").replace("~0", "~")
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def load_reviews(packet, review):
    inputs = {p.stem: json.loads(p.read_text()) for p in sorted((packet/"groups").glob("G*.json"))}
    rows = [json.loads(p.read_text()) for p in sorted((review/"groups").glob("G*.json"))]
    if len(rows) != len(inputs) or {r["sample_id"] for r in rows} != set(inputs):
        raise ValueError("Every sampled group needs an input-only review")
    ledger = []
    for row in rows:
        raw = inputs[row["sample_id"]]
        if row["group_id"] != raw["oracle"]["group_id"]:
            raise ValueError("Wrong group identity")
        expected = {}
        for i, member in enumerate(raw["members"]):
            sem = member["semantic"]
            for j, gate in enumerate(sem["gates"]):
                key = (sem["project"]["id"], sem["chain_id"], gate["gate_uid"])
                expected[key] = f"/members/{i}/semantic/gates/{j}"
        seen = set()
        requirements = {q["requirement_id"] for q in raw["oracle"]["requirements"]}
        for a in row["gate_assessments"]:
            if a["classification"] not in {"security", "functional", "uncertain"}:
                raise ValueError("Invalid classification")
            if a["coverage"] not in {"covered", "partial", "missing", "not-required", "uncertain"}:
                raise ValueError("Invalid coverage")
            if not set(a["requirement_ids"]) <= requirements:
                raise ValueError("Unknown output requirement")
            if not a.get("input_locators"):
                raise ValueError("Assessment has no input locator")
            for loc in a["input_locators"]:
                if not loc.startswith("/members/"):
                    raise ValueError("Gate evidence must come from a member input")
                pointer(raw, loc)
            for cid in a["chain_ids"]:
                key = (a["project"], cid, a["gate_uid"])
                if key not in expected or key in seen:
                    raise ValueError(f"Missing/duplicate gate identity: {row['sample_id']} {key}")
                seen.add(key)
                ledger.append({"sample_id": row["sample_id"], "project": key[0], "chain_id": key[1],
                               "gate_uid": key[2], "input_locator": expected[key],
                               **{k: a[k] for k in ("classification", "security_goal", "coverage", "requirement_ids", "reason")}})
        if seen != set(expected):
            raise ValueError(f"Unreviewed input gates: {row['sample_id']} {set(expected)-seen}")
        if bool(row["missing_semantics"]) != (row["verdict"] == "input-security-omission"):
            raise ValueError(f"Gap/verdict mismatch: {row['sample_id']}")
        for gap in row["missing_semantics"]:
            for loc in gap["input_locators"]:
                pointer(raw, loc)
    return inputs, rows, ledger


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", default="design/paperdata/group-oracle-review-30pct")
    parser.add_argument("--out-dir")
    args = parser.parse_args()
    packet = ROOT/args.packet
    review = packet/"validation/chain-input-only-v1"
    output = ROOT/args.out_dir if args.out_dir else review
    if (output/"report.md").exists():
        parser.error("Refusing to overwrite existing report; use a fresh --out-dir")
    inputs, rows, ledger = load_reviews(packet, review)
    counts = Counter(r["verdict"] for r in rows)
    gate_classes = Counter(a["classification"] for r in rows for a in r["gate_assessments"])
    gate_coverage = Counter(a["coverage"] for r in rows for a in r["gate_assessments"])
    members = sum(len(r["members"]) for r in inputs.values())
    requirements = sum(len(r["oracle"]["requirements"]) for r in inputs.values())
    command = "python design/paperdata/script/render_chain_input_oracle_review.py --packet " + shlex.quote(args.packet)
    if args.out_dir:
        command += " --out-dir " + shlex.quote(args.out_dir)
    labels = {"no-confirmed-input-omission": "未确认输入安全语义遗漏", "input-security-omission": "有输入安全语义遗漏", "uncertain": "待判"}
    body = ["# Call-chain 输入 → Group Oracle：安全语义保留核验", "", f"> 汇总命令（仓库根）：`{command}`。读取已撰写的逐组核验 JSON；已有报告不覆盖。", "",
            "本报告更正前几轮的比较范围：**只对比 oracle 构建时已有的 call-chain 信息与最终 oracle，不对照完整项目源码补充检查。**", "",
            f"范围：**{len(rows)} 个组、{members} 个输入成员、{len(ledger)} 次 gate 记录、{requirements} 条输出 requirements**。",
            f"组内合并相同 gate 后，逐项评判 {sum(gate_classes.values())} 条 gate 语义记录；所有原始成员均保留。", "",
            f"结果：**{counts['input-security-omission']} 组存在输入安全语义遗漏；{counts['no-confirmed-input-omission']} 组未确认遗漏；{counts['uncertain']} 组待判。**",
            "“未确认遗漏”只表示输入中已表达的安全目标未发现丢失。零 gate 输入不证明项目没有安全检查，也不证明生成的额外规则正确。", "",
            "## 正确的比较边界", "",
            "- 输入：原始样本 JSON 的 members[].semantic，包括 gates 的 steps/default/on_error、内嵌 source_rules、values、handler、sink 和 sink_constraint。",
            "- 输出：同一组 oracle.requirements。按安全目标及条件判断是否保留，不要求逐句复写实现。",
            "- 普通类型、非空、格式、存在性、路由名称解析、重试等功能信息允许省略；没有明确安全作用时不升级成权限要求。",
            "- 不打开项目源码寻找输入中没有的控制；不因外部源码对输入的反证删除成员，也不借能力卡创造输入安全检查。",
            "- proposals/assessments只能解释已知输入主题的去向，不用它们或此前源码审阅扩大比较基准。输入自身是否正确，是另一个评估问题。", "",
            "## 原先八项结论的口径更正", "",
            "| 组 | 原先声称的缺口 | 本次如何处理 |", "|---|---|---|",
            "| G01 | 目的地ACL | 原输入 gates=[]；撤回将此源码事实算作oracle漏提。 |",
            "| G07 | 节点RPC权限、环境变量过滤 | 这些主题不在原输入；撤回原缺口。链内已记录的审批/执行条件另行按输入检查。 |",
            "| G09 | host-control权限 | 不在原输入；撤回原缺口。 |",
            "| G26 | workdir防注入 | 输入只有轮询结果条件；撤回原缺口。 |",
            "| G28 | sandbox附件路径 | 两个成员 gates=[]；撤回原缺口。 |",
            "| G06 | URL秘密、SSRF过滤 | 两项已明确记录在输入gate中，可直接与空oracle比较。 |",
            "| G25 | 网站blocklist | 输入已有check_website_access及分支，可直接比较。 |",
            "| G31 | ephemeral隐私 | 改为核对输入已记录的slash上下文匹配、有效期及回复路由；不引入外部源码payload字段。 |", "",
            "之前的8/39源码缺口、116/12源码路径结论及规则准确性统计不能当作本报告的输入→oracle指标。", "",
            "## 全部组结果", "", "| 组 | 输入成员 / gate次数 | 本次结论 | 输入依据 |", "|---|---:|---|---|"]
    for row in rows:
        raw = inputs[row["sample_id"]]
        link = os.path.relpath(review/"groups"/f"{row['sample_id']}.md", output)
        occurrences = sum(len(m["semantic"]["gates"]) for m in raw["members"])
        body.append(f"| [{row['sample_id']}]({link}) | {len(raw['members'])} / {occurrences} | {labels[row['verdict']]} | {row['summary'].replace('|','/')} |")
    body += ["", "## 输入中已存在但未保留的安全语义", ""]
    for row in rows:
        if row["missing_semantics"]:
            body += [f"### {row['sample_id']}", ""]
            for gap in row["missing_semantics"]:
                body += ["- " + gap["description"], "  " + gap["reason"], "  Gate：" + ", ".join(gap["gate_uids"])]
            body += [""]
    body += ["## 可核验产物", "", "逐组JSON使用JSON Pointer定位原始输入；[逐成员gate台账](gate-ledger.jsonl)逐项覆盖全部输入gate。",
             "[核验清单](review-manifest.json)记录原始样本与审阅文件SHA256。原oracle和历史源码审阅保留。",
             "本轮为agent对冻结输入的语义核验，未进行真人签核或运行验证；不沿用源码推断作为完整性证据。", ""]
    output.mkdir(parents=True, exist_ok=True)
    (output/"report.md").write_text("\n".join(body), encoding="utf-8")
    (output/"gate-ledger.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False)+"\n" for r in ledger), encoding="utf-8")
    manifest = {"standard": "call-chain-input-security-retention/v1", "generation_command": command,
                "groups": len(rows), "members": members, "gate_occurrences": len(ledger), "output_requirements": requirements,
                "group_verdicts": dict(counts), "deduplicated_gate_classifications": dict(gate_classes), "deduplicated_gate_coverage": dict(gate_coverage),
                "project_source_as_completeness_baseline": False, "runtime_validation": False, "human_signoff": False,
                "input_json_sha256": {str(p.relative_to(ROOT)): sha(p) for p in sorted((packet/"groups").glob("G*.json"))},
                "review_json_sha256": {str(p.relative_to(ROOT)): sha(p) for p in sorted((review/"groups").glob("G*.json"))},
                "generator_sha256": sha(Path(__file__))}
    (output/"review-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(output/"report.md")


if __name__ == "__main__":
    main()
