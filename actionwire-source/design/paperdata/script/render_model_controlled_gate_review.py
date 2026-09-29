#!/usr/bin/env python3
"""Publish the four-group review with an explicit model-origin admission rule."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import shlex

from render_chain_input_oracle_review import ROOT, pointer, sha

SUBJECTS = ("G06", "G07", "G25", "G31")


def load_reviews(packet, review):
    rows, ledger = [], []
    for sid in SUBJECTS:
        raw = json.loads((packet/"groups"/f"{sid}.json").read_text())
        row = json.loads((review/"groups"/f"{sid}.json").read_text())
        if row["sample_id"] != sid or row["group_id"] != raw["oracle"]["group_id"]:
            raise ValueError("Group mismatch")
        expected = {}
        for i, m in enumerate(raw["members"]):
            sem = m["semantic"]
            for j, g in enumerate(sem["gates"]):
                expected[(sem["project"]["id"], sem["chain_id"], g["gate_uid"])] = f"/members/{i}/semantic/gates/{j}"
        seen = set()
        reqs = {q["requirement_id"] for q in raw["oracle"]["requirements"]}
        for g in row["gate_reviews"]:
            origin = g["origin_status"]
            if origin not in {"model-origin-proven", "non-model-proven", "unknown"}:
                raise ValueError("Invalid origin status")
            eligible = (False if g["classification"] == "functional" or origin == "non-model-proven" else
                        True if g["classification"] == "security" and origin == "model-origin-proven" else None)
            if g["eligible"] is not eligible:
                raise ValueError(f"Admission rule mismatch: {sid} {g['gate_uid']}")
            if g["coverage"] in {"missing", "partial", "covered"} and eligible is not True:
                raise ValueError("Only admitted gates may have a required-coverage verdict")
            if not set(g["requirement_ids"]) <= reqs:
                raise ValueError("Unknown requirement")
            if not g["input_locators"]:
                raise ValueError("Missing input provenance")
            for loc in g["input_locators"]:
                if not loc.startswith("/members/"):
                    raise ValueError("Origin evidence must be member input, not oracle/proposal")
                pointer(raw, loc)
            for loc in g.get("output_locators", []):
                pointer(raw, loc)
            for cid in g["chain_ids"]:
                key = (g["project"], cid, g["gate_uid"])
                if key not in expected or key in seen:
                    raise ValueError("Gate membership mismatch or duplicate")
                seen.add(key)
                ledger.append({"sample_id": sid, "project": key[0], "chain_id": key[1], "gate_uid": key[2],
                               "input_locator": expected[key], **{k: g[k] for k in ("checked_subject", "policy_or_context_fields", "origin_status", "eligible", "coverage", "reason")}})
        if seen != set(expected):
            raise ValueError("Not every input gate was reviewed")
        if bool(row["retained_omissions"]) != (row["verdict"] == "confirmed-qualified-omission"):
            raise ValueError("Group verdict/gap mismatch")
        admitted = {g["gate_uid"] for g in row["gate_reviews"] if g["eligible"] is True and g["coverage"] in {"missing", "partial"}}
        for gap in row["retained_omissions"]:
            if not gap.get("gate_uids") or not set(gap["gate_uids"]) <= admitted:
                raise ValueError("Gap relies on an unqualified gate")
            for loc in gap["input_locators"]:
                pointer(raw, loc)
        rows.append(row)
    return rows, ledger


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir")
    args = parser.parse_args()
    packet = ROOT/"design/paperdata/group-oracle-review-30pct"
    review = packet/"validation/model-controlled-input-v1"
    output = ROOT/args.out_dir if args.out_dir else review
    if (output/"report.md").exists():
        parser.error("Refusing to overwrite an existing report; use a fresh --out-dir")
    rows, ledger = load_reviews(packet, review)
    counts = Counter(r["verdict"] for r in rows)
    origin_counts = Counter(g["origin_status"] for r in rows for g in r["gate_reviews"])
    coverage_counts = Counter(g["coverage"] for r in rows for g in r["gate_reviews"])
    command = "python design/paperdata/script/render_model_controlled_gate_review.py"
    if args.out_dir:
        command += " --out-dir " + shlex.quote(args.out_dir)
    labels = {"confirmed-qualified-omission": "仍确认不完整", "qualified-checks-covered": "合格检查已覆盖", "insufficient-provenance": "来源证据不足，待判"}
    body = ["# 四组复核：只要求保留被检查值源自模型的安全 gate", "", f"> 汇总命令（仓库根）：`{command}`。读取逐项审阅记录，不自动生成来源结论；重现请使用新的 --out-dir。", "",
            "本轮只复核此前判为不完整的 **G06、G07、G25、G31**，共 **11 个成员、141 次 gate 记录（52 个组内去重记录）、10 条已有 requirements**。",
            f"结论：**{counts['confirmed-qualified-omission']} 组仍确认不完整；{counts['insufficient-provenance']} 组因检查参数来源未证明而待判；{counts['qualified-checks-covered']} 组可明确判为合格检查均已覆盖。**", "",
            "G06/G25保留确认遗漏；G07/G31不再计为确认遗漏，但不能据来源不明改判为完整或不可由模型控制。其余35个组未应用本轮新增门槛，不能由此推算全39组的通过率。", "",
            "## 判定标准", "",
            "必须保留 = 检查具有安全意义，并且call-chain输入明确证明被检查主体来自模型字段（可经过已记录的派生）。",
            "- 不把整个args绑定多个gate视为每个gate字段都模型可控；helper的params与工具args不是同一对象。",
            "- 只有字段来源、赋值/解构/转换或实参传递在输入中有明确记载，才记model-origin-proven。同名变量、同链出现、一般能力标签和proposal文字都不补齐缺失的边。",
            "- 被检查URL可来自模型，而regex、blocklist、policy.enabled是比较基准或适用条件；不要求这些基准也来自模型。",
            "- 已证明的模型URL→检查结果→条件分支仍可追溯到模型输入；这不表示模型能任意指定检查结果。",
            "- 来源unknown的安全gate暂不进入必须保留集合，标not-assessable；不是证实其不受模型影响，也不是oracle已覆盖。普通功能gate仍可省略。",
            "- 只使用原Gxx.json里的成员IR；没有读取项目源码补数据流。model-origin-proven是对输入记录的判断，不是独立源码或运行证明。", "",
            "## 逐组结论", "", "| 组 | 本轮结论 | 参数来源与覆盖 |", "|---|---|---|"]
    for row in rows:
        link = os.path.relpath(review/"groups"/f"{row['sample_id']}.md", output)
        body.append(f"| [{row['sample_id']}]({link}) | {labels[row['verdict']]} | {row['summary'].replace('|','/')} |")
    body += ["", "## 关键来源链", "",
             "**G06：** 入口source_parameter明确包含urls；gate.input/steps将_url和url绑定为urls列表元素。秘密模式与SSRF过滤均具模型来源，最终oracle为空，两个安全目标仍缺。策略配置不改变被检查对象的来源。", "",
             "**G25：** 直接check_website_access的input明确写args-derived URL；随后的blocked判断明确来自该调用返回值。已有scheme/SSRF规则覆盖相应目标，但域名blocklist目标仍缺。只用这对明确来源记录确认缺口；更深_download_image中的同名URL实例暂不补猜跨helper来源。", "",
             "**G07：** 只有args→聚合CV→多个gate_id；没有args字段到command/analysis/segments/ask/security实参的完整映射。内部command→analysis关系不补足模型起点；ask也未证明必定来自可信配置。此前授权范围/审批遗漏均转为来源待证。", "",
             "**G31：** 上游可见args.target被解析为工具handler的chat_id；下游slash helper也检查名为chat_id的形参。但缺少跨发送函数/adapter的实参传递或值ID连接，不能认定两者就是同一个模型派生值。uid、时钟、TTL和stash另列运行上下文；此前slash-context遗漏暂不计为确认。", "",
             "## 需要补什么才能解除待判", "",
             "- G07：记录工具模型字段→实际命令/argv→analysis结果→审批helper实参各字段的def-use；对ask/security单独标配置、固定值、模型字段或unknown，并保存实际绑定证据。",
             "- G31：记录args.target→解析/目录结果→每个发送helper和adapter的chat_id实参/形参关系；若路径中被配置目的地替换，必须保留替换，不能继承上游模型来源标签。",
             "这些是补充call-chain来源证据的建议，本轮未改写原始输入或canonical oracle，也未把待判假定为通过。", "",
             "## 核验产物", "",
             "[逐出现位置台账](gate-origin-ledger.jsonl)覆盖全部141次gate；各组JSON把检查主体与policy/context字段分开，附输入JSON Pointer。",
             "[清单](review-manifest.json)记录输入、审阅文件哈希和计数。此前[输入语义审阅](../chain-input-only-v1/report.md)未施加模型来源门槛，其4组遗漏是旧口径。", ""]
    output.mkdir(parents=True, exist_ok=True)
    (output/"report.md").write_text("\n".join(body), encoding="utf-8")
    (output/"gate-origin-ledger.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False)+"\n" for r in ledger), encoding="utf-8")
    manifest = {"standard": "model-origin-qualified-input-security/v1", "generation_command": command, "selected_groups": list(SUBJECTS),
                "scope": "Only the four prior omission groups; no new verdict for remaining35 groups", "group_verdicts": dict(counts),
                "members": 11, "gate_occurrences": len(ledger), "unique_gate_reviews": sum(len(r['gate_reviews']) for r in rows), "existing_requirements": 10,
                "origin_counts_deduplicated": dict(origin_counts), "coverage_counts_deduplicated": dict(coverage_counts),
                "external_source_used": False, "runtime_validation": False, "human_signoff": False,
                "input_json_sha256": {str((packet/'groups'/f'{sid}.json').relative_to(ROOT)): sha(packet/'groups'/f'{sid}.json') for sid in SUBJECTS},
                "review_json_sha256": {str((review/'groups'/f'{sid}.json').relative_to(ROOT)): sha(review/'groups'/f'{sid}.json') for sid in SUBJECTS},
                "generator_sha256": sha(Path(__file__)), "pointer_helper_sha256": sha(Path(__file__).with_name('render_chain_input_oracle_review.py'))}
    (output/"review-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(output/"report.md")


if __name__ == "__main__":
    main()
