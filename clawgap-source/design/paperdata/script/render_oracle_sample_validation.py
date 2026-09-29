#!/usr/bin/env python3
"""Validate and publish every member of an expanded security-only oracle review."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import shlex

from render_group_oracle_source_review import ROOT, dump, freeze_evidence, sha


def load_review(packet, review):
    sampling = json.loads((packet / "manifest.json").read_text())
    originals = {p.stem: json.loads(p.read_text()) for p in sorted((packet / "groups").glob("G*.json"))}
    reports = [json.loads(p.read_text()) for p in sorted((review / "groups").glob("G*.json"))]
    if len(reports) != sampling["sample_count"] or {r["sample_id"] for r in reports} != set(originals):
        raise ValueError("Full sampled group coverage is required")
    if [originals[s]["oracle"]["group_id"] for s in sorted(originals)] != sampling["selected_group_ids"]:
        raise ValueError("Sample identity/order mismatch")
    for path, expected in sampling["input_sha256"].items():
        if sha(ROOT / path) != expected:
            raise ValueError(f"Original input drift: {path}")
    for report in reports:
        original = originals[report["sample_id"]]["oracle"]
        if report["group_id"] != original["group_id"]:
            raise ValueError("Group identity mismatch")
        expected = [(c["project"], c["chain_id"]) for c in original["member_chain_refs"]]
        actual = [(c["project"], c["chain_id"]) for c in report["chain_reviews"]]
        if sorted(expected) != sorted(actual):
            raise ValueError(f"Chain coverage mismatch: {report['sample_id']}")
        if sorted(q["requirement_id"] for q in original["requirements"]) != sorted(q["requirement_id"] for q in report["requirement_reassessment"]):
            raise ValueError(f"Requirement coverage mismatch: {report['sample_id']}")
        if bool(report["retained_security_gaps"]) != (report["security_completeness"] == "missing-security-semantics"):
            raise ValueError("Gap/verdict mismatch")
        valid_members = {c["chain_id"] for c in report["chain_reviews"] if c["verdict"] == "valid"}
        for gap in report["retained_security_gaps"]:
            if not gap.get("evidence") or not set(gap["affected_chain_ids"]) <= valid_members:
                raise ValueError("Gap must bind to source-supported sampled members and evidence")
    reused = json.loads((review / "reuse-manifest.json").read_text())
    for item in reused:
        for key in ("security_review", "source_trace"):
            if sha(ROOT / item[key]) != item[f"{key}_sha256"]:
                raise ValueError("Reused review changed")
        if sha(packet / "groups" / f"{item['sample_id']}.json") != item["sample_json_sha256"]:
            raise ValueError("Reused sample changed")
    return sampling, originals, reports, reused


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", default="design/paperdata/group-oracle-review-30pct")
    parser.add_argument("--out-dir", help="New publication directory; defaults to packet/validation/security-only-v1")
    args = parser.parse_args()
    packet = ROOT / args.packet
    review = packet / "validation/security-only-v1"
    output = ROOT / args.out_dir if args.out_dir else review
    if (output / "report.md").exists():
        parser.error("Refusing to overwrite an existing report; use a fresh --out-dir")
    sampling, originals, reports, reused = load_review(packet, review)
    basis = json.loads((review / "source-basis.json").read_text())
    for item in basis.values():
        if sha(ROOT / item["archive"]) != item["archive_sha256"]:
            raise ValueError("Source archive changed")
    output.mkdir(parents=True, exist_ok=True)
    inventory, citations = freeze_evidence(reports, basis, output)
    coverage = Counter(r["security_completeness"] for r in reports)
    soundness = Counter(r["security_soundness"] for r in reports)
    chain_counts = Counter(c["verdict"] for r in reports for c in r["chain_reviews"])
    requirement_roles = Counter(q["role"] for r in reports for q in r["requirement_reassessment"])
    n = len(reports)
    chain_count = sum(chain_counts.values())
    req_count = sum(requirement_roles.values())
    singleton = sum(len(o["oracle"]["member_chain_refs"]) == 1 for o in originals.values())
    command = "python design/paperdata/script/render_oracle_sample_validation.py --packet " + shlex.quote(args.packet)
    if args.out_dir:
        command += " --out-dir " + shlex.quote(args.out_dir)
    labels = {"no-confirmed-omission": "未确认安全遗漏", "missing-security-semantics": "有安全缺口", "uncertain": "证据不足",
              "acceptable": "可接受", "needs-correction": "需修正"}
    body = ["# 30% Group Oracle 安全检查验证", "", f"> 抽样命令（仓库根目录）：`{sampling['generation_command']}`", "",
            f"> 结果汇总命令：`{command}`。读取已撰写的审阅 JSON，不重新执行源码推理；已有报告拒绝覆盖，复现请用新的 --out-dir。", "",
            f"已检查 **{n}/{sampling['population_count']} 个 group oracle（{n/sampling['population_count']:.2%}）**，逐项处理 **{chain_count} 条结构成员、{req_count} 条已有 requirements**。",
            f"其中 {len(reused)} 组复用此前安全检查 v2 结论（样本及源码哈希一致），{n-len(reused)} 组为新增源码审阅。", "",
            f"安全检查覆盖：**{coverage['no-confirmed-omission']}/{n} 组未确认遗漏，{coverage['missing-security-semantics']}/{n} 组有明确安全缺口，{coverage['uncertain']}/{n} 组无法判断。**",
            f"已有规则及分组适用性另评：**{soundness['acceptable']} 组可接受、{soundness['needs-correction']} 组需修正、{soundness['uncertain']} 组证据不足。**",
            "“未确认遗漏”不等于已有规则正确或应用安全；功能检查可以省略，错误的能力类型或不适用规则仍需独立记录。", "",
            f"结构成员：**{chain_counts['valid']} 条有条件性源码路径依据，{chain_counts['misaligned']} 条分支/分派不匹配，{chain_counts['uncertain']} 条未决**。全部原成员保留；不把检查完成数当作运行可达数。", "",
            "## 抽样口径", "",
            f"总体固定为 baseline 的129组（68 singleton +61多链组），覆盖485 eligible chains；本次样本含{singleton}个singleton、{n-singleton}个多链组。",
            "沿用seed=20260922，先重放原13组抽样，再用同一RNG从按group_id排序的剩余116组中随机取26组。总样本39组无重复；未按项目、规则数、状态或结论挑选。",
            "这是原随机样本的条件等概率扩样；总体先后无放回抽样形成39组随机集合。没有将Python sample(k=39)误称为原sample(k=13)的相同前缀。",
            "39组占总体30.23%，来自ceil(129×30%)；128条链不是单独抽取30%的链，125条规则也不是独立随机样本。", "",
            "## 验证判据", "",
            "- 只把实际handler到具体terminal路径内、具有源证据的权限/能力限制、受保护资源访问或敏感数据保护遗漏计为安全缺口。",
            "- 普通类型/必填/非空/格式/时区/功能默认等可不进入安全oracle；已有抽象安全目标不必重复每个实现细节。",
            "- terminal之后的交付、后端检查或其他效果不反推为当前链的前置遗漏；路径内真实异步审批仍需保留。",
            "- 适用条件不成立不等于规则为假；缺政策依据不等于源码反证。保留配置例外、trusted runtime参数、受限值域和不同项目的策略。",
            "- 具体sink形状优先：wb不能按文件读取评价，Popen(argv)不能按shell grammar评价；聚合call_chain文本不能当唯一执行顺序。", "",
            "## 全部组结果", "", "| 组 | 成员 / 规则 | 安全覆盖 | 规则与适用性 | 主要结论 |", "|---|---:|---|---|---|"]
    for r in reports:
        link = os.path.relpath(review / "groups" / f"{r['sample_id']}.md", output)
        body.append(f"| [{r['sample_id']}]({link}) | {len(r['chain_reviews'])} / {len(r['requirement_reassessment'])} | {labels[r['security_completeness']]} | {labels[r['security_soundness']]} | {r['summary'].replace('|','/')} |")
    body += ["", "## 确认的安全语义缺口", ""]
    for r in reports:
        if r["retained_security_gaps"]:
            body += [f"### {r['sample_id']}", ""]
            for gap in r["retained_security_gaps"]:
                body += ["- " + gap["description"], "  " + gap.get("reason", gap.get("basis", "")), "  适用成员：" + ", ".join(gap["affected_chain_ids"])]
            body += [""]
    body += ["## 结构成员异常", "", "这些成员没有从分母删除；原始oracle和canonical产物均保留。", "",
             "| 组 | Chain | 源码反例/边界 |", "|---|---|---|"]
    for r in reports:
        for c in r["chain_reviews"]:
            if c["verdict"] != "valid":
                body.append(f"| {r['sample_id']} | `{c['chain_id']}` | {c['trace'].replace('|','/')} |")
    body += ["", "## 来源与限制", "",
             f"引用文件来自{len(basis)}个CodeQL src.zip；归档及引用文件SHA256、引用行号已校验。见[源码证据索引](evidence-index.md)、[审阅清单](review-manifest.json)。",
             "revision采用原manifest标签，未独立证明为上游Git blob；结论绑定归档字节。当前capability-card若已变化，仍使用抽样时保存的exact_quote。",
             "本轮为agent源码审阅，不是运行时验证或真人签核。valid只指源码支持的条件路径；插件别名factory等未给定扩展不用于补造默认内建分派路径。",
             "安全缺口指oracle遗漏源码中已有控制，不是已确认程序漏洞。相同缺口可关联多成员，未把规则/链数当独立漏洞数。",
             "已处理全部39组、128个成员和125条规则；证据不足明确保留，不据此虚构全129组的逐项验收。", ""]
    (output / "report.md").write_text("\n".join(body), encoding="utf-8")
    index = ["# 30% 样本源码证据", "", "链接指向本次冻结的归档源文件。", ""]
    for sid, refs in citations.items():
        index += [f"## {sid}", ""]
        unique = {(r['project'], r['path'], r['line_start'], r['line_end'], r['claim']): r for r in refs}
        for r in unique.values():
            index.append(f"- [{r['project']}/{r['path']}:{r['line_start']}–{r['line_end']}](<{output/r['snapshot']}:{r['line_start']}>)：{r['claim']}")
        index += [""]
    (output / "evidence-index.md").write_text("\n".join(index), encoding="utf-8")
    dump(output / "source-inventory.json", inventory)
    dump(output / "review-manifest.json", {"generation_command": command, "standard": "security-check-coverage-only/v2", "groups": n,
         "structural_members_reviewed": chain_count, "requirements_reviewed": req_count, "reused_groups": len(reused), "new_groups": n-len(reused),
         "security_completeness": dict(coverage), "security_soundness": dict(soundness), "chain_verdicts": dict(chain_counts), "requirement_roles": dict(requirement_roles),
         "source_files": len(inventory), "source_basis_sha256": sha(review/"source-basis.json"), "reuse_manifest_sha256": sha(review/"reuse-manifest.json"),
         "sampling_manifest_sha256": sha(packet/"manifest.json"), "review_json_sha256": {str(p.relative_to(ROOT)): sha(p) for p in sorted((review/"groups").glob("G*.json"))},
         "sample_json_sha256": {str(p.relative_to(ROOT)): sha(p) for p in sorted((packet/"groups").glob("G*.json"))},
         "runtime_validation": False, "human_signoff": False, "generator_sha256": sha(Path(__file__)),
         "source_copy_helper_sha256": sha(Path(__file__).with_name("render_group_oracle_source_review.py"))})
    print(output/"report.md")


if __name__ == "__main__":
    main()
