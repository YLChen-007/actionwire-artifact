#!/usr/bin/env python3
"""Publish the security-only reassessment without overwriting prior reviews."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import shlex

from render_group_oracle_source_review import ROOT, dump, freeze_evidence, sha


def load_reassessments(packet, review, previous):
    reports = [json.loads(p.read_text()) for p in sorted((review / "groups").glob("G*.json"))]
    if len(reports) != 13 or {r["sample_id"] for r in reports} != {f"G{i:02d}" for i in range(1, 14)}:
        raise ValueError("Expected all 13 fixed sampled groups")
    for report in reports:
        sid = report["sample_id"]
        original = json.loads((packet / "groups" / f"{sid}.json").read_text())
        prior = json.loads((previous / "groups" / f"{sid}.json").read_text())
        if report["group_id"] != original["oracle"]["group_id"]:
            raise ValueError(f"Group changed: {sid}")
        ids = [q["requirement_id"] for q in report["requirement_reassessment"]]
        if sorted(ids) != sorted(q["requirement_id"] for q in original["oracle"]["requirements"]):
            raise ValueError(f"Requirement coverage mismatch: {sid}")
        indices = [o["original_index"] for o in report["prior_omission_reassessment"]]
        if sorted(indices) != list(range(1, len(prior["omissions"]) + 1)):
            raise ValueError(f"Prior omission coverage mismatch: {sid}")
        has_gap = bool(report["retained_security_gaps"])
        if has_gap != (report["security_completeness"] == "missing-security-semantics"):
            raise ValueError(f"Inconsistent completeness result: {sid}")
        allowed = {r["chain_id"] for r in original["oracle"]["member_chain_refs"]}
        for gap in report["retained_security_gaps"]:
            if not set(gap["affected_chain_ids"]) <= allowed or not gap.get("evidence"):
                raise ValueError(f"Gap lacks member-bound source evidence: {sid}")
    return reports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", default="design/paperdata/group-oracle-review-10pct/validation/security-only-v2")
    args = parser.parse_args()
    packet = ROOT / "design/paperdata/group-oracle-review-10pct"
    previous = packet / "validation/source-review-v1"
    review = packet / "validation/security-only-v2"
    output = ROOT / args.out_dir
    if (output / "report.md").exists():
        parser.error("Refusing to overwrite a review; choose a fresh --out-dir")
    reports = load_reassessments(packet, review, previous)
    basis = json.loads((previous / "source-basis.json").read_text())
    for item in basis.values():
        if sha(ROOT / item["archive"]) != item["archive_sha256"]:
            raise ValueError("Source archive changed")
    output.mkdir(parents=True, exist_ok=True)
    inventory, citations = freeze_evidence(reports, basis, output)
    coverage = Counter(r["security_completeness"] for r in reports)
    soundness = Counter(r["security_soundness"] for r in reports)
    classification = Counter(o["classification"] for r in reports for o in r["prior_omission_reassessment"])
    command = "python design/paperdata/script/render_security_only_oracle_review.py"
    if args.out_dir != parser.get_default("out_dir"):
        command += " --out-dir " + shlex.quote(args.out_dir)
    labels = {"no-confirmed-omission": "未确认安全遗漏", "missing-security-semantics": "仍缺安全语义",
              "uncertain": "证据不足", "acceptable": "安全范围内可接受", "needs-correction": "需修正"}
    body = ["# Group Oracle 复评：只考察安全检查", "", f"> 汇总复现命令（仓库根）：`{command}`。",
            "> 生成器读取已撰写的逐组复评 JSON，不代替源码审阅；已有报告拒绝覆盖，重现时使用新的 --out-dir。", "",
            "本轮按用户明确的新判据复评全部 **13 组、25 条成员链、28 条已有 requirements**。",
            "**非安全检查没有进入 group oracle 是合理的，不构成不完整。** 上一轮将部分功能细节和链外后续行为计入了完整性判断，判据过宽；其“0 组完整”结论不再用于本轮标准。", "",
            f"安全检查覆盖：**{coverage['no-confirmed-omission']}/13 组未确认安全遗漏；{coverage['missing-security-semantics']}/13 组仍缺安全语义；{coverage['uncertain']}/13 组无法判断。**",
            "“未确认安全遗漏”只评价这组采样链中的安全检查覆盖，不等于已有每条规则都正确，也不表示全项目安全。", "",
            f"已有规则另评：**{soundness['acceptable']} 组在安全范围内可接受，{soundness['needs-correction']} 组需修正，{soundness['uncertain']} 组证据不足。**",
            "空 oracle 可以没有错误规则但仍漏安全检查（G06）；纯功能规则不用于充当安全覆盖证据（G02）。", "",
            "## 本轮判据", "",
            "1. 只把有具体源依据、限制权限/能力/受保护资源访问或敏感数据传播的检查视为安全检查，例如 ACL、审批授权、SSRF、secret 防护、host-control 和危险环境变量过滤。",
            "2. 必填值、类型、普通非空/格式、status 枚举、日期/时区、默认值、持久化和资源存在性通常是功能行为；除非有具体安全作用证据，否则缺失不扣分。",
            "3. 范围固定为原采样 handler 到具体 terminal；该路径实际经过的异步授权仍在范围内。terminal 之后的交付、后端授权、任务执行或输出处理单列上下文，不反推成本条链的安全遗漏。",
            "4. 按安全目标覆盖判定，不要求 oracle 镜像每个 if、辅助函数或实现细节；已有概括性的授权规则可以覆盖其具体资源权限实现。",
            "5. 规则适用条件不成立不等于规则为假；缺少规范依据也不等于已被源码反证。误提取与安全遗漏分开判断。", "",
            "## 逐组结果", "", "| 组 | 安全检查覆盖 | 已有规则评价 | 复评理由 |", "|---|---|---|---|"]
    for report in reports:
        sid = report["sample_id"]
        link = os.path.relpath(review / "groups" / f"{sid}.md", output)
        body.append(f"| [{sid}]({link}) | {labels[report['security_completeness']]} | {labels[report['security_soundness']]} | {report['summary'].replace('|', '/')} |")
    body += ["", "## 仍需补充的安全语义", ""]
    for report in reports:
        if not report["retained_security_gaps"]:
            continue
        body += [f"### {report['sample_id']}", ""]
        for gap in report["retained_security_gaps"]:
            body += [f"- {gap['description']}", f"  {gap.get('reason', gap.get('basis', ''))}"]
        body += [""]
    body += ["## 对上一轮结论的具体修正", "",
             "- G02 的时间转换和排期功能细节、G03/G04 的普通参数检查不再要求进入安全 oracle；Poco 请求之后的后端权限也不计为本条 pre-HTTP 链的遗漏。",
             "- G08/G10/G12 不因已有授权或隔离要求未列出每个实现细节再次扣完整性分；异步审批 IR 的描述错误仍可单独修正。",
             "- G13 原 URL 规则已经含配置例外，且明确覆盖 external provider responses。上一轮不能仅凭“目的地非模型控制”或“访问 localhost”反驳该规则；项目允许端点政策仍缺充分证据。",
             "- G11 的条件式 URL 规则在该成员上不适用，不等于规则逻辑错误；TLS 政策缺证不等于已反证，session_id 也可能承载敏感权限。",
             "- G05 把字符串检查归为防数据外泄，仍是已有规则的安全语义误归类；允许省略功能检查并不会使这一误归类正确。", "",
             "## 证据与范围", "",
             "逐组 JSON 完整保留对上一轮每个遗漏项的重新分类，以及全部 28 条已有规则的角色/准确性复评。",
             "[源码证据索引](evidence-index.md) 提供文件快照链接；源文件与原 CodeQL 归档的 SHA256 和行号均校验。新增的 destination ACL 依据也已冻结。",
             "本轮是 agent 源码复评，没有运行验证或真人签核。结论绑定 src.zip 内容；revision 沿用原 manifest 标签，未独立证明上游 Git blob 对应关系。",
             "原始抽样、canonical oracle、v1 逐组证据均保留。v1 是较宽的语义审阅历史，本报告是本轮安全检查覆盖判据的结果。", ""]
    (output / "report.md").write_text("\n".join(body), encoding="utf-8")
    index = ["# 安全检查复评证据", "", "所有引用均指向归档源码快照，不指向当前 benchmark 工作树。", ""]
    for sid, refs in citations.items():
        index += [f"## {sid}", ""]
        unique = {(r['project'], r['path'], r['line_start'], r['line_end'], r['claim']): r for r in refs}
        for ref in unique.values():
            index.append(f"- [{ref['project']}/{ref['path']}:{ref['line_start']}–{ref['line_end']}](<{output / ref['snapshot']}:{ref['line_start']}>)：{ref['claim']}")
        index += [""]
    (output / "evidence-index.md").write_text("\n".join(index), encoding="utf-8")
    dump(output / "source-inventory.json", inventory)
    dump(output / "review-manifest.json", {"review_standard": "security-check-coverage-only/v2", "generation_command": command,
         "groups": 13, "chains": 25, "requirements": 28, "security_completeness": dict(coverage), "security_soundness": dict(soundness),
         "prior_omission_classification": dict(classification), "reviewer": "agent-source-review", "runtime_validated": False, "human_signoff": False,
         "source_files": len(inventory), "source_basis_sha256": sha(previous / "source-basis.json"),
         "review_json_sha256": {str(p.relative_to(ROOT)): sha(p) for p in sorted((review / "groups").glob("G*.json"))},
         "previous_review_json_sha256": {str(p.relative_to(ROOT)): sha(p) for p in sorted((previous / "groups").glob("G*.json"))},
         "generator_sha256": sha(Path(__file__)), "source_copy_helper_sha256": sha(Path(__file__).with_name("render_group_oracle_source_review.py"))})
    print(output / "report.md")


if __name__ == "__main__":
    main()
