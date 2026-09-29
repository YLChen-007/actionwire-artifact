#!/usr/bin/env python3
"""Validate authored source reviews, freeze cited files, and create a report once."""

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


def dump(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def evidence_rows(value):
    if isinstance(value, dict):
        if all(key in value for key in ("project", "path", "line_start", "line_end")):
            yield value
        for child in value.values():
            yield from evidence_rows(child)
    elif isinstance(value, list):
        for child in value:
            yield from evidence_rows(child)


def load_reviews(packet, review):
    originals = {p.stem: json.loads(p.read_text()) for p in sorted((packet / "groups").glob("G*.json"))}
    reports = [json.loads(p.read_text()) for p in sorted((review / "groups").glob("G*.json"))]
    if len(reports) != 13 or {r["sample_id"] for r in reports} != set(originals):
        raise ValueError("Require exactly all 13 sampled groups")
    for r in reports:
        original = originals[r["sample_id"]]
        if r["group_id"] != original["oracle"]["group_id"]:
            raise ValueError("Group identity mismatch")
        actual = [(m["project"], m["chain_id"]) for m in r["chain_reviews"]]
        expected = [(m["project"], m["chain_id"]) for m in original["oracle"]["member_chain_refs"]]
        if sorted(actual) != sorted(expected):
            raise ValueError(f"Member coverage mismatch: {r['sample_id']}")
        actual = [q["requirement_id"] for q in r["requirement_reviews"]]
        expected = [q["requirement_id"] for q in original["oracle"]["requirements"]]
        if sorted(actual) != sorted(expected):
            raise ValueError(f"Requirement coverage mismatch: {r['sample_id']}")
    manifest = json.loads((packet / "manifest.json").read_text())
    for path, expected in manifest["input_sha256"].items():
        if sha(ROOT / path) != expected:
            raise ValueError(f"Sample input changed: {path}")
    return reports, originals


def freeze_evidence(reports, basis, output):
    inventory, locations = {}, {}
    for report in reports:
        refs = list(evidence_rows(report))
        locations[report["sample_id"]] = []
        for ref in refs:
            project, path = ref["project"], Path(ref["path"])
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("Unsafe evidence path")
            source = Path(basis[project]["extracted_root"]) / path
            expected = basis[project]["files"][str(path)]
            if sha(source) != expected:
                raise ValueError(f"Archived evidence changed: {source}")
            lines = source.read_text(errors="replace").splitlines()
            if not 1 <= ref["line_start"] <= ref["line_end"] <= len(lines):
                raise ValueError(f"Evidence line range invalid: {ref}")
            relative = Path("sources") / project / path
            target = output / relative
            if target.exists() and target.read_bytes() != source.read_bytes():
                raise ValueError(f"Refusing source overwrite: {target}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
            inventory[str(relative)] = {"sha256": expected, "recorded_revision": basis[project]["revision"],
                                        "archive": basis[project]["archive"], "archive_sha256": basis[project]["archive_sha256"]}
            locations[report["sample_id"]].append({**ref, "snapshot": str(relative)})
    return inventory, locations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", default="design/paperdata/group-oracle-review-10pct")
    parser.add_argument("--review-dir", default="design/paperdata/group-oracle-review-10pct/validation/source-review-v1")
    parser.add_argument("--out-dir", help="Defaults to --review-dir; existing report is never overwritten")
    args = parser.parse_args()
    packet, review = ROOT / args.packet, ROOT / args.review_dir
    output = ROOT / (args.out_dir or args.review_dir)
    if (output / "report.md").exists() or (output / "review-manifest.json").exists():
        parser.error("Existing report: choose a fresh --out-dir; authored reviews remain unchanged.")
    reports, originals = load_reviews(packet, review)
    basis = json.loads((review / "source-basis.json").read_text())
    for project in basis.values():
        if sha(ROOT / project["archive"]) != project["archive_sha256"]:
            raise ValueError("Source archive changed")
    output.mkdir(parents=True, exist_ok=True)
    inventory, locations = freeze_evidence(reports, basis, output)
    repository_evidence = []
    for report in reports:
        for ref in report.get("repository_evidence", []):
            source = ROOT / ref["path"]
            if not 1 <= ref["line_start"] <= ref["line_end"] <= len(source.read_text().splitlines()):
                raise ValueError("Repository evidence line range invalid")
            relative = Path("repository-sources") / ref["path"]
            target = output / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
            repository_evidence.append({**ref, "sha256": sha(source), "snapshot": str(relative), "basis": "current-repository-not-historical-query"})
    group_counts = Counter(r["verdict"] for r in reports)
    requirement_counts = Counter(q["verdict"] for r in reports for q in r["requirement_reviews"])
    chain_counts = Counter(c["verdict"] for r in reports for c in r["chain_reviews"])
    command = "python design/paperdata/script/render_group_oracle_source_review.py"
    if args.packet != parser.get_default("packet"):
        command += f" --packet {shlex.quote(args.packet)}"
    if args.review_dir != parser.get_default("review_dir"):
        command += f" --review-dir {shlex.quote(args.review_dir)}"
    if args.out_dir:
        command += f" --out-dir {shlex.quote(args.out_dir)}"
    intro = ["# 抽样 Group Oracle 源码语义校验", "", f"> 统计与源码证据整理命令（仓库根目录）：`{command}`。",
             "> 此命令读取已撰写的逐组 JSON，不重新执行语义审阅；已有报告拒绝覆盖，重现请用新的 --out-dir。", "",
             "本次完成 **13/13 个抽中组、25/25 条成员链、28/28 条已有 requirements** 的 agent 源码审阅。另检查 3 个空 requirement 组的遗漏。",
             "结论针对这 13 个固定样本及分析时 CodeQL 源码归档；不是对全部 129 组的逐项验收，也不是运行时或独立真人签核结果。", "",
             f"**组结论：完整 {group_counts['complete']}；不完整 {group_counts['incomplete']}；存在错误或不适用语义 {group_counts['incorrect']}；无法判断 {group_counts['uncertain']}。**",
             "组级结论互斥；incorrect 优先表示实质错配，也可能同时存在遗漏。完整只指在此次明确审阅范围内未发现缺项，不表示穷尽证明。", "",
             f"**已有规则：源码支持 {requirement_counts['supported']}；需细化 {requirement_counts['needs-refinement']}；无充分依据或不适用 {requirement_counts['unsupported']}；无法判断 {requirement_counts['uncertain']}。**",
             "supported 仅表示该语义有源码支持，部分是功能合同；不能直接算作已经具备规范证据的安全 requirement。", "",
             "## 核验方法与判据", "",
             "逐成员追踪真实 handler → 受控值/可信上下文 → 分支条件与 gate → 具体 sink；必要时继续查看异步队列、服务端授权或返回值处理，以标清效果边界。",
             "完整性检查同时考虑：HC/ST 是否适配；已有规则是否有依据；是否丢失明确源策略；适用条件、资源范围、默认值和 branch/gate 顺序是否准确。",
             "普通 capability card 只描述能力；不单凭能力、某个 if、局部函数缺少校验或 LLM 推理文本新增安全义务。", "",
             "## 逐组结论", "", "| 样本 | 链 / 规则 | 结论 | 主要问题 |", "|---|---:|---|---|"]
    labels = {"complete": "完整", "incomplete": "不完整", "incorrect": "错误/适用性错配", "uncertain": "无法判断"}
    for report in reports:
        sid = report["sample_id"]
        link = os.path.relpath(review / "groups" / f"{sid}.md", output)
        intro.append(f"| [{sid}]({link}) | {len(report['chain_reviews'])} / {len(report['requirement_reviews'])} | {labels[report['verdict']]} | {report['summary'].replace('|', '/')} |")
    intro += ["", "## 共性问题", "",
              "1. **具体参数形状被泛化**：固定服务 URL 被按任意 URL 分析，argv 入口混入 shell parser 规则；snapshot 的封闭参数映射没有保留。",
              "2. **来源和资源范围丢失**：session、channel、agent group、task DB、browser target 等可信上下文，不能与模型内容参数混为一谈。",
              "3. **效果边界错位**：enqueue 不等于交付或状态变更；异步 pending approval 不等于 Boolean gate；后端授权与后置输出 redaction 不能当作客户端 sink 前检查。",
              "4. **规则与政策脱节**：文本非空不等于防外泄，具备 HTTP/browser 能力不自动要求统一 TLS、拒绝 loopback 或重新授权。",
              "5. **路径相关性不足**：G13 的长 call_chain 序列混有不同分支节点；必须结合实际控制流解释，不能把所有附带 gates 当作一条路径上的前置检查。", "",
              "G06 的两个确定遗漏有直接源策略依据：URL 携带 secret 的拒绝，以及具有配置例外和 metadata 永久拒绝的 SSRF 预检。",
              "G09 的 host-control policy、G10 的目标 group 管理员审批也有明确源依据。源码中已有这些控制，因此 oracle 遗漏本身不等于实现漏洞。", "",
              "## 证据与复核边界", "",
              "- 5 个 CodeQL src.zip 的哈希，以及所有实际引用文件的内容哈希和行号均已核对；引用文件复制在 sources/，见 [源码证据索引](evidence-index.md)。",
              "- revision 采用原始 manifest 的标识。尝试独立 Git blob 比对时，记录标识下未定位到对应源码文件；本轮不把这些标签当成已独立证明的上游 Git revision。实际结论绑定 src.zip 内容和 SHA256。",
              "- 所有原始 28 条规则引用的 evidence 都是 ordinary capability-card。语义上有源码支持与原始规范证据链充分，是两个不同结论。当前设计的规范门禁另见 design/common/cross-project-oracle.md §4.3。",
              "- 原 capability card 已发生变化；本轮使用采样包保存的 exact_quote。新增源证据和修订建议没有回写 canonical oracle、原样本 JSON 或论文统计。",
              "- 当前 QL renderer 的源代码可解释分支合并格式，但未证明它与历史生成时字节一致；将其作为仓库当前实现证据单独留存。",
              "- 未执行外部服务、浏览器或攻击验证；valid 只表示存在源码支持的条件性 handler-to-sink 路径，不能替代动态可达性结论。", ""]
    (output / "report.md").write_text("\n".join(intro), encoding="utf-8")
    evidence_md = ["# 源码证据索引", "", "文件来自分析 CodeQL 归档；重复引用按组去重。", ""]
    for sid, refs in locations.items():
        evidence_md += [f"## {sid}", ""]
        unique = {(r['project'], r['path'], r['line_start'], r['line_end'], r['claim']): r for r in refs}
        for ref in unique.values():
            evidence_md.append(f"- [{ref['project']}/{ref['path']}:{ref['line_start']}–{ref['line_end']}](<{output / ref['snapshot']}:{ref['line_start']}>)：{ref['claim']}")
        evidence_md += [""]
    evidence_md += ["## 当前仓库解释证据", "", "以下文件不属于 benchmark 的分析源码归档，也未证明与历史生成器相同。", ""]
    for ref in repository_evidence:
        evidence_md.append(f"- [{ref['path']}:{ref['line_start']}](<{output / ref['snapshot']}:{ref['line_start']}>)：{ref['claim']}")
    (output / "evidence-index.md").write_text("\n".join(evidence_md), encoding="utf-8")
    dump(output / "source-inventory.json", inventory)
    audit = {"review_method": "agent-source-review", "human_signoff": False, "runtime_validation": False,
             "generation_command": command, "groups": 13, "chains": 25, "requirements": 28,
             "group_verdicts": dict(group_counts), "requirement_verdicts": dict(requirement_counts), "chain_verdicts": dict(chain_counts),
             "review_json_sha256": {str(p.relative_to(ROOT)): sha(p) for p in sorted((review / "groups").glob("G*.json"))},
             "source_basis_sha256": sha(review / "source-basis.json"), "source_files": len(inventory),
             "repository_evidence": repository_evidence,
             "generator_sha256": sha(Path(__file__)), "original_population_sha256": sha(packet / "population.json")}
    dump(output / "review-manifest.json", audit)
    print(output / "report.md")


if __name__ == "__main__":
    main()
