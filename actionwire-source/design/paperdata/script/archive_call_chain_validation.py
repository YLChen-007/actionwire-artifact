#!/usr/bin/env python3
"""Archive only the completed second call-chain review as paper data."""
import argparse
from collections import Counter
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SOURCE = "output/cross-project/manual-call-chain-gate-review-100-v1/validation/all-100-v2"
DEFAULT_OUT = "design/paperdata/validate-call-chain"
SHARDS = {"hermes-browser", "hermes-other", "openclaw", "other-projects", "reviews"}
DATA_SUFFIXES = {".md", ".json", ".jsonl", ".csv", ".xlsx"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def relocated_target(raw, old_parent, new_parent, destinations):
    wrapped = raw.startswith("<") and raw.endswith(">")
    target = raw[1:-1] if wrapped else raw
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", target) or target.startswith("#"):
        return raw
    match = re.match(r"^(.*?)(:\d+)?$", target)
    file, anchor = match.group(1), match.group(2) or ""
    old = Path(file)
    old = (old_parent / old).resolve() if not old.is_absolute() else old.resolve()
    if not old.is_file():
        return raw
    if old in destinations:
        link = os.path.relpath(destinations[old], new_parent)
    else:
        # Keep upstream generators, benchmark code and historical references external.
        link = str(old)
    link += anchor
    return f"<{link}>" if wrapped or " " in link else link


def relocate_markdown(text, old, new, destinations):
    output = []
    fence = 0
    for line in text.splitlines(keepends=True):
        ticks = len(line) - len(line.lstrip("`"))
        if ticks >= 3:
            if not fence:
                fence = ticks
            elif ticks >= fence:
                fence = 0
        elif not fence:
            line = re.sub(r"\]\((<[^>]+>|[^)\n]+)\)",
                          lambda m: "](" + relocated_target(m.group(1), old.parent, new.parent, destinations) + ")",
                          line)
        output.append(line)
    return "".join(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=DEFAULT_SOURCE)
    parser.add_argument("--out-dir", default=DEFAULT_OUT)
    args = parser.parse_args()
    source, out = (ROOT / args.source).resolve(), (ROOT / args.out_dir).resolve()
    if out.exists():
        parser.error("Archive destination already exists; choose a new --out-dir to preserve existing notes.")
    packet = source.parents[1]
    publication = json.loads((source / "publication.json").read_text())
    assert publication["status"] == "complete"
    for name, expected in publication["output_sha256"].items():
        assert digest((source / name).read_bytes()) == expected, name
    reviews = read_jsonl(source / "reviews.jsonl")
    sample = read_jsonl(packet / "sample.jsonl")
    sampling = json.loads((packet / "manifest.json").read_text())
    assert len(reviews) == len(sample) == 100
    assert {r["sample_id"] for r in reviews} == {r["sample_id"] for r in sample}
    counts = dict(Counter(r["detector_missed_security_gate"] for r in reviews))
    assert counts == publication["counts"] == {"yes": 8, "no": 51, "not-applicable": 41}
    assert sum(len(r["missing_security_gates"]) for r in reviews) == 12
    population = read_jsonl(packet / "population.jsonl")
    assert len(population) == sampling["population_count"] == 603
    project_rows = []
    for project in sorted({r["project"] for r in reviews}):
        group = [r for r in reviews if r["project"] == project]
        c = Counter(r["detector_missed_security_gate"] for r in group)
        project_rows.append(dict(project=project, population=sampling["population_project_counts"][project],
                                 sampled=len(group), missing_security_gate=c["yes"],
                                 no_missing_gate_found=c["no"], selected_role_not_applicable=c["not-applicable"]))
    selected = {}
    for file in source.rglob("*"):
        relative = file.relative_to(source)
        if file.is_file() and file.suffix in DATA_SUFFIXES and (
            len(relative.parts) == 1 or len(relative.parts) == 2 and relative.parts[0] in SHARDS
        ):
            selected[file.resolve()] = relative
    # The sample definition is shared input, not a first-pass review result.
    for name in ["sample.jsonl", "population.jsonl", "manifest.json", "detected-gates.csv"]:
        selected[(packet / name).resolve()] = Path("sample") / name
    destinations = {old: out / relative for old, relative in selected.items()}
    command = shlex.join(["python", "design/paperdata/script/archive_call_chain_validation.py",
                          "--source", args.source, "--out-dir", args.out_dir])
    out.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".validate-call-chain-", dir=out.parent))
    records = []
    try:
        for old, relative in sorted(selected.items()):
            content = old.read_bytes()
            destination = staging / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if old.suffix == ".md":
                destination.write_text(relocate_markdown(content.decode(), old, out / relative, destinations))
            elif old.suffix == ".xlsx":
                from openpyxl import load_workbook
                workbook = load_workbook(old)
                for sheet in workbook:
                    for row in sheet:
                        for cell in row:
                            if cell.hyperlink and cell.hyperlink.target:
                                target = Path(cell.hyperlink.target)
                                target = (old.parent / target).resolve() if not target.is_absolute() else target.resolve()
                                if target in destinations:
                                    cell.hyperlink.target = str(destinations[target])
                workbook.save(destination)
            else:
                destination.write_bytes(content)
            assert old.read_bytes() == content, f"Source changed while archiving: {old}"
            records.append(dict(source=str(old.relative_to(ROOT)), source_sha256=digest(content),
                                archived_path=str(relative), archived_sha256=digest(destination.read_bytes())))
        summary = dict(record_date="2026-09-22", review_date="2026-09-21", round="second",
                       source=str(source.relative_to(ROOT)), population_count=603, sample_count=100,
                       project_count=12, seed=sampling["seed"], without_replacement=True,
                       counts=counts, missing_control_family_occurrences=12,
                       fresh_behavioral_assertions=65, full_L2_runs=0,
                       sample_pipeline_eligible=79, sample_pipeline_excluded=21,
                       projects=project_rows)
        (staging / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
        with (staging / "project-statistics.csv").open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(project_rows[0])); writer.writeheader(); writer.writerows(project_rows)
        lines = ["# 调用链安全检查点验证记录（第二轮）", "",
                 f"> 从仓库根目录执行的完整归档命令：`{command}`", "",
                 "记录日期：2026-09-22。验证日期：2026-09-21。这里只归档第二轮结果及其共享样本定义。", "",
                 "## 统计结果", "",
                 "从 12 个项目的 **603 条 detector 调用链记录**中，使用随机种子 `20260921` 无放回抽取 **100 条**；第二轮已逐条完成源码复核。", "",
                 "| 第二轮结论 | 调用链数 |", "|---|---:|",
                 "| 存在遗漏的同源安全 gate | **8** |",
                 "| 未发现遗漏的同源安全 gate | **51** |",
                 "| 所选敏感 sink 值不受模型控制，不适用该 gate 召回口径 | **41** |",
                 "| 已复核总数 | **100** |", "",
                 "8 条阳性记录合计涉及 **12 个调用链—缺失控制族条目**，不是 12 类全局独立控制，也不是 12 个漏洞。41 条不适用记录已完成复核，不表示任务未完成。", "",
                 "执行了 **65 项隔离行为断言**；完整 L2 执行数为 **0**。断言通过只证明记录的行为，其中也包括对失效安全检查的复现。", "",
                 "## 统计口径", "",
                 "- 只计入与同一模型可控输入、所选敏感 sink 参数相关的既有安全检查；普通字段存在性、类型、格式或结果数量处理不自动视为安全 gate。",
                 "- 管理员权限、功能开关、其他参数角色上的检查单独记录，不能直接算作所选值上的漏检。",
                 "- Python `call_chain` 字符串可能聚合多个中间函数，不能仅依据相邻函数名否定实际 handler→sink 路径。",
                 "- 样本原管线中有 79 条 eligible、21 条 excluded；这是下游管线资格，和本轮 8/51/41 的源码复核分类是不同维度。",
                 "- 本记录是源码验证及局部隔离行为检查，不是全量 L2、漏洞确认数或全基准 gate 召回率。", "",
                 "## 按项目分布", "",
                 "| 项目 | 总体记录 | 样本 | 遗漏安全 gate | 未发现遗漏 | 所选角色不适用 |", "|---|---:|---:|---:|---:|---:|"]
        for row in project_rows:
            lines.append(f"| {row['project']} | {row['population']} | {row['sampled']} | {row['missing_security_gate']} | {row['no_missing_gate_found']} | {row['selected_role_not_applicable']} |")
        lines += ["| **合计** | **603** | **100** | **8** | **51** | **41** |", "",
                  "## 文件索引", "",
                  "- [第二轮完整报告](report.md)：结论、限定条件、修正说明及全部 100 条记录索引。",
                  "- [逐链 CSV](review.csv) / [工作簿](review.xlsx) / [结构化证据](reviews.jsonl)。",
                  "- [遗漏控制项清单](security-gate-omissions.csv)。",
                  "- [统计 JSON](summary.json) / [按项目统计 CSV](project-statistics.csv)。",
                  "- [样本清单](sample/sample.jsonl) / [总体 ID 清单](sample/population.jsonl) / [抽样 manifest](sample/manifest.json)。",
                  "- [完成审计](completion-audit.json) / [源码一致性](evidence-source-verification.json) / [detector 输入核对](detector-input-verification.json)。",
                  "- [归档 manifest](archive-manifest.json)：来源路径、原始及归档 SHA-256。", "",
                  "逐链报告位于 `reviews/`；四个复核分片的 JSON/报告/控制结果随第二轮数据一并保存。", "",
                  "## 来源与保存方式", "",
                  f"来源为仓库内 `{source.relative_to(ROOT)}`。未复制第一轮报告，也未移动或删除原始运行目录，以保留原生成命令及来源引用。",
                  "第二轮原报告中的历史比较说明按原文保留；相关旧报告和生成脚本仅作为外部来源链接，不属于本目录归档内容。",
                  "归档仅调整 Markdown 与工作簿的文件链接。`publication.json` 保留上游发布时的哈希；归档副本（含调整后的链接）应使用 `archive-manifest.json` 验证。",
                  "生成脚本、完整 benchmark 源码和 CodeQL 数据库继续使用原仓库位置。归档命令只创建新目录；目标已存在时会拒绝覆盖，保护后续人工记录。", ""]
        (staging / "README.md").write_text("\n".join(lines))
        generated = {name: digest((staging / name).read_bytes()) for name in ["README.md", "summary.json", "project-statistics.csv"]}
        manifest = dict(schema_version="paperdata-call-chain-review-archive/v1", round="second",
                        generation_command=command, generator_sha256=digest(Path(__file__).read_bytes()),
                        source=str(source.relative_to(ROOT)), archive=str(out.relative_to(ROOT)),
                        record_date="2026-09-22", records=records, generated_sha256=generated)
        (staging / "archive-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
        if out.exists():
            raise FileExistsError(out)
        staging.rename(out)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    print(f"Archived second-round review: {out / 'README.md'} ({len(records)} source files)")


if __name__ == "__main__":
    main()
