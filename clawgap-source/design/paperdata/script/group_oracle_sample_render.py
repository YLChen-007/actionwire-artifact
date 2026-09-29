"""Readable, create-only group-oracle sample pages."""

import json


def pretty(value):
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def render(record, command, root):
    oracle, group = record["oracle"], record["group"]
    lines = [f"# {record['sample_id']} — {oracle['group_id']}", "",
             f"> 从仓库根复现（输出目录必须不存在）：`{command}`", "",
             f"[原始数据快照]({record['sample_id']}.json) · [抽样总览](../README.md)", "",
             f"- Handler criterion: `{oracle['handler_criterion_id']}` — {record['handler_criterion']['canonical_label']}",
             f"- Sink type: `{oracle['sink_type_id']}` — {record['sink_type']['criterion']['canonical_label']}",
             f"- 链数：{group['chain_count']}；项目：{', '.join(group['projects'])}；原始状态：`{oracle['status']}`。",
             "- complete/partial 是已有生成状态，所有人工结论均待填写。", "",
             "## Requirements", ""]
    if not oracle["requirements"]:
        lines += ["原始 oracle 的 requirements 为空；请检查是否遗漏应有要求，以及拒绝 proposal 的理由。", ""]
    for req in oracle["requirements"]:
        lines += [f"### {req['requirement_id']} — {req['dimension']}", "",
                  f"**Rule:** {req['rule']}", "", f"**Applicability:** {req['applicability']}", "",
                  f"- Evidence: {', '.join(req['evidence_ids'])}",
                  f"- Origin gates: {', '.join(req['origin_gate_ids']) or '(none)'}",
                  "- Origin chains: " + ", ".join(f"{r['project']}:{r['chain_id']}" for r in req['origin_chain_refs']),
                  "- 人工结论（正确 / 需修改 / 无依据 / 不确定）：", "- 理由与证据：", ""]
    lines += ["## 全部成员链", "", "JSON 快照包含每条链的完整 semantic IR、gates 和 sink constraint。",
              "源码定位对应记录中的 revision；当前工作树可能已变化。CodeQL 源码归档路径也保存在 JSON 中。", ""]
    for member in record["members"]:
        sem = member["semantic"]
        lines += [f"### {sem['project']['id']}:{sem['chain_id']}", "",
                  f"- Revision: `{sem['project']['revision']}`",
                  f"- Handler: `{sem['handler']['qualified_name']}` @ `{sem['handler']['location']}`",
                  f"- Sink: `{sem['sink']['label']}` @ `{sem['sink']['location']}`",
                  f"- 原始 semantic IR：[第 {member['line']} 行](<{root / member['artifact']}:{member['line']}>)",
                  "", "````json", pretty(sem["sink_constraint"]).rstrip(), "````", ""]
        for gate in sem["gates"]:
            lines += [f"- Gate `{gate['gate_uid']}` @ `{gate['callsite']}`: "
                      + gate["semantic"].get("summary", "(see JSON)")]
        lines += [""]
    lines += ["## 推导证据（保存的原始引文）", "",
              "以下引文来自生成时的 evidence-index；文件 SHA256 是当时整个来源文件的哈希。",
              "除 requirement/assessment 引用外，也附上成员链绑定的 capability card 供审查空规则或被拒绝的 proposal。", ""]
    for ev in record["evidence"]:
        drift = "一致" if ev["current_source_matches"] else "已变化或不可用；以保存的引文审查当时推导"
        lines += [f"### {ev['evidence_id']} — {ev['kind']}", "",
                  f"- 来源：`{ev['source_path']}`；locator: `{ev['locator']}`",
                  f"- Recorded SHA256: `{ev['sha256']}`；当前文件：{drift}。",
                  f"- 本检查包用途：`{ev['review_context']}`；保存引文与原文件哈希一致：`{ev['quote_matches_recorded_source']}`。",
                  f"- Supported claim: {ev['supported_claim']}", "",
                  "````text", ev["exact_quote"], "````", ""]
    lines += ["## Proposal 审核记录", "", "完整 proposal 和 seed profile 保存在本组 JSON 中。", ""]
    for item in record["assessments"]:
        lines += [f"- `{item['proposal_id']}` — **{item['decision']}**: {item['reason']}"]
    lines += ["", "## 人工检查记录", "", "- Reviewer / 日期：", "- 分组与成员对齐是否正确：",
              "- Requirement 是否具有安全意义及规范依据：", "- Applicability 是否适用于对应成员：",
              "- 是否遗漏要求 / 错误拒绝 proposal：", "- 总体结论（正确 / 需修改 / 不确定）：",
              "- 修正建议与源码证据：", ""]
    return "\n".join(lines)

