/**
 * @id clawgap/hermes-sinks
 * @name hermes tool-execution sinks (AgentFuzz is_sink migrated)
 * @description 枚举 hermes-agent 中所有命中迁移版 AgentFuzz `is_sink_af` 的工具执行 sink 调用点，
 *              用于验证是否覆盖 13 个 CVE/Issue JSON 的 d5_sink_points。
 *              验证 DB：~/my-project/agent-research/clawgap/codeql-db/hermes-agent-db（xclaw 源树，d5 抽取依据）。
 * @kind table
 * @tags clawgap
 */

import python
import util.util
import call.sinks_af

// A callable passed to asyncio.to_thread has no direct method CallNode. Preserve the semantic
// method name so method-based GT coverage reports Firecrawl's scrape primitive correctly.
predicate isThreadedCallableSink(CallNode cn, string method) {
  cn.getFunction().(AttrNode).getNode().getName() = "to_thread" and
  cn.getArg(0).(AttrNode).getNode().getName() = method
  or
  projectThreadedCallableSink(cn, method, _)
}

// sink 调用点的简短标签：属性调用取 `obj.method`，裸名调用取 `name`。
string sinkLabel(CallNode cn) {
  isThreadedCallableSink(cn, result)
  or
  not exists(string method | isThreadedCallableSink(cn, method)) and
  exists(AttrNode a | a = cn.getFunction() |
    result = a.getObject().getNode().toString() + "." + a.getNode().getName()
  )
  or
  not exists(string method | isThreadedCallableSink(cn, method)) and
  not cn.getFunction() instanceof AttrNode and
  result = cn.getFunction().getNode().toString()
}

from CallNode cn
where
  is_sink_af(cn) and
  isIncludeLocation2(cn.getLocation())
select cn.getLocation().getFile().getRelativePath() as file,
  cn.getLocation().getStartLine() as line, sinkLabel(cn) as sink
