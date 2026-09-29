/**
 * @id clawgap/hermes-callchain
 * @name hermes tool-entry to sink call chains
 * @description 从 hermes 工具 handler（registry.register 注册的入口）出发，沿调用图
 *              （AgentFuzz 原始方案：FunctionInvocation/method/direct/module/add）走到 sink，
 *              输出 root / sink / 分类 / 完整链路。
 * @kind table
 * @tags clawgap
 */

import call.call
import util.util

// 用自由变量 (handler, depth, callee) 一体绑定，避免「类字段多值 → 列间笛卡尔积」的问题
// （Source 的 depth/callee 对同一 handler 实体是多值的，分列 select 会错配）。
from FunctionObject handler, int d, CallNode callee
where
  is_tool_handler(handler) and
  isIncludeLocation2(handler.getFunction().getLocation()) and
  d = [1 .. 8] and
  r_calls(handler, callee, d) and
  is_sink(callee)
select
  handler.getName() as tool_handler,
  handler.getFunction().getLocation().getFile().getRelativePath() as tool_file,
  handler.getFunction().getLocation().getStartLine() as tool_line,
  d as depth,
  sink_category(callee) as sink_category,
  get_sink_location(callee) as sink_location,
  print_callchain(handler, callee, d) as call_chain
