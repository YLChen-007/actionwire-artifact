/**
 * @id clawgap/hermes-tool-handlers
 * @name hermes tool handler entries (call-chain root anchors)
 * @description 枚举 hermes-agent 中所有「工具 handler 入口」—— 即 registry.register(name=..., handler=...)
 *              注册的 root anchor。复用 call.qll 的 is_register_call；与 is_tool_handler 同形地解析
 *              两种 handler 写法：
 *                form=named       : handler=<具名函数>          → 取该具名函数（wrapper），如 _handle_terminal
 *                form=lambda-body : handler=lambda ...: real(...) → 取 lambda 体内调用的具名函数，如 execute_code
 *              额外补出 forwarded_body：handler 体内 1-hop、定义在同文件、工程内的被调函数（覆盖
 *              _handle_terminal→terminal_tool / _skill_view_with_bump→skill_view 这类「GT 锚在工具体」的情形）。
 *              不带 sink 可达约束 —— 输出全部 handler 入口（与 get_callchain_and_location.ql 互补）。
 * @kind table
 * @tags clawgap
 */

import python
import call.call
import util.util

// 注册调用的工具名字面量（name="terminal" → terminal）；非字面量/缺失则记 "?"。
string regToolName(CallNode reg) {
  result = reg.getArgByName("name").getNode().(StrConst).getText()
  or
  not exists(reg.getArgByName("name").getNode().(StrConst)) and result = "?"
}

// (toolName, form, handlerFunc)：与 call.qll 的 is_tool_handler 同形的两形态解析，
// 但额外回收注册工具名与命中形态。
predicate registeredHandler(string toolName, string form, FunctionObject f) {
  exists(CallNode reg | is_register_call(reg) and toolName = regToolName(reg) |
    // 形态 1：handler=<具名函数>
    reg.getArgByName("handler").(NameNode).getId() = f.getName() and
    reg.getLocation().getFile() = f.getFunction().getLocation().getFile() and
    form = "named"
    or
    // 形态 2：handler=lambda args, **kw: realfunc(...) —— 取 lambda 体内调用的具名函数
    exists(Lambda lam, CallNode inner |
      reg.getArgByName("handler").getNode() = lam and
      inner.getScope() = lam.getInnerScope() and
      inner.getFunction().(NameNode).getId() = f.getName() and
      reg.getLocation().getFile() = f.getFunction().getLocation().getFile()
    ) and
    form = "lambda-body"
  )
}

predicate modeledHandler(string toolName, string form, FunctionObject f) {
  registeredHandler(toolName, form, f)
  or
  projectToolHandler(f) and toolName = toolHandlerName(f) and form = "project-adapter"
}

// handler 体内 1-hop、同文件、工程内的被调函数（即工具体）。
predicate bodyOf(FunctionObject handler, FunctionObject body) {
  calls(handler, body) and
  body.getFunction().getLocation().getFile() = handler.getFunction().getLocation().getFile() and
  isIncludeLocation2(body.getFunction().getLocation())
}

string forwardedBodyStr(FunctionObject handler) {
  result =
    strictconcat(FunctionObject body |
      bodyOf(handler, body)
    |
      body.getName() + "@" + body.getFunction().getLocation().getStartLine().toString(), ", "
    )
  or
  not bodyOf(handler, _) and result = "-"
}

from string toolName, string form, FunctionObject f
where
  modeledHandler(toolName, form, f) and
  isIncludeLocation2(f.getFunction().getLocation())
select toolName as tool_name, form, f.getName() as handler_func,
  f.getFunction().getLocation().getFile().getRelativePath() as file,
  f.getFunction().getLocation().getStartLine() as line, forwardedBodyStr(f) as forwarded_body
