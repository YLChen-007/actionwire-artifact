/**
 * @id clawgap/diag-isinstance
 * @name diag: why terminal `if not isinstance(command,str)` guard yields no candidate
 * @kind table
 * @tags clawgap
 */

import python
import call.call
import call.sinks_af
import util.util

// --- copy of get_gates.ql chain helpers ---
predicate onChainMid(FunctionObject f, CallNode sink) {
  exists(FunctionObject h, int d, int k |
    is_tool_handler(h) and is_sink_af(sink) and isIncludeLocation2(sink.getLocation()) and
    r_calls(h, sink, d) and find_mid(h, sink, f, d, k)
  )
}

predicate sinkwardCall(FunctionObject f, CallNode cs, CallNode sink) {
  onChainMid(f, sink) and
  (
    cs = sink and sink.getScope() = f.getFunction()
    or
    exists(FunctionObject next | onChainMid(next, sink) and calls_cn(f, next, cs))
  )
}

FunctionObject terminalTool() {
  result.getName() = "terminal_tool" and
  result.getFunction().getLocation().getFile().getRelativePath() = "tools/terminal_tool.py"
}

// the isinstance(command,...) call(s) in terminal_tool
CallNode isinstCall() {
  result.getScope() = terminalTool().getFunction() and
  result.getFunction().(NameNode).getId() = "isinstance" and
  result.getAnArg().(NameNode).getId() = "command"
}

from string probe, int cnt
where
  probe = "P0: terminal_tool onChain?" and
  cnt = count(CallNode s | onChainMid(terminalTool(), s))
  or
  probe = "P1: isinstance(command) calls in terminal_tool" and
  cnt = count(CallNode c | c = isinstCall())
  or
  probe = "P2: of those, call node IS a ConditionBlock (B1 anchorable)" and
  cnt = count(CallNode c | c = isinstCall() and c.getBasicBlock() instanceof ConditionBlock)
  or
  probe = "P3: of those, call node's BB is controlled-test of an if (getLastNode)" and
  cnt =
    count(CallNode c |
      c = isinstCall() and
      exists(ConditionBlock cb | cb.getLastNode().getNode() = c.getNode().getParentNode*())
    )
  or
  probe = "P4: exists sink-ward cs in terminal_tool (sinkwardCall)" and
  cnt = count(CallNode cs | sinkwardCall(terminalTool(), cs, _))
  or
  probe = "P5: FULL — isinstance's cb controls a sink-ward cs (A ∧ B1)" and
  cnt =
    count(CallNode c, CallNode cs |
      c = isinstCall() and
      c.getBasicBlock() instanceof ConditionBlock and
      sinkwardCall(terminalTool(), cs, _) and
      c.getBasicBlock().(ConditionBlock).controls(cs.getBasicBlock(), _)
    )
  or
  probe = "P6: alt — the enclosing If's ConditionBlock controls a sink-ward cs" and
  cnt =
    count(ConditionBlock cb, CallNode cs |
      cb.getScope() = terminalTool().getFunction() and
      cb.getLastNode().getNode() = any(Expr e | e.getASubExpression*() = isinstCall().getNode()) and
      sinkwardCall(terminalTool(), cs, _) and
      cb.controls(cs.getBasicBlock(), _)
    )
select probe, cnt
