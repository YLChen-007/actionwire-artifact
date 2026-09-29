/**
 * @id clawgap/diag-terminal
 * @name diag: terminal_tool approval gate —— (A) 支配 vs (C) 同源污点
 * @kind table
 * @tags clawgap
 */

import python
import call.call
import call.sinks_af
import util.util
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

FunctionObject terminalTool() {
  result.getName() = "terminal_tool" and
  result.getFunction().getLocation().getFile().getRelativePath() = "tools/terminal_tool.py"
}

// source = terminal_tool 的 command 形参
predicate cmdSource(DataFlow::Node n) {
  n.(DataFlow::ParameterNode).getParameter().(Name).getId() = "command" and
  n.getScope() = terminalTool().getFunction()
}

// 复刻 get_gates.ql 的路径/字符串附加步（这里命令场景其实不依赖，但保持一致）
predicate pathStringStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(CallNode c | succ.asCfgNode() = c |
    c.getFunction().(AttrNode).getName() =
      ["join", "strip", "lower", "replace", "format", "encode", "decode"] and
    (pred.asCfgNode() = c.getAnArg() or pred.asCfgNode() = c.getFunction().(AttrNode).getObject())
    or
    c.getFunction().(NameNode).getId() = ["str"] and pred.asCfgNode() = c.getAnArg()
  )
}

// waypoints
predicate waypoint(DataFlow::Node n, string label) {
  // A: _check_all_guards(command, ...) 的实参（gate 的 g 腿）
  exists(CallNode c |
    c.getFunction().(NameNode).getId() = "_check_all_guards" and n.asCfgNode() = c.getAnArg()
  ) and
  label = "A_gateArg(_check_all_guards)"
  or
  // B: 同文件 env.execute(command) 的实参（本地 sink-ward 调用）
  exists(CallNode c |
    c.getFunction().(AttrNode).getName() = "execute" and
    c.getLocation().getFile().getRelativePath() = "tools/terminal_tool.py" and
    n.asCfgNode() = c.getAnArg()
  ) and
  label = "B_envExecuteArg"
  or
  // C: 真正的 af-sink（Popen/run，跨文件，经 env 服务句柄桥）实参
  exists(CallNode sink | is_sink_af(sink) and onChainMid(terminalTool(), sink) |
    n.asCfgNode() = sink.getAnArg()
  ) and
  label = "C_afSinkArg(Popen/run cross-file)"
}

predicate onChainMid(FunctionObject f, CallNode sink) {
  exists(FunctionObject h, int d, int k |
    is_tool_handler(h) and is_sink_af(sink) and isIncludeLocation2(sink.getLocation()) and
    r_calls(h, sink, d) and find_mid(h, sink, f, d, k)
  )
}

module DiagConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { cmdSource(n) }

  predicate isSink(DataFlow::Node n) { waypoint(n, _) }

  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) { pathStringStep(a, b) }
}

module DiagFlow = TaintTracking::Global<DiagConfig>;

// (A) 支配：terminal_tool 里引用了 approval / force 的条件块，是否 controls 同文件 env.execute 的 BB？
predicate condControlsExec(string which, int controlsExec) {
  which = ["force", "approval"] and
  controlsExec =
    count(ConditionBlock cb, CallNode ex |
      cb.getScope() = terminalTool().getFunction() and
      ex.getFunction().(AttrNode).getName() = "execute" and
      ex.getLocation().getFile().getRelativePath() = "tools/terminal_tool.py" and
      cb.controls(ex.getBasicBlock(), _) and
      exists(Name nm |
        nm.getAFlowNode().getBasicBlock() = cb and nm.getId() = which
      )
    )
}

from string kind, string label, int a, int b
where
  kind = "taint" and
  label = any(string l | waypoint(_, l)) and
  a = count(DataFlow::Node n | waypoint(n, label) and DiagFlow::flow(_, n)) and
  b = count(DataFlow::Node n | waypoint(n, label))
  or
  kind = "controls" and
  (label = "force" or label = "approval") and
  condControlsExec(label, a) and
  b = -1
select kind, label, a as reached_or_controls, b as total
