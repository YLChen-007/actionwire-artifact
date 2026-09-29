/**
 * @id clawgap/diag-skillview
 * @name diag: skill_view name→sink taint waypoints
 * @kind table
 * @tags clawgap
 */

import python
import call.call
import call.sinks_af
import util.util
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

// 复刻 get_gates.ql 的路径/字符串附加步
predicate pathStringStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(CallNode c | succ.asCfgNode() = c |
    c.getFunction().(AttrNode).getName() =
      [
        "join", "expanduser", "abspath", "realpath", "normpath", "normcase", "dirname", "basename",
        "resolve", "absolute", "joinpath", "with_name", "with_suffix", "strip", "lstrip", "rstrip",
        "lower", "upper", "replace", "format", "encode", "decode"
      ] and
    (pred.asCfgNode() = c.getAnArg() or pred.asCfgNode() = c.getFunction().(AttrNode).getObject())
    or
    c.getFunction().(NameNode).getId() = ["Path", "PurePath", "str", "fspath"] and
    pred.asCfgNode() = c.getAnArg()
  )
  or
  exists(BinaryExprNode b |
    b.getOp() instanceof Div and succ.asCfgNode() = b and pred.asCfgNode() = b.getAnOperand()
  )
}

// source = skill_view 的 name 形参
predicate nameSource(DataFlow::Node n) {
  n.(DataFlow::ParameterNode).getParameter().(Name).getId() = "name" and
  n.getScope().(Function).getName() = "skill_view" and
  n.getLocation().getFile().getRelativePath() = "tools/skills_tool.py"
}

// 各个 waypoint（都在 skills_tool.py）
predicate waypoint(DataFlow::Node n, string label) {
  n.getLocation().getFile().getRelativePath() = "tools/skills_tool.py" and
  (
    // A: gate 调用 _skill_lookup_path_error(...) 的实参
    exists(CallNode c |
      c.getFunction().(NameNode).getId() = "_skill_lookup_path_error" and
      n.asCfgNode() = c.getAnArg()
    ) and
    label = "A_gateArg(_skill_lookup_path_error)"
    or
    // B: `search_dir / name` —— Div 结果（direct_path 的 RHS）
    exists(BinaryExprNode b | b.getOp() instanceof Div and n.asCfgNode() = b) and
    label = "B_div(search_dir/name)"
    or
    // C: _record(...) 调用的第二个实参（direct_path / "SKILL.md"）
    exists(CallNode c |
      c.getFunction().(NameNode).getId() = "_record" and n.asCfgNode() = c.getArg(1)
    ) and
    label = "C_recordArg1(smd)"
    or
    // D: _record 的形参 smd（污点是否进入嵌套函数）
    n.(DataFlow::ParameterNode).getParameter().(Name).getId() = "smd" and
    label = "D_recordParam(smd)"
    or
    // E: candidates.append(...) 的实参（进入列表）
    exists(CallNode c |
      c.getFunction().(AttrNode).getName() = "append" and n.asCfgNode() = c.getAnArg()
    ) and
    label = "E_append(candidates)"
    or
    // F: read_text() 的接收者（真正被污染的 skill_md）
    exists(CallNode c |
      c.getFunction().(AttrNode).getName() = "read_text" and
      n.asCfgNode() = c.getFunction().(AttrNode).getObject()
    ) and
    label = "F_readTextRECEIVER(skill_md)"
    or
    // G: read_text() 的 getAnArg()（= get_gates.ql 里 sinkArgNode 实际锚的节点！）
    exists(CallNode c |
      c.getFunction().(AttrNode).getName() = "read_text" and n.asCfgNode() = c.getAnArg()
    ) and
    label = "G_readTextGETANARG(encoding=)"
  )
}

module DiagConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { nameSource(n) }

  predicate isSink(DataFlow::Node n) { waypoint(n, _) }

  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) { pathStringStep(a, b) }
}

module DiagFlow = TaintTracking::Global<DiagConfig>;

from string label, int reached
where
  reached = count(DataFlow::Node n | waypoint(n, label) and DiagFlow::flow(_, n)) and
  exists(DataFlow::Node n | waypoint(n, label)) // 该 waypoint 存在
select label, reached as reached_by_taint,
  count(DataFlow::Node n | waypoint(n, label)) as total_waypoint_nodes
