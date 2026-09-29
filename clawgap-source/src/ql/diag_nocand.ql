/**
 * @id clawgap/diag-nocand
 * @name diag: why the 9 no-candidate guards aren't extracted by (B)
 * @kind table
 * @tags clawgap
 */

import python
import call.call
import util.util

// a check CallNode of interest
predicate checkCall(CallNode c, string tag) {
  c.getFunction().(NameNode).getId() = "isinstance" and
  c.getLocation().getFile().getRelativePath() = "tools/terminal_tool.py" and
  tag = "isinstance(command)"
  or
  c.getFunction().(AttrNode).getName() = "search" and
  c.getFunction().(AttrNode).getObject().(NameNode).getId() = "_PREFIX_RE" and
  tag = "_PREFIX_RE.search (browser/web)"
}

from string tag, int nCalls, int nInConditionBlock
where
  checkCall(_, tag) and
  nCalls = count(CallNode c | checkCall(c, tag)) and
  // of those, how many sit directly IN a ConditionBlock (=> (B1) `vc.getBasicBlock()=cb` could anchor)
  nInConditionBlock =
    count(CallNode c | checkCall(c, tag) and c.getBasicBlock() instanceof ConditionBlock)
select tag, nCalls, nInConditionBlock as n_call_node_is_conditionblock

