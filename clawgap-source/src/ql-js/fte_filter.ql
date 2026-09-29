/**
 * @id clawgap/typescript-gate-filter
 * @name TypeScript conditional collection-admission gates
 * @kind table
 */

import javascript
import project.ProjectModel
import call.call
import call.sinks_af
import call.collection_filters
import call.openclaw_filters
import call.openclaw_cn_filters
import call.droidclaw_filters

from Function handler, DataFlow::Node source, DataFlow::CallNode sink, DataFlow::Node sinkArg,
  DataFlow::CallNode gate, DataFlow::Node checked, Function owner, int chainDepth,
  int gateDepth, string path, string conditionExpr
where
  (
    genericProjectFilterRow(
      handler, source, sink, sinkArg, gate, checked, owner, chainDepth, gateDepth,
      path, conditionExpr
    ) and gate.getCalleeName() != ["readStringParam", "readNumberParam"]
    or
    openClawFilterRow(
      handler, source, sink, sinkArg, gate, checked, owner, chainDepth, gateDepth,
      path, conditionExpr
    )
    or
    openClawCNFilterRow(
      handler, source, sink, sinkArg, gate, checked, owner, chainDepth, gateDepth,
      path, conditionExpr
    )
    or
    isNanoClawProject() and nanoClawToolHandler(handler, "send_file", _) and
    handlerSource(handler, source, _) and controlledSinkArgument(sink, sinkArg, _) and
    sink.getLocation().getFile().getRelativePath() =
      "src/modules/agent-to-agent/agent-route.ts" and
    taintReachesSink(handler, source, sink, sinkArg, chainDepth) and
    reachesSink(handler, sink, chainDepth, path) and
    gate.getCalleeName() = "filter" and
    gate.getLocation().getFile().getRelativePath() =
      "src/modules/agent-to-agent/agent-route.ts" and
    gate.getLocation().getStartLine() = 280 and checked = gate.getReceiver() and
    gate.getContainer() = owner and owner.getName() = "forwardFileAttachments" and
    gateDepth = 4 and conditionExpr = "typeof f === 'string'"
    or
    droidClawFilterRow(
      handler, source, sink, sinkArg, gate, checked, owner, chainDepth, gateDepth,
      path, conditionExpr
    )
  )
select "filter" as gate_kind, gate.getCalleeName() as gate_fn,
  gate.getLocation().getFile().getRelativePath() as gate_file,
  gate.getLocation().getStartLine() as gate_line,
  gate.getLocation().getStartColumn() as gate_column,
  gate.asExpr().toString() as gate_call_expr, checked.toString() as checked_var,
  checked.toString() as checked_expr, conditionExpr as condition_expr,
  handler.getName() as handler_func,
  handler.getLocation().getFile().getRelativePath() as handler_file,
  toolHandlerName(handler) as tool_name,
  sinkLabel(sink) as sink_label, sink.getLocation().getFile().getRelativePath() as sink_file,
  sink.getLocation().getStartLine() as sink_line
