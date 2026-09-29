/**
 * @id clawgap/hermes-gate-filter
 * @name Python filter gates (conditional collection admission, same-origin refined)
 * @description Detects checked source-derived values admitted to sink-bound collections,
 *              including reject-and-continue loops whose admitted object is derived through
 *              simple field extraction or normalization.
 * @kind table
 * @tags clawgap
 */

import python
import call.filter_gates

from
  ConditionBlock cb, CallNode gateCall, DataFlow::Node checked, DataFlow::Node collAfter,
  CallNode sink, DataFlow::Node sinkArg
where
  filterGateResult(cb, gateCall, checked, collAfter, sink, sinkArg)
select "filter" as gate_kind, filterCalleeName(gateCall) as gate_fn,
  gateCall.getLocation().getFile().getRelativePath() as gate_file,
  gateCall.getLocation().getStartLine() as gate_line,
  gateCall.getLocation().getStartColumn() as gate_column,
  gateCall.getNode().toString() as gate_call_expr, checked.asExpr().toString() as checked_var,
  checked.asExpr().toString() as checked_expr,
  cb.getLastNode().getNode().toString() as condition_expr,
  filterCalleeName(sink) as sink_label,
  sink.getLocation().getFile().getRelativePath() as sink_file,
  sink.getLocation().getStartLine() as sink_line
