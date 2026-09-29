/**
 * @id clawgap/python-field-flow-exclusions
 * @name Field-sensitive Python exclusions
 * @kind table
 */

import python
import project.ProjectModel
import call.call
import call.sinks_af
import field_flow.FieldFlow
import semmle.python.dataflow.new.TaintTracking

predicate modelHandlerSource(
  FunctionObject handler, DataFlow::Node root, string sourceParameter
) {
  is_tool_handler(handler) and
  root.(DataFlow::ParameterNode).getScope() = handler.getFunction() and
  root.(DataFlow::ParameterNode).getParameter().(Name).getId() = sourceParameter and
  (
    projectToolHandler(handler) and
    projectHandlerSourceParameter(
      handler, root.(DataFlow::ParameterNode).getParameter()
    )
    or
    not projectToolHandler(handler) and sourceParameter != ["self", "cls"]
  )
}

module ExclusionFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    exists(FunctionObject handler, DataFlow::Node root, string field, string accessKind |
      modelHandlerSource(handler, root, _) and fieldRead(root, field, node, accessKind)
    )
  }

  predicate isSink(DataFlow::Node node) { sinkSensitiveNode(_, node, _) }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    fieldFlowTransformStep(pred, succ) or projectBridgeTaintStep(pred, succ) or
    explicitFieldBridgeStep(pred, succ)
  }
}

module ExclusionFlow = DataFlow::Global<ExclusionFlowConfig>;

string exclusionReason(FunctionObject handler, CallNode sink) {
  handler.getFunction().getLocation().getFile() != sink.getLocation().getFile() and
  result = "missing-explicit-bridge"
  or
  handler.getFunction().getLocation().getFile() = sink.getLocation().getFile() and
  result = "sibling-argument"
}

from FunctionObject handler, DataFlow::Node root, DataFlow::Node source,
  string sourceParameter, string field, string accessKind, CallNode sink,
  DataFlow::Node sinkArgument, string sinkRole, int depth
where
  modelHandlerSource(handler, root, sourceParameter) and
  fieldRead(root, field, source, accessKind) and
  is_sink_af(sink) and sinkSensitiveNode(sink, sinkArgument, sinkRole) and
  depth = [1 .. 8] and r_calls(handler, sink, depth) and
  // Emit the finite structural field/sink-role domain. The converter subtracts
  // exact positive witnesses; avoiding a global `not flow` keeps this query bounded.
  source != sinkArgument
select activeProjectId() as project, handler.getQualifiedName() as handler_name,
  handler.getFunction().getLocation().getFile().getRelativePath() as handler_file,
  handler.getFunction().getLocation().getStartLine() as handler_line,
  sourceParameter, field, fieldFlowLocation(source) as property_read,
  sink.getLocation().getFile().getRelativePath() as sink_file,
  sink.getLocation().getStartLine() as sink_line,
  sink.getLocation().getStartColumn() as sink_column, sinkRole,
  "model-arbitrary" as value_authority, exclusionReason(handler, sink) as exclusion_reason,
  "field-read@" + fieldFlowLocation(source) + ";sink-role@" +
    fieldFlowLocation(sinkArgument) as path_nodes,
  accessKind, "" as transforms
