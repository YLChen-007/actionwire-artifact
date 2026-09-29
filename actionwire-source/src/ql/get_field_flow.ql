/**
 * @id clawgap/python-field-flow
 * @name Field-sensitive Python handler-to-sink witnesses
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

module FieldFlowConfig implements DataFlow::ConfigSig {
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

module FieldFlow = DataFlow::Global<FieldFlowConfig>;

predicate admittedBridgeStep(DataFlow::Node pred, DataFlow::Node succ) {
  projectBridgeTaintStep(pred, succ) or explicitFieldBridgeStep(pred, succ)
}

string proofKind(DataFlow::Node source, DataFlow::Node sink) {
  DataFlow::localFlow(source, sink) and result = "direct"
  or
  not DataFlow::localFlow(source, sink) and
  exists(DataFlow::Node pred, DataFlow::Node succ |
    admittedBridgeStep(pred, succ) and
    DataFlow::localFlow(source, pred) and DataFlow::localFlow(succ, sink)
  ) and result = "explicit-bridge"
  or
  not DataFlow::localFlow(source, sink) and
  not exists(DataFlow::Node pred, DataFlow::Node succ |
    admittedBridgeStep(pred, succ) and
    DataFlow::localFlow(source, pred) and DataFlow::localFlow(succ, sink)
  ) and result = "interprocedural"
}

string transformSummary(DataFlow::Node source, DataFlow::Node sink) {
  result = strictconcat(DataFlow::Node node, string transform |
    fieldFlowTransform(node, transform) and
    FieldFlow::flow(source, node) and FieldFlow::flow(node, sink)
  | transform, ";" order by node.getLocation().getStartLine())
  or
  not exists(DataFlow::Node node, string transform |
    fieldFlowTransform(node, transform) and
    FieldFlow::flow(source, node) and FieldFlow::flow(node, sink)
  ) and result = ""
}

bindingset[proof]
string pathSummary(DataFlow::Node source, DataFlow::Node sink, string proof) {
  proof != "explicit-bridge" and
  result = "field-read@" + fieldFlowLocation(source) + ";sink-role@" +
    fieldFlowLocation(sink)
  or
  proof = "explicit-bridge" and
  exists(DataFlow::Node pred, DataFlow::Node succ |
    admittedBridgeStep(pred, succ) and
    DataFlow::localFlow(source, pred) and DataFlow::localFlow(succ, sink) and
    result = "field-read@" + fieldFlowLocation(source) + ";argument@" +
      fieldFlowLocation(pred) + ";bridge@" + fieldFlowLocation(succ) +
      ";sink-role@" + fieldFlowLocation(sink)
  )
}

from FunctionObject handler, DataFlow::Node root, DataFlow::Node source,
  string sourceParameter, string field, string accessKind, CallNode sink,
  DataFlow::Node sinkArgument, string sinkRole, string proof
where
  modelHandlerSource(handler, root, sourceParameter) and
  fieldRead(root, field, source, accessKind) and
  sinkSensitiveNode(sink, sinkArgument, sinkRole) and
  FieldFlow::flow(source, sinkArgument) and proof = proofKind(source, sinkArgument)
select activeProjectId() as project, handler.getQualifiedName() as handler_name,
  handler.getFunction().getLocation().getFile().getRelativePath() as handler_file,
  handler.getFunction().getLocation().getStartLine() as handler_line,
  sourceParameter, field, fieldFlowLocation(source) as property_read,
  sink.getLocation().getFile().getRelativePath() as sink_file,
  sink.getLocation().getStartLine() as sink_line,
  sink.getLocation().getStartColumn() as sink_column, sinkRole,
  "model-arbitrary" as value_authority, proof,
  pathSummary(source, sinkArgument, proof) as path_nodes,
  accessKind, transformSummary(source, sinkArgument) as transforms
