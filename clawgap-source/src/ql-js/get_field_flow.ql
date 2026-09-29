/**
 * @id clawgap/javascript-field-flow
 * @name Field-sensitive JavaScript/TypeScript handler-to-sink witnesses
 * @kind table
 */

import javascript
import project.ProjectModel
import call.call
import call.sinks_af
import field_flow.FieldFlow

module FieldFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    exists(Function handler, DataFlow::Node root, string sourceName, string field,
      string accessKind |
      handlerSource(handler, root, sourceName) and fieldRead(root, field, node, accessKind)
    )
  }

  predicate isSink(DataFlow::Node node) { controlledSinkArgument(_, node, _) }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    fieldFlowTransformStep(pred, succ) or explicitFieldBridgeStep(pred, succ)
  }
}

module FieldFlow = DataFlow::Global<FieldFlowConfig>;

string proofKind(DataFlow::Node source, DataFlow::Node sink) {
  localTaint(source, sink) and result = "direct"
  or
  not localTaint(source, sink) and
  exists(DataFlow::Node pred, DataFlow::Node succ |
    explicitFieldBridgeStep(pred, succ) and
    localTaint(source, pred) and localTaint(succ, sink)
  ) and result = "explicit-bridge"
  or
  not localTaint(source, sink) and
  not exists(DataFlow::Node pred, DataFlow::Node succ |
    explicitFieldBridgeStep(pred, succ) and
    localTaint(source, pred) and localTaint(succ, sink)
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
    explicitFieldBridgeStep(pred, succ) and
    localTaint(source, pred) and localTaint(succ, sink) and
    result = "field-read@" + fieldFlowLocation(source) + ";argument@" +
      fieldFlowLocation(pred) + ";bridge@" + fieldFlowLocation(succ) +
      ";sink-role@" + fieldFlowLocation(sink)
  )
}

from Function handler, DataFlow::Node root, DataFlow::Node source,
  string sourceParameter, string field, string accessKind, DataFlow::CallNode sink,
  DataFlow::Node sinkArgument, string sinkRole, string proof, string toolName
where
  projectToolHandler(handler, toolName, _) and handlerSource(handler, root, sourceParameter) and
  fieldRead(root, field, source, accessKind) and
  controlledSinkArgument(sink, sinkArgument, sinkRole) and
  FieldFlow::flow(source, sinkArgument) and proof = proofKind(source, sinkArgument)
select activeProjectId() as project, handler.getName() as handler_name,
  handler.getFile().getRelativePath() as handler_file,
  handler.getLocation().getStartLine() as handler_line,
  sourceParameter, field, fieldFlowLocation(source) as property_read,
  sink.getFile().getRelativePath() as sink_file,
  sink.getLocation().getStartLine() as sink_line,
  sink.getLocation().getStartColumn() as sink_column, sinkRole,
  "model-arbitrary" as value_authority, proof,
  pathSummary(source, sinkArgument, proof) as path_nodes,
  accessKind, transformSummary(source, sinkArgument) as transforms
