/**
 * @id clawgap/javascript-field-flow-exclusions
 * @name Field-sensitive JavaScript/TypeScript exclusions
 * @kind table
 */

import javascript
import project.ProjectModel
import call.call
import call.sinks_af
import field_flow.FieldFlow

module ExclusionFlowConfig implements DataFlow::ConfigSig {
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

module ExclusionFlow = DataFlow::Global<ExclusionFlowConfig>;

string exclusionReason(Function handler, DataFlow::CallNode sink) {
  handler.getFile() != sink.getFile() and result = "missing-explicit-bridge"
  or
  handler.getFile() = sink.getFile() and result = "sibling-argument"
}

from Function handler, DataFlow::Node root, DataFlow::Node source,
  string sourceParameter, string field, string accessKind, DataFlow::CallNode sink,
  DataFlow::Node sinkArgument, string sinkRole, string toolName, int depth, string path
where
  projectToolHandler(handler, toolName, _) and handlerSource(handler, root, sourceParameter) and
  fieldRead(root, field, source, accessKind) and
  controlledSinkArgument(sink, sinkArgument, sinkRole) and
  reachesSink(handler, sink, depth, path) and
  // Emit the finite structural field/sink-role domain. The converter subtracts
  // exact positive witnesses; avoiding a global `not flow` keeps this query bounded.
  source != sinkArgument
select activeProjectId() as project, handler.getName() as handler_name,
  handler.getFile().getRelativePath() as handler_file,
  handler.getLocation().getStartLine() as handler_line,
  sourceParameter, field, fieldFlowLocation(source) as property_read,
  sink.getFile().getRelativePath() as sink_file,
  sink.getLocation().getStartLine() as sink_line,
  sink.getLocation().getStartColumn() as sink_column, sinkRole,
  "model-arbitrary" as value_authority, exclusionReason(handler, sink) as exclusion_reason,
  "field-read@" + fieldFlowLocation(source) + ";sink-role@" +
    fieldFlowLocation(sinkArgument) as path_nodes,
  accessKind, "" as transforms
