/**
 * @id clawgap/javascript-project-field-bridges
 * @name Project-bound JavaScript/TypeScript exact-field bridges
 * @kind table
 */

import javascript
import project.ProjectModel
import field_flow.FieldFlow
import field_flow.ProjectFieldBridges

from Function handler, DataFlow::Node root, DataFlow::Node source,
  string sourceParameter, string field, string accessKind, DataFlow::CallNode sink,
  DataFlow::Node sinkArgument, string sinkRole
where
  projectFieldBridgeRow(
    handler, root, source, sourceParameter, field, accessKind, sink, sinkArgument, sinkRole
  )
select activeProjectId() as project, handler.getName() as handler_name,
  handler.getFile().getRelativePath() as handler_file,
  handler.getLocation().getStartLine() as handler_line,
  sourceParameter, field, fieldFlowLocation(source) as property_read,
  sink.getFile().getRelativePath() as sink_file,
  sink.getLocation().getStartLine() as sink_line,
  sink.getLocation().getStartColumn() as sink_column, sinkRole,
  "model-arbitrary" as value_authority, "explicit-bridge" as proof,
  "field-read@" + fieldFlowLocation(source) + ";argument@" +
    fieldFlowLocation(root) + ";bridge@" + fieldFlowLocation(sink) +
    ";sink-role@" + fieldFlowLocation(sinkArgument) as path_nodes,
  accessKind, "" as transforms
