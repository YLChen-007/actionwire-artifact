/**
 * @id clawgap/openclaw-handler-to-sink
 * @name taint-valid OpenClaw handler to sink chains
 * @kind table
 */

import javascript
import project.ProjectModel
import call.call
import call.sinks_af

from Function handler, string toolName, string sourceName, DataFlow::CallNode sink, int depth,
  string path, DataFlow::Node source, DataFlow::Node argument, string facet
where
  projectToolHandler(handler, toolName, _) and
  handlerSource(handler, source, sourceName) and
  is_sink_af(sink) and
  controlledSinkArgument(sink, argument, facet) and
  taintReachesSink(handler, source, sink, argument, depth) and
  reachesSink(handler, sink, depth, path)
select handler.getName() as handler_func,
  handler.getFile().getRelativePath() as handler_file,
  handler.getLocation().getStartLine() as handler_line, depth,
  sinkLabel(sink) as sink_label, sink.getLocation().getFile().getRelativePath() as sink_file,
  sink.getLocation().getStartLine() as sink_line, depth.toString() + "#" + path as call_chain,
  activeProjectId() as project_id, toolName as tool_name,
  handler.getName() as handler_qualified_name, sourceName as source_parameter,
  sink.getLocation().getStartColumn() as sink_column,
  facet as sink_argument
