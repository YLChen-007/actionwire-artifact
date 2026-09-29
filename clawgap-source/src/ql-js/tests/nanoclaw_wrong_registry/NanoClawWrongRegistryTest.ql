import javascript
import project.ProjectModel
import call.call
import call.sinks_af

from string verdict
where
  isNanoClawProject() and
  exists(Function handler | nanoClawToolHandler(handler, "add_mcp_server", _)) and
  exists(DataFlow::CallNode sink | sinkCanonicalId(sink) = "NC-APPROVAL-PERSIST") and
  not exists(Function handler, DataFlow::Node source, DataFlow::CallNode sink,
    DataFlow::Node sinkArg, int depth |
    nanoClawToolHandler(handler, "add_mcp_server", _) and
    handlerSource(handler, source, _) and controlledSinkArgument(sink, sinkArg, _) and
    taintReachesSink(handler, source, sink, sinkArg, depth) and
    reachesSink(handler, sink, depth, _)
  ) and
  verdict = "wrong-registry-literal-does-not-bridge"
select verdict
