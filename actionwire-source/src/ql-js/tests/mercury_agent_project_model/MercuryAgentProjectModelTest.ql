import javascript
import project.ProjectModel
import call.call
import call.sinks_af

from string kind, string name, string detail
where
  kind = "adapter" and name = activeProjectId() and detail = activeProjectAdapter()
  or
  exists(Function handler, string toolName |
    mercuryAgentToolHandler(handler, toolName, _) and kind = "handler" and name = toolName and
    detail = handler.getFile().getRelativePath()
  )
  or
  exists(DataFlow::CallNode sink |
    is_sink_af(sink) and kind = "sink" and name = sinkLabel(sink) and
    detail = sink.getLocation().getFile().getRelativePath()
  )
  or
  exists(Function handler, DataFlow::Node source, DataFlow::CallNode sink,
    DataFlow::Node sinkArg, int depth |
    handlerSource(handler, source, _) and controlledSinkArgument(sink, sinkArg, _) and
    taintReachesSink(handler, source, sink, sinkArg, depth) and reachesSink(handler, sink, depth, _) and
    kind = "chain" and name = toolHandlerName(handler) and detail = sinkLabel(sink)
  )
  or
  exists(Function handler, DataFlow::Node source, DataFlow::CallNode sink,
    DataFlow::Node sinkArg, int depth, string facet |
    mercuryAgentToolHandler(handler, "install_skill", _) and handlerSource(handler, source, _) and
    sink.getLocation().getFile().getRelativePath() = "src/skills/loader.ts" and
    controlledSinkArgument(sink, sinkArg, facet) and
    taintReachesSink(handler, source, sink, sinkArg, depth) and reachesSink(handler, sink, depth, _) and
    kind = "facet" and name = facet and detail = sinkLabel(sink)
  )
  or
  not exists(Function handler |
    mercuryAgentToolHandler(handler, "ordinary", _)
  ) and
  count(DataFlow::CallNode sink |
    is_sink_af(sink) and sink.getLocation().getFile().getRelativePath() = "src/unrelated.ts"
  ) = 3 and kind = "shared-sink" and name = "unregistered-handler" and
  detail = "three-primitives-detected"
select kind, name, detail
