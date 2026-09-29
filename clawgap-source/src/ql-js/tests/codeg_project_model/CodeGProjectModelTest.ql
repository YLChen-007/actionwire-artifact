import javascript
import project.ProjectModel
import call.call
import call.sinks_af

from string kind, string name, string detail
where
  kind = "adapter" and name = activeProjectId() and detail = activeProjectAdapter()
  or
  exists(Function handler, string toolName |
    codeGToolHandler(handler, toolName, _) and kind = "handler" and name = toolName and
    detail = handler.getFile().getRelativePath()
  )
  or
  exists(Function handler, DataFlow::Node source, string toolName, string parameterName |
    codeGToolHandler(handler, toolName, _) and handlerSource(handler, source, parameterName) and
    kind = "source" and name = toolName and detail = parameterName
  )
  or
  exists(DataFlow::CallNode sink |
    is_sink_af(sink) and kind = "sink" and name = sinkLabel(sink) and
    detail = sink.getLocation().getFile().getRelativePath()
  )
  or
  exists(Function handler, string toolName, DataFlow::Node source, DataFlow::CallNode sink,
    DataFlow::Node sinkArg, int depth |
    codeGToolHandler(handler, toolName, _) and handlerSource(handler, source, _) and
    controlledSinkArgument(sink, sinkArg, "prompt-blocks") and
    taintReachesSink(handler, source, sink, sinkArg, depth) and
    reachesSink(handler, sink, depth, _) and kind = "chain" and name = toolName and
    detail = sinkLabel(sink)
  )
  or
  not exists(DataFlow::CallNode sink |
    is_sink_af(sink) and sink.getLocation().getFile().getRelativePath() = [
      "src/lib/tauri.ts", "src/unrelated.ts", "src/fake.test.ts"
    ]
  ) and kind = "negative" and name = "legacy-generic-and-test-boundaries" and detail = "absent"
select kind, name, detail
