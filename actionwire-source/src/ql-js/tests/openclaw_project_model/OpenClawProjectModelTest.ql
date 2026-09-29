import javascript
import project.ProjectModel
import call.call
import call.sinks_af
import call.openclaw_cn_filters

from string kind, string name, string detail
where
  kind = "adapter" and name = activeProjectId() and detail = activeProjectAdapter()
  or
  not exists(Function handler, DataFlow::Node source, DataFlow::CallNode sink,
    DataFlow::Node sinkArg, DataFlow::CallNode gate, DataFlow::Node checked,
    Function owner, int chainDepth, int gateDepth, string path,
    string conditionExpr |
    openClawCNFilterRow(handler, source, sink, sinkArg, gate, checked, owner,
      chainDepth, gateDepth, path, conditionExpr)
  ) and kind = "filter-isolation" and name = "openclaw-cn-only-signatures" and
  detail = "absent"
  or
  exists(Function handler, string toolName, string model |
    openClawToolHandler(handler, toolName, model) and kind = "handler" and
    name = toolName and detail = handler.getFile().getRelativePath()
  )
  or
  exists(Function handler, string toolName, DataFlow::Node source,
    DataFlow::CallNode sink, DataFlow::Node sinkArg, int depth, string path |
    openClawToolHandler(handler, toolName, _) and handlerSource(handler, source, _) and
    is_sink_af(sink) and controlledSinkArgument(sink, sinkArg, _) and
    taintReachesSink(handler, source, sink, sinkArg, depth) and
    reachesSink(handler, sink, depth, path) and kind = "chain" and
    name = toolName and detail = sinkLabel(sink)
  )
  or
  exists(Function handler, DataFlow::Node source, DataFlow::CallNode gate,
    DataFlow::CallNode sink |
    openClawToolHandler(handler, "exec", _) and handlerSource(handler, source, _) and
    gate.getContainer() = handler and gate.getCalleeName() = "assertAllowed" and
    localTaint(source, gate.getArgument(0)) and sink.getContainer() = handler and
    sinkLabel(sink) = "spawn" and
    gate.getBasicBlock().(ReachableBasicBlock).dominates(sink.getBasicBlock()) and
    kind = "gate" and name = gate.getCalleeName() and detail = "source-tainted-dominance"
  )
  or
  not exists(Function handler |
    openClawToolHandler(handler, _, _) and handler.getFile().getRelativePath() =
      ["src/agents/pi-tool-definition-adapter.ts", "src/channels/plugins/agent-tools/plugin.ts",
       "src/agents/tools/fake.test.ts", "src/unrelated.ts"]
  ) and kind = "negative" and name = "excluded-execute-forms" and detail = "absent"
select kind, name, detail
