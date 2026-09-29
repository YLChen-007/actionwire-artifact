import javascript
import project.ProjectModel
import call.sinks_af
import call.call
import call.openclaw_filters
import field_flow.FieldFlow
import field_flow.ProjectFieldBridges

from string kind, string name, string detail
where
  kind = "adapter" and name = activeProjectId() and detail = activeProjectAdapter()
  or
  exists(Function handler, DataFlow::Node root, DataFlow::Node source,
    string sourceParameter, string field, string accessKind,
    DataFlow::CallNode sink, DataFlow::Node sinkArg, string sinkRole |
    projectFieldBridgeRow(
      handler, root, source, sourceParameter, field, accessKind, sink, sinkArg, sinkRole
    ) and
    kind = "field-bridge" and name = "media-to-feishu-url" and detail = "exact"
  )
  or
  kind = "identity" and name = "mutually-exclusive" and isOpenClawCNProject() and
  not isOpenClawProject() and detail = "accepted"
  or
  not exists(Function handler, DataFlow::Node source, DataFlow::CallNode sink,
    DataFlow::Node sinkArg, DataFlow::CallNode gate, DataFlow::Node checked,
    Function owner, int chainDepth, int gateDepth, string path,
    string conditionExpr |
    openClawFilterRow(handler, source, sink, sinkArg, gate, checked, owner,
      chainDepth, gateDepth, path, conditionExpr)
  ) and kind = "filter-isolation" and name = "openclaw-only-signatures" and
  detail = "absent"
  or
  kind = "handler-summary" and name =
    count(Function handler, string toolName, string model |
      openClawCNToolHandler(handler, toolName, model)
    ).toString() + "-rows" and
  detail = count(string toolName |
    exists(Function handler, string model |
      openClawCNToolHandler(handler, toolName, model)
    )
  ).toString() + "-names"
  or
  kind = "sink-summary" and name = count(DataFlow::CallNode sink |
    is_sink_af(sink)
  ).toString() + "-calls" and detail = "strict-shapes"
  or
  exists(DataFlow::CallNode sink |
    is_sink_af(sink) and kind = "sink" and name = sinkLabel(sink) and
    detail = sinkCapability(sink)
  )
  or
  not exists(Function handler |
    openClawCNToolHandler(handler, _, _) and handler.getFile().getRelativePath() = [
      "src/agents/pi-tool-definition-adapter.ts",
      "src/channels/plugins/agent-tools/plugin.ts",
      "src/agents/tools/fake.test.ts",
      "src/unrelated.ts"
    ]
  ) and
  exists(DataFlow::CallNode sink |
    sinkCanonicalId(sink) = "OC-NETWORK-FETCH" and
    sink.getLocation().getFile().getRelativePath() = "src/unrelated.ts"
  ) and kind = "shared-sink" and name = "non-handler-fetch" and detail = "detected"
select kind, name, detail
