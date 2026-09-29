import javascript
import project.ProjectModel
import call.call
import call.sinks_af

from string kind, string name, string detail
where
  exists(Function handler, DataFlow::Node source, DataFlow::CallNode sink,
    DataFlow::Node sinkArg, int depth, string path |
    handlerSource(handler, source, _) and controlledSinkArgument(sink, sinkArg, _) and
    taintReachesSink(handler, source, sink, sinkArg, depth) and
    reachesSink(handler, sink, depth, path) and
    (
      handler.getFile().getRelativePath() = "src/agents/bash-tools.exec.ts" and
      sink.getLocation().getFile().getRelativePath() = "src/node-host/runner.ts" and
      kind = "bridge-chain" and name = "node.invoke" and detail = sinkLabel(sink)
      or
      handler.getFile().getRelativePath() = "src/agents/tools/image-tool.ts" and
      sink.getLocation().getFile().getRelativePath() = "src/media/fetch.ts" and
      kind = "second-order-chain" and name = "image" and detail = sinkLabel(sink)
    )
  )
  or
  exists(Function handler, DataFlow::Node source, DataFlow::CallNode sink,
    DataFlow::Node sinkArg, DataFlow::CallNode gate, DataFlow::Node checked,
    Function owner, int chainDepth, int gateDepth, string path |
    handlerSource(handler, source, _) and
    policyDecisionGateForSink(
      handler, source, sink, sinkArg, gate, checked, owner,
      chainDepth, gateDepth, path
    ) and
    sink.getLocation().getFile().getRelativePath() = "src/node-host/runner.ts" and
    kind = "decision-gate" and name = gate.getCalleeName() and
    detail = "branch-confirmed"
  )
select kind, name, detail
