import javascript
import project.ProjectModel
import call.sinks_af
import call.openclaw_filters

from string tool, string gateName, string gateFile, int gateLine, string sinkLabelResult
where
  exists(Function handler, DataFlow::Node source, DataFlow::CallNode sink,
    DataFlow::Node sinkArg, DataFlow::CallNode gate, DataFlow::Node checked,
    Function owner, int chainDepth, int gateDepth, string path,
    string conditionExpr |
    openClawFilterRow(handler, source, sink, sinkArg, gate, checked, owner,
      chainDepth, gateDepth, path, conditionExpr) and
    tool = toolHandlerName(handler) and gateName = gate.getCalleeName() and
    gateFile = gate.getLocation().getFile().getRelativePath() and
    gateLine = gate.getLocation().getStartLine() and sinkLabelResult = sinkLabel(sink)
  )
select tool, gateName, gateFile, gateLine, sinkLabelResult
