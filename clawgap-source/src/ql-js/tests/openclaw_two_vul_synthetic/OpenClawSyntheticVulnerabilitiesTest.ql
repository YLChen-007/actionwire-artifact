/**
 * Synthetic-only witnesses for two OpenClaw reports whose source revisions do not
 * coexist in the upstream v2026.2.1 benchmark.
 */

import javascript
import project.ProjectModel
import call.call
import call.sinks_af

from string report, string tool, string sink, string facet
where
  exists(Function handler, DataFlow::Node source, DataFlow::CallNode sinkCall,
    DataFlow::Node sinkArg, int depth, string path |
    openClawToolHandler(handler, tool, _) and handlerSource(handler, source, _) and
    controlledSinkArgument(sinkCall, sinkArg, facet) and
    taintReachesSink(handler, source, sinkCall, sinkArg, depth) and
    reachesSink(handler, sinkCall, depth, path) and
    (
      tool = "browser" and sinkCanonicalId(sinkCall) = "OC-BROWSER-CHROME-MCP-CALL" and
      report = "Advisory-GHSA-527m-976r-jf79-dataflow-wait-fn-existing-session"
      or
      tool = "message" and sinkCanonicalId(sinkCall) = "OC-FILE-READ" and
      sinkCall.getLocation().getFile().getRelativePath() = "src/infra/fs-safe.ts" and
      report = "Media_Root_Bypass-ISSUE-REPORT-fixed"
    ) and
    sink = sinkLabel(sinkCall)
  )
select report, tool, sink, facet
