/** Project-bound exact-field bridges that cross runtime registries or queues. */

import javascript
import project.ProjectModel
import call.call
import call.sinks_af

/**
 * OpenClaw-CN passes the message tool's `args` object unchanged as the
 * `params` property of runMessageAction. Only the audited `media` property is
 * admitted through the outbound plugin registry to Feishu's fetch URL.
 */
predicate projectFieldBridgeRow(
  Function handler, DataFlow::Node root, DataFlow::Node source,
  string sourceParameter, string field, string accessKind,
  DataFlow::CallNode sink, DataFlow::Node sinkArgument, string sinkRole
) {
  openClawCNToolHandler(handler, "message", _) and
  handlerSource(handler, root, sourceParameter) and
  field = "media" and accessKind = "project-bound-property-read" and
  controlledSinkArgument(sink, sinkArgument, sinkRole) and sinkRole = "url" and
  sinkCanonicalId(sink) = "OCCN-FEISHU-MEDIA-FETCH" and
  exists(DataFlow::CallNode boundary, ObjectExpr payload |
    boundary.getContainer() = handler and boundary.getCalleeName() = "runMessageAction" and
    payload = boundary.getArgument(0).asExpr() and
    localTaint(root, payload.getPropertyByName("params").getInit().flow())
  ) and
  exists(DataFlow::CallNode read |
    read.getCalleeName() = "readStringParam" and read.getNumArgument() >= 2 and
    read.getArgument(0).toString() = "params" and
    read.getArgument(1).mayHaveStringValue("media") and
    read.getContainer().(Function).getName() = "handleSendAction" and
    read.getFile().getRelativePath() = "src/infra/outbound/message-action-runner.ts" and
    source = read
  )
}
