/** Field-sensitive model-input flow primitives for JavaScript and TypeScript. */

import javascript
import call.call

/**
 * A constant property read rooted in `root`.
 *
 * `read` is the selected property value.  The base object and a computed
 * selector are not promoted to the property value.
 */
predicate fieldRead(
  DataFlow::Node root, string field, DataFlow::Node read, string accessKind
) {
  exists(PropAccess access |
    localTaint(root, access.getBase().flow()) and
    field = access.getPropertyName() and read = access.flow() and
    accessKind = "property-read"
  )
  or
  exists(IndexExpr access, Literal key |
    key = access.getIndex() and field = key.getStringValue() and
    localTaint(root, access.getBase().flow()) and
    read = access.flow() and accessKind = "index-read"
  )
}

/** Reserved explicit RPC bridge used by fixtures and generated adapters. */
predicate explicitFieldBridgeStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(DataFlow::CallNode send, Function receive |
    send.getCalleeName() = "fieldFlowRpcSend" and pred = send.getArgument(0) and
    send.getFile().getRelativePath() = "src/flow.ts" and
    receive.getName() = "fieldFlowRpcReceive" and
    receive.getFile().getRelativePath() = "src/flow.ts" and
    succ = DataFlow::parameterNode(receive.getParameter(0))
  )
}

/** Stable location used in the flat QL exchange row. */
string fieldFlowLocation(DataFlow::Node node) {
  result = node.getLocation().getFile().getRelativePath() + ":" +
    node.getLocation().getStartLine().toString() + ":" +
    node.getLocation().getStartColumn().toString()
}

/** A deliberately small transform vocabulary; unknown calls remain ordinary path nodes. */
predicate fieldFlowTransform(DataFlow::Node node, string transform) {
  exists(DataFlow::CallNode call, string name |
    node = call and name = call.getCalleeName() and
    name = ["trim", "toLowerCase", "toUpperCase", "resolve", "normalize", "parse"] and
    transform = name
  )
}

/** Value-preserving transform edge admitted by the field-sensitive layer. */
predicate fieldFlowTransformStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(DataFlow::CallNode call, string name |
    name = call.getCalleeName() and
    name = ["trim", "toLowerCase", "toUpperCase", "resolve", "normalize", "parse"] and
    (
      pred = call.getReceiver()
      or pred = call.getArgument(0)
    ) and
    succ = call
  )
}
