/** Field-sensitive model-input flow primitives for Python. */

import python
import semmle.python.dataflow.new.DataFlow

/**
 * A constant property read rooted in `root`.
 *
 * The returned `read` node is the value of the selected field, never the
 * containing object or the selector/key expression.  Starting taint at this
 * node is what prevents one model-controlled property from tainting siblings.
 */
predicate fieldRead(
  DataFlow::Node root, string field, DataFlow::Node read, string accessKind
) {
  exists(CallNode call, AttrNode getter, StringLiteral key, Expr base |
    call.getFunction() = getter and getter.getName() = "get" and
    key = call.getArg(0).getNode() and field = key.getText() and
    base = getter.getObject().getNode() and
    DataFlow::localFlow(root, DataFlow::exprNode(base)) and
    read.asCfgNode() = call and accessKind = "mapping-get"
  )
  or
  exists(Subscript subscript, StringLiteral key |
    key = subscript.getIndex() and field = key.getText() and
    DataFlow::localFlow(root, DataFlow::exprNode(subscript.getObject())) and
    read = DataFlow::exprNode(subscript) and accessKind = "mapping-subscript"
  )
}

/** Reserved explicit RPC bridge used by fixtures and generated adapters. */
predicate explicitFieldBridgeStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(CallNode send, FunctionObject receive, Parameter parameter |
    send.getFunction().(NameNode).getId() = "field_flow_rpc_send" and
    send.getLocation().getFile().getRelativePath() = "test.py" and
    pred.asCfgNode() = send.getArg(0) and
    receive.getName() = "field_flow_rpc_receive" and
    receive.getFunction().getLocation().getFile().getRelativePath() = "test.py" and
    parameter = receive.getFunction().getArg(0) and
    succ.(DataFlow::ParameterNode).getParameter() = parameter
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
  exists(CallNode call, string name |
    node.asCfgNode() = call and
    (
      name = call.getFunction().(AttrNode).getName()
      or name = call.getFunction().(NameNode).getId()
    ) and
    name = ["strip", "lower", "upper", "resolve", "expanduser", "urlparse"] and
    transform = name
  )
}

/** Value-preserving transform edge admitted by the field-sensitive layer. */
predicate fieldFlowTransformStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(CallNode call, string name |
    (
      name = call.getFunction().(AttrNode).getName() and
      pred.asCfgNode() = call.getFunction().(AttrNode).getObject()
      or
      name = call.getFunction().(NameNode).getId() and pred.asCfgNode() = call.getArg(0)
    ) and
    name = ["strip", "lower", "upper", "resolve", "expanduser", "urlparse"] and
    succ.asCfgNode() = call
  )
}
