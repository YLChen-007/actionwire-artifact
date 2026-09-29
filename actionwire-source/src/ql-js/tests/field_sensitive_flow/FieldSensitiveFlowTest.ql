import javascript
import field_flow.FieldFlow

predicate modelRoot(DataFlow::Node root) {
  exists(Function handler |
    handler.getName() = "modelHandler" and
    root = DataFlow::parameterNode(handler.getParameter(0))
  )
}

string fixtureRole(string callee) {
  callee = "fieldFlowSinkPath" and result = "path"
  or callee = "fieldFlowSinkUrl" and result = "url"
  or callee = "fieldFlowSinkTimeout" and result = "timeout"
  or callee = "fieldFlowSinkMapValue" and result = "map-value"
  or callee = "fieldFlowSinkSelectorValue" and result = "selector-value"
  or callee = "fieldFlowSinkWholeObject" and result = "whole-object"
  or callee = "fieldFlowSinkSameName" and result = "same-name"
  or callee = "fieldFlowSinkProvider" and result = "provider"
  or callee = "fieldFlowSinkRpc" and result = "rpc"
  or callee = "fieldFlowSinkUnbridged" and result = "unbridged"
}

predicate fixtureSink(DataFlow::CallNode call, DataFlow::Node node, string role) {
  role = fixtureRole(call.getCalleeName()) and node = call.getArgument(0)
}

module FixtureConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    exists(DataFlow::Node root, string field, string accessKind |
      modelRoot(root) and fieldRead(root, field, node, accessKind)
    )
  }

  predicate isSink(DataFlow::Node node) { fixtureSink(_, node, _) }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    fieldFlowTransformStep(pred, succ) or explicitFieldBridgeStep(pred, succ)
  }
}

module FixtureFlow = DataFlow::Global<FixtureConfig>;

bindingset[field, role]
predicate hasFlow(string field, string role) {
  exists(DataFlow::Node root, DataFlow::Node source, DataFlow::Node sink, string accessKind |
    modelRoot(root) and fieldRead(root, field, source, accessKind) and
    fixtureSink(_, sink, role) and FixtureFlow::flow(source, sink)
  )
}

bindingset[field, role]
predicate hasDirectFlow(string field, string role) {
  exists(DataFlow::Node root, DataFlow::Node source, DataFlow::Node sink, string accessKind |
    modelRoot(root) and fieldRead(root, field, source, accessKind) and
    fixtureSink(_, sink, role) and localTaint(source, sink)
  )
}

bindingset[field, role]
predicate hasExplicitBridgeFlow(string field, string role) {
  exists(DataFlow::Node root, DataFlow::Node source, DataFlow::Node sink,
    DataFlow::Node pred, DataFlow::Node succ, string accessKind |
    modelRoot(root) and fieldRead(root, field, source, accessKind) and
    fixtureSink(_, sink, role) and explicitFieldBridgeStep(pred, succ) and
    localTaint(source, pred) and localTaint(succ, sink)
  )
}

bindingset[role]
predicate anyModelFieldFlowsTo(string role) {
  exists(DataFlow::Node root, DataFlow::Node source, DataFlow::Node sink,
    string field, string accessKind |
    modelRoot(root) and fieldRead(root, field, source, accessKind) and
    fixtureSink(_, sink, role) and FixtureFlow::flow(source, sink)
  )
}

from string kind, string name, string detail
where
  kind = "witness" and name = "path" and detail = "path:direct" and
    hasDirectFlow("path", "path")
  or
  kind = "witness" and name = "timeout" and detail = "timeout:direct" and
    hasDirectFlow("timeout", "timeout")
  or
  kind = "witness" and name = "url" and detail = "url:interprocedural" and
    hasFlow("url", "url") and not hasDirectFlow("url", "url")
  or
  kind = "witness" and name = "command" and detail = "rpc:explicit-bridge" and
    hasExplicitBridgeFlow("command", "rpc")
  or
  kind = "exclusion" and name = "map-key-not-value" and
    not hasFlow("mapKey", "map-value") and detail = "absent"
  or
  kind = "exclusion" and name = "whole-object-does-not-imply-property" and
    not anyModelFieldFlowsTo("whole-object") and
    detail = "absent"
  or
  kind = "exclusion" and name = "same-name-no-dataflow" and
    not hasFlow("path", "same-name") and detail = "absent"
  or
  kind = "exclusion" and name = "sibling-argument" and
    not hasFlow("path", "timeout") and detail = "absent"
  or
  kind = "exclusion" and name = "selector-not-selected-content" and
    not hasFlow("selector", "selector-value") and detail = "absent"
  or
  kind = "exclusion" and name = "operator-config" and
    not anyModelFieldFlowsTo("same-name") and detail = "absent"
  or
  kind = "exclusion" and name = "provider-response" and
    not anyModelFieldFlowsTo("provider") and detail = "absent"
  or
  kind = "exclusion" and name = "missing-explicit-bridge" and
    not hasFlow("noBridge", "unbridged") and detail = "absent"
select kind, name, detail
