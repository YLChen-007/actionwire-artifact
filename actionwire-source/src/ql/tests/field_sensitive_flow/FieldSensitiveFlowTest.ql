import python
import field_flow.FieldFlow
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

predicate modelRoot(DataFlow::Node root) {
  exists(FunctionObject handler |
    handler.getName() = "model_handler" and
    root.(DataFlow::ParameterNode).getScope() = handler.getFunction() and
    root.(DataFlow::ParameterNode).getParameter().(Name).getId() = "args"
  )
}

predicate fixtureSink(CallNode call, DataFlow::Node node, string role) {
  call.getFunction().(NameNode).getId() = "field_flow_sink_" + role and
  node.asCfgNode() = call.getArg(0)
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
    fixtureSink(_, sink, role) and DataFlow::localFlow(source, sink)
  )
}

bindingset[field, role]
predicate hasExplicitBridgeFlow(string field, string role) {
  exists(DataFlow::Node root, DataFlow::Node source, DataFlow::Node sink,
    DataFlow::Node pred, DataFlow::Node succ, string accessKind |
    modelRoot(root) and fieldRead(root, field, source, accessKind) and
    fixtureSink(_, sink, role) and explicitFieldBridgeStep(pred, succ) and
    DataFlow::localFlow(source, pred) and DataFlow::localFlow(succ, sink)
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
    not hasFlow("map_key", "map_value") and detail = "absent"
  or
  kind = "exclusion" and name = "whole-object-does-not-imply-property" and
    not anyModelFieldFlowsTo("whole_object") and
    detail = "absent"
  or
  kind = "exclusion" and name = "same-name-no-dataflow" and
    not hasFlow("path", "same_name") and detail = "absent"
  or
  kind = "exclusion" and name = "sibling-argument" and
    not hasFlow("path", "timeout") and detail = "absent"
  or
  kind = "exclusion" and name = "selector-not-selected-content" and
    not hasFlow("selector", "selector_value") and detail = "absent"
  or
  kind = "exclusion" and name = "operator-config" and
    not anyModelFieldFlowsTo("same_name") and detail = "absent"
  or
  kind = "exclusion" and name = "provider-response" and
    not anyModelFieldFlowsTo("provider") and detail = "absent"
  or
  kind = "exclusion" and name = "missing-explicit-bridge" and
    not hasFlow("no_bridge", "unbridged") and detail = "absent"
select kind, name, detail
