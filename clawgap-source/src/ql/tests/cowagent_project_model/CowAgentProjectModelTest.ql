import python
import call.call
import call.sinks_af
import project.ProjectModel
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

string fixtureSinkLabel(CallNode sink) {
  sink.getFunction().(AttrNode).getObject().getNode().toString() = "subprocess" and
  sink.getFunction().(AttrNode).getName() = "run" and result = "process"
  or
  sink.getFunction().(AttrNode).getObject().getNode().toString() = "requests" and
  sink.getFunction().(AttrNode).getName() = "get" and result = "network"
  or
  sink.getFunction().(AttrNode).getName() = "goto" and result = "browser"
  or
  sink.getFunction().(NameNode).getId() = "open" and result = "file"
}

predicate fixtureSinkArg(CallNode sink, DataFlow::Node node) {
  is_sink_af(sink) and
  exists(string label | fixtureSinkLabel(sink) = label) and
  node.asCfgNode() = sink.getAnArg()
}

predicate fixtureTransformInput(DataFlow::Node node) {
  exists(CallNode call, FunctionObject transform, string signature, string role |
    projectKnownTransformFunction(transform, signature, role) and
    projectKnownTransformCallSite(call, transform, signature) and
    call.getFunction().(AttrNode).getName() = transform.getName() and
    node.asCfgNode() = call.getAnArg()
  )
}

predicate fixtureBrowserServiceTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(FunctionObject caller, FunctionObject callee, CallNode call, int index |
    cowBrowserServiceEdge(caller, callee, call) and
    pred.asCfgNode() = call.getArg(index) and
    succ.(DataFlow::ParameterNode).getParameter() =
      callee.getFunction().getArg(index + 1)
  )
}

module FixtureFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    exists(FunctionObject handler, Parameter parameter |
      projectHandlerSourceParameter(handler, parameter) and
      node.(DataFlow::ParameterNode).getScope() = handler.getFunction() and
      node.(DataFlow::ParameterNode).getParameter() = parameter
    )
  }

  predicate isSink(DataFlow::Node node) {
    fixtureSinkArg(_, node) or fixtureTransformInput(node)
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    fixtureBrowserServiceTaintStep(pred, succ) or projectBridgeTaintStep(pred, succ)
  }
}

module FixtureFlow = TaintTracking::Global<FixtureFlowConfig>;

predicate handlerTaintsSink(FunctionObject handler, CallNode sink) {
  exists(DataFlow::Node source, DataFlow::Node sinkArg, Parameter parameter |
    projectHandlerSourceParameter(handler, parameter) and
    source.(DataFlow::ParameterNode).getScope() = handler.getFunction() and
    source.(DataFlow::ParameterNode).getParameter() = parameter and
    fixtureSinkArg(sink, sinkArg) and
    FixtureFlow::flow(source, sinkArg)
  )
}

string edgeKind(FunctionObject caller, FunctionObject callee, CallNode call) {
  cowActionMapEdge(caller, callee, call) and result = "action-map"
  or cowBrowserServiceEdge(caller, callee, call) and result = "browser-service"
  or cowSubmitCallbackEdge(caller, callee, call) and result = "submit-callback"
}

from string kind, string name, string detail
where
  kind = "adapter" and name = activeProjectId() and detail = activeProjectAdapter()
  or
  exists(FunctionObject handler |
    projectToolHandler(handler) and
    kind = "handler" and name = projectToolName(handler) and
    detail = handler.getQualifiedName()
  )
  or
  exists(FunctionObject handler |
    projectToolHandler(handler) and
    kind = "registration" and name = projectToolName(handler) and
    detail = projectRegistrationMetadata(handler, "handler-model")
  )
  or
  exists(FunctionObject caller, FunctionObject callee, CallNode call |
    kind = "edge" and name = edgeKind(caller, callee, call) and
    detail = caller.getQualifiedName() + "->" + callee.getQualifiedName()
  )
  or
  exists(FunctionObject handler, CallNode sink, int depth |
    projectToolHandler(handler) and depth = [1 .. 8] and
    r_calls(handler, sink, depth) and is_sink_af(sink) and
    kind = "chain" and name = projectToolName(handler) and
    detail = fixtureSinkLabel(sink)
  )
  or
  exists(FunctionObject handler, CallNode sink |
    projectToolHandler(handler) and handlerTaintsSink(handler, sink) and
    kind = "taint" and name = projectToolName(handler) and
    detail = fixtureSinkLabel(sink)
  )
  or
  exists(FunctionObject transform, string signature, string role |
    projectKnownTransformFunction(transform, signature, role) and
    kind = "transform-signature" and name = transform.getName() and
    detail = signature + ":" + role
  )
  or
  exists(
    FunctionObject handler, FunctionObject transform, CallNode transformCall, CallNode sink,
    DataFlow::Node source, DataFlow::Node transformInput, DataFlow::Node transformOutput,
    DataFlow::Node sinkArg, Parameter parameter, string signature, string role
  |
    projectToolHandler(handler) and projectToolName(handler) = "read" and
    projectHandlerSourceParameter(handler, parameter) and
    source.(DataFlow::ParameterNode).getScope() = handler.getFunction() and
    source.(DataFlow::ParameterNode).getParameter() = parameter and
    projectKnownTransformFunction(transform, signature, role) and
    projectKnownTransformCallSite(transformCall, transform, signature) and
    (
      calls_cn(handler, transform, transformCall)
      or
      transformCall.getScope() = handler.getFunction() and
      transformCall.getFunction().(AttrNode).getName() = transform.getName()
    ) and
    transformInput.asCfgNode() = transformCall.getAnArg() and
    transformOutput.asCfgNode() = transformCall and
    FixtureFlow::flow(source, transformInput) and
    fixtureSinkArg(sink, sinkArg) and sink.getScope() = handler.getFunction() and
    DataFlow::localFlow(transformOutput, sinkArg) and
    kind = "transform-flow" and name = projectToolName(handler) and
    detail = signature + ":" + role + "->" + fixtureSinkLabel(sink)
  )
  or
  not exists(FunctionObject transform, string signature, string role |
    projectKnownTransformFunction(transform, signature, role) and
    (
      transform.getName() = "_resolve_paths"
      or
      transform.getName() = "_resolve_path" and
      transform.getFunction().getLocation().getFile().getRelativePath() =
        "agent/tools/edit/edit.py"
    )
  ) and kind = "negative" and name = "transform-near-misses" and detail = "absent"
  or
  not exists(FunctionObject transform, CallNode call, string signature, string role |
    projectKnownTransformFunction(transform, signature, role) and
    signature = "agent/tools/read/read.py::Read._resolve_path" and
    call.getLocation().getFile().getRelativePath() = "agent/tools/edit/edit.py" and
    call.getFunction().(AttrNode).getName() = transform.getName() and
    projectKnownTransformCallSite(call, transform, signature)
  ) and kind = "negative" and name = "transform-wrong-callsite" and detail = "absent"
select kind, name, detail
