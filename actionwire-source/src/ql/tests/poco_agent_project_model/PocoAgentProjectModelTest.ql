import python
import call.call
import call.sinks_af
import call.filter_gates
import project.ProjectModel
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

string sourceParameters(FunctionObject handler) {
  result = strictconcat(Parameter p |
    projectHandlerSourceParameter(handler, p)
  | p.(Name).getId(), ";" order by p.getLocation().getStartColumn())
}

string fixtureSink(CallNode sink) {
  sink.getFunction().(AttrNode).getName() = "post" and result = "post"
  or
  sink.getFunction().(AttrNode).getName() = "request" and result = "request"
}

predicate fixtureHandlerSource(FunctionObject handler, DataFlow::Node source) {
  projectToolHandler(handler) and
  source.(DataFlow::ParameterNode).getScope() = handler.getFunction() and
  projectHandlerSourceParameter(
    handler, source.(DataFlow::ParameterNode).getParameter()
  )
}

predicate fixtureJsonSink(CallNode sink, DataFlow::Node sinkNode, string role) {
  projectAdditionalSink(sink) and
  sinkSensitiveNode(sink, sinkNode, role) and
  role = "rpc-payload"
}

module PocoFixtureFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    fixtureHandlerSource(_, source)
  }

  predicate isSink(DataFlow::Node sinkNode) { fixtureJsonSink(_, sinkNode, _) }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    projectBridgeTaintStep(pred, succ)
  }
}

module PocoFixtureFlow = TaintTracking::Global<PocoFixtureFlowConfig>;

from string kind, string name, string detail
where
  kind = "adapter" and name = activeProjectId() and detail = activeProjectAdapter()
  or
  exists(FunctionObject handler |
    projectToolHandler(handler) and kind = "handler" and
    name = projectToolName(handler) and detail = handler.getQualifiedName()
  )
  or
  exists(FunctionObject handler |
    projectToolHandler(handler) and kind = "source" and
    name = projectToolName(handler) and detail = sourceParameters(handler)
  )
  or
  exists(FunctionObject caller, FunctionObject callee, CallNode call |
    pocoInjectedClientEdge(caller, callee, call) and kind = "edge" and
    name = projectToolName(caller) and
    detail = caller.getQualifiedName() + "->" + callee.getQualifiedName()
  )
  or
  exists(CallNode sink |
    projectAdditionalSink(sink) and kind = "sink" and
    name = fixtureSink(sink) and
    detail = sink.getLocation().getFile().getRelativePath()
  )
  or
  exists(FunctionObject handler, DataFlow::Node source, CallNode sink,
    DataFlow::Node sinkNode |
    fixtureHandlerSource(handler, source) and fixtureJsonSink(sink, sinkNode, _) and
    PocoFixtureFlow::flow(source, sinkNode) and kind = "flow" and
    name = projectToolName(handler) and detail = fixtureSink(sink) + ":json"
  )
  or
  exists(CallNode sink, DataFlow::Node sinkNode, string role |
    fixtureJsonSink(sink, sinkNode, role) and kind = "role" and
    name = fixtureSink(sink) and detail = role
  )
  or
  exists(ConditionBlock cb, CallNode gate, DataFlow::Node checked,
    DataFlow::Node collAfter, CallNode sink, DataFlow::Node sinkNode |
    filterGateCoreResult(cb, gate, checked, collAfter, sink, sinkNode) and
    kind = "filter" and name = checked.asExpr().toString() and
    detail = gate.getLocation().getStartLine().toString() + ":admission"
  )
select kind, name, detail
