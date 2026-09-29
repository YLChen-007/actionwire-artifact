import python
import call.call
import call.sinks_af
import project.ProjectModel
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

string edgeKind(FunctionObject caller, FunctionObject callee, CallNode call) {
  astrComponentEdge(caller, callee, call) and result = "component"
  or astrToThreadCallbackEdge(caller, callee, call) and result = "to-thread"
}

string sourceParameters(FunctionObject handler) {
  result = strictconcat(Parameter p |
    projectHandlerSourceParameter(handler, p)
  | p.(Name).getId(), ";" order by p.getLocation().getStartColumn())
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
    kind = "source" and name = projectToolName(handler) and
    detail = sourceParameters(handler)
  )
  or
  exists(FunctionObject caller, FunctionObject callee, CallNode call |
    kind = "edge" and name = edgeKind(caller, callee, call) and
    detail = caller.getQualifiedName() + "->" + callee.getQualifiedName()
  )
  or
  exists(FunctionObject caller, FunctionObject callee |
    calls(caller, callee) and
    caller.getName() = ["write_file", "edit_file", "exec", "_probe_local_file"] and
    callee.getName() = "_run" and
    kind = "call-edge" and name = caller.getQualifiedName() and
    detail = callee.getQualifiedName()
  )
  or
  exists(FunctionObject helper, CallNode gate |
    projectNestedGateHelper(helper, gate, detail) and
    kind = "nested-gate" and name = helper.getName()
  )
  or
  exists(FunctionObject transform, string role |
    projectKnownTransformFunction(transform, detail, role) and
    kind = "transform" and name = transform.getName()
  )
select kind, name, detail
