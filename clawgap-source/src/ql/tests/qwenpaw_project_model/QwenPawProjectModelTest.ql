import python
import call.call
import call.sinks_af
import project.ProjectModel

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
  exists(FunctionObject handler |
    projectToolHandler(handler) and
    kind = "registration" and name = projectToolName(handler) and
    detail = projectRegistrationMetadata(handler, "handler-model")
  )
  or
  exists(FunctionObject handler |
    projectToolHandler(handler) and
    kind = "profile" and name = handler.getQualifiedName() and
    detail = projectRegistrationMetadata(handler, "backend-profile")
  )
  or
  exists(FunctionObject caller, FunctionObject callee, CallNode call |
    qwenToThreadCallbackEdge(caller, callee, call) and
    kind = "edge" and name = "to-thread" and
    detail = caller.getQualifiedName() + "->" + callee.getQualifiedName()
  )
  or
  exists(FunctionObject handler, CallNode gate, ControlFlowNode checked |
    projectPreHandlerGate(handler, gate, checked, detail) and
    kind = "pre-handler-gate" and name = projectToolName(handler)
  )
  or
  exists(FunctionObject transform, string signature, string role |
    projectKnownTransformFunction(transform, signature, role) and
    kind = "transform-signature" and name = transform.getName() and
    detail = signature + ":" + role
  )
  or
  not exists(FunctionObject transform, string signature, string role |
    projectKnownTransformFunction(transform, signature, role) and
    transform.getName() = ["_collapse_embedded_newline", "_collapse_embedded_newlines"] and
    transform.getFunction().getLocation().getFile().getRelativePath() =
      "src/qwenpaw/agents/tools/wrong_shell.py"
  ) and kind = "negative" and name = "transform-near-misses" and detail = "absent"
select kind, name, detail
