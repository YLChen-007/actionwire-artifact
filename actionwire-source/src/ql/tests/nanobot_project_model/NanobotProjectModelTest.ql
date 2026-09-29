import python
import call.call
import call.sinks_af
import project.ProjectModel
import semmle.python.dataflow.new.DataFlow

string sourceParameters(FunctionObject handler) {
  result = strictconcat(Parameter p |
    projectHandlerSourceParameter(handler, p)
  | p.(Name).getId(), ";" order by p.getLocation().getStartColumn())
}

string fixtureSink(CallNode sink) {
  sink.getFunction().(AttrNode).getName() = "create_subprocess_shell" and
  result = "process"
  or
  sink.getFunction().(NameNode).getId() = "open" and result = "file"
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
  exists(FunctionObject handler, CallNode sink |
    projectToolHandler(handler) and sink.getScope() = handler.getFunction() and
    is_sink_af(sink) and kind = "sink" and
    name = projectToolName(handler) and detail = fixtureSink(sink)
  )
  or
  exists(CallNode sink, DataFlow::Node node, string role |
    sink.getLocation().getFile().getRelativePath() = "nanobot/agent/tools/web.py" and
    sinkSensitiveNode(sink, node, role) and kind = "sensitive" and
    name = sink.getScope().(Function).getName() and
    detail = role + ":" + node.asCfgNode().getNode().toString()
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
    transform.getName() = ["_resolve_paths", "_resolve_path"] and
    transform.getFunction().getLocation().getFile().getRelativePath() =
      "nanobot/agent/tools/wrong_filesystem.py"
  ) and kind = "negative" and name = "transform-near-misses" and detail = "absent"
select kind, name, detail
