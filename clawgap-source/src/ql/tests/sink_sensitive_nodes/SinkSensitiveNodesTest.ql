import python
import call.sinks_af
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

private predicate fixtureFile(CallNode sink) {
  sink.getLocation().getFile().getRelativePath() =
    [
      "test.py", "tools/approval.py", "tools/browser_camofox.py", "tools/browser_tool.py",
      "tools/delivery.py", "tools/environments/managed_modal.py"
    ]
}

private string caseName(CallNode sink) {
  result = sink.getScope().(Function).getName()
}

private string sinkName(CallNode sink) {
  result = sink.getFunction().(AttrNode).getName()
  or
  result = sink.getFunction().(NameNode).getId()
}

private string nodeLabel(DataFlow::Node node) {
  result = node.asCfgNode().getNode().(StringLiteral).getText()
  or
  not node.asCfgNode().getNode() instanceof StringLiteral and
  result = node.asCfgNode().getNode().toString()
}

private predicate fixtureSource(Function f, DataFlow::Node source, string parameter) {
  source.(DataFlow::ParameterNode).getScope() = f and
  parameter = source.(DataFlow::ParameterNode).getParameter().(Name).getId() and
  parameter != "self"
}

module FixtureFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Function f, string parameter | fixtureSource(f, source, parameter))
  }

  predicate isSink(DataFlow::Node sinkNode) { sinkSensitiveNode(_, sinkNode) }
}

module FixtureFlow = TaintTracking::Global<FixtureFlowConfig>;

from string kind, string testCase, string sink, string role, string detail
where
  exists(CallNode call, DataFlow::Node node |
    fixtureFile(call) and
    sinkSensitiveNode(call, node, role) and
    kind = "node" and
    testCase = caseName(call) and
    sink = sinkName(call) and
    detail = nodeLabel(node)
  )
  or
  exists(CallNode call, DataFlow::Node source, DataFlow::Node node, Function f |
    fixtureFile(call) and
    f = call.getScope().(Function) and
    fixtureSource(f, source, detail) and
    sinkSensitiveNode(call, node, role) and
    FixtureFlow::flow(source, node) and
    kind = "flow" and
    testCase = caseName(call) and
    sink = sinkName(call)
  )
select kind, testCase, sink, role, detail
