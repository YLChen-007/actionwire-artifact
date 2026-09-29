import python
import gate.GateShapes

private predicate testedFunction(string name) {
  name = [
    "direct_condition", "assigned_result", "tuple_unpacked_result", "mapping_truthiness",
    "nested_constructor", "nested_producer"
  ]
}

from string testCase, string shape, string gateName, int line
where
  exists(ConditionBlock condition, CallNode call, Function scope |
    scope = condition.getScope() and
    testedFunction(scope.getName()) and
    gateCallShape(condition, call, shape) and
    testCase = scope.getName() and
    gateName = calleeName(call) and
    line = call.getLocation().getStartLine()
  )
  or
  exists(If guard, Expr test, Function scope |
    scope = guard.getScope() and
    scope.getName() = "mapping_truthiness" and
    callFreeEarlyExitCondition(guard, test) and
    testCase = scope.getName() and
    shape = "inline-condition" and
    gateName = "<complete condition>" and
    line = test.getLocation().getStartLine()
  )
select testCase, shape, gateName, line
