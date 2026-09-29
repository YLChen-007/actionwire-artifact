/**
 * Synthetic-only witness for a later Nanobot login-shell source shape that is
 * not present in the pinned v0.1.4.post5 empirical benchmark.
 */

import python
import call.call
import call.sinks_af
import project.ProjectModel

predicate sourceFileString(string value) {
  exists(StringLiteral literal |
    literal.getLocation().getFile().getRelativePath() =
      "nanobot/agent/tools/shell.py" and
    literal.getText() = value
  )
}

from FunctionObject handler, CallNode sink
where
  projectToolHandler(handler) and
  projectToolName(handler) = "exec" and
  sink.getScope() = handler.getFunction() and
  is_sink_af(sink) and
  sink.getFunction().(AttrNode).getNode().getName() = "create_subprocess_exec" and
  sink.getFunction().(AttrNode).getObject().getNode().toString() = "asyncio" and
  sourceFileString("HOME") and
  sourceFileString("-l") and
  sourceFileString("-c") and
  not sourceFileString("--noprofile") and
  not sourceFileString("--norc")
select
  "Advisory-GHSA-jccr-rrw2-vc8h-login-shell-env-disclosure", "exec",
  "create_subprocess_exec", "command;login;HOME"
