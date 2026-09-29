/**
 * @id clawgap/hermes-prompt-entry-anchors
 * @name hermes prompt-entry and AIAgent construction anchors
 * @description Conservatively enumerates every in-scope AIAgent.run_conversation(...)
 *              call and every AIAgent(...) construction.  Classification and
 *              cross-function ownership (for persistent CLI/TUI/gateway agents)
 *              are completed by the deterministic prompt-entry resolver.
 * @kind table
 * @tags clawgap
 */

import python
import util.util

predicate isRunConversationCall(CallNode c) {
  c.getFunction().(AttrNode).getNode().getName() = "run_conversation"
}

predicate isChatWrapperCall(CallNode c) {
  c.getFunction().(AttrNode).getNode().getName() = "chat" and
  c.getLocation().getFile().getRelativePath() = "hermes_cli/oneshot.py"
}

predicate isDirectRunConversationReference(CallNode c) {
  c.getFunction().(AttrNode).getNode().getName() = "submit" and
  c.getArg(0).(AttrNode).getNode().getName() = "run_conversation"
}

/**
 * Match context-preserving executor wrappers such as:
 *
 *   pool.submit(context.run, agent.run_conversation, prompt)
 *
 * The callable passed to submit is shifted by one position because
 * context.run is itself the executor callback.
 */
predicate isContextRunConversationReference(CallNode c) {
  c.getFunction().(AttrNode).getNode().getName() = "submit" and
  c.getArg(0).(AttrNode).getNode().getName() = "run" and
  c.getArg(1).(AttrNode).getNode().getName() = "run_conversation"
}

predicate isRunConversationReference(CallNode c) {
  isDirectRunConversationReference(c) or
  isContextRunConversationReference(c)
}

predicate isAIAgentConstructor(CallNode c) {
  c.getFunction().(NameNode).getId() = "AIAgent"
}

string scopeName(CallNode c) {
  result = c.getScope().(Function).getName()
  or
  not exists(c.getScope().(Function)) and result = "<module>"
}

string receiverExpr(CallNode c) {
  result = c.getFunction().(AttrNode).getNode().getObject().toString()
  or
  not exists(c.getFunction().(AttrNode)) and result = "-"
}

string platformExpr(CallNode c) {
  result = c.getArgByName("platform").getNode().toString()
  or
  not exists(c.getArgByName("platform")) and result = "-"
}

string enabledToolsetsExpr(CallNode c) {
  result = c.getArgByName("enabled_toolsets").getNode().toString()
  or
  not exists(c.getArgByName("enabled_toolsets")) and result = "-"
}

string disabledToolsetsExpr(CallNode c) {
  result = c.getArgByName("disabled_toolsets").getNode().toString()
  or
  not exists(c.getArgByName("disabled_toolsets")) and result = "-"
}

string promptExpr(CallNode c) {
  result = c.getArgByName("user_message").getNode().toString()
  or
  not exists(c.getArgByName("user_message")) and
  exists(c.getArg(0)) and result = c.getArg(0).getNode().toString()
  or
  not exists(c.getArgByName("user_message")) and
  not exists(c.getArg(0)) and result = "-"
}

string referencedPromptExpr(CallNode c) {
  isDirectRunConversationReference(c) and
  result = c.getArg(1).getNode().toString()
  or
  isContextRunConversationReference(c) and
  result = c.getArg(2).getNode().toString()
  or
  not exists(c.getArg(1)) and result = "-"
}

bindingset[path]
string coarseClass(string path) {
  path = "cli.py" and result = "external-or-inherited"
  or path = "hermes_cli/oneshot.py" and result = "external"
  or path = "tui_gateway/server.py" and result = "external-or-internal"
  or path = "cron/scheduler.py" and result = "external"
  or path = "gateway/run.py" and result = "external-or-inherited"
  or path = "gateway/platforms/api_server.py" and result = "external"
  or path = "gateway/platforms/feishu_comment.py" and result = "external"
  or path.matches("acp_adapter/%") and result = "external"
  or path = "rl_cli.py" and result = "caller-defined"
  or path = "batch_runner.py" and result = "caller-defined"
  or path = "run_agent.py" and result = "internal-or-caller-defined"
  or path.matches("tools/%") and result = "internal"
  or path.matches("agent/%") and result = "internal"
  or not path = [
    "cli.py", "hermes_cli/oneshot.py", "tui_gateway/server.py",
    "cron/scheduler.py", "gateway/run.py", "gateway/platforms/api_server.py",
    "gateway/platforms/feishu_comment.py", "rl_cli.py", "batch_runner.py",
    "run_agent.py"
  ] and
  not path.matches("acp_adapter/%") and
  not path.matches("tools/%") and
  not path.matches("agent/%") and result = "unresolved"
}

string promptColumn(CallNode c, string kind) {
  kind = ["run_conversation", "chat_wrapper"] and result = promptExpr(c)
  or
  kind = "run_conversation_reference" and result = referencedPromptExpr(c)
  or
  kind = "agent_constructor" and result = "-"
}

string platformColumn(CallNode c, string kind) {
  kind = "agent_constructor" and result = platformExpr(c)
  or
  kind = ["run_conversation", "chat_wrapper", "run_conversation_reference"] and result = "-"
}

string enabledColumn(CallNode c, string kind) {
  kind = "agent_constructor" and result = enabledToolsetsExpr(c)
  or
  kind = ["run_conversation", "chat_wrapper", "run_conversation_reference"] and result = "-"
}

string disabledColumn(CallNode c, string kind) {
  kind = "agent_constructor" and result = disabledToolsetsExpr(c)
  or
  kind = ["run_conversation", "chat_wrapper", "run_conversation_reference"] and result = "-"
}

from CallNode c, string kind, string path
where
  isIncludeLocation2(c.getLocation()) and
  path = c.getLocation().getFile().getRelativePath() and
  (
    isRunConversationCall(c) and kind = "run_conversation"
    or
    isChatWrapperCall(c) and kind = "chat_wrapper"
    or
    isRunConversationReference(c) and kind = "run_conversation_reference"
    or
    isAIAgentConstructor(c) and kind = "agent_constructor"
  )
select kind as anchor_kind, path as file,
  c.getLocation().getStartLine() as line, scopeName(c) as scope,
  receiverExpr(c) as receiver,
  promptColumn(c, kind) as prompt_expr,
  platformColumn(c, kind) as platform_expr,
  enabledColumn(c, kind) as enabled_toolsets_expr,
  disabledColumn(c, kind) as disabled_toolsets_expr,
  coarseClass(path) as coarse_class
