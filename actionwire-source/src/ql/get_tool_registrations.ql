/**
 * @id clawgap/hermes-tool-registrations
 * @name hermes tool registration metadata
 * @description Enumerates static registry.register(...) declarations and plugin
 *              ctx.register_tool(...) declarations, preserving unresolved
 *              expressions for factory/dynamic registrations.
 * @kind table
 * @tags clawgap
 */

import python
import util.util

predicate isRegistryRegistration(CallNode c) {
  c.getFunction().(AttrNode).getNode().getName() = "register" and
  c.getFunction().(AttrNode).getNode().getObject().toString() = "registry"
}

predicate isPluginRegistration(CallNode c) {
  c.getFunction().(AttrNode).getNode().getName() = "register_tool"
}

string registrationKind(CallNode c) {
  isRegistryRegistration(c) and result = "registry"
  or
  isPluginRegistration(c) and result = "plugin-context"
}

string toolNameExpr(CallNode c) {
  result = c.getArgByName("name").getNode().(StringLiteral).getText()
  or
  not exists(c.getArgByName("name").getNode().(StringLiteral)) and
  exists(c.getArgByName("name")) and result = c.getArgByName("name").getNode().toString()
  or
  not exists(c.getArgByName("name")) and result = "-"
}

string toolsetExpr(CallNode c) {
  result = c.getArgByName("toolset").getNode().(StringLiteral).getText()
  or
  not exists(c.getArgByName("toolset").getNode().(StringLiteral)) and
  exists(c.getArgByName("toolset")) and result = c.getArgByName("toolset").getNode().toString()
  or
  not exists(c.getArgByName("toolset")) and result = "-"
}

string handlerExpr(CallNode c) {
  result = c.getArgByName("handler").getNode().toString()
  or
  not exists(c.getArgByName("handler")) and result = "-"
}

string checkFnExpr(CallNode c) {
  result = c.getArgByName("check_fn").getNode().toString()
  or
  not exists(c.getArgByName("check_fn")) and result = "-"
}

string requiresEnvExpr(CallNode c) {
  result = c.getArgByName("requires_env").getNode().toString()
  or
  not exists(c.getArgByName("requires_env")) and result = "-"
}

string isAsyncExpr(CallNode c) {
  result = c.getArgByName("is_async").getNode().toString()
  or
  not exists(c.getArgByName("is_async")) and result = "-"
}

from CallNode reg
where
  isIncludeLocation2(reg.getLocation()) and
  (isRegistryRegistration(reg) or isPluginRegistration(reg))
select registrationKind(reg) as registration_kind,
  toolNameExpr(reg) as tool_name,
  toolsetExpr(reg) as canonical_toolset,
  handlerExpr(reg) as handler_expr,
  checkFnExpr(reg) as check_fn_expr,
  requiresEnvExpr(reg) as requires_env_expr,
  isAsyncExpr(reg) as is_async_expr,
  reg.getLocation().getFile().getRelativePath() as file,
  reg.getLocation().getStartLine() as line
