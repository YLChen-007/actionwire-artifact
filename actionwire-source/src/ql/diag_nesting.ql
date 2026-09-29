/**
 * @id clawgap/diag-nesting
 * @name diag: parent-gate -> child-gate min call level (nested-in-gate)
 * @description 计算已 identified 父 gate 到子 gate 的 in-scope 最短调用跳数（nested-in-gate 的 L{k}）。
 *              reachAt 的基例锚定在父 gate 集合上，避免物化全图闭包。
 * @kind table
 * @tags clawgap
 */

import python
import call.call
import util.util

predicate parentFn(FunctionObject p, string name) {
  name = ["check_website_access", "_is_blocked_device", "is_safe_url", "check_all_command_guards"] and
  p.getName() = name
}

predicate childName(string name) {
  name =
    [
      "_match_host_against_rule", "_is_blocked_device_path", "_is_blocked_ip",
      "detect_dangerous_command", "detect_hardline_command", "_check_sudo_stdin_guard",
      "check_command_security", "_command_matches_permanent_allowlist"
    ]
}

// 从父 gate 出发的有界最短跳数（基例锚在 parentFn，故不铺满全图）
predicate reachAt(FunctionObject root, FunctionObject b, int d) {
  parentFn(root, _) and d = 1 and inscope_calls(root, b)
  or
  d in [2 .. 6] and
  exists(FunctionObject mid | reachAt(root, mid, d - 1) and inscope_calls(mid, b))
}

from string parent, string child, int level
where
  exists(FunctionObject p, FunctionObject c |
    parentFn(p, parent) and c.getName() = child and childName(child) and
    level = min(int d | reachAt(p, c, d))
  )
select parent, child, level as min_call_level
