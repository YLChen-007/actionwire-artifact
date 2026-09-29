/**
 * @id clawgap/verify-delivery-bridge
 * @name 验证 delivery_bridge：send_message_tool → 网关/插件平台发送 sink
 * @description 证明 hardcode 的 delivery_bridge 把 Discord-Mention 的跨组件边接上了：
 *              以 d5 handler send_message_tool 为根，看其是否经新桥到达 gateway/plugins 投递 sink。
 * @kind table
 * @tags clawgap
 */

import python
import call.call
import call.sinks_af
import util.util

string sinkLabel(CallNode cn) {
  exists(AttrNode a | a = cn.getFunction() |
    result = a.getObject().getNode().toString() + "." + a.getNode().getName()
  )
  or
  not cn.getFunction() instanceof AttrNode and
  result = cn.getFunction().getNode().toString()
}

from FunctionObject handler, int d, CallNode sink
where
  handler.getName() = "send_message_tool" and
  d = [1 .. 8] and
  r_calls(handler, sink, d) and
  is_sink_af(sink) and
  sink.getLocation().getFile().getRelativePath().regexpMatch("(gateway/platforms|plugins/platforms).*")
select handler.getName() as root, d as depth, sinkLabel(sink) as sink_label,
  sink.getLocation().getFile().getRelativePath() as sink_file,
  sink.getLocation().getStartLine() as sink_line, print_callchain(handler, sink, d) as call_chain
