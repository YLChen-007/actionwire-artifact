/** Shared revision-pinned DroidClaw semantic handler/source/sink identities. */

import javascript
import project.ProjectModel
import call.call
import call.sinks_af

predicate droidClawHandlerSink(string toolName, DataFlow::CallNode sink) {
  toolName = "tap" and sinkCanonicalId(sink) = "DC-ACTION-TAP"
  or
  toolName = "type" and sinkCanonicalId(sink) = "DC-ACTION-TYPE"
  or
  toolName = "swipe" and sinkCanonicalId(sink) = "DC-ACTION-SWIPE"
  or
  toolName = "launch" and sinkCanonicalId(sink) = "DC-ACTION-LAUNCH"
  or
  toolName = "paste" and sinkCanonicalId(sink) = "DC-ACTION-PASTE"
  or
  toolName = "screenshot" and sinkCanonicalId(sink) = "DC-ACTION-SCREENSHOT"
  or
  toolName = "longpress" and sinkCanonicalId(sink) = "DC-ACTION-LONGPRESS"
  or
  toolName = "clipboard_set" and sinkCanonicalId(sink) = "DC-ACTION-CLIPBOARD-SET"
  or
  toolName = "open_url" and sinkCanonicalId(sink) = "DC-ACTION-OPEN-URL"
  or
  toolName = "switch_app" and sinkCanonicalId(sink) = "DC-ACTION-SWITCH-APP"
  or
  toolName = "keyevent" and sinkCanonicalId(sink) = "DC-ACTION-KEYEVENT"
  or
  toolName = "open_settings" and sinkCanonicalId(sink) = "DC-ACTION-OPEN-SETTINGS"
  or
  toolName = "scroll" and sinkCanonicalId(sink) = "DC-ACTION-SCROLL"
  or
  toolName = "pull_file" and sinkCanonicalId(sink) = "DC-ACTION-PULL-FILE"
  or
  toolName = "push_file" and sinkCanonicalId(sink) = "DC-ACTION-PUSH-FILE"
  or
  toolName = "shell" and sinkCanonicalId(sink) = "DC-ACTION-SHELL"
  or
  toolName = "copy_visible_text" and sinkCanonicalId(sink) = "DC-SKILL-COPY-VISIBLE-TEXT"
  or
  toolName = "find_and_tap" and sinkCanonicalId(sink) = "DC-SKILL-FIND-AND-TAP"
  or
  toolName = "compose_email" and sinkCanonicalId(sink) = "DC-ACTION-COMPOSE-EMAIL"
}

predicate droidClawSemanticChain(
  Function handler, DataFlow::Node source, DataFlow::CallNode sink,
  DataFlow::Node sinkArg, string toolName, string sourceName,
  int chainDepth, string path
) {
  isDroidClawProject() and droidClawToolHandler(handler, toolName, _) and
  handlerSource(handler, source, sourceName) and droidClawHandlerSink(toolName, sink) and
  controlledSinkArgument(sink, sinkArg, _) and
  reachesSink(handler, sink, chainDepth, path)
}
