/**
 * Project adapter contract for Python benchmark databases.
 *
 * An adapter supplies identity, concrete tool roots and names, source parameters,
 * registration metadata, location exclusions, dynamic call edges, and optional
 * sink extensions. A database must select exactly one identity in
 * get_project_model.ql before any pipeline stage runs.
 */

import python

predicate isHermesProject() {
  exists(FunctionObject f |
    f.getName() = "terminal_tool" and
    f.getFunction().getLocation().getFile().getRelativePath() = "tools/terminal_tool.py"
  )
}

predicate isCowAgentProject() {
  exists(Class base, Function method |
    base.getName() = "BaseTool" and
    base.getAMethod() = method and
    method.getName() = "execute_tool"
  )
}

predicate isAstrBotProject() {
  exists(Class base, Function baseCall, Class fileRead, Function concreteCall |
    base.getName() = "FunctionTool" and
    base.getAMethod() = baseCall and baseCall.getName() = "call" and
    fileRead.getName() = "FileReadTool" and
    fileRead.getAMethod() = concreteCall and concreteCall.getName() = "call" and
    (
      fileRead.getClassObject().isSubclassOf(base.getClassObject())
      or fileRead.getABase().toString().matches("FunctionTool%")
    )
  )
}

predicate isQwenPawProject() {
  exists(FunctionObject shell, FunctionObject browser |
    shell.getName() = "execute_shell_command" and
    shell.getFunction().getLocation().getFile().getRelativePath() =
      "src/qwenpaw/agents/tools/shell.py" and
    browser.getName() = "browser_use" and
    browser.getFunction().getLocation().getFile().getRelativePath() =
      "src/qwenpaw/agents/tools/browser_control.py"
  )
}

predicate isNanobotProject() {
  exists(Class base, Function baseExecute, Class concrete, Function concreteExecute |
    base.getName() = "Tool" and
    base.getLocation().getFile().getRelativePath() = "nanobot/agent/tools/base.py" and
    base.getAMethod() = baseExecute and baseExecute.getName() = "execute" and
    concrete.getName() = "ExecTool" and
    concrete.getLocation().getFile().getRelativePath() = "nanobot/agent/tools/shell.py" and
    concrete.getAMethod() = concreteExecute and concreteExecute.getName() = "execute"
  )
}

predicate isPocoAgentProject() {
  exists(FunctionObject channelFactory, FunctionObject memoryFactory |
    channelFactory.getName() = "create_channel_runtime_mcp_server" and
    channelFactory.getFunction().getLocation().getFile().getRelativePath() =
      "executor/app/core/channel_runtime.py" and
    memoryFactory.getName() = "create_memory_mcp_server" and
    memoryFactory.getFunction().getLocation().getFile().getRelativePath() =
      "executor/app/core/memory.py"
  )
}

string activeProjectId() {
  isHermesProject() and result = "hermes-agent"
  or
  isCowAgentProject() and result = "chatgpt-on-wechat"
  or
  isAstrBotProject() and result = "AstrBot"
  or
  isQwenPawProject() and result = "QwenPaw"
  or
  isNanobotProject() and result = "nanobot"
  or
  isPocoAgentProject() and result = "poco-agent"
}

string activeProjectAdapter() {
  isHermesProject() and result = "hermes"
  or
  isCowAgentProject() and result = "cowagent"
  or
  isAstrBotProject() and result = "astrbot"
  or
  isQwenPawProject() and result = "qwenpaw"
  or
  isNanobotProject() and result = "nanobot"
  or
  isPocoAgentProject() and result = "poco-agent"
}

predicate cowToolHandler(FunctionObject f, Class c) {
  isCowAgentProject() and
  c.getAMethod() = f.getFunction() and
  f.getName() = "execute" and
  exists(Class base |
    base.getName() = "BaseTool" and
    c != base and
    (
      c.getClassObject().isSubclassOf(base.getClassObject())
      or
      c.getABase().toString() = "BaseTool"
    )
  )
}

predicate astrToolHandler(FunctionObject f, Class c) {
  isAstrBotProject() and
  c.getAMethod() = f.getFunction() and
  f.getName() = "call" and
  exists(Class base |
    base.getName() = "FunctionTool" and
    c != base and
    (
      c.getClassObject().isSubclassOf(base.getClassObject())
      or c.getABase().toString().matches("FunctionTool%")
      or c.getABase().toString() = "NeoSkillToolBase"
    )
  )
}

/** Hardcoded QwenPaw built-ins referenced by `_create_toolkit.tool_functions`. */
predicate qwenBuiltinToolHandler(FunctionObject f) {
  isQwenPawProject() and
  f.getFunction().getLocation().getFile().getRelativePath().matches(
    "src/qwenpaw/agents/tools/%"
  ) and
  exists(Assign assignment, Name target, Dict table, Name handlerRef |
    assignment.getScope().(Function).getName() = "_create_toolkit" and
    assignment.getATarget() = target and target.getId() = "tool_functions" and
    assignment.getValue() = table and
    table.getAValue().getAChildNode*() = handlerRef and
    handlerRef.getId() = f.getName()
  )
}

/**
 * QwenPaw registers memory-manager tools after `_create_toolkit`: each supported
 * backend returns `self.memory_search` from `list_memory_tools()`, then the agent
 * passes every returned callable to `toolkit.register_tool_function`.
 */
predicate qwenMemoryToolHandler(FunctionObject f, Class backend) {
  isQwenPawProject() and
  backend.getAMethod() = f.getFunction() and f.getName() = "memory_search" and
  (
    backend.getName() = "ReMeLightMemoryManager" and
    backend.getLocation().getFile().getRelativePath() =
      "src/qwenpaw/agents/memory/reme_light_memory_manager.py"
    or
    backend.getName() = "ADBPGMemoryManager" and
    backend.getLocation().getFile().getRelativePath() =
      "src/qwenpaw/agents/memory/adbpg_memory_manager.py"
  ) and
  exists(Function listTools, Return returned, List tools, Attribute member |
    backend.getAMethod() = listTools and listTools.getName() = "list_memory_tools" and
    returned.getScope() = listTools and returned.getValue() = tools and
    tools.getAnElt() = member and member.getName() = f.getName() and
    member.getObject().(Name).getId() = "self"
  ) and
  exists(CallNode listCall, CallNode registerCall, AttrNode listReceiver,
    AttrNode toolkitReceiver |
    listCall.getLocation().getFile().getRelativePath() =
      "src/qwenpaw/agents/react_agent.py" and
    listCall.getFunction().(AttrNode).getName() = "list_memory_tools" and
    listReceiver = listCall.getFunction().(AttrNode).getObject() and
    listReceiver.getName() = "memory_manager" and
    listReceiver.getObject().(NameNode).getId() = "self" and
    registerCall.getLocation().getFile() = listCall.getLocation().getFile() and
    registerCall.getScope() = listCall.getScope() and
    registerCall.getFunction().(AttrNode).getName() = "register_tool_function" and
    toolkitReceiver = registerCall.getFunction().(AttrNode).getObject() and
    toolkitReceiver.getName() = "toolkit" and
    toolkitReceiver.getObject().(NameNode).getId() = "self" and
    registerCall.getArg(0).(NameNode).getId() = "tool_fn"
  )
}

predicate qwenToolHandler(FunctionObject f) {
  qwenBuiltinToolHandler(f)
  or qwenMemoryToolHandler(f, _)
}

/**
 * A policy call that executes before QwenPaw dispatches the same `tool_input`
 * dictionary to a concrete registered handler. The explicit adapter contract keeps
 * pre-handler execution order without pretending that the handler calls its guard.
 */
predicate projectPreHandlerGate(
  FunctionObject handler, CallNode gateCall, ControlFlowNode checked, string kind
) {
  qwenToolHandler(handler) and
  gateCall.getLocation().getFile().getRelativePath() =
    "src/qwenpaw/agents/tool_guard_mixin.py" and
  gateCall.getScope().(Function).getName() = "_decide_guard_action" and
  gateCall.getFunction().(AttrNode).getName() = "guard" and
  gateCall.getArgByName("only_always_run").getNode().(UnaryExpr).getOp() instanceof Not and
  checked = gateCall.getArg(1) and
  kind = "assign-then-branch [pre-handler]"
}

predicate nanobotToolHandler(FunctionObject f, Class c) {
  isNanobotProject() and
  c.getAMethod() = f.getFunction() and f.getName() = "execute" and
  c.getLocation().getFile().getRelativePath().matches("nanobot/agent/tools/%") and
  exists(Class base |
    base.getName() = "Tool" and
    base.getLocation().getFile().getRelativePath() = "nanobot/agent/tools/base.py" and
    c != base and
    (
      c.getClassObject().isSubclassOf(base.getClassObject())
      or c.getABase().toString() = ["Tool", "_FsTool"]
    )
  )
}

predicate pocoToolDecorator(FunctionObject f, CallNode decorator) {
  isPocoAgentProject() and
  f.getFunction().getLocation().getFile().getRelativePath() =
    ["executor/app/core/channel_runtime.py", "executor/app/core/memory.py"] and
  decorator = f.getFunction().getADecorator().getAFlowNode() and
  decorator.getFunction().(NameNode).getId() = "tool" and
  decorator.getArg(0).getNode() instanceof StringLiteral
}

predicate pocoToolHandler(FunctionObject f) { pocoToolDecorator(f, _) }

predicate projectToolHandler(FunctionObject f) {
  cowToolHandler(f, _)
  or astrToolHandler(f, _)
  or qwenToolHandler(f)
  or nanobotToolHandler(f, _)
  or pocoToolHandler(f)
}

predicate projectHandlerSourceParameter(FunctionObject f, Parameter p) {
  cowToolHandler(f, _) and
  p = f.getFunction().getArg(_) and
  not p.(Name).getId() = ["self", "cls"]
  or
  astrToolHandler(f, _) and
  p = f.getFunction().getArg(_) and
  not p.(Name).getId() = ["self", "cls", "context"]
  or
  qwenToolHandler(f) and
  p = f.getFunction().getArg(_) and
  not p.(Name).getId() = ["self", "cls"]
  or
  nanobotToolHandler(f, _) and
  p = f.getFunction().getArg(_) and
  not p.(Name).getId() = ["self", "cls", "kwargs"]
  or
  pocoToolHandler(f) and
  p = f.getFunction().getArg(_) and p.(Name).getId() = "args"
}

string cowClassToolName(string className) {
  className = "Bash" and result = "bash"
  or className = "BrowserTool" and result = "browser"
  or className = "Read" and result = "read"
  or className = "Write" and result = "write"
  or className = "Edit" and result = "edit"
  or className = "Ls" and result = "ls"
  or className = "Send" and result = "send"
  or className = "EnvConfig" and result = "env_config"
  or className = "SchedulerTool" and result = "scheduler"
  or className = "WebSearch" and result = "web_search"
  or className = "WebFetch" and result = "web_fetch"
  or className = "Vision" and result = "vision"
  or className = "MemorySearchTool" and result = "memory_search"
  or className = "MemoryGetTool" and result = "memory_get"
}

string astrClassToolName(string className) {
  className = "CuaScreenshotTool" and result = "astrbot_cua_screenshot"
  or className = "CuaMouseClickTool" and result = "astrbot_cua_mouse_click"
  or className = "CuaKeyboardTypeTool" and result = "astrbot_cua_keyboard_type"
  or className = "FileReadTool" and result = "astrbot_file_read_tool"
  or className = "FileWriteTool" and result = "astrbot_file_write_tool"
  or className = "FileEditTool" and result = "astrbot_file_edit_tool"
  or className = "GrepTool" and result = "astrbot_grep_tool"
  or className = "FileUploadTool" and result = "astrbot_upload_file"
  or className = "FileDownloadTool" and result = "astrbot_download_file"
  or className = "PythonTool" and result = "astrbot_execute_ipython"
  or className = "LocalPythonTool" and result = "astrbot_execute_python"
  or className = "ExecuteShellTool" and result = "astrbot_execute_shell"
  or className = "BrowserExecTool" and result = "astrbot_execute_browser"
  or className = "BrowserBatchExecTool" and result = "astrbot_execute_browser_batch"
  or className = "RunBrowserSkillTool" and result = "astrbot_run_browser_skill"
  or className = "GetExecutionHistoryTool" and result = "astrbot_get_execution_history"
  or className = "AnnotateExecutionTool" and result = "astrbot_annotate_execution"
  or className = "CreateSkillPayloadTool" and result = "astrbot_create_skill_payload"
  or className = "GetSkillPayloadTool" and result = "astrbot_get_skill_payload"
  or className = "CreateSkillCandidateTool" and result = "astrbot_create_skill_candidate"
  or className = "ListSkillCandidatesTool" and result = "astrbot_list_skill_candidates"
  or className = "EvaluateSkillCandidateTool" and result = "astrbot_evaluate_skill_candidate"
  or className = "PromoteSkillCandidateTool" and result = "astrbot_promote_skill_candidate"
  or className = "ListSkillReleasesTool" and result = "astrbot_list_skill_releases"
  or className = "RollbackSkillReleaseTool" and result = "astrbot_rollback_skill_release"
  or className = "SyncSkillReleaseTool" and result = "astrbot_sync_skill_release"
  or className = "FutureTaskTool" and result = "future_task"
  or className = "KnowledgeBaseQueryTool" and result = "astr_kb_search"
  or className = "SendMessageToUserTool" and result = "send_message_to_user"
  or className = "TavilyWebSearchTool" and result = "web_search_tavily"
  or className = "TavilyExtractWebPageTool" and result = "tavily_extract_web_page"
  or className = "BochaWebSearchTool" and result = "web_search_bocha"
  or className = "BraveWebSearchTool" and result = "web_search_brave"
  or className = "FirecrawlWebSearchTool" and result = "web_search_firecrawl"
  or className = "FirecrawlExtractWebPageTool" and result = "firecrawl_extract_web_page"
  or className = "BaiduWebSearchTool" and result = "web_search_baidu"
  or className = "MCPTool" and result = "mcp-dynamic"
}

string nanobotClassToolName(string className) {
  className = "ReadFileTool" and result = "read_file"
  or className = "WriteFileTool" and result = "write_file"
  or className = "EditFileTool" and result = "edit_file"
  or className = "ListDirTool" and result = "list_dir"
  or className = "ExecTool" and result = "exec"
  or className = "WebSearchTool" and result = "web_search"
  or className = "WebFetchTool" and result = "web_fetch"
  or className = "MessageTool" and result = "message"
  or className = "SpawnTool" and result = "spawn"
  or className = "CronTool" and result = "cron"
  or className = "MCPToolWrapper" and result = "mcp-dynamic"
}

string projectToolName(FunctionObject f) {
  exists(Class c |
    cowToolHandler(f, c) and cowClassToolName(c.getName()) = result
  )
  or
  cowToolHandler(f, _) and
  not exists(Class c, string name |
    cowToolHandler(f, c) and cowClassToolName(c.getName()) = name
  ) and
  result = f.getName()
  or
  exists(Class c |
    astrToolHandler(f, c) and astrClassToolName(c.getName()) = result
  )
  or
  exists(Class c |
    astrToolHandler(f, c) and
    not exists(string name | astrClassToolName(c.getName()) = name) and
    result = c.getName()
  )
  or
  qwenToolHandler(f) and result = f.getName()
  or
  exists(Class c |
    nanobotToolHandler(f, c) and nanobotClassToolName(c.getName()) = result
  )
  or
  exists(Class c |
    nanobotToolHandler(f, c) and
    not exists(string name | nanobotClassToolName(c.getName()) = name) and
    result = c.getName()
  )
  or
  exists(CallNode decorator |
    pocoToolDecorator(f, decorator) and
    result = decorator.getArg(0).getNode().(StringLiteral).getText()
  )
}

string projectRegistrationMetadata(FunctionObject f, string key) {
  cowToolHandler(f, _) and key = "handler-model" and result = "BaseTool-subclass.execute"
  or
  projectToolHandler(f) and key = "tool-name" and result = projectToolName(f)
  or
  astrToolHandler(f, _) and key = "handler-model" and result = "FunctionTool-subclass.call"
  or
  qwenToolHandler(f) and key = "handler-model" and
  qwenBuiltinToolHandler(f) and
  result = "QwenPawAgent._create_toolkit.tool_functions"
  or
  qwenMemoryToolHandler(f, _) and key = "handler-model" and
  result = "QwenPawAgent.memory_manager.list_memory_tools"
  or
  exists(Class backend |
    qwenMemoryToolHandler(f, backend) and key = "backend-profile" and
    (
      backend.getName() = "ReMeLightMemoryManager" and result = "remelight-default"
      or backend.getName() = "ADBPGMemoryManager" and result = "adbpg-optional"
    )
  )
  or
  nanobotToolHandler(f, _) and key = "handler-model" and result = "Tool-subclass.execute"
  or
  pocoToolHandler(f) and key = "handler-model" and result = "claude-agent-sdk.@tool"
}

predicate nestedCallNode(FunctionObject caller, CallNode cn) {
  caller.getFunction().getBody().getAnItem().getAChildNode+().getAFlowNode() = cn and
  not exists(Function inner |
    caller.getFunction().getBody().getAnItem().getAChildNode+() = inner and
    inner.getBody().getAnItem().getAChildNode+().getAFlowNode() = cn
  )
}

/** BrowserTool.execute: handler = _ACTION_MAP.get(action); handler(self, args). */
predicate cowActionMapEdge(FunctionObject caller, FunctionObject callee, CallNode cn) {
  isCowAgentProject() and
  caller.getName() = "execute" and
  callee.getName().matches("_do_%") and
  exists(Class browser |
    browser.getName() = "BrowserTool" and
    browser.getAMethod() = caller.getFunction() and
    browser.getAMethod() = callee.getFunction()
  ) and
  exists(Assign assignment, Name target, Dict table, Name callback |
    assignment.getScope() = callee.getFunction().getScope() and
    assignment.getATarget() = target and target.getId() = "_ACTION_MAP" and
    assignment.getValue() = table and table.getAValue() = callback and
    callback.getId() = callee.getName()
  ) and
  cn.getFunction().(NameNode).getId() = "handler" and
  nestedCallNode(caller, cn)
}

/** BrowserService public method: self._submit(self._do_x, args...) -> _do_x. */
predicate cowSubmitCallbackEdge(FunctionObject caller, FunctionObject callee, CallNode cn) {
  isCowAgentProject() and
  exists(Class service |
    service.getName() = "BrowserService" and
    service.getAMethod() = caller.getFunction() and
    service.getAMethod() = callee.getFunction()
  ) and
  cn.getFunction().(AttrNode).getName() = "_submit" and
  cn.getArg(0).(AttrNode).getName() = callee.getName() and
  nestedCallNode(caller, cn)
}

/** BrowserTool action helper -> BrowserService public method on a runtime service object. */
predicate cowBrowserServiceEdge(FunctionObject caller, FunctionObject callee, CallNode cn) {
  isCowAgentProject() and
  caller.getName().matches("_do_%") and
  exists(Class browser, Class service |
    browser.getName() = "BrowserTool" and
    browser.getAMethod() = caller.getFunction() and
    service.getName() = "BrowserService" and
    service.getAMethod() = callee.getFunction()
  ) and
  cn.getFunction().(AttrNode).getName() = callee.getName() and
  nestedCallNode(caller, cn)
}

/** QwenPaw's Windows shell branch passes `_execute_subprocess_sync` to to_thread. */
predicate qwenToThreadCallbackEdge(
  FunctionObject caller, FunctionObject callee, CallNode cn
) {
  isQwenPawProject() and
  caller.getFunction().getLocation().getFile().getRelativePath() =
    "src/qwenpaw/agents/tools/shell.py" and
  callee.getFunction().getLocation().getFile() =
    caller.getFunction().getLocation().getFile() and
  cn.getFunction().(AttrNode).getName() = "to_thread" and
  cn.getArg(0).(NameNode).getId() = callee.getName() and
  nestedCallNode(caller, cn)
}

string pocoInjectedClientClass(string handle) {
  handle = "runtime_client" and result = "ChannelRuntimeClient"
  or
  handle = "memory_client" and result = "MemoryClient"
}

/** Nested SDK tools call methods on clients injected into their enclosing factory. */
predicate pocoInjectedClientEdge(
  FunctionObject caller, FunctionObject callee, CallNode cn
) {
  isPocoAgentProject() and
  pocoToolHandler(caller) and
  exists(AttrNode invoked, NameNode receiver, string handle, Class target |
    invoked = cn.getFunction() and
    receiver = invoked.getObject() and
    handle = receiver.getId() and
    pocoInjectedClientClass(handle) = target.getName() and
    target.getAMethod() = callee.getFunction() and
    invoked.getName() = callee.getName() and
    nestedCallNode(caller, cn)
  )
}

/** Preserve model-controlled payload fields when a poco tool packs them into JSON. */
predicate pocoContainerValueStep(ControlFlowNode pred, ControlFlowNode succ) {
  isPocoAgentProject() and
  (
    exists(Dict container |
      pred = container.getAValue().getAFlowNode() and
      succ = container.getAFlowNode()
    )
    or
    exists(List container |
      pred = container.getAnElt().getAFlowNode() and
      succ = container.getAFlowNode()
    )
    or
    exists(Tuple container |
      pred = container.getAnElt().getAFlowNode() and
      succ = container.getAFlowNode()
    )
  )
}

string astrComponentClass(string handle) {
  handle = "fs" and result = "LocalFileSystemComponent"
  or handle = "shell" and result = "LocalShellComponent"
  or handle = "python" and result = "LocalPythonComponent"
}

/** Runtime ComputerBooter component dispatch: sb.fs/shell/python.<method>(...). */
predicate astrComponentEdge(FunctionObject caller, FunctionObject callee, CallNode cn) {
  isAstrBotProject() and
  exists(AttrNode invoked, AttrNode component, string handle, Class target |
    invoked = cn.getFunction() and component = invoked.getObject() and
    component.getName() = handle and astrComponentClass(handle) = target.getName() and
    target.getAMethod() = callee.getFunction() and invoked.getName() = callee.getName() and
    nestedCallNode(caller, cn)
  )
}

/** Exact lexical containment for a callback declared inside its caller. */
predicate astrNestedFunction(FunctionObject caller, FunctionObject callee) {
  caller.getFunction().getBody().getAnItem().getAChildNode+() = callee.getFunction()
}

/** asyncio.to_thread(fn, ...), including the nested `_run` callbacks in local components. */
predicate astrToThreadCallbackEdge(
  FunctionObject caller, FunctionObject callee, CallNode cn
) {
  isAstrBotProject() and
  (
    cn.getFunction().(NameNode).getId() = "to_thread"
    or
    cn.getFunction().(AttrNode).getName() = "to_thread" and
    cn.getFunction().(AttrNode).getObject().getNode().toString() = "asyncio"
  ) and
  cn.getArg(0).(NameNode).getId() = callee.getName() and
  nestedCallNode(caller, cn) and
  (
    astrNestedFunction(caller, callee)
    or
    callee.getName() != "_run" and
    callee.getFunction().getEnclosingModule() = caller.getFunction().getEnclosingModule()
  )
}

/** A caller parameter referenced by an exact nested to_thread callback closure. */
predicate astrClosureCapture(
  FunctionObject caller, FunctionObject callee, Parameter parameter, NameNode captured
) {
  astrNestedFunction(caller, callee) and
  parameter = caller.getFunction().getArg(_) and
  not parameter.(Name).getId() = ["self", "cls"] and
  captured.getId() = parameter.(Name).getId() and
  callee.getFunction().getBody().getAnItem().getAChildNode+().getAFlowNode() = captured
}

/**
 * Python points-to can merge the many same-named nested `_run` functions in this project.
 * Only the lexical owner may invoke one of these callbacks; the adapter supplies that edge.
 */
predicate projectRejectFunctionInvocation(FunctionObject caller, FunctionObject callee) {
  isAstrBotProject() and
  callee.getName() = "_run" and
  exists(FunctionObject owner |
    astrNestedFunction(owner, callee) and caller != owner
  )
}

predicate projectAdditionalCallEdge(
  FunctionObject caller, FunctionObject callee, CallNode cn
) {
  cowActionMapEdge(caller, callee, cn)
  or cowSubmitCallbackEdge(caller, callee, cn)
  or cowBrowserServiceEdge(caller, callee, cn)
  or qwenToThreadCallbackEdge(caller, callee, cn)
  or pocoInjectedClientEdge(caller, callee, cn)
  or astrComponentEdge(caller, callee, cn)
  or astrToThreadCallbackEdge(caller, callee, cn)
}

/** Adapters may add sinks that are not part of the shared AgentFuzz-derived catalog. */
predicate projectAdditionalSink(CallNode cn) {
  isAstrBotProject() and
  cn.getLocation().getFile().getRelativePath() =
    "astrbot/core/computer/file_read_utils.py" and
  (
    cn.getScope().(Function).getName() = "read_local_text_range_sync" and
    cn.getFunction().(NameNode).getId() = "open"
    or
    projectThreadedCallableSink(cn, "read_bytes", _)
  )
  or
  isPocoAgentProject() and
  cn.getLocation().getFile().getRelativePath() =
    "executor/app/core/channel_runtime.py" and
  cn.getFunction().(AttrNode).getObject().getNode().toString() = "client" and
  cn.getFunction().(AttrNode).getName() = "post"
  or
  isPocoAgentProject() and
  cn.getLocation().getFile().getRelativePath() =
    "executor/app/core/memory.py" and
  cn.getFunction().(AttrNode).getObject().getNode().toString() = "client" and
  cn.getFunction().(AttrNode).getName() = "request"
  or
  exists(string project | activeProjectId() = project) and
  cn.getFunction().getNode().toString() = "__clawgap_no_project_sink__"
}

/** Adapter sink shape for `to_thread(Path(path).read_bytes)`. */
predicate projectThreadedCallableSink(
  CallNode cn, string method, ControlFlowNode receiver
) {
  isAstrBotProject() and
  cn.getFunction().(NameNode).getId() = "to_thread" and
  cn.getArg(0).(AttrNode).getName() = method and
  receiver = cn.getArg(0).(AttrNode).getObject()
}

/** Project-scoped, audited transform functions consumed by fte_transform.ql. */
predicate projectKnownTransformFunction(
  FunctionObject f, string signature, string role
) {
  isAstrBotProject() and
  f.getName() = "_resolve_tool_path" and
  signature = "astrbot/core/tools/computer_tools/fs.py::_resolve_tool_path" and
  role = "sink-transform"
  or
  isCowAgentProject() and
  f.getFunction().getLocation().getFile().getRelativePath() =
    "agent/tools/read/read.py" and
  f.getName() = "_resolve_path" and
  signature = "agent/tools/read/read.py::Read._resolve_path" and
  role = "sink-transform"
  or
  isNanobotProject() and
  f.getFunction().getLocation().getFile().getRelativePath() =
    "nanobot/agent/tools/filesystem.py" and
  f.getName() = "_resolve_path" and
  signature = "nanobot/agent/tools/filesystem.py::_resolve_path" and
  role = "sink-transform"
  or
  isQwenPawProject() and
  f.getFunction().getLocation().getFile().getRelativePath() =
    "src/qwenpaw/agents/tools/shell.py" and
  f.getName() = "_collapse_embedded_newlines" and
  signature = "src/qwenpaw/agents/tools/shell.py::_collapse_embedded_newlines" and
  role = "sink-transform"
}

/** Restrict exact project signatures to their audited invocation scope. */
predicate projectKnownTransformCallSite(
  CallNode call, FunctionObject target, string signature
) {
  projectKnownTransformFunction(target, signature, _) and
  (
    signature = "agent/tools/read/read.py::Read._resolve_path" and
    call.getLocation().getFile().getRelativePath() = "agent/tools/read/read.py"
    or
    signature != "agent/tools/read/read.py::Read._resolve_path"
  )
}

/** A source-influenced child gate inside a returning policy helper. */
predicate projectNestedGateHelper(
  FunctionObject helper, CallNode gateCall, string kind
) {
  isAstrBotProject() and
  helper.getName() = "_normalize_rw_path" and
  gateCall.getScope() = helper.getFunction() and
  gateCall.getFunction().(NameNode).getId() = "_is_path_within_allowed_roots" and
  kind = "nested-call [parent:_normalize_rw_path]"
}

bindingset[path]
predicate projectExcludedLocationString(string path) {
  isHermesProject() and path.matches("%/web/%")
  or
  isCowAgentProject() and path.matches("%.agentfuzz-main-venv%")
  or
  isAstrBotProject() and path.matches("%pysa-runs_AstrBot%")
}
