/**
 * clawgap — AgentFuzz sink 定义迁移版（步骤 2：tool 执行 sink 点）
 *
 * 直接迁移自 existworks/AgentFuzz/ql/call/call.qll 的 `is_sink`（逐字搬运，仅把谓词名改为
 * `is_sink_af` 以避免与 ql/call/call.qll 里既有的 `is_sink`（is_cmd/net/path/other_sink）冲突——
 * 既有那套按用户要求「先不用管」，保持不变）。
 *
 * 该 is_sink 已针对本仓 13 个 hermes-agent CVE/Issue JSON 的 d5_sink_points 做过逐条标注
 * （见下方 inline 注释：每个 disjunct 对应哪个 JSON 的哪个 sink；forwarder/已覆盖的 sink 也记录在案）。
 *
 * 复用 call.qll 的辅助谓词：definition_node / call_node / print_function / first_attrnode。
 * 验证用 DB：~/my-project/agent-research/clawgap/codeql-db/hermes-agent-db
 * （源根 benchmark/python/hermes-agent）。
 *
 * SPEC（管辖文档，见 docs-map.yaml）：design/hermes-agent/call-chain/call_chain_hermes-design.md
 */

import python
import util.util
import call.call
import project.ProjectModel
import semmle.python.dataflow.new.DataFlow

predicate is_sink_af(CallNode cn) {
    projectAdditionalSink(cn)
    or
    (
      cn.getFunction().(AttrNode).getNode().getName() = "submit" and
      cn.getArg(0).(AttrNode).getNode().getName() = "run" and
      cn.getArg(0).(AttrNode).getNode().getObject().toString() = "subprocess"
    ) or
    (
      cn.getFunction().(AttrNode).getNode().getName() = "execute_code"
    ) or
    (
      cn.getFunction().(AttrNode).getNode().getName() = "Popen" and
      cn.getFunction().(AttrNode).getObject().getNode().toString() = "subprocess"
    )
    or
    (
      cn.getFunction().(AttrNode).getNode().getName() in ["request","get"] and
      (
      exists(With wi, CallNode cn2, NameNode nn |
          wi.getScope() = cn.getScope() and
          nn = wi.getAChildNode().getAFlowNode() and
          cn2 = wi.getAChildNode().getAFlowNode() |
          nn.getId() = cn.getFunction().(AttrNode).getObject().getNode().toString() and
          cn2.getFunction().(AttrNode).getNode().getName() in ["AsyncClient", "ClientSession","Session"]
          // and  cn2.getFunction().(AttrNode).getObject().getNode().toString() in ["aiohttp", "httpx","requests"]
          )
        or
        exists( DefinitionNode dn |
          definition_node(cn.getFunction().(AttrNode).getNode().getScope().(Function), dn) |
          dn.getNode().toString() = cn.getFunction().(AttrNode).getObject().getNode().toString() and
          dn.getValue().(CallNode).getFunction().(AttrNode).getNode().getName() in ["AsyncClient", "ClientSession","Session"]
          // and dn.getValue().(CallNode).getFunction().(AttrNode).getObject().getNode().toString() in ["aiohttp", "httpx","requests"]
        )
      )
    )
    or
    (
      cn.getFunction().(AttrNode).getNode().getName() in ["arun"] and
      (
      exists(With wi, CallNode cn2, NameNode nn |
          wi.getScope() = cn.getScope() and
          nn = wi.getAChildNode().getAFlowNode() and
          cn2 = wi.getAChildNode().getAFlowNode() |
          nn.getId() = cn.getFunction().(AttrNode).getObject().getNode().toString() and
          cn2.getFunction().getNode().toString() in ["AsyncWebCrawler"]
          )
        or
        exists( DefinitionNode dn |
          definition_node(cn.getFunction().(AttrNode).getNode().getScope().(Function), dn) |
          dn.getNode().toString() = cn.getFunction().(AttrNode).getObject().getNode().toString() and
          dn.getValue().(CallNode).getFunction().getNode().toString() in ["AsyncWebCrawler"])
      )
    )
    or
    (
      cn.getFunction().(NameNode).getNode().toString() = "eval"
    )
    or
    (
      cn.getFunction().(NameNode).getNode().toString() = "exec"
    )
    or
    (
      cn.getFunction().(AttrNode).getNode().getName() = "run" and
     exists( DefinitionNode dn |
       definition_node(cn.getFunction().(AttrNode).getNode().getScope().(Function), dn) |
       dn.getNode().toString() = cn.getFunction().(AttrNode).getObject().getNode().toString() and
        dn.getValue().(CallNode).getNode().getFunc().toString() = "ShellTool")
    )
    or
    (
      cn.getFunction().(AttrNode).getNode().getName() = "execute" and
     exists( DefinitionNode dn |
       definition_node(cn.getFunction().(AttrNode).getNode().getScope().(Function), dn) |
       dn.getNode().toString() = cn.getFunction().(AttrNode).getObject().getNode().toString() and
       print_function(dn.getValue().(CallNode)).matches("%.cursor") )
    )
    or
    (
      cn.getFunction().(AttrNode).getNode().getName() = "run" and
      cn.getFunction().(AttrNode).getObject().getNode().toString() = "subprocess"
    )
    or
    (
      cn.getFunction().(AttrNode).getNode().getName() in ["get", "post", "request"] and
      cn.getFunction().(AttrNode).getObject().getNode().toString() = "requests"
    )
    or
    (
      cn.getFunction().(AttrNode).getNode().getName() = "system" and
      cn.getFunction().(AttrNode).getObject().getNode().toString() = "os"
    )
    or
    (
      cn.getFunction().(AttrNode).getNode().getName() = "run" and
      exists( DefinitionNode dn |
        definition_node(cn.getFunction().(AttrNode).getNode().getScope*().(Function), dn) |
        dn.getNode().toString() = cn.getFunction().(AttrNode).getObject().getNode().toString() and
         dn.getValue().(CallNode).getNode().getFunc().toString() = "PythonREPL")
    )
    or
    (
      cn.getFunction().(AttrNode).getNode().getName() = "run_cell" and
      exists( DefinitionNode dn |
        definition_node(cn.getFunction().(AttrNode).getNode().getScope().(Function), dn) |
        dn.getNode().toString() = cn.getFunction().(AttrNode).getObject().getNode().toString() and
         dn.getValue().(CallNode).getNode().getFunc().toString() = "get_ipython")
    )
    or
    (
      cn.getFunction().getNode().toString() = "GitLoader"
    )
    or
    (
      cn.getFunction().(AttrNode).getNode().getName() in ["run", "invoke"] and
      exists( DefinitionNode dn |
        definition_node(cn.getFunction().(AttrNode).getNode().getScope().(Function), dn) |
        dn.getNode().toString() = cn.getFunction().(AttrNode).getObject().getNode().toString() and
        dn.getValue().(CallNode).getFunction().(AttrNode).getNode().getName() = "from_llm" and
        dn.getValue().(CallNode).getFunction().(AttrNode).getObject().getNode().toString() in ["SQLDatabaseChain", "SQLDatabaseSequentialChain"])
    )
    or
    print_function(cn).matches("%session.execute")
    or
    print_function(cn).matches("connection.execute")
    or
    print_function(cn).matches("jinja.from_string")
    or
    (cn.getFunction().(AttrNode).getNode().getName() = "load" and
      exists( DefinitionNode dn |
        definition_node(cn.getFunction().(AttrNode).getNode().getScope*().(Function), dn) |
        dn.getNode().toString() = cn.getFunction().(AttrNode).getObject().getNode().toString() and
         dn.getValue().(CallNode).getNode().getFunc().toString() in ["AsyncHtmlLoader", "WebBaseLoader"])
    )
    or
    (
      exists(ParameterDefinition pd, AttrNode an | pd.getScope() = cn.getScope() and pd.getAnnotation() = an|
      cn.getFunction().(AttrNode).getNode().getName() = "request" and
      pd.getName() =  cn.getFunction().(AttrNode).getObject().getNode().toString() and
      an.getNode().getName().matches("%Client") and an.getObject().getNode().toString() = "httpx")
    )
    or
    // Issue-hermes-agent-220: path traversal in skill_view -> arbitrary file read.
    // source: /root/project/xclaw-project/hermes-agent/llm-enhance/cve-finding/InformationLeak/Issue-hermes-agent-220-skill-view-name-traversal.json
    // Both d5 sink points are pathlib .read_text() calls and are covered by this single
    // name-only read_text disjunct:
    //   - skill_md.read_text(encoding="utf-8")     at tools/skills_tool.py:1052
    //   - target_file.read_text(encoding="utf-8")  at tools/skills_tool.py:1197
    // Trade-off: name-only match also fires on any unrelated pathlib.Path.read_text() in the
    // project. A tighter object-constrained variant could split it into the skill_md / target_file
    // receivers, but both receivers are bound from conditional/selected paths (skill_dir/file_path
    // joins) so a DefinitionNode->constructor match would be unreliable; the broad read_text match
    // is the robust choice here.
    (
      cn.getFunction().(AttrNode).getNode().getName() = "read_text"
    )
    or
    // Issue-hermes-agent-8033: DNS-rebinding TOCTOU SSRF on web_extract path.
    // sink: provider.extract(safe_urls, format=format) at tools/web_tools.py:1036
    // (the two httpx.AsyncClient.get sinks in this issue are already covered by the
    //  ["request","get"] + With/AsyncClient disjunct above).
    (
      cn.getFunction().(AttrNode).getNode().getName() = "extract" and
      cn.getFunction().(AttrNode).getObject().getNode().toString() = "provider"
    )
    or
    // Rebuilt Hermes DB: direct SDK/network primitives corresponding to the D5 ground truth.
    // WebSocket CDP dispatch; constrain the receiver to the names used by the old supervisor
    // and the current browser_cdp_tool implementation to avoid matching platform adapter sends.
    (
      cn.getFunction().(AttrNode).getNode().getName() = "send" and
      cn.getFunction().(AttrNode).getObject().getNode().toString() in ["ws", "self._ws"]
    )
    or
    // Matrix message delivery primitive.
    (
      cn.getFunction().(AttrNode).getNode().getName() = "send_message_event"
    )
    or
    // Firecrawl passes the scrape method as a callable to asyncio.to_thread rather than
    // invoking scrape directly at the syntax level.
    (
      cn.getFunction().(AttrNode).getNode().getName() = "to_thread" and
      cn.getFunction().(AttrNode).getObject().getNode().toString() = "asyncio" and
      cn.getArg(0).(AttrNode).getNode().getName() = "scrape"
    )
    or
    // Exa content extraction primitive.
    (
      cn.getFunction().(AttrNode).getNode().getName() = "get_contents"
    )
    or
    // Parallel SDK extraction primitive; distinguish it from unrelated extract methods by
    // requiring the immediate receiver to be the SDK's beta namespace.
    (
      cn.getFunction().(AttrNode).getNode().getName() = "extract" and
      cn.getFunction().(AttrNode).getObject().(AttrNode).getNode().getName() = "beta"
    )
    or
    // PTY process-spawn primitive used by local background terminal execution.
    (
      cn.getFunction().(AttrNode).getNode().getName() = "spawn" and
      cn.getFunction().(AttrNode).getObject().getNode().toString() = "_PtyProcessCls"
    )
    or
    // Issue-hermes-agent-8034: prompt-injection SSRF via browser_navigate (local backend
    // skips is_safe_url). sink: _run_browser_command(session, "open", [url], ...) at
    // tools/browser_tool.py:2410. _run_browser_command is a multi-command dispatcher
    // (open/click/fill/eval/...), so constrain to the "open" navigation command only.
    (
      cn.getFunction().(NameNode).getNode().toString() = "_run_browser_command" and
      cn.getArg(1).getNode().(StringLiteral).getText() = "open"
    )
    or
    // Issue-hermes-agent-8034: Camofox local-backend navigation sink.
    // sink: camofox_navigate(url, task_id) at tools/browser_tool.py:2389
    (
      cn.getFunction().(NameNode).getNode().toString() = "camofox_navigate"
    )
    or
    // Issue-hermes-agent-8035: read_file tool credential exfiltration — missing
    // path-gate members let read_file("~/.hermes/auth.json") fall through to the
    // real in-process file-read primitive.
    // sink: file_ops.read_file(path, offset, limit) at tools/file_tools.py:932.
    // file_ops is bound from the _get_file_ops() factory (not a direct
    // ShellFileOperations(...) constructor), so a DefinitionNode->constructor match
    // is unreliable; constrain on the object name "file_ops" instead.
    // NOTE: the second d5 sink point (json.dumps(result_dict) at file_tools.py:1042)
    // is a high-level tool-output serialization/pipeline forwarder, not the real
    // dangerous file-read primitive, so it is intentionally NOT registered.
    (
      cn.getFunction().(AttrNode).getNode().getName() = "read_file" and
      cn.getFunction().(AttrNode).getObject().getNode().toString() = "file_ops"
    )
    or
    // Issue Add_admin_permission_checks_for_Python_and_Shell_execution-PathMismatch:
    // non-admin path-gate reuses the read-allowed roots (incl. global skills dir) for write/edit,
    // so a model-supplied write/edit path reaches the real in-process filesystem-write primitive
    // in LocalFileSystemComponent.
    // sinks: open(abs_path, mode, ...) at astrbot/core/computer/booters/local.py:280 (write_file)
    //        open(abs_path, "w", ...)  at astrbot/core/computer/booters/local.py:264 (edit_file)
    // builtin open is a bare-name (NameNode) call; constrain on a write-mode 2nd positional arg so
    // this fires on the write/edit opens but NOT the read open (open(abs_path, encoding=...)) at
    // local.py:249 in the same component.
    (
      cn.getFunction().(NameNode).getNode().toString() = "open" and
      (
        cn.getArg(1).getNode().(StringLiteral).getText() in
          ["w", "a", "x", "w+", "a+", "r+", "wb", "ab", "wt", "at"] or
        cn.getArg(1).getNode().(Name).getId() = "mode"
      )
    )
    or
    // Advisory-GHSA-3jx4-q2m7-r496-WorkspaceHardlinkAlias: a workspace hardlink alias satisfies the
    // pathname-containment gate while the read sink operates on the underlying (out-of-workspace)
    // inode. Register the real in-process file-read primitives the model-supplied path reaches.
    // sink (#2): file_path.open("rb") at astrbot/core/computer/file_read_utils.py:277
    //   file_path is bound from Path(path); match .open() on a Path-constructed object.
    (
      cn.getFunction().(AttrNode).getNode().getName() = "open" and
      exists( DefinitionNode dn |
        definition_node(cn.getFunction().(AttrNode).getNode().getScope*().(Function), dn) |
        dn.getNode().toString() = cn.getFunction().(AttrNode).getObject().getNode().toString() and
        dn.getValue().(CallNode).getNode().getFunc().toString() = "Path")
    )
    or
    // Advisory-GHSA-3jx4-q2m7-r496-WorkspaceHardlinkAlias:
    // sink (#3): Path(path).read_bytes — real in-process byte-read primitive on the aliased inode.
    // At file_read_utils.py:299 it is passed by reference into to_thread (a cross-thread forwarder),
    // so there is no read_bytes() CallNode there; this disjunct fires on the equivalent direct call
    // Path(path).read_bytes() at file_read_utils.py:289 (same primitive, same path flow / module).
    // Remaining d5 sink points for this issue are accounted for as:
    //  - read_file_tool_result (fs.py:284) and sb.fs.write_file (fs.py:351): high-level tool
    //    forwarders/orchestration wrappers, NOT the real primitive -> intentionally NOT registered.
    //  - open(abs_path, mode, ...) at booters/local.py:280 (write_file): already covered by the
    //    builtin-open write disjunct added for the PathMismatch issue above.
    (
      cn.getFunction().(AttrNode).getNode().getName() = "read_bytes" and
      cn.getFunction().(AttrNode).getObject().(CallNode).getNode().getFunc().toString() = "Path"
    )
    or
    // Issue-nanobot-1817: restrictToWorkspace bypass via tilde paths in the exec tool's
    // path extraction (_extract_absolute_paths). The model-driven `exec` tool call reaches
    // ExecTool._spawn, which hands the command to a real shell via `-c` and spawns it.
    // source: /root/project/xclaw-project/nanobot/llm-enhance/official-cve/issue-security/Issue-nanobot-1817.json
    // sink: asyncio.create_subprocess_exec(*args, ...) with args=[shell_program,"-c",command]
    //       at nanobot/agent/tools/shell.py:493 — the lowest in-process process-spawn primitive.
    // Constrained on object "asyncio" so it fires reliably without matching unrelated
    // create_subprocess_exec receivers.
    //
    // Issue-nanobot-2826: LLM-supplied working_dir escapes workspace, turning the exec
    // tool into an arbitrary-file-delete primitive. Its only d5 sink point is the same
    // asyncio.create_subprocess_exec(*args, ...) at nanobot/agent/tools/shell.py:493 and
    // is therefore already covered by this disjunct.
    // source: /root/project/xclaw-project/nanobot/llm-enhance/official-cve/issue-security/Issue-nanobot-2826.json
    // Issue-nanobot-845: restrictToWorkspace lacks process-level isolation so exec'd shell
    // commands read implicit out-of-workspace paths. Its only d5 sink point is likewise the
    // same asyncio.create_subprocess_exec at nanobot/agent/tools/shell.py:493 — already
    // covered by this disjunct.
    // source: /root/project/xclaw-project/nanobot/llm-enhance/official-cve/issue-security/Issue-nanobot-845.json
    (
      cn.getFunction().(AttrNode).getNode().getName() = "create_subprocess_exec" and
      cn.getFunction().(AttrNode).getObject().getNode().toString() = "asyncio"
    )
    or
    // CVE-2026-32008-browser-file-scheme-navigation: missing scheme allowlist on the
    // LLM-facing browser tool lets a model-supplied file://, about:, or data: URL reach
    // the Playwright navigation primitive, disclosing local files via auto-snapshot.
    // source: /root/project/xclaw-project/chatgpt-on-wechat/llm-enhance/cve-finding/similar/Info_Leak/CVE-2026-32008-browser-file-scheme-navigation.json
    // sink: resp = page.goto(url, wait_until="domcontentloaded", timeout=timeout)
    //       at agent/tools/browser/browser_service.py:685 — the lowest in-process navigation
    //       primitive. `page` is bound from self._page (an attribute, not a constructor), so a
    //       DefinitionNode->constructor match is unreliable; constrain on object name "page".
    (
      cn.getFunction().(AttrNode).getNode().getName() = "goto" and
      cn.getFunction().(AttrNode).getObject().getNode().toString() = "page"
    )
    or
    // Advisory-GHSA-jccr-rrw2-vc8h-Read-proc-self-environ: the read tool's path-gate denies
    // only the literal ~/.cow/.env credential file, so a model-supplied procfs alias such as
    // /proc/self/environ falls through to the real in-process file-read primitive.
    // source: /root/project/xclaw-project/chatgpt-on-wechat/llm-enhance/cve-finding/similar/Auth_Bypass/Advisory-GHSA-jccr-rrw2-vc8h-Read-proc-self-environ.json
    // sink: with open(absolute_path, 'r', encoding='utf-8-sig') as f at agent/tools/read/read.py:250.
    // builtin open is a bare-name (NameNode) call; the existing open disjunct above is constrained
    // to WRITE modes, so this read-mode open is not covered. Constrain on a read-mode 2nd positional
    // arg so this fires on the file-read open without re-matching the write opens.
    // NOTE: this over-matches any open(x, "r"/"rb"/"rt", ...) read call in the project; acceptable
    // since a read-mode open is the file-read primitive this Filesystem-Path-Gate issue targets.
    (
      cn.getFunction().(NameNode).getNode().toString() = "open" and
      cn.getArg(1).getNode().(StringLiteral).getText() in ["r", "rb", "rt"]
    )
    or
    // Issue-hermes-agent-38035-matrix-adapter-markdown: Content-Output-Guardrail-Gate.
    // Markdown->HTML for the Matrix formatted_body is emitted without sanitizing raw HTML /
    // javascript: links, so model/user-controlled markup reaches the Matrix HTTP send.
    // source: /root/project/xclaw-project/hermes-agent/llm-enhance/cve-finding/Injection/Issue-hermes-agent-38035-matrix-adapter-markdown.json
    // sink: async with session.put(url, headers=headers, json=payload) as resp
    //       at tools/send_message_tool.py:1541 (JSON cites :1393 @ commit 77a1650c) — the
    //       lowest in-process outbound-delivery primitive. `session` is bound from
    //       `async with aiohttp.ClientSession() as session`; match put on object "session".
    //       Over-match: any aiohttp session.put(...) whose receiver var is named `session`;
    //       acceptable. A tighter With/ClientSession-constrained variant (like the
    //       ["request","get"] disjunct above) is the opt-in alternative.
    (
      cn.getFunction().(AttrNode).getNode().getName() = "put" and
      cn.getFunction().(AttrNode).getObject().getNode().toString() = "session"
    )
    or
    // Current-only rendering sink retained alongside AgentFuzz's session.put sink.
    (
      cn.getFunction().(AttrNode).getNode().getName() = "convert" and
      cn.getFunction().(AttrNode).getObject().getNode().toString() = "md"
    )
    or
    // Advisory-GHSA-qmwg-qprg-3j38-browser-eval-private-nav: Network-URL-SSRF-Gate.
    // browser_console eval can navigate the page to a private/internal URL (no post-eval
    // current-URL re-check) and browser_snapshot then reads the page content. Register the
    // eval (navigation-driving) and snapshot (content-read) primitives.
    // source: /root/project/xclaw-project/hermes-agent/llm-enhance/cve-finding/similar/info_leak/Advisory-GHSA-qmwg-qprg-3j38-browser-eval-private-nav.json
    // sink #1: supervisor.evaluate_runtime(expression) at tools/browser_tool.py:2858
    //   (CDP supervisor fast-path eval). `supervisor` is bound from SUPERVISOR_REGISTRY.get().
    (
      cn.getFunction().(AttrNode).getNode().getName() = "evaluate_runtime" and
      cn.getFunction().(AttrNode).getObject().getNode().toString() = "supervisor"
    )
    or
    // Advisory-GHSA-qmwg-qprg-3j38-browser-eval-private-nav (cont.)
    // sink #2: _run_browser_command(effective_task_id, "eval", [expression]) at
    //   tools/browser_tool.py:2894 (agent-browser CLI fallback eval). _run_browser_command
    //   is a multi-command dispatcher (open/click/fill/eval/snapshot/...); constrain on the
    //   "eval" discriminator at arg index 1. Also matches the second eval call at :3056.
    // source: /root/project/xclaw-project/hermes-agent/llm-enhance/cve-finding/similar/info_leak/Advisory-GHSA-qmwg-qprg-3j38-browser-eval-private-nav.json
    (
      cn.getFunction().(NameNode).getNode().toString() = "_run_browser_command" and
      cn.getArg(1).getNode().(StringLiteral).getText() = "eval"
    )
    or
    // Advisory-GHSA-qmwg-qprg-3j38-browser-eval-private-nav (cont.)
    // sink #3: _run_browser_command(effective_task_id, "snapshot", args) at
    //   tools/browser_tool.py:2544 (page-content read). Constrain on the "snapshot"
    //   discriminator at arg index 1. Benign over-match: the redirect-guard snapshot at
    //   :2495 in the same dispatcher also fires; acceptable. The d5 "response = {...}" entry
    //   at :2557 is a control-flow dict literal, not a call sink, so it is not registered.
    // source: /root/project/xclaw-project/hermes-agent/llm-enhance/cve-finding/similar/info_leak/Advisory-GHSA-qmwg-qprg-3j38-browser-eval-private-nav.json
    (
      cn.getFunction().(NameNode).getNode().toString() = "_run_browser_command" and
      cn.getArg(1).getNode().(StringLiteral).getText() = "snapshot"
    )
    or
    // CVE-2026-Discord-Mention-Bypass-Mattermost-Slack: Content-Output-Guardrail-Gate.
    // Missing mass-mention suppression lets <!everyone>/@all reach the Slack & Mattermost
    // post primitives. Register the platform message-send primitives.
    // source: /root/project/xclaw-project/hermes-agent/llm-enhance/cve-finding/Mass-Ping/CVE-2026-Discord-Mention-Bypass-Mattermost-Slack.json
    // sink (Slack): self._get_client(chat_id).chat_postMessage(**kwargs) at
    //   gateway/platforms/slack.py:1179 (JSON cites :1106) — distinctive Slack SDK send
    //   method; match by name.
    (
      cn.getFunction().(AttrNode).getNode().getName() = "chat_postMessage"
    )
    or
    // CVE-2026-Discord-Mention-Bypass-Mattermost-Slack (cont.)
    // sink (Mattermost adapter): self._api_post("posts", payload). The path discriminator
    // targets message posts rather than every call through the adapter's HTTP helper.
    (
      cn.getFunction().(AttrNode).getNode().getName() = "_api_post" and
      cn.getArg(0).getNode().(StringLiteral).getText() = "posts"
    )
    or
    // CVE-2026-Discord-Mention-Bypass-Mattermost-Slack (cont.)
    // sink (Mattermost standalone): aiohttp session.post(...); match the receiver name used
    // by the standalone sender.
    (
      cn.getFunction().(AttrNode).getNode().getName() = "post" and
      cn.getFunction().(AttrNode).getObject().getNode().toString() = "session"
    )
    or
    // CVE-2026-28391-exec-allow-pattern-shell-chain: Command-Exec-Allowlist-Gate. The exec
    // allowlist (_guard_command) regex-matches a prefix of the lowercased raw command while the
    // real shell executes the full chained string, so a model-supplied `echo SAFE; touch ...`
    // reaches the shell. ExecTool._spawn's Windows (non-multiline) branch hands the raw command
    // straight to the OS shell via asyncio.create_subprocess_shell.
    // source: /root/project/xclaw-project/nanobot/llm-enhance/cve-finding/similar/Auth_Bypass/CVE-2026-28391-exec-allow-pattern-shell-chain.json
    // sink: asyncio.create_subprocess_shell(command, ...) at nanobot/agent/tools/shell.py:479
    //       — the lowest in-process shell-spawn primitive on that branch. Constrained on object
    //       "asyncio" (mirrors the create_subprocess_exec disjunct above); residual over-match:
    //       any asyncio.create_subprocess_shell(...) call in the project — acceptable, since
    //       create_subprocess_shell is itself a shell-exec primitive.
    // NOTE: this issue's OTHER d5 sink point — the Unix branch
    //       `args.extend(["-c", command]); asyncio.create_subprocess_exec(*args, ...)` at
    //       nanobot/agent/tools/shell.py:493 — is already covered by the
    //       asyncio.create_subprocess_exec disjunct above (Issue-nanobot-1817).
    (
      cn.getFunction().(AttrNode).getNode().getName() = "create_subprocess_shell" and
      cn.getFunction().(AttrNode).getObject().getNode().toString() = "asyncio"
    )
    // --- already-covered sinks (no new disjunct added; recorded for traceability) ---
    //
    // Advisory-GHSA-QWJC-XV6C-MQFX-Agent-Bash-Variant: bash safety blocklist undersizes the
    // shell=True capability. sink: process = subprocess.Popen(...) at agent/tools/bash/bash.py:257
    // source: /root/project/xclaw-project/chatgpt-on-wechat/llm-enhance/cve-finding/RCE/Advisory-GHSA-QWJC-XV6C-MQFX-Agent-Bash-Variant.json
    // already covered by the subprocess.Popen disjunct above.
    //
    // CVE-2026-30741-Agent-Dangerous-Tool-Auto-Execution: missing dangerous-tool approval gate.
    // sink: process = subprocess.Popen(...) at agent/tools/bash/bash.py:257
    // source: /root/project/xclaw-project/chatgpt-on-wechat/llm-enhance/cve-finding/similar/RCE/CVE-2026-30741-Agent-Dangerous-Tool-Auto-Execution.json
    // already covered by the subprocess.Popen disjunct above.
    //
    // Advisory-GHSA-56f2-hvwg-5743-Vision-Tool: missing SSRF gate before vision image download.
    // sink: resp = requests.get(url, timeout=30) at agent/tools/vision/vision.py:709
    // source: /root/project/xclaw-project/chatgpt-on-wechat/llm-enhance/cve-finding/similar/SSRF_Network/Advisory-GHSA-56f2-hvwg-5743-Vision-Tool.json
    // already covered by the requests.get/post/request disjunct above.
    //
    // CVE-2026-28451-vision-tool: same missing SSRF gate on the vision tool.
    // sink: resp = requests.get(url, timeout=30) at agent/tools/vision/vision.py:709
    // source: /root/project/xclaw-project/chatgpt-on-wechat/llm-enhance/cve-finding/similar/SSRF_Network/CVE-2026-28451-vision-tool.json
    // already covered by the requests.get/post/request disjunct above.
    //
    // CVE-2026-32019-chatgpt-on-wechat-web_fetch-special-use-ipv4: scheme-only gate undersizes the
    // SSRF capability. sinks: response = requests.get(...) at agent/tools/web_fetch/web_fetch.py:121
    // (_fetch_webpage) and agent/tools/web_fetch/web_fetch.py:161 (_fetch_document).
    // source: /root/project/xclaw-project/chatgpt-on-wechat/llm-enhance/cve-finding/similar/SSRF/CVE-2026-32019-chatgpt-on-wechat-web_fetch-special-use-ipv4.json
    // both already covered by the requests.get/post/request disjunct above.
    //
    // CVE-2026-Device-Blocking-Expanduser-Bypass: Filesystem-Path-Gate (read_file device
    // blocklist bypass). d5 sink point file_ops.read_file(path, offset, limit) at
    // tools/file_tools.py:794 is already covered by the file_ops.read_file disjunct
    // (Issue-hermes-agent-8035) above; the inner ShellFileOperations.read_file self._exec()
    // calls (tools/file_operations.py:908,952) are its shell-exec sub-ops reached through
    // that covered node, not separately registered.
    // source: /root/project/xclaw-project/hermes-agent/llm-enhance/cve-finding/Concurrency/CVE-2026-Device-Blocking-Expanduser-Bypass.json
    //
    // fix_security___block_sandbox_backend_creds_from_subprocess_e-6a320e8b-MessagingCreds-Exploit-TP:
    // Process-Environment-Isolation-Gate (messaging creds leak into subprocess env). Its only
    // d5 sink point is LocalEnvironment._run_bash subprocess.Popen(env=run_env) at
    // tools/environments/local.py:544 — already covered by the subprocess.Popen disjunct above.
    // source: /root/project/xclaw-project/hermes-agent/llm-enhance/cve-finding/InformationLeak/fix_security___block_sandbox_backend_creds_from_subprocess_e-6a320e8b-MessagingCreds-Exploit-TP.json
    //
    // fix__add_missing_dangerous_command_patterns_in_approval_py-fd335a4e-Remote-Code-Execution-Pattern-Bypass:
    // Command-Exec-Allowlist-Gate (incomplete dangerous-pattern denylist). d5 sink point
    // CommandEnvironment.execute _wrap_command (tools/environments/base.py:864) is a
    // string-wrapping helper, not an exec primitive; the real primitive is LocalEnvironment
    // subprocess.Popen at tools/environments/local.py:544 — already covered by the
    // subprocess.Popen disjunct above.
    // source: /root/project/xclaw-project/hermes-agent/llm-enhance/cve-finding/Other/fix__add_missing_dangerous_command_patterns_in_approval_py-fd335a4e-Remote-Code-Execution-Pattern-Bypass.json
    //
    // CVE-Project-Code-Execution-Mode-Bypass: Tool-Action-Approval-Gate (execute_code lacked
    // an approval gate). Its only d5 sink point is subprocess.Popen at
    // tools/code_execution_tool.py:1045 — already covered by the subprocess.Popen disjunct above.
    // source: /root/project/xclaw-project/hermes-agent/llm-enhance/cve-finding/RCE/CVE-Project-Code-Execution-Mode-Bypass.json
    //
    // Advisory-GHSA-9q2p-vc84-2rwm-exec-comment-tail-allow-pattern-bypass:
    // Command-Exec-Allowlist-Gate (an unquoted `#` comment tail in the raw command bypasses the
    // allow-pattern regex while the shell ignores the tail). Its only d5 sink point
    // asyncio.create_subprocess_exec at nanobot/agent/tools/shell.py:493 is already covered by
    // the asyncio.create_subprocess_exec disjunct above.
    // source: /root/project/xclaw-project/nanobot/llm-enhance/cve-finding/similar/RCE/Advisory-GHSA-9q2p-vc84-2rwm-exec-comment-tail-allow-pattern-bypass.json
    //
    // Advisory-GHSA-jj82-76v6-933r-exec-allowlist-wrapper-bypass:
    // Command-Exec-Allowlist-Gate (allow_patterns approves only a wrapper prefix while bash -c
    // runs the full command). Its only d5 sink point asyncio.create_subprocess_exec at
    // nanobot/agent/tools/shell.py:493 is already covered by the asyncio.create_subprocess_exec
    // disjunct above.
    // source: /root/project/xclaw-project/nanobot/llm-enhance/cve-finding/similar/RCE/Advisory-GHSA-jj82-76v6-933r-exec-allowlist-wrapper-bypass.json
    //
    // Advisory-GHSA-jccr-rrw2-vc8h-login-shell-env-disclosure:
    // Process-Environment-Isolation-Gate (the reduced child env still forwards HOME and _spawn
    // launches bash/zsh as a login shell `-l`, so startup files re-import exported secrets). Its
    // only d5 sink point asyncio.create_subprocess_exec at nanobot/agent/tools/shell.py:493 is
    // already covered by the asyncio.create_subprocess_exec disjunct above.
    // source: /root/project/xclaw-project/nanobot/llm-enhance/cve-finding/similar/Auth_Bypass/Advisory-GHSA-jccr-rrw2-vc8h-login-shell-env-disclosure.json
    //
    // CVE-2026-31993-exec-allow-pattern-shell-chain-bypass:
    // Command-Exec-Allowlist-Gate (prefix allow-pattern vs `&&`-chained shell exec). Two d5 sink
    // points: (1) the real primitive asyncio.create_subprocess_exec at shell.py:492 is already
    // covered by the asyncio.create_subprocess_exec disjunct above; (2) `process = await
    // self._spawn(...)` at nanobot/agent/tools/shell.py:271 is the in-process _spawn wrapper, NOT
    // the real process-spawn primitive, so it is intentionally NOT registered.
    // source: /root/project/xclaw-project/nanobot/llm-enhance/cve-finding/similar/Auth_Bypass/CVE-2026-31993-exec-allow-pattern-shell-chain-bypass.json
    //
    // Advisory-GHSA-5326-6f73-m96w-exec-allow-pattern-shell-chain-bypass:
    // Command-Exec-Allowlist-Gate (`&&` shell chaining gives the sink capability beyond the
    // allow-pattern coverage). Its only d5 sink point asyncio.create_subprocess_exec at
    // nanobot/agent/tools/shell.py:493 is already covered by the asyncio.create_subprocess_exec
    // disjunct above.
    // source: /root/project/xclaw-project/nanobot/llm-enhance/cve-finding/similar/RCE/Advisory-GHSA-5326-6f73-m96w-exec-allow-pattern-shell-chain-bypass.json
    //
    // Advisory-GHSA-jccr-rrw2-vc8h-guard-gap:
    // Command-Exec-Allowlist-Gate (QwenPaw's dangerous_shell_commands jq denylist covers
    // /proc/environ, jq system() and jq file flags but not jq $ENV, so a model-supplied
    // `jq -n '$ENV.SECRET'` falls through to the shell sink which runs jq with the inherited
    // os.environ). Two d5 sink points, both at src/qwenpaw/agents/tools/shell.py:
    //  (1) asyncio.create_subprocess_shell(cmd, ..., env=env) at shell.py:527 — the real
    //      in-process shell-spawn primitive — is already covered by the
    //      asyncio.create_subprocess_shell disjunct above (added for CVE-2026-28391).
    //  (2) env = os.environ.copy() at shell.py:501 — an environment-read setup helper that just
    //      builds the env dict later passed via env= to the subprocess; NOT the dangerous exec
    //      primitive itself, so it is intentionally NOT registered (the real primitive is the
    //      create_subprocess_shell sink covered above).
    // source: /root/project/xclaw-project/QwenPaw/llm-enhance/cve-finding/similar/Auth_Bypass/Advisory-GHSA-jccr-rrw2-vc8h-guard-gap.json
    or
    // CVE-Project-Code-Execution-Mode-Bypass: the terminal comparison path reaches the
    // approval-policy sink while execute_code lacks an equivalent args.code-dependent check.
    // source: /root/my-project/agent-research/clawgap/design/hermes-agent/groundtruth/new-vuls/CVE-Project-Code-Execution-Mode-Bypass.json
    // sink: prompt_dangerous_approval(command, combined_desc, ...) at tools/approval.py:1220.
    // Constrain the bare-name call to check_all_command_guards so the older call in
    // check_dangerous_command at tools/approval.py:868 is not also classified as this sink.
    (
      cn.getFunction().(NameNode).getNode().toString() = "prompt_dangerous_approval" and
      cn.getScope().(Function).getName() = "check_all_command_guards" and
      cn.getLocation().getFile().getRelativePath() = "tools/approval.py"
    )
}

/** A direct `requests` call whose dangerous facet is the outbound URL. */
private predicate isRequestsUrlSink(CallNode cn) {
  cn.getFunction().(AttrNode).getNode().getName() in ["get", "post", "request"] and
  cn.getFunction().(AttrNode).getObject().getNode().toString() = "requests"
}

/** A modeled session/client HTTP call whose dangerous facet is the outbound URL. */
private predicate isSessionUrlSink(CallNode cn) {
  cn.getFunction().(AttrNode).getNode().getName() in ["request", "get"] and
  (
    exists(With wi, CallNode cn2, NameNode nn |
      wi.getScope() = cn.getScope() and
      nn = wi.getAChildNode().getAFlowNode() and
      cn2 = wi.getAChildNode().getAFlowNode() |
      nn.getId() = cn.getFunction().(AttrNode).getObject().getNode().toString() and
      cn2.getFunction().(AttrNode).getNode().getName() in
        ["AsyncClient", "ClientSession", "Session"]
    )
    or
    exists(DefinitionNode dn |
      definition_node(cn.getFunction().(AttrNode).getNode().getScope().(Function), dn) |
      dn.getNode().toString() =
        cn.getFunction().(AttrNode).getObject().getNode().toString() and
      dn.getValue().(CallNode).getFunction().(AttrNode).getNode().getName() in
        ["AsyncClient", "ClientSession", "Session"]
    )
  )
}

/** A parameter-annotated httpx client request whose dangerous facet is the URL. */
private predicate isAnnotatedHttpxUrlSink(CallNode cn) {
  exists(ParameterDefinition pd, AttrNode an |
    pd.getScope() = cn.getScope() and pd.getAnnotation() = an |
    cn.getFunction().(AttrNode).getNode().getName() = "request" and
    pd.getName() = cn.getFunction().(AttrNode).getObject().getNode().toString() and
    an.getNode().getName().matches("%Client") and
    an.getObject().getNode().toString() = "httpx"
  )
}

private predicate isGenericHttpUrlSink(CallNode cn) {
  isRequestsUrlSink(cn)
  or isSessionUrlSink(cn)
  or isAnnotatedHttpxUrlSink(cn)
}

/** The URL expression for a modeled HTTP sink, accounting for request(method, url). */
private predicate httpUrlNode(CallNode sink, ControlFlowNode node) {
  isGenericHttpUrlSink(sink) and
  (
    sink.getFunction().(AttrNode).getNode().getName() in ["get", "post"] and
    node = sink.getArg(0)
    or
    sink.getFunction().(AttrNode).getNode().getName() = "request" and
    node = sink.getArg(1)
    or
    node = sink.getArgByName("url")
  )
}

/**
 * Exact, source-audited RPC payload exceptions. These are deliberately not a generic
 * `json`/`data` rule: a new exception must identify the project, source scope, call shape,
 * and payload argument explicitly.
 */
private predicate auditedRpcPayloadNode(CallNode sink, ControlFlowNode node) {
  isHermesProject() and
  sink.getLocation().getFile().getRelativePath() =
    "tools/environments/managed_modal.py" and
  sink.getScope().(Function).getName() = "_request" and
  sink.getFunction().(AttrNode).getObject().getNode().toString() = "requests" and
  sink.getFunction().(AttrNode).getNode().getName() = "request" and
  node = sink.getArgByName("json")
  or
  isPocoAgentProject() and
  sink.getLocation().getFile().getRelativePath() =
    "executor/app/core/channel_runtime.py" and
  sink.getScope().(Function).getName() in ["_request", "download_artifact"] and
  sink.getFunction().(AttrNode).getObject().getNode().toString() = "client" and
  sink.getFunction().(AttrNode).getNode().getName() = "post" and
  node = sink.getArgByName("json")
  or
  isPocoAgentProject() and
  sink.getLocation().getFile().getRelativePath() =
    "executor/app/core/memory.py" and
  sink.getScope().(Function).getName() = "_request" and
  sink.getFunction().(AttrNode).getObject().getNode().toString() = "client" and
  sink.getFunction().(AttrNode).getNode().getName() = "request" and
  node = sink.getArgByName("json")
  or
  // Issue-hermes-agent-8034: Camofox sends the browser target in its internal JSON
  // payload; the requests URL only selects the configured local Camofox endpoint.
  // source: /root/project/xclaw-project/hermes-agent/llm-enhance/official-cve/issue-security/Issue-hermes-agent-8034.json
  isHermesProject() and
  sink.getLocation().getFile().getRelativePath() = "tools/browser_camofox.py" and
  sink.getScope().(Function).getName() = "_post" and
  sink.getFunction().(AttrNode).getObject().getNode().toString() = "requests" and
  sink.getFunction().(AttrNode).getNode().getName() = "post" and
  node = sink.getArgByName("json")
  or
  // nanobot's revision-pinned web-search adapter sends the model-supplied query in
  // `params`; the URL selects a fixed/configured search provider rather than carrying it.
  // source: /root/my-project/agent-research/clawgap/design/nanobot/nanobot-v0.1.4.post5-acceptance.json
  isNanobotProject() and
  sink.getLocation().getFile().getRelativePath() = "nanobot/agent/tools/web.py" and
  sink.getScope().(Function).getName() in
    ["_search_brave", "_search_searxng", "_search_jina"] and
  sink.getFunction().(AttrNode).getObject().getNode().toString() = "client" and
  sink.getFunction().(AttrNode).getNode().getName() = "get" and
  node = sink.getArgByName("params")
}

private string sinkCallName(CallNode sink) {
  result = sink.getFunction().(AttrNode).getNode().getName()
  or
  result = sink.getFunction().(NameNode).getNode().toString()
}

private predicate isSubprocessRunSink(CallNode sink) {
  sink.getFunction().(AttrNode).getNode().getName() = "run" and
  sink.getFunction().(AttrNode).getObject().getNode().toString() = "subprocess"
}

private predicate isSubprocessPopenSink(CallNode sink) {
  sink.getFunction().(AttrNode).getNode().getName() = "Popen" and
  sink.getFunction().(AttrNode).getObject().getNode().toString() = "subprocess"
}

private predicate isExecutorSubmitSink(CallNode sink) {
  sink.getFunction().(AttrNode).getNode().getName() = "submit" and
  sink.getArg(0).(AttrNode).getNode().getName() = "run" and
  sink.getArg(0).(AttrNode).getNode().getObject().toString() = "subprocess"
}

private predicate isAsyncioProcessSink(CallNode sink, string kind) {
  sink.getFunction().(AttrNode).getNode().getName() = kind and
  kind in ["create_subprocess_exec", "create_subprocess_shell"] and
  sink.getFunction().(AttrNode).getObject().getNode().toString() = "asyncio"
}

private predicate isPtySpawnSink(CallNode sink) {
  sink.getFunction().(AttrNode).getNode().getName() = "spawn" and
  sink.getFunction().(AttrNode).getObject().getNode().toString() = "_PtyProcessCls"
}

private predicate processKeywordNode(CallNode sink, ControlFlowNode node) {
  exists(string name |
    name in ["shell", "executable", "cwd", "env", "preexec_fn", "input"] and
    node = sink.getArgByName(name)
  )
}

/** Command/argv plus only the process controls that can change the spawned capability. */
private predicate processSensitiveNode(CallNode sink, ControlFlowNode node) {
  (
    (isSubprocessRunSink(sink) or isSubprocessPopenSink(sink)) and
    (node = sink.getArg(0) or processKeywordNode(sink, node))
  )
  or
  isExecutorSubmitSink(sink) and
  (node = sink.getArg(1) or processKeywordNode(sink, node))
  or
  isAsyncioProcessSink(sink, "create_subprocess_exec") and
  (node = sink.getArg(_) or processKeywordNode(sink, node))
  or
  isAsyncioProcessSink(sink, "create_subprocess_shell") and
  (node = sink.getArg(0) or processKeywordNode(sink, node))
  or
  isPtySpawnSink(sink) and
  (
    node = sink.getArg(0)
    or
    exists(string name | name in ["cwd", "env"] and node = sink.getArgByName(name))
  )
}

private predicate browserCommandSink(CallNode sink, string command) {
  sink.getFunction().(NameNode).getNode().toString() = "_run_browser_command" and
  sink.getArg(1).getNode().(StringLiteral).getText() = command
}

/** URL input captured by an AsyncHtmlLoader/WebBaseLoader instance before `.load()`. */
private predicate loaderUrlNode(CallNode sink, ControlFlowNode node) {
  sinkCallName(sink) = "load" and
  exists(DefinitionNode dn, CallNode constructor |
    definition_node(sink.getFunction().(AttrNode).getNode().getScope*().(Function), dn) |
    dn.getNode().toString() =
      sink.getFunction().(AttrNode).getObject().getNode().toString() and
    constructor = dn.getValue() and
    constructor.getFunction().getNode().toString() in ["AsyncHtmlLoader", "WebBaseLoader"] and
    (
      node = constructor.getArg(0)
      or
      exists(string name |
        name in ["web_path", "web_paths", "url", "urls"] and
        node = constructor.getArgByName(name)
      )
    )
  )
}

/** URL or URL-list values for network, extraction, and browser-navigation sinks. */
private predicate semanticUrlNode(CallNode sink, ControlFlowNode node) {
  httpUrlNode(sink, node)
  or
  sinkCallName(sink) = "arun" and
  (node = sink.getArg(0) or node = sink.getArgByName("url"))
  or
  sinkCallName(sink) in ["extract", "get_contents"] and
  (node = sink.getArg(0) or node = sink.getArgByName("urls"))
  or
  sinkCallName(sink) = "to_thread" and
  sink.getArg(0).(AttrNode).getNode().getName() = "scrape" and
  (node = sink.getArg(1) or node = sink.getArgByName("url"))
  or
  loaderUrlNode(sink, node)
  or
  browserCommandSink(sink, "open") and node = sink.getArg(2)
  or
  sinkCallName(sink) = "camofox_navigate" and
  (node = sink.getArg(0) or node = sink.getArgByName("url"))
  or
  sinkCallName(sink) = "goto" and
  (node = sink.getArg(0) or node = sink.getArgByName("url"))
}

private predicate isBareFirstArgumentSink(CallNode sink) {
  sink.getFunction().(NameNode).getNode().toString() in
    ["eval", "exec", "open", "prompt_dangerous_approval"]
}

private predicate isAttributeFirstArgumentSink(CallNode sink) {
  sinkCallName(sink) in
    [
      "execute_code", "run", "invoke", "execute", "system", "run_cell", "from_string",
      "send", "convert", "evaluate_runtime", "read_file"
    ] and
  not isSubprocessRunSink(sink)
}

private predicate ordinaryNamedArgumentNode(CallNode sink, ControlFlowNode node) {
  exists(string name |
    name in
      [
        "code", "source", "command", "query", "statement", "operation", "sql", "template",
        "path", "file", "raw_cell", "expression", "data"
      ] and
    node = sink.getArgByName(name)
  )
}

/** Code, command, SQL, template, path, and serialized-message first arguments. */
private predicate ordinarySensitiveArgumentNode(CallNode sink, ControlFlowNode node) {
  (isBareFirstArgumentSink(sink) or isAttributeFirstArgumentSink(sink)) and
  (node = sink.getArg(0) or ordinaryNamedArgumentNode(sink, node))
}

/** GitLoader constructor controls retained from its API-specific capability card. */
private predicate gitLoaderSensitiveNode(CallNode sink, ControlFlowNode node) {
  sink.getFunction().getNode().toString() = "GitLoader" and
  (
    node = sink.getArg(0) or node = sink.getArg(1)
    or
    exists(string name |
      name in ["repo_path", "clone_url"] and node = sink.getArgByName(name)
    )
  )
}

private predicate isAiohttpDeliverySink(CallNode sink) {
  sink.getFunction().(AttrNode).getNode().getName() in ["post", "put"] and
  sink.getFunction().(AttrNode).getObject().getNode().toString() = "session"
}

/** Content-bearing values for the exact delivery primitives modeled by is_sink_af. */
private predicate deliverySensitiveNode(CallNode sink, ControlFlowNode node) {
  sinkCallName(sink) = "send_message_event" and
  (node = sink.getArg(2) or node = sink.getArgByName("content"))
  or
  sinkCallName(sink) = "chat_postMessage" and node = sink.getKwargs()
  or
  sinkCallName(sink) = "_api_post" and
  (node = sink.getArg(1) or node = sink.getArgByName("payload"))
  or
  isAiohttpDeliverySink(sink) and
  (node = sink.getArgByName("json") or node = sink.getArgByName("data"))
}

/** Dispatcher values whose sensitive position depends on the literal operation. */
private predicate browserDispatcherSensitiveNode(CallNode sink, ControlFlowNode node) {
  browserCommandSink(sink, "eval") and node = sink.getArg(2)
  or
  browserCommandSink(sink, "snapshot") and node = sink.getArg(0)
}

/** Path-bearing receivers and loader instances whose constructor state carries the target. */
private predicate semanticReceiverNode(CallNode sink, ControlFlowNode node) {
  sinkCallName(sink) in ["read_text", "open", "read_bytes"] and
  node = sink.getFunction().(AttrNode).getObject()
  or
  exists(ControlFlowNode receiver |
    projectThreadedCallableSink(sink, _, receiver) and node = receiver
  )
}

/**
 * The security-relevant value consumed by a sink call.
 *
 * Every family explicitly identifies the capability-bearing argument or receiver. There is no
 * fallback to every argument/receiver: adding a sink requires adding its sensitive-node mapping.
 */
predicate sinkSensitiveNode(CallNode sink, DataFlow::Node node, string role) {
  is_sink_af(sink) and
  (
    role = "url" and
    exists(ControlFlowNode url | semanticUrlNode(sink, url) and node.asCfgNode() = url)
    or
    role = "rpc-payload" and
    exists(ControlFlowNode payload |
      auditedRpcPayloadNode(sink, payload) and node.asCfgNode() = payload
    )
    or
    role = "argument" and
    exists(ControlFlowNode argument |
      (
        processSensitiveNode(sink, argument)
        or ordinarySensitiveArgumentNode(sink, argument)
        or gitLoaderSensitiveNode(sink, argument)
        or deliverySensitiveNode(sink, argument)
        or browserDispatcherSensitiveNode(sink, argument)
      ) and
      node.asCfgNode() = argument
    )
    or
    role = "receiver" and
    exists(ControlFlowNode receiver |
      semanticReceiverNode(sink, receiver) and node.asCfgNode() = receiver
    )
  )
}

/** Role-agnostic compatibility wrapper for taint configurations. */
predicate sinkSensitiveNode(CallNode sink, DataFlow::Node node) {
  exists(string role | sinkSensitiveNode(sink, node, role))
}
