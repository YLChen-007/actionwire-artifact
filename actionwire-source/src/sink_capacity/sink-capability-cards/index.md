# Sink API capability cards — index

Auto-generated from `src/ql/call/sinks_af.qll` by `src/sink_capacity`. Each row is one `is_sink_af` disjunct; each has its own card file `<slug>.md`.

Total sink APIs: **50**

| # | card | api | capability_class | kind | doc source | qll line |
|---|------|-----|------------------|------|-----------|----------|
| 0 | [unclassified.UNKNOWN](unclassified.UNKNOWN.md) | `UNKNOWN` | other | library | project source | 25 |
| 1 | [subprocess.run.via-executor-submit](subprocess.run.via-executor-submit.md) | `subprocess.run (Executor.submit)` | process-spawn | library | subprocess.run | 30 |
| 2 | [execute_code](execute_code.md) | `execute_code (attr call)` | code-eval | project | project source | 33 |
| 3 | [subprocess.Popen](subprocess.Popen.md) | `subprocess.Popen` | process-spawn | library | subprocess.Popen | 37 |
| 4 | [http.session.request-get](http.session.request-get.md) | `httpx/aiohttp/requests session .get/.request` | network-egress | library | httpx.AsyncClient.get | 48 |
| 5 | [crawl4ai.AsyncWebCrawler.arun](crawl4ai.AsyncWebCrawler.arun.md) | `AsyncWebCrawler.arun` | network-egress | library | project source | 69 |
| 6 | [builtins.eval](builtins.eval.md) | `builtins.eval` | code-eval | library | builtins.eval | 80 |
| 7 | [builtins.exec](builtins.exec.md) | `builtins.exec` | code-eval | library | builtins.exec | 84 |
| 8 | [langchain.ShellTool.run](langchain.ShellTool.run.md) | `ShellTool.run` | process-spawn | library | project source | 92 |
| 9 | [db.cursor.execute](db.cursor.execute.md) | `DB-API cursor.execute` | sql-exec | library | project source | 100 |
| 10 | [subprocess.run](subprocess.run.md) | `subprocess.run` | process-spawn | library | subprocess.run | 105 |
| 11 | [requests.get-post-request](requests.get-post-request.md) | `requests.get/post/request` | network-egress | library | requests.get | 110 |
| 12 | [os.system](os.system.md) | `os.system` | process-spawn | library | os.system | 114 |
| 13 | [langchain.PythonREPL.run](langchain.PythonREPL.run.md) | `PythonREPL.run` | code-eval | library | project source | 123 |
| 14 | [IPython.run_cell](IPython.run_cell.md) | `InteractiveShell.run_cell` | code-eval | library | project source | 131 |
| 15 | [langchain.GitLoader](langchain.GitLoader.md) | `GitLoader` | network-egress | library | project source | 135 |
| 16 | [langchain.SQLDatabaseChain.run](langchain.SQLDatabaseChain.run.md) | `SQLDatabaseChain.run/invoke` | sql-exec | library | project source | 144 |
| 17 | [sqlalchemy.session.execute](sqlalchemy.session.execute.md) | `SQLAlchemy session.execute` | sql-exec | library | project source | 147 |
| 18 | [sqlalchemy.connection.execute](sqlalchemy.connection.execute.md) | `connection.execute` | sql-exec | library | project source | 149 |
| 19 | [jinja2.from_string](jinja2.from_string.md) | `Jinja2 Environment.from_string` | template-injection | library | project source | 151 |
| 20 | [langchain.WebBaseLoader.load](langchain.WebBaseLoader.load.md) | `AsyncHtmlLoader/WebBaseLoader.load` | network-egress | library | project source | 157 |
| 21 | [httpx.Client.request](httpx.Client.request.md) | `httpx.Client.request (annotated param)` | network-egress | library | httpx.Client.request | 162 |
| 22 | [pathlib.Path.read_text](pathlib.Path.read_text.md) | `pathlib.Path.read_text` | file-read | library | pathlib.Path.read_text | 179 |
| 23 | [provider.extract](provider.extract.md) | `WebSearchProvider.extract` | network-egress | project | project source | 188 |
| 24 | [websocket.send.cdp](websocket.send.cdp.md) | `WebSocket send (CDP dispatch)` | code-eval | library | project source | 196 |
| 25 | [matrix.send_message_event](matrix.send_message_event.md) | `mautrix Client.send_message_event` | delivery-render | library | project source | 201 |
| 26 | [firecrawl.scrape.to-thread](firecrawl.scrape.to-thread.md) | `Firecrawl scrape via asyncio.to_thread` | network-egress | library | project source | 207 |
| 27 | [exa.get_contents](exa.get_contents.md) | `Exa get_contents` | network-egress | library | project source | 214 |
| 28 | [parallel.beta.extract](parallel.beta.extract.md) | `Parallel beta.extract` | network-egress | library | project source | 220 |
| 29 | [ptyprocess.PtyProcess.spawn](ptyprocess.PtyProcess.spawn.md) | `ptyprocess PtyProcess.spawn` | process-spawn | library | project source | 227 |
| 30 | [_run_browser_command.open](_run_browser_command.open.md) | `_run_browser_command(..., "open")` | browser-nav | project | project source | 235 |
| 31 | [camofox_navigate](camofox_navigate.md) | `camofox_navigate` | browser-nav | project | project source | 242 |
| 32 | [file_ops.read_file](file_ops.read_file.md) | `ShellFileOperations.read_file` | file-read | project | project source | 256 |
| 33 | [builtins.open.write](builtins.open.write.md) | `builtins.open (write mode)` | file-write | library | builtins.open | 270 |
| 34 | [pathlib.Path.open](pathlib.Path.open.md) | `pathlib.Path(...).open` | file-read | library | pathlib.Path.open | 284 |
| 35 | [pathlib.Path.read_bytes](pathlib.Path.read_bytes.md) | `pathlib.Path(...).read_bytes` | file-read | library | pathlib.Path.read_bytes | 302 |
| 36 | [asyncio.create_subprocess_exec](asyncio.create_subprocess_exec.md) | `asyncio.create_subprocess_exec` | process-spawn | library | asyncio.create_subprocess_exec | 326 |
| 37 | [playwright.page.goto](playwright.page.goto.md) | `playwright Page.goto` | browser-nav | library | project source | 339 |
| 38 | [builtins.open.read](builtins.open.read.md) | `builtins.open (read mode)` | file-read | library | builtins.open | 354 |
| 39 | [aiohttp.session.put](aiohttp.session.put.md) | `aiohttp ClientSession.put` | delivery-render | library | project source | 365 |
| 40 | [markdown.md.convert](markdown.md.convert.md) | `markdown Markdown.convert` | delivery-render | library | markdown.Markdown.convert | 376 |
| 41 | [supervisor.evaluate_runtime](supervisor.evaluate_runtime.md) | `CDPSupervisor.evaluate_runtime (Runtime.evaluate)` | code-eval | project | project source | 388 |
| 42 | [_run_browser_command.eval](_run_browser_command.eval.md) | `_run_browser_command(..., "eval")` | code-eval | project | project source | 399 |
| 43 | [_run_browser_command.snapshot](_run_browser_command.snapshot.md) | `_run_browser_command(..., "snapshot")` | browser-content-read | project | project source | 411 |
| 44 | [slack.chat_postMessage](slack.chat_postMessage.md) | `Slack WebClient.chat_postMessage` | delivery-render | library | project source | 423 |
| 45 | [mattermost._api_post.posts](mattermost._api_post.posts.md) | `Mattermost _api_post("posts", ...)` | delivery-render | project | project source | 430 |
| 46 | [aiohttp.session.post](aiohttp.session.post.md) | `aiohttp ClientSession.post` | delivery-render | library | project source | 439 |
| 47 | [asyncio.create_subprocess_shell](asyncio.create_subprocess_shell.md) | `asyncio.create_subprocess_shell` | process-spawn | library | asyncio.create_subprocess_shell | 458 |
| 48 | [prompt_dangerous_approval](prompt_dangerous_approval.md) | `prompt_dangerous_approval` | user-consent | project | project source | 573 |
| 49 | [mercury.command-approval](mercury.command-approval.md) | `PermissionManager.askHandler` | user-consent | project | Mercury project source | - |
