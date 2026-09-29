"""
Parse src/ql/call/sinks_af.qll and enumerate every sink API disjunct defined in
`is_sink_af`, producing a `SinkAPI` registry.

Design:
  1. Depth-aware splitter cuts the predicate body into top-level `or`-separated
     disjuncts (guarantees completeness — every disjunct becomes one row).
  2. An ordered RULES table classifies each disjunct into a clean SinkAPI
     (id / capability_class / import_path for doc introspection / kind).
     Matching is by distinctive substrings of the disjunct's QL text, so it is
     robust to disjunct ordering. A generic fallback labels anything unmatched
     so nothing is silently dropped.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional


@dataclass
class SinkAPI:
    slug: str                      # filesystem-safe id -> card file name (<slug>.md)
    api: str                       # display id, e.g. "subprocess.Popen"
    capability_class: str          # process-spawn / file-read / network-egress / ...
    kind: str                      # "library" | "project" (project-internal wrapper)
    import_path: Optional[str]     # dotted path for introspection, e.g. "subprocess.Popen"; None for project/builtin-special
    match: str                     # short human note on how the QL disjunct matches
    ql_index: int = 0              # 0-based disjunct index within is_sink_af
    ql_start_line: int = 0         # 1-based line in sinks_af.qll where the disjunct begins
    ql_snippet: str = ""           # raw QL text of the disjunct (comments stripped)

    def to_row(self) -> dict:
        d = asdict(self)
        d.pop("ql_snippet", None)
        return d


# --------------------------------------------------------------------------- #
# 1. Split is_sink_af body into top-level disjuncts
# --------------------------------------------------------------------------- #
def _predicate_body(text: str) -> tuple[str, int]:
    """Return (body_between_outer_braces, offset_of_body_start) for is_sink_af."""
    m = re.search(r"predicate\s+is_sink_af\s*\(\s*CallNode\s+cn\s*\)\s*\{", text)
    if not m:
        raise ValueError("is_sink_af predicate not found")
    start = m.end()  # just past the opening {
    depth = 1
    i = start
    n = len(text)
    while i < n and depth > 0:
        c = text[i]
        if c == '"':                       # skip string literal
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == '\\' else 1
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start:i], start
        i += 1
    raise ValueError("unbalanced braces in is_sink_af")


def _strip_line_comments(body: str) -> str:
    out = []
    for line in body.splitlines():
        j = line.find("//")
        out.append(line[:j] if j >= 0 else line)
    return "\n".join(out)


def split_disjuncts(body: str) -> list[str]:
    """Cut body into segments separated by the keyword `or` at brace/paren depth 0."""
    body = _strip_line_comments(body)
    segs: list[str] = []
    depth = 0
    start = 0
    i = 0
    n = len(body)
    while i < n:
        c = body[i]
        if c == '"':
            i += 1
            while i < n and body[i] != '"':
                i += 2 if body[i] == '\\' else 1
            i += 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif (
            depth == 0
            and body.startswith("or", i)
            and (i == 0 or not (body[i - 1].isalnum() or body[i - 1] == "_"))
            and (i + 2 >= n or not (body[i + 2].isalnum() or body[i + 2] == "_"))
        ):
            segs.append(body[start:i])
            i += 2
            start = i
            continue
        i += 1
    segs.append(body[start:])
    return [s.strip() for s in segs if s.strip()]


# --------------------------------------------------------------------------- #
# 2. Classify a disjunct into a SinkAPI
# --------------------------------------------------------------------------- #
# Each rule: (test(text)->bool, SinkAPI-without-ql-fields). First match wins.
# `test` uses distinctive substrings of the disjunct's QL text.
def _has(*subs):
    def t(text: str) -> bool:
        return all(s in text for s in subs)
    return t


_RULES: list[tuple] = [
    # ---- user consent / approval ----
    (_has("prompt_dangerous_approval", '"check_all_command_guards"'),
     ("prompt_dangerous_approval", "prompt_dangerous_approval", "user-consent", "project", None,
      "prompt_dangerous_approval(command, description, ...)")),
    # ---- process / command execution ----
    (_has('= "submit"', "subprocess"),
     ("subprocess.run.via-executor-submit", "subprocess.run (Executor.submit)", "process-spawn", "library", "subprocess.run",
      'X.submit(subprocess.run, ...)')),
    (_has('= "Popen"', "subprocess"),
     ("subprocess.Popen", "subprocess.Popen", "process-spawn", "library", "subprocess.Popen",
      "subprocess.Popen(...)")),
    (_has('= "run"', "subprocess"),
     ("subprocess.run", "subprocess.run", "process-spawn", "library", "subprocess.run",
      "subprocess.run(...)")),
    (_has('= "system"', '"os"'),
     ("os.system", "os.system", "process-spawn", "library", "os.system", "os.system(cmd)")),
    (_has("create_subprocess_exec", "asyncio"),
     ("asyncio.create_subprocess_exec", "asyncio.create_subprocess_exec", "process-spawn", "library",
      "asyncio.create_subprocess_exec", "asyncio.create_subprocess_exec(*args)")),
    (_has("create_subprocess_shell", "asyncio"),
     ("asyncio.create_subprocess_shell", "asyncio.create_subprocess_shell", "process-spawn", "library",
      "asyncio.create_subprocess_shell", "asyncio.create_subprocess_shell(cmd)")),
    (_has('"ShellTool"'),
     ("langchain.ShellTool.run", "ShellTool.run", "process-spawn", "library", None, "<ShellTool>.run(...)")),
    (_has('= "spawn"', '"_PtyProcessCls"'),
     ("ptyprocess.PtyProcess.spawn", "ptyprocess PtyProcess.spawn", "process-spawn", "library", None,
      "_PtyProcessCls.spawn(argv, ...)")),
    # ---- code / template evaluation ----
    (_has('= "execute_code"'),
     ("execute_code", "execute_code (attr call)", "code-eval", "project", None, "<obj>.execute_code(...)")),
    (_has('(NameNode).getNode().toString() = "eval"'),
     ("builtins.eval", "builtins.eval", "code-eval", "library", "builtins.eval", "eval(expr)")),
    (_has('(NameNode).getNode().toString() = "exec"'),
     ("builtins.exec", "builtins.exec", "code-eval", "library", "builtins.exec", "exec(code)")),
    (_has('"PythonREPL"'),
     ("langchain.PythonREPL.run", "PythonREPL.run", "code-eval", "library", None, "<PythonREPL>.run(code)")),
    (_has("get_ipython", "run_cell"),
     ("IPython.run_cell", "InteractiveShell.run_cell", "code-eval", "library", None, "<get_ipython()>.run_cell(code)")),
    (_has("evaluate_runtime", "supervisor"),
     ("supervisor.evaluate_runtime", "CDPSupervisor.evaluate_runtime (Runtime.evaluate)", "code-eval", "project",
      None, "supervisor.evaluate_runtime(expression)")),
    (_has('= "send"', '["ws", "self._ws"]'),
     ("websocket.send.cdp", "WebSocket send (CDP dispatch)", "code-eval", "library", None,
      "ws.send(json.dumps(cdp_request))")),
    (_has("_run_browser_command", '"eval"'),
     ("_run_browser_command.eval", '_run_browser_command(..., "eval")', "code-eval", "project", None,
      '_run_browser_command(task, "eval", [expr])')),
    # ---- browser navigation / content ----
    (_has("_run_browser_command", '"open"'),
     ("_run_browser_command.open", '_run_browser_command(..., "open")', "browser-nav", "project", None,
      '_run_browser_command(task, "open", [url])')),
    (_has("_run_browser_command", '"snapshot"'),
     ("_run_browser_command.snapshot", '_run_browser_command(..., "snapshot")', "browser-content-read", "project", None,
      '_run_browser_command(task, "snapshot", ...)')),
    (_has("camofox_navigate"),
     ("camofox_navigate", "camofox_navigate", "browser-nav", "project", None, "camofox_navigate(url, task_id)")),
    (_has('= "goto"', '"page"'),
     ("playwright.page.goto", "playwright Page.goto", "browser-nav", "library", None, "page.goto(url)")),
    # ---- network egress ----
    (_has('["request","get"]', "AsyncClient"),
     ("http.session.request-get", "httpx/aiohttp/requests session .get/.request", "network-egress", "library",
      "httpx.AsyncClient.get", "<AsyncClient|ClientSession|Session>.get/request(url)")),
    (_has('["arun"]', "AsyncWebCrawler"),
     ("crawl4ai.AsyncWebCrawler.arun", "AsyncWebCrawler.arun", "network-egress", "library", None,
      "<AsyncWebCrawler>.arun(url)")),
    (_has('["get", "post", "request"]', '"requests"'),
     ("requests.get-post-request", "requests.get/post/request", "network-egress", "library", "requests.get",
      "requests.get/post/request(url)")),
    (_has("%Client", "httpx"),
     ("httpx.Client.request", "httpx.Client.request (annotated param)", "network-egress", "library",
      "httpx.Client.request", "<httpx.Client param>.request(url)")),
    (_has('= "extract"', '"provider"'),
     ("provider.extract", "WebSearchProvider.extract", "network-egress", "project", None, "provider.extract(urls)")),
    (_has('= "to_thread"', '= "scrape"'),
     ("firecrawl.scrape.to-thread", "Firecrawl scrape via asyncio.to_thread", "network-egress", "library", None,
      "asyncio.to_thread(client.scrape, ...)")),
    (_has('= "get_contents"'),
     ("exa.get_contents", "Exa get_contents", "network-egress", "library", None,
      "<Exa client>.get_contents(urls, ...)")),
    (_has('= "extract"', '= "beta"'),
     ("parallel.beta.extract", "Parallel beta.extract", "network-egress", "library", None,
      "<AsyncParallel>.beta.extract(urls=...)")),
    (_has("AsyncHtmlLoader", "WebBaseLoader"),
     ("langchain.WebBaseLoader.load", "AsyncHtmlLoader/WebBaseLoader.load", "network-egress", "library", None,
      "<WebBaseLoader>.load()")),
    (_has('= "GitLoader"'),
     ("langchain.GitLoader", "GitLoader", "network-egress", "library", None, "GitLoader(...)")),
    # ---- file read / write ----
    (_has('= "read_text"'),
     ("pathlib.Path.read_text", "pathlib.Path.read_text", "file-read", "library", "pathlib.Path.read_text",
      "<Path>.read_text(...)")),
    (_has('= "read_file"', '"file_ops"'),
     ("file_ops.read_file", "ShellFileOperations.read_file", "file-read", "project", None,
      "file_ops.read_file(path, ...)")),
    (_has('= "read_bytes"', "Path"),
     ("pathlib.Path.read_bytes", "pathlib.Path(...).read_bytes", "file-read", "library", "pathlib.Path.read_bytes",
      "Path(path).read_bytes()")),
    (_has('= "open"', "Path"),
     ("pathlib.Path.open", "pathlib.Path(...).open", "file-read", "library", "pathlib.Path.open",
      "Path(path).open('rb')")),
    (_has('= "open"', '["w", "a"'),
     ("builtins.open.write", "builtins.open (write mode)", "file-write", "library", "builtins.open",
      "open(path, 'w'/'a'/...)")),
    (_has('= "open"', '["r", "rb", "rt"]'),
     ("builtins.open.read", "builtins.open (read mode)", "file-read", "library", "builtins.open",
      "open(path, 'r'/'rb'/'rt')")),
    # ---- delivery / rendering ----
    (_has('= "send_message_event"'),
     ("matrix.send_message_event", "mautrix Client.send_message_event", "delivery-render", "library", None,
      "client.send_message_event(room_id, event_type, content)")),
    (_has('= "put"', '= "session"'),
     ("aiohttp.session.put", "aiohttp ClientSession.put", "delivery-render", "library", None,
      "session.put(url, ...)")),
    (_has('= "convert"', '"md"'),
     ("markdown.md.convert", "markdown Markdown.convert", "delivery-render", "library", "markdown.Markdown.convert",
      "md.convert(text)")),
    (_has('= "chat_postMessage"'),
     ("slack.chat_postMessage", "Slack WebClient.chat_postMessage", "delivery-render", "library", None,
      "<Slack WebClient>.chat_postMessage(...)")),
    (_has('= "_api_post"', '= "posts"'),
     ("mattermost._api_post.posts", 'Mattermost _api_post("posts", ...)', "delivery-render", "project", None,
      'self._api_post("posts", payload)')),
    (_has('= "post"', '= "session"'),
     ("aiohttp.session.post", "aiohttp ClientSession.post", "delivery-render", "library", None,
      "session.post(url, ...)")),
    # ---- SQL / template ----
    (_has(".cursor"),
     ("db.cursor.execute", "DB-API cursor.execute", "sql-exec", "library", None, "<cursor>.execute(sql)")),
    (_has("from_llm", "SQLDatabaseChain"),
     ("langchain.SQLDatabaseChain.run", "SQLDatabaseChain.run/invoke", "sql-exec", "library", None,
      "<SQLDatabaseChain>.run/invoke(...)")),
    (_has("%session.execute"),
     ("sqlalchemy.session.execute", "SQLAlchemy session.execute", "sql-exec", "library", None, "session.execute(sql)")),
    (_has("connection.execute"),
     ("sqlalchemy.connection.execute", "connection.execute", "sql-exec", "library", None, "connection.execute(sql)")),
    (_has("jinja.from_string"),
     ("jinja2.from_string", "Jinja2 Environment.from_string", "template-injection", "library", None,
      "jinja.from_string(tpl)")),
]


def classify(snippet: str) -> tuple:
    for test, rec in _RULES:
        if test(snippet):
            return rec
    # fallback: pull a method or bare name so nothing is dropped
    m = re.search(r'getName\(\)\s*=\s*"([^"]+)"', snippet) or re.search(
        r'toString\(\)\s*=\s*"([^"]+)"', snippet
    )
    name = m.group(1) if m else "UNKNOWN"
    slug = "unclassified." + re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    return (slug, name, "other", "library", None, "unclassified disjunct")


# --------------------------------------------------------------------------- #
# 3. Top-level API
# --------------------------------------------------------------------------- #
def extract(qll_path: str | Path) -> list[SinkAPI]:
    text = Path(qll_path).read_text(encoding="utf-8")
    body, body_off = _predicate_body(text)
    disjuncts = split_disjuncts(body)

    # map each disjunct to its line in the original file using a monotonic cursor
    # over a distinctive probe (longest quoted literal, else longest code line).
    cursor = body_off

    def start_line(snippet: str) -> int:
        nonlocal cursor
        lits = re.findall(r'"[^"]+"', snippet)
        probe = max(lits, key=len) if lits else max(
            (ln.strip() for ln in snippet.splitlines()), key=len, default=""
        )
        if probe:
            idx = text.find(probe, cursor)
            if idx >= 0:
                cursor = idx + len(probe)
                return text.count("\n", 0, idx) + 1
        return 0

    seen: set[str] = set()
    out: list[SinkAPI] = []
    for i, d in enumerate(disjuncts):
        slug, api, cls, kind, imp, match = classify(d)
        line = start_line(d)
        # ensure unique slug (duplicate underlying API disambiguated by index)
        base = slug
        k = 2
        while slug in seen:
            slug = f"{base}.{k}"
            k += 1
        seen.add(slug)
        out.append(
            SinkAPI(
                slug=slug, api=api, capability_class=cls, kind=kind, import_path=imp,
                match=match, ql_index=i, ql_start_line=line,
                ql_snippet=re.sub(r"\n\s*\n", "\n", d.strip()),
            )
        )
    return out


if __name__ == "__main__":
    import sys
    apis = extract(sys.argv[1] if len(sys.argv) > 1 else "src/ql/call/sinks_af.qll")
    print(f"{len(apis)} sink API disjuncts\n")
    for a in apis:
        print(f"[{a.ql_index:2}] L{a.ql_start_line:<4} {a.capability_class:20} {a.kind:7} {a.api}")
