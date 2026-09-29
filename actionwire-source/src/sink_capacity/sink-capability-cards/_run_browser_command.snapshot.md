# _run_browser_command(task_id, "snapshot", args)

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-0e3c34f894bdc24e
api: _run_browser_command(task_id, "snapshot", args)
api_family: _run_browser_command.snapshot
runtime:
  language: python
  ecosystem: project-source
  package: _run_browser_command
  version: legacy-source-bound
capability_class: browser-content-read
normative_authority: capability-facts-only
bound_sinks:
- browser_snapshot
roles:
- role_id: command
  description: Legacy controlled role command.
  bindings:
  - expression: args
    caller_bindable: true
facets:
- facet_id: legacy-facet-7ab9ec18
  capability: Read the full accessibility tree (ARIA snapshot) of the currently loaded page in the browser session, including all visible text, headings, paragraphs, link texts, button labels, form field values, and landmark regions.
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-1f2a8e4d
  capability: Enumerate every interactive element on the page — links, buttons, inputs, selects, textareas — each annotated with a stable ref ID (e.g. @e1, @e2) that can be passed to browser_click / browser_type for follow-on interactions.
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-27c58cee
  capability: 'In full mode (no `-c` flag): extract the complete page text content, including non-interactive body text, table contents, list items, and aria-label/aria-describedby annotations.'
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-8614c6b1
  capability: 'In compact mode (`-c` flag): extract only interactive elements and their labels/states, producing a lean action-oriented view of the page.'
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-e6ad9663
  capability: Read form input current values, including prefilled or user-typed text in text fields, selected options in dropdowns, and checkbox/radio toggle states.
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-55ba7bb8
  capability: Read content that was dynamically injected or modified by client-side JavaScript — the snapshot reflects the live DOM accessibility tree, not the initial server-rendered HTML.
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-3662cbc1
  capability: Read content from any origin/domain the browser session has navigated to, including cross-origin pages loaded in the same tab.
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-6f9f0bf2
  capability: Read content behind authentication gates (OAuth, session cookies, JWTs) because the snapshot inherits the browser session's full credential state — cookies, localStorage, sessionStorage, and HTTP auth headers.
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-400cf9e4
  capability: 'Capture page metadata: document title, URL, and loading state from the accessibility tree root node.'
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-da9897a5
  capability: Read content of iframes whose accessibility trees are exposed to the parent document (same-origin iframes or cross-origin iframes with appropriate permissions).
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-a6a5a505
  capability: 'Read hidden-but-accessible content: elements with `aria-hidden="false"` that are off-screen, in collapsed sections, or behind modals, as long as they remain in the accessibility tree.'
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-68d2c7e2
  capability: 'In cloud/CDP mode: read page content rendered on a remote Browserbase/Browser Use instance, the snapshot traverses the wire via the CDP `Accessibility.getFullAXTree` (or equivalent) command over the WebSocket connection; no local browser needed.'
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-577df37d
  capability: 'In local mode: read page content rendered in a local headless Chromium instance launched via `agent-browser --session`, using the local filesystem for socket communication.'
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-82bc0d9a
  role_id: null
  value: Defaults to full snapshot mode (all page content) when `args` is omitted or empty; compact mode only when `-c` is explicitly passed.
  security_effect: Defaults to full snapshot mode (all page content) when `args` is omitted or empty; compact mode only when `-c` is explicitly passed.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-cfcedeb7
  role_id: null
  value: 'Inherits the full browser session state: all cookies, localStorage, sessionStorage, IndexedDB, and HTTP authentication credentials of the current session.'
  security_effect: 'Inherits the full browser session state: all cookies, localStorage, sessionStorage, IndexedDB, and HTTP authentication credentials of the current session.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-a2771102
  role_id: null
  value: Inherits the current page URL — whatever page the browser session is presently displaying is what gets snapshotted; there is no URL parameter on the snapshot command itself.
  security_effect: Inherits the current page URL — whatever page the browser session is presently displaying is what gets snapshotted; there is no URL parameter on the snapshot command itself.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-66574832
  role_id: null
  value: Inherits environment variables from the parent process (`os.environ`), including PATH, AGENT_BROWSER_SOCKET_DIR, and AGENT_BROWSER_IDLE_TIMEOUT_MS — controlled through the hermes-agent process environment.
  security_effect: Inherits environment variables from the parent process (`os.environ`), including PATH, AGENT_BROWSER_SOCKET_DIR, and AGENT_BROWSER_IDLE_TIMEOUT_MS — controlled through the hermes-agent process environment.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-ef006ab1
  role_id: null
  value: 'Inherits proxy configuration from the session setup (`_get_session_info`): cloud sessions route through Browserbase proxies; local sessions use the host''s network configuration.'
  security_effect: 'Inherits proxy configuration from the session setup (`_get_session_info`): cloud sessions route through Browserbase proxies; local sessions use the host''s network configuration.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-97151630
  role_id: null
  value: 'In local mode: the browser process inherits the host''s filesystem access, network interfaces, and any `--no-sandbox` flag auto-injected when running as root or under AppArmor-restricted user namespaces.'
  security_effect: 'In local mode: the browser process inherits the host''s filesystem access, network interfaces, and any `--no-sandbox` flag auto-injected when running as root or under AppArmor-restricted user namespaces.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-8b4408a6
  role_id: null
  value: The agent-browser daemon auto-starts if not already running for the session, and persists across commands — a snapshot can be taken silently at any time after a single navigate, without visible side effects to the page.
  security_effect: The agent-browser daemon auto-starts if not already running for the session, and persists across commands — a snapshot can be taken silently at any time after a single navigate, without visible side effects to the page.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-87d1e6a0
  role_id: null
  value: Snapshot output is returned as raw JSON parsed from stdout; there is no size limit applied at the CLI layer — the full accessibility tree text is captured regardless of length (truncation/summarization is applied in the Python wrapper at 8000 chars, but the underlying CLI returns unbounded output).
  security_effect: Snapshot output is returned as raw JSON parsed from stdout; there is no size limit applied at the CLI layer — the full accessibility tree text is captured regardless of length (truncation/summarization is applied in the Python wrapper at 8000 chars, but the underlying CLI returns unbounded output).
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-42117acc
  role_id: null
  value: 'In cloud mode (`--cdp`): the command connects to a remote WebSocket URL determined by `_get_session_info(task_id)`, meaning the snapshot reads whatever page that remote browser instance has loaded.'
  security_effect: 'In cloud mode (`--cdp`): the command connects to a remote WebSocket URL determined by `_get_session_info(task_id)`, meaning the snapshot reads whatever page that remote browser instance has loaded.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: '# Normal use: agent retrieves page content after navigation

    from tools.browser_tool import browser_navigate, browser_snapshot


    browser_navigate("https://example.com", task_id="task_1")

    result = browser_snapshot(task_id="task_1")  # compact snapshot by default

    print(result)  # {"success": true, "snapshot": "...", "element_count": 42}


    # Full content read

    result = browser_snapshot(full=True, task_id="task_1")

    print(result)  # complete page accessibility tree'
  capability_edge: '# Attacker-controlled model triggers a full snapshot to read authenticated

    # content from a session that was navigated to a sensitive internal page.

    # The model controls `args` (empty = full dump, or ["-c"] = interactive scan).

    from tools.browser_tool import _run_browser_command


    # Full dump of current page — all visible text, form values, hidden labels

    result = _run_browser_command("task_1", "snapshot", args=[])

    page_content = result["data"]["snapshot"]   # complete accessibility tree text

    refs = result["data"]["refs"]               # all interactive element refs


    # Compact scan: enumerate all clickable/typeable elements with their labels

    result = _run_browser_command("task_1", "snapshot", args=["-c"])

    interactive_elements = result["data"]["snapshot"]


    # The snapshot inherits the session''s authenticated state — if the browser

    # is logged into an internal dashboard, the snapshot captures:

    #   - All visible dashboard data (user lists, API keys, financial figures)

    #   - Pre-filled form values in input fields

    #   - CSRF tokens rendered in hidden inputs or meta tags (if exposed to a11y tree)

    #   - Page title and URL (often containing resource IDs)'
provenance:
- tools/browser_tool.py:1895-1901 — _run_browser_command(task_id, command, args) signature and docstring
- tools/browser_tool.py:1991-2098 — builds and executes `agent-browser --json snapshot [args]` via subprocess.Popen
- tools/browser_tool.py:2113-2149 — reads stdout from temp file, parses JSON, extracts data.snapshot and data.refs
- tools/browser_tool.py:2517-2583 — browser_snapshot() wrapper that delegates to _run_browser_command(task_id, 'snapshot', args)
- tools/browser_tool.py:1968-1975 — cloud mode uses --cdp <WebSocket URL> to connect to remote Browserbase/Browser Use instance; local mode uses --session to launch local headless Chromium
- tools/browser_tool.py:11-12 — docstring confirms snapshot uses agent-browser's accessibility tree (ariaSnapshot)
- tools/browser_tool.py:2014-2018 — subprocess inherits os.environ and merges browser-specific PATH, AGENT_BROWSER_SOCKET_DIR
- 'agent-browser npm package: `snapshot` command calls CDP Accessibility.getFullAXTree (or ariaSnapshot in newer CDP) against the connected browser target, returning a text serialization of the AXTree'
```
