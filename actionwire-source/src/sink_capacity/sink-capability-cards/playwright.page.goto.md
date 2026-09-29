# playwright Page.goto

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-f33e8810d1253e04
api: playwright Page.goto
api_family: playwright.page.goto
runtime:
  language: python
  ecosystem: python-runtime
  package: playwright
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
facets:
- facet_id: legacy-facet-9c147231
  capability: Navigate a headful/headless Chromium (or Firefox via Camoufox) browser tab to ANY URL
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-6517b282
  capability: SSRF — access internal/private network resources reachable from the host where the
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-7ad91d28
  capability: 'Loopback: http://127.0.0.1, http://[::1], http://localhost on any port.'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-b8e67d31
  capability: 'RFC 1918: http://10.x.x.x, http://172.16-31.x.x, http://192.168.x.x.'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-84c13a33
  capability: 'Link-local: http://169.254.x.x, including cloud metadata endpoints.'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-898337ab
  capability: 'Cloud metadata service access:'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-fad0dce7
  capability: 'AWS IMDSv1/v2: http://169.254.169.254/latest/meta-data/,'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-376bc2ee
  capability: 'GCP: http://metadata.google.internal/computeMetadata/v1/.'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-ca5a1551
  capability: 'Azure: http://169.254.169.254/metadata/instance.'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-2761c5cd
  capability: 'DigitalOcean: http://169.254.169.254/metadata/v1.json.'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-77bd13f5
  capability: 'Oracle Cloud: http://169.254.169.254/opc/v2/instance/.'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-86c0e0d3
  capability: 'URL scheme abuse — the browser resolves ANY registered scheme, not just http/https:'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-2e3e4fa5
  capability: file:// — read local files from the host filesystem (file:///etc/passwd,
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-2a4cc841
  capability: 'data: — render attacker-supplied HTML/JS/CSS inline as a fully functional page'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-8405d91b
  capability: 'about: — access browser internal pages (about:blank, about:version,'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-d3ac5f61
  capability: 'javascript: — execute JS in the context of the CURRENT page when navigating from'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-7ca965e9
  capability: 'blob: — create and navigate to blob URLs containing arbitrary content, useful'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-2423ede4
  capability: 'view-source: — view the source of any reachable URL, including local files'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-bc5c5d48
  capability: 'In Chromium: chrome://, chrome-extension://, devtools:// — access browser'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-e9d44c72
  capability: Arbitrary TCP port probing — every https?:// navigation attempts a TCP+TLS
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-ae1cabf6
  capability: 'HTTP redirect following (IMPLICIT — enabled by default): the browser follows 3xx'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-c9e5fd61
  capability: 'JavaScript-driven navigation: after the initial page loads (especially with'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-54ae185b
  capability: 'DNS resolution at connect-time (IMPLICIT): the hostname in the URL is resolved to'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-511ba963
  capability: 'Browser cookie and storage access: navigating to an origin the browser has'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-437d3fac
  capability: 'Referer control: the optional `referer` parameter sets the Referer header'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-fbb16683
  capability: 'Response exfiltration path: page.goto returns a Response object containing status,'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-9892136b
  capability: 'Service Worker registration: a malicious page loaded via page.goto can call'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-8aafe6e8
  capability: 'WebSocket / WebRTC origination: JavaScript on the loaded page can open WebSocket'
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
- default_id: legacy-default-ae74d280
  role_id: null
  value: wait_until defaults to "load" — the method waits for the full page load event
  security_effect: wait_until defaults to "load" — the method waits for the full page load event
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-d4ef8e75
  role_id: null
  value: timeout defaults to 30 000 ms (30 seconds), which is sufficient for most internal
  security_effect: timeout defaults to 30 000 ms (30 seconds), which is sufficient for most internal
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-16a45a0a
  role_id: null
  value: Redirect following is ON by default and cannot be disabled via page.goto
  security_effect: Redirect following is ON by default and cannot be disabled via page.goto
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-bc3fba34
  role_id: null
  value: The browser shares its network namespace with the OS process that launched it;
  security_effect: The browser shares its network namespace with the OS process that launched it;
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-cea9204e
  role_id: null
  value: The browser inherits the host's environment variables (http_proxy, https_proxy,
  security_effect: The browser inherits the host's environment variables (http_proxy, https_proxy,
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-1b5b5940
  role_id: null
  value: If Playwright launches the browser with `--no-sandbox` (common in Docker/CI),
  security_effect: If Playwright launches the browser with `--no-sandbox` (common in Docker/CI),
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: See the source-owned legacy card for the original benign example.
  capability_edge: See the source-owned legacy card for the original capability-edge example.
provenance:
- source-owned legacy capability card
```
