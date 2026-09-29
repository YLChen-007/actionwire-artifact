# AsyncHtmlLoader/web_path / WebBaseLoader.load(web_path)

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-419a277ba9ca7576
api: AsyncHtmlLoader/web_path / WebBaseLoader.load(web_path)
api_family: langchain.WebBaseLoader.load
runtime:
  language: python
  ecosystem: python-runtime
  package: langchain
  version: legacy-source-bound
capability_class: network-egress
normative_authority: capability-facts-only
bound_sinks:
- WebBaseLoader.load()
- AsyncHtmlLoader.load()
- WebBaseLoader.alazy_load()
- AsyncHtmlLoader.alazy_load()
roles:
- role_id: destination-url
  description: Legacy controlled role destination-url.
  bindings:
  - expression: url
    caller_bindable: true
  - expression: urls
    caller_bindable: true
facets:
- facet_id: legacy-facet-b786005a
  capability: The API fetches and parses HTML content from one or more URLs supplied as `web_path`.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-2579c38f
  capability: It issues an outbound HTTP(S) GET request to the target URL and returns the response body as LangChain Document objects.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-cf5da70f
  capability: When the attacker controls `web_path`, the API becomes a general-purpose server-side HTTP client under attacker direction.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-f0e4e460
  capability: 'It can target any routable IPv4 or IPv6 address, including:'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-4ddf5324
  capability: 'It can target cloud metadata endpoints:'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-b2ebb7f0
  capability: It can scan internal ports by varying the port component of the URL — discovering running services via response timing, content differences, or error messages.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-fd34bcf8
  capability: It can issue requests with arbitrary query strings and paths attached to the base URL, including fuzzing internal API surfaces.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-2fa43622
  capability: The sync variant (`WebBaseLoader`) uses the `requests` library; the async variant (`AsyncHtmlLoader`) uses `aiohttp`.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-d9e42f44
  capability: Any custom headers set via the `header_template` or `requests_kwargs` constructor parameters are sent to the attacker-chosen host (credential leakage of configured auth tokens/cookies to the target).
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-9a147a3f
  capability: The `requests_per_second`, `continue_on_failure`, and `raise_for_status` parameters are attacker-observable (timing side-channel) but benign in a capability sense.
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
- default_id: legacy-default-e6f9b8af
  role_id: null
  value: HTTP redirects are followed silently and by default. Both `requests` (sync) and `aiohttp` (async, when `allow_redirects` is not explicitly set) follow 3xx responses up to a default limit. An attacker can stage a redirect chain that lands on an internal address after the initial fetch passes any front-door URL check.
  security_effect: HTTP redirects are followed silently and by default. Both `requests` (sync) and `aiohttp` (async, when `allow_redirects` is not explicitly set) follow 3xx responses up to a default limit. An attacker can stage a redirect chain that lands on an internal address after the initial fetch passes any front-door URL check.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-b05e3355
  role_id: null
  value: 'DNS resolution is performed at connect time, not at URL-parse time. This enables DNS-rebinding attacks: the attacker''s DNS returns a public-safe IP initially, then returns 127.0.0.1 on subsequent resolution, bypassing any single-resolution-time check.'
  security_effect: 'DNS resolution is performed at connect time, not at URL-parse time. This enables DNS-rebinding attacks: the attacker''s DNS returns a public-safe IP initially, then returns 127.0.0.1 on subsequent resolution, bypassing any single-resolution-time check.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-24ba3682
  role_id: null
  value: 'By default the HTTP client inherits the host process''s network environment: the same VPC, subnet, security groups, IAM role, proxy settings, and `/etc/hosts` entries. No network sandboxing is applied.'
  security_effect: 'By default the HTTP client inherits the host process''s network environment: the same VPC, subnet, security groups, IAM role, proxy settings, and `/etc/hosts` entries. No network sandboxing is applied.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-b8303c97
  role_id: null
  value: The `requests` session and `aiohttp` client session, if reused, may retain cookies set by Set-Cookie response headers from a prior attacker-controlled fetch, which can be forwarded to subsequent internal targets (session-cookie-based SSRF chaining).
  security_effect: The `requests` session and `aiohttp` client session, if reused, may retain cookies set by Set-Cookie response headers from a prior attacker-controlled fetch, which can be forwarded to subsequent internal targets (session-cookie-based SSRF chaining).
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-c2dc3aaf
  role_id: null
  value: The `bs_kwargs` and `parser` arguments control HTML parsing only and do not constrain the network request; they present no defense against SSRF.
  security_effect: The `bs_kwargs` and `parser` arguments control HTML parsing only and do not constrain the network request; they present no defense against SSRF.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-5cb424a3
  role_id: null
  value: The `web_path` can be a single string URL or a list of URLs; a list provides no defense — each entry is fetched independently.
  security_effect: The `web_path` can be a single string URL or a list of URLs; a list provides no defense — each entry is fetched independently.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-dade65db
  role_id: null
  value: 'There is no built-in URL scheme restriction: file://, gopher://, dict://, and other non-HTTP schemes may be reachable depending on the underlying requests/aiohttp adapter configuration, though the default adapters are typically HTTP(S)-only.'
  security_effect: 'There is no built-in URL scheme restriction: file://, gopher://, dict://, and other non-HTTP schemes may be reachable depending on the underlying requests/aiohttp adapter configuration, though the default adapters are typically HTTP(S)-only.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-81dfafc3
  role_id: null
  value: Both loader variants accept a `requests_kwargs` dict that is forwarded directly to the underlying HTTP call; any proxy, verify, auth, or timeout overrides in that dict apply to the attacker-chosen target.
  security_effect: Both loader variants accept a `requests_kwargs` dict that is forwarded directly to the underlying HTTP call; any proxy, verify, auth, or timeout overrides in that dict apply to the attacker-chosen target.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'from langchain_community.document_loaders import WebBaseLoader


    loader = WebBaseLoader("https://en.wikipedia.org/wiki/LangChain")

    docs = loader.load()

    # docs is a list of Document objects with page_content and metadata

    '
  capability_edge: '# AWS IMDSv1 credential exfiltration via SSRF

    from langchain_community.document_loaders import WebBaseLoader


    loader = WebBaseLoader("http://169.254.169.254/latest/meta-data/iam/security-credentials/")

    docs = loader.load()

    # docs[0].page_content contains IAM role names


    # DNS rebinding chain (first request resolves to attacker.com,

    # redirect to http://127.0.0.1:6379/ probes local Redis)

    loader = WebBaseLoader("https://attacker.com/redirect-to-redis")

    docs = loader.load()

    # docs may contain Redis protocol responses if Redis is listening on 127.0.0.1:6379


    # Async variant: parallel internal port scan

    from langchain_community.document_loaders import AsyncHtmlLoader

    import asyncio


    urls = [f"http://192.168.1.{i}:8080/" for i in range(1, 255)]

    loader = AsyncHtmlLoader(urls)

    docs = asyncio.run(loader.aload())

    # time-based or content-based discovery of internal HTTP services

    '
provenance:
- OWASP Server-Side Request Forgery Prevention Cheat Sheet (https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) — covers internal IP blocking, metadata endpoints, DNS rebinding, redirect following, and scheme restrictions as the canonical SSRF capability surface.
- '{''CWE-918'': ''Server-Side Request Forgery (SSRF) (https://cwe.mitre.org/data/definitions/918.html) — classifies the attacker-controlled URL → server-side fetch pattern.''}'
- LangChain documentation for WebBaseLoader / AsyncHtmlLoader — confirms `web_path` is the sole required parameter controlling the fetch target.
- Requests library documentation — confirms default redirect-following (`allow_redirects=True`), default DNS resolution at connect time, and no built-in IP allow/block filtering.
- aiohttp documentation — confirms default `allow_redirects=True` and session-level cookie persistence.
- AWS IMDS documentation — confirms `169.254.169.254` metadata endpoint and credential retrieval paths.
```
