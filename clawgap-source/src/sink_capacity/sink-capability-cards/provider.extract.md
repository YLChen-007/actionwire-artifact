# WebSearchProvider.extract(urls: List[str], **kwargs: Any) -> Any

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-340b9c19c1282af2
api: 'WebSearchProvider.extract(urls: List[str], **kwargs: Any) -> Any'
api_family: provider.extract
runtime:
  language: python
  ecosystem: project-source
  package: provider
  version: legacy-source-bound
capability_class: network-egress-via-saas-proxy
normative_authority: capability-facts-only
bound_sinks: []
roles:
- role_id: destination-url
  description: Legacy controlled role destination-url.
  bindings:
  - expression: urls
    caller_bindable: true
facets:
- facet_id: legacy-facet-c43252e6
  capability: The API can cause a third-party SaaS backend (Tavily, Firecrawl, Exa, or Parallel) to make an outbound HTTP request to any attacker-specified URL and return the fetched page content into the agent process.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-432d3d7f
  capability: The returned content (markdown, HTML, raw text) is ingested into the LLM context window — the attacker can inject arbitrary text into the model's conversation by controlling which URL is fetched.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-a5687230
  capability: Each provider is an independent network-position proxy with a different egress IP address and potentially different internal-network reachability (cloud provider vs self-hosted).
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-730c16db
  capability: The SaaS backends follow HTTP 3xx redirects by default — an attacker-controlled URL can redirect to a second URL of the attacker's choice, including internal/private addresses if the SaaS backend's network position permits.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-e2d3a63e
  capability: The SaaS backends resolve DNS at connect time on the server side — the attacker can use DNS rebinding (short TTL, TOCTOU between the initial DNS check and the actual connect) to pivot from an initially-resolved public IP to a private IP.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-d5dd0d3d
  capability: Firecrawl explicitly documents post-redirect URL re-check (firecrawl/provider.py:424-425), confirming that redirect-following is default behavior and the final URL after redirects may differ from the submitted URL.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-06c54f70
  capability: The SaaS backends perform server-side HTML rendering/conversion (HTML→markdown) — the attacker can serve HTML that triggers server-side rendering behaviors (SSRF via server-side includes, JavaScript-free content smuggling via `<iframe>`/`<object>`/`<meta refresh>` that the renderer may resolve).
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-3abb6637
  capability: 'The attacker can target internal network addresses reachable from the SaaS backend''s network position: cloud metadata endpoints (169.254.169.254 on AWS/GCP/Azure), internal services, localhost of the SaaS infrastructure, link-local addresses.'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-5dd0a44d
  capability: The attacker can probe the SaaS backend's outbound connectivity by supplying URLs with arbitrary schemes and ports — HTTP, HTTPS on any TCP port; some backends may support non-HTTP schemes if the underlying HTTP client does not restrict them.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-2d933640
  capability: The attacker can exfiltrate data from the SaaS backend's network by encoding it in the URL path/query of a request to an attacker-controlled server (DNS lookups, HTTP request logging) — the SaaS backend's outbound IP, User-Agent, and request timing are observable.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-56afac95
  capability: The attacker can use the SaaS backend to bypass egress firewalls that would block direct outbound connections from the agent host — the agent reaches the SaaS API on a well-known port (443), and the SaaS backend performs the actual page fetch from a different network.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-c7929ce4
  capability: Multiple URLs can be submitted in a single call (urls is a List[str]) — the attacker can batch requests across different targets, including mixing public URLs with internal-network probes.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-9f60fa15
  capability: The returned content carries metadata (title, sourceURL, raw_content) that may leak information about the SaaS backend's internal resolution (e.g., resolved IP embedded in metadata, timing side-channels in response ordering).
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
- default_id: legacy-default-c64bb620
  role_id: null
  value: HTTP redirect following is ON by default in all four provider backends (standard httpx/SDK behavior).
  security_effect: HTTP redirect following is ON by default in all four provider backends (standard httpx/SDK behavior).
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-afe62b21
  role_id: null
  value: DNS resolution happens at the SaaS service side — the SaaS backend's DNS resolver and network position determine what IP the hostname resolves to.
  security_effect: DNS resolution happens at the SaaS service side — the SaaS backend's DNS resolver and network position determine what IP the hostname resolves to.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-a49f3b5b
  role_id: null
  value: HTML-to-markdown conversion happens server-side at the SaaS backend before content reaches the agent.
  security_effect: HTML-to-markdown conversion happens server-side at the SaaS backend before content reaches the agent.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-bb4223ab
  role_id: null
  value: The SaaS API endpoints use HTTPS (port 443) — the agent→SaaS connection is encrypted, but the SaaS→target-URL connection may use plain HTTP if the URL scheme is http://.
  security_effect: The SaaS API endpoints use HTTPS (port 443) — the agent→SaaS connection is encrypted, but the SaaS→target-URL connection may use plain HTTP if the URL scheme is http://.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-1a0e3504
  role_id: null
  value: 'Timeouts vary by provider: Tavily 60s (tavily/provider.py:57), Firecrawl 60s per-URL (firecrawl/provider.py:492), Exa uses SDK default, Parallel uses SDK default.'
  security_effect: 'Timeouts vary by provider: Tavily 60s (tavily/provider.py:57), Firecrawl 60s per-URL (firecrawl/provider.py:492), Exa uses SDK default, Parallel uses SDK default.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-060899a0
  role_id: null
  value: No URL scheme restriction in the provider contracts — http://, https:// are supported; ftp://, file://, gopher:// depend on the SaaS backend's HTTP client capabilities.
  security_effect: No URL scheme restriction in the provider contracts — http://, https:// are supported; ftp://, file://, gopher:// depend on the SaaS backend's HTTP client capabilities.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-e2d06627
  role_id: null
  value: Raw and rendered content are both returned (raw_content and content fields) — the attacker gets two content representations injected.
  security_effect: Raw and rendered content are both returned (raw_content and content fields) — the attacker gets two content representations injected.
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
