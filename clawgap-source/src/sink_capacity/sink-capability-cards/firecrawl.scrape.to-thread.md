# Firecrawl.scrape

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-3b2487467f5840eb
api: Firecrawl.scrape
api_family: firecrawl.scrape.to-thread
runtime:
  language: python
  ecosystem: python-runtime
  package: firecrawl
  version: legacy-source-bound
capability_class: network-egress
normative_authority: capability-facts-only
bound_sinks:
- asyncio.to_thread(client.scrape, url, ...)
roles:
- role_id: destination-url
  description: Legacy controlled role destination-url.
  bindings:
  - expression: url
    caller_bindable: true
facets:
- facet_id: legacy-facet-99cd9d08
  capability: Fetch and parse a caller-selected URL through the configured Firecrawl service.
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
- default_id: legacy-default-35537d97
  role_id: null
  value: Redirect, DNS, authentication, and rendering behavior follow the configured Firecrawl backend.
  security_effect: Redirect, DNS, authentication, and rendering behavior follow the configured Firecrawl backend.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: await asyncio.to_thread(client.scrape, 'https://example.com')
  capability_edge: A private or special-use destination can become SSRF when no destination policy is enforced.
provenance:
- src/ql/call/sinks_af.qll Firecrawl sink
```
