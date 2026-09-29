# aiohttp.ClientSession.put

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-0f221f2bc0d0578c
api: aiohttp.ClientSession.put
api_family: aiohttp.session.put
runtime:
  language: python
  ecosystem: python-runtime
  package: aiohttp
  version: legacy-source-bound
capability_class: delivery-render
normative_authority: capability-facts-only
bound_sinks:
- session.put(url, json=payload, ...)
roles:
- role_id: content
  description: Legacy controlled role content.
  bindings:
  - expression: payload
    caller_bindable: true
- role_id: destination-url
  description: Legacy controlled role destination-url.
  bindings:
  - expression: url
    caller_bindable: true
facets:
- facet_id: legacy-facet-b8b50d7e
  capability: Send caller-influenced structured content to a remote delivery endpoint using HTTP PUT.
  role_ids:
  - content
  - destination-url
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
library_guarantees: []
defaults:
- default_id: legacy-default-6bd79c5c
  role_id: null
  value: Session credentials, cookies, proxy settings, redirects, and TLS policy follow the aiohttp session configuration.
  security_effect: Session credentials, cookies, proxy settings, redirects, and TLS policy follow the aiohttp session configuration.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'await session.put(matrix_url, json={''body'': ''hello''})'
  capability_edge: A controlled payload can trigger mentions or unsafe rendering in the destination service.
provenance:
- src/ql/call/sinks_af.qll aiohttp PUT sink
```
