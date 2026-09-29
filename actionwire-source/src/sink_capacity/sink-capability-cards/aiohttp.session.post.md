# aiohttp.ClientSession.post

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-c1fdc0b4515b38af
api: aiohttp.ClientSession.post
api_family: aiohttp.session.post
runtime:
  language: python
  ecosystem: python-runtime
  package: aiohttp
  version: legacy-source-bound
capability_class: delivery-render
normative_authority: capability-facts-only
bound_sinks:
- session.post(url, json=payload, ...)
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
- facet_id: legacy-facet-5be65b47
  capability: Submit caller-influenced content to an HTTP-backed messaging or automation endpoint.
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
- default_id: legacy-default-a7f92af7
  role_id: null
  value: Session authentication, cookies, proxy settings, redirects, and TLS policy follow the aiohttp session configuration.
  security_effect: Session authentication, cookies, proxy settings, redirects, and TLS policy follow the aiohttp session configuration.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'await session.post(webhook_url, json={''text'': ''hello''})'
  capability_edge: A controlled payload can cause broad mentions, unsafe rendering, or unintended remote actions.
provenance:
- src/ql/call/sinks_af.qll aiohttp POST sink
```
