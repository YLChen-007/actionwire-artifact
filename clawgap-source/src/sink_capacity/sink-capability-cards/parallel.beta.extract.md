# Parallel.beta.extract

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-cf53a32c327d06c1
api: Parallel.beta.extract
api_family: parallel.beta.extract
runtime:
  language: python
  ecosystem: python-runtime
  package: parallel
  version: legacy-source-bound
capability_class: network-egress
normative_authority: capability-facts-only
bound_sinks:
- parallel_client.beta.extract(urls=..., ...)
roles:
- role_id: destination-url
  description: Legacy controlled role destination-url.
  bindings:
  - expression: urls
    caller_bindable: true
facets:
- facet_id: legacy-facet-a81e0de5
  capability: Send caller-selected URLs to the Parallel extraction service and return extracted content.
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
- default_id: legacy-default-afc06b12
  role_id: null
  value: The configured service credential and service-side network policy apply.
  security_effect: The configured service credential and service-side network policy apply.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: await client.beta.extract(urls=['https://example.com'])
  capability_edge: Unvalidated destinations can expose content outside the intended public-web scope.
provenance:
- src/ql/call/sinks_af.qll Parallel extraction sink
```
