# httpx.AsyncClient.post(url, *, content=..., data=..., files=..., json=..., ...)

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-07270440da1dc963
api: httpx.AsyncClient.post(url, *, content=..., data=..., files=..., json=..., ...)
api_family: httpx.AsyncClient.post
runtime:
  language: python
  ecosystem: python-runtime
  package: httpx
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
- facet_id: legacy-facet-cbd39f08
  capability: 'API: `httpx.AsyncClient.post(url, *, content=..., data=..., files=..., json=..., ...)`'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-b008332f
  capability: 'Capability class: `network-egress`'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-8b25f0e7
  capability: 'Controlled argument: the destination URL and/or outbound request body.'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-94634154
  capability: 'Capability constraint: performs an HTTP POST to the selected destination and transmits the'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-d8f5576e
  capability: 'Source: HTTPX async client public API.'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
library_guarantees: []
defaults: []
example_usage:
  benign: See the source-owned legacy card for the original benign example.
  capability_edge: See the source-owned legacy card for the original capability-edge example.
provenance:
- source-owned legacy capability card
```
